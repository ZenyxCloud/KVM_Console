package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type testCluster struct {
	caPEM []byte
	srv   *httptest.Server
	port  int
}

func newTestCluster(t *testing.T, name string) *testCluster {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Proxmox Virtual Environment " + name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name + "-node1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(fakePVEHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return &testCluster{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), srv: srv, port: port}
}

func TestSeveralClustersWithTheirOwnCA(t *testing.T) {
	a := newTestCluster(t, "cluster-a")
	b := newTestCluster(t, "cluster-b")
	rogue := newTestCluster(t, "rogue")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cluster-a.pem"), a.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster-b.crt"), b.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}

	ports := strconv.Itoa(a.port) + "," + strconv.Itoa(b.port) + "," + strconv.Itoa(rogue.port)
	env := map[string]string{
		"API_KEY":              testAPIKey,
		"WHMCS_IPS":            "127.0.0.1",
		"PVE_ALLOWED_NETWORKS": "127.0.0.0/8",
		"PVE_ALLOWED_PORTS":    ports,
		"PVE_CA_FILE":          dir,
		"ALLOWED_ORIGINS":      testOrigin,
	}
	cfg, err := LoadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	gw := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	h := &harness{t: t, gw: gw, srv: srv}

	open := func(port int) (*http.Response, error) {
		f := url.Values{
			"securityToken":         {testAPIKey},
			"URL":                   {"https://127.0.0.1:" + strconv.Itoa(port) + "/api2/json/nodes/pve1/qemu/101/vncwebsocket?port=5900&vncticket=" + url.QueryEscape(testTicket)},
			"COOKIE[PVEAuthCookie]": {testCookie},
			"ip":                    {"127.0.0.1"},
		}
		status, body := h.requestToken(f)
		if status != http.StatusCreated {
			t.Fatalf("token for port %d: %d %v", port, status, body)
		}
		conn, resp, err := h.dial(body["token"].(string), testOrigin)
		if err == nil {
			conn.Close(websocket.StatusNormalClosure, "")
		}
		return resp, err
	}

	for name, c := range map[string]*testCluster{"cluster-a": a, "cluster-b": b} {
		if _, err := open(c.port); err != nil {
			t.Errorf("%s should be reachable: %v", name, err)
		}
	}
	if resp, err := open(rogue.port); err == nil || resp.StatusCode != http.StatusBadGateway {
		t.Errorf("cluster with an unknown CA must be refused, got %v %v", resp, err)
	}
}

func TestCAFileList(t *testing.T) {
	a := newTestCluster(t, "a")
	b := newTestCluster(t, "b")
	dir := t.TempDir()
	fa, fb := filepath.Join(dir, "a.pem"), filepath.Join(dir, "b.pem")
	os.WriteFile(fa, a.caPEM, 0o600)
	os.WriteFile(fb, b.caPEM, 0o600)
	pool, err := loadCAs([]string{fa, fb})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(pool.Subjects()); n != 2 {
		t.Fatalf("expected 2 CAs, got %d", n)
	}
	if _, err := loadCAs([]string{filepath.Join(dir, "missing.pem")}); err == nil {
		t.Fatal("missing file must fail")
	}
	empty := t.TempDir()
	if _, err := loadCAs([]string{empty}); err == nil {
		t.Fatal("empty directory must fail")
	}
	bad := filepath.Join(dir, "bad.pem")
	os.WriteFile(bad, []byte("not a certificate"), 0o600)
	if _, err := loadCAs([]string{bad}); err == nil {
		t.Fatal("invalid PEM must fail")
	}
}
