package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const (
	testAPIKey  = "0123456789abcdef0123456789abcdef"
	testCookie  = "PVE:client101@pve:6740A1B2::c2lnbmF0dXJl+/="
	testTicket  = "PVEVNC:6740A1B2::dGlja2V0+/="
	testOrigin  = "https://my.zenyx.eu"
	bigFrameLen = 3 << 20
)

type fakePVE struct {
	srv  *httptest.Server
	port int
}

func newFakePVE(t *testing.T) *fakePVE {
	t.Helper()
	srv := httptest.NewTLSServer(fakePVEHandler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return &fakePVE{srv: srv, port: port}
}

func fakePVEHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/nodes/pve1/qemu/101/vncwebsocket", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("PVEAuthCookie")
		if err != nil || c.Value != testCookie || r.URL.Query().Get("vncticket") != testTicket || r.URL.Query().Get("port") != "5900" {
			http.Error(w, "permission denied", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Origin") != "" {
			http.Error(w, "unexpected origin", http.StatusBadRequest)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}})
		if err != nil {
			return
		}
		conn.SetReadLimit(-1)
		ctx := context.Background()
		if err := conn.Write(ctx, websocket.MessageBinary, []byte("RFB 003.008\n")); err != nil {
			return
		}
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			switch string(data) {
			case "big":
				data = bytes.Repeat([]byte{0xAB}, bigFrameLen)
			case "bye":
				conn.Close(websocket.StatusNormalClosure, "vm stopped")
				return
			default:
				data = append([]byte("echo:"), data...)
			}
			if err := conn.Write(ctx, typ, data); err != nil {
				return
			}
		}
	})
	return mux
}

func testConfig(t *testing.T, pve *fakePVE, overrides map[string]string) *Config {
	t.Helper()
	env := map[string]string{
		"API_KEY":              testAPIKey,
		"WHMCS_IPS":            "127.0.0.1, ::1",
		"PVE_ALLOWED_NETWORKS": "127.0.0.0/8",
		"PVE_ALLOWED_PORTS":    strconv.Itoa(pve.port),
		"ALLOWED_ORIGINS":      testOrigin,
		"PING_INTERVAL":        "1s",
	}
	for k, v := range overrides {
		env[k] = v
	}
	cfg, err := LoadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(pve.srv.Certificate())
	cfg.PVETLS.RootCAs = pool
	return cfg
}

type harness struct {
	t   *testing.T
	pve *fakePVE
	gw  *Server
	srv *httptest.Server
}

func newHarness(t *testing.T, overrides map[string]string) *harness {
	t.Helper()
	pve := newFakePVE(t)
	gw := NewServer(testConfig(t, pve, overrides), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(gw.Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, pve: pve, gw: gw, srv: srv}
}

func (h *harness) pveURL(host string) string {
	return "https://" + host + ":" + strconv.Itoa(h.pve.port) +
		"/api2/json/nodes/pve1/qemu/101/vncwebsocket?port=5900&vncticket=" + url.QueryEscape(testTicket)
}

func (h *harness) requestToken(form url.Values) (int, map[string]any) {
	h.t.Helper()
	resp, err := http.Post(h.srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		h.t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func (h *harness) validForm() url.Values {
	return url.Values{
		"securityToken":         {testAPIKey},
		"URL":                   {h.pveURL("127.0.0.1")},
		"host":                  {"127.0.0.1:" + strconv.Itoa(h.pve.port)},
		"COOKIE[PVEAuthCookie]": {testCookie},
		"ip":                    {"127.0.0.1"},
	}
}

func (h *harness) issue() string {
	h.t.Helper()
	status, body := h.requestToken(h.validForm())
	if status != http.StatusCreated {
		h.t.Fatalf("token status %d: %v", status, body)
	}
	tok, _ := body["token"].(string)
	if !validToken(tok) {
		h.t.Fatalf("bad token %q", tok)
	}
	return tok
}

func (h *harness) dial(tok, origin string) (*websocket.Conn, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hdr := http.Header{}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	wsURL := "ws" + strings.TrimPrefix(h.srv.URL, "http") + "/auth/" + tok + "/proxmox"
	return websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: hdr, Subprotocols: []string{"binary", "base64"}})
}

func TestPublicHealthOnlyReportsLiveness(t *testing.T) {
	h := newHarness(t, nil)
	conn, _, err := h.dial(h.issue(), testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	h.issue()
	waitFor(t, func() bool { return h.gw.sessions.Active() == 1 })

	resp, err := http.Get(h.srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(body) != 1 || body["status"] != "ok" {
		t.Fatalf("health status %d, body %v", resp.StatusCode, body)
	}
}

func TestConsoleRoundTrip(t *testing.T) {
	h := newHarness(t, nil)
	conn, _, err := h.dial(h.issue(), testOrigin)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(-1)
	if conn.Subprotocol() != "binary" {
		t.Fatalf("subprotocol %q", conn.Subprotocol())
	}
	ctx := context.Background()
	typ, data, err := conn.Read(ctx)
	if err != nil || typ != websocket.MessageBinary || string(data) != "RFB 003.008\n" {
		t.Fatalf("banner %v %q %v", typ, data, err)
	}
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	typ, data, err = conn.Read(ctx)
	if err != nil || typ != websocket.MessageText || string(data) != "echo:hello" {
		t.Fatalf("echo %v %q %v", typ, data, err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("big")); err != nil {
		t.Fatal(err)
	}
	_, data, err = conn.Read(ctx)
	if err != nil || len(data) != bigFrameLen {
		t.Fatalf("big frame len %d err %v", len(data), err)
	}
	time.Sleep(1500 * time.Millisecond)
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("after-ping")); err != nil {
		t.Fatal(err)
	}
	if _, data, err = conn.Read(ctx); err != nil || string(data) != "echo:after-ping" {
		t.Fatalf("after keepalive %q %v", data, err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("bye")); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Fatalf("expected normal close from proxmox, got %v", err)
	}
	waitFor(t, func() bool { return h.gw.sessions.Active() == 0 })
}

type consoleHandshake struct {
	http.ResponseWriter
	wire *bufio.ReadWriter
}

func (w *consoleHandshake) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, wire, err := w.ResponseWriter.(http.Hijacker).Hijack()
	w.wire = wire
	return conn, wire, err
}

func TestProxmoxAcceptsTerminalInputFrames(t *testing.T) {
	// Real Proxmox rejects fragmented frames and forwards each payload to
	// the same terminal byte stream. A generic websocket server accepts fragments.
	input := bytes.Repeat([]byte("é"), 80<<10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handshake := &consoleHandshake{ResponseWriter: w}
		upstream, err := websocket.Accept(handshake, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}})
		if err != nil {
			t.Error(err)
			return
		}
		defer upstream.CloseNow()

		var output []byte
		for len(output) < len(input) {
			var header [2]byte
			if _, err := io.ReadFull(handshake.wire, header[:]); err != nil {
				t.Error(err)
				return
			}
			if header[0] != 0x82 || header[1]&0x80 == 0 {
				t.Errorf("expected a masked, final binary frame, got %x", header)
				return
			}
			size := uint64(header[1] & 0x7f)
			switch size {
			case 126:
				var extended uint16
				if err := binary.Read(handshake.wire, binary.BigEndian, &extended); err != nil {
					t.Error(err)
					return
				}
				size = uint64(extended)
			case 127:
				if err := binary.Read(handshake.wire, binary.BigEndian, &size); err != nil {
					t.Error(err)
					return
				}
			}
			if size == 0 || size > 128<<10 {
				t.Errorf("unsupported Proxmox frame size %d", size)
				return
			}
			var mask [4]byte
			if _, err := io.ReadFull(handshake.wire, mask[:]); err != nil {
				t.Error(err)
				return
			}
			payload := make([]byte, size)
			if _, err := io.ReadFull(handshake.wire, payload); err != nil {
				t.Error(err)
				return
			}
			for i := range payload {
				payload[i] ^= mask[i%len(mask)]
			}
			output = append(output, payload...)
		}
		if !bytes.Equal(output, input) {
			t.Error("Proxmox did not receive the original terminal input")
			return
		}
		if err := upstream.Write(context.Background(), websocket.MessageBinary, []byte("OK")); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()

	pveURL, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(pveURL.Port())
	pve := &fakePVE{srv: srv, port: port}
	gateway := NewServer(testConfig(t, pve, nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	gatewayServer := httptest.NewServer(gateway.Handler())
	defer gatewayServer.Close()
	h := &harness{t: t, pve: pve, gw: gateway, srv: gatewayServer}

	conn, _, err := h.dial(h.issue(), testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, input); err != nil {
		t.Fatal(err)
	}
	if _, reply, err := conn.Read(ctx); err != nil || string(reply) != "OK" {
		t.Fatalf("terminal reply %q: %v", reply, err)
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	h := newHarness(t, nil)
	tok := h.issue()
	conn, _, err := h.dial(tok, testOrigin)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	conn.Close(websocket.StatusNormalClosure, "")
	_, resp, err := h.dial(tok, testOrigin)
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay must be refused, got %v %v", resp, err)
	}
}

func TestTokenExpires(t *testing.T) {
	h := newHarness(t, map[string]string{"TOKEN_TTL": "30"})
	tok := h.issue()
	h.gw.tokens.now = func() time.Time { return time.Now().Add(31 * time.Second) }
	_, resp, err := h.dial(tok, testOrigin)
	if err == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired token must be refused, got %v %v", resp, err)
	}
	if h.gw.tokens.Pending() != 0 {
		t.Fatal("expired token still stored")
	}
}

func TestOriginCheckedBeforeTokenIsConsumed(t *testing.T) {
	h := newHarness(t, nil)
	tok := h.issue()
	_, resp, err := h.dial(tok, "https://evil.example")
	if err == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign origin must be refused, got %v %v", resp, err)
	}
	_, resp, err = h.dial(tok, "")
	if err == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing origin must be refused, got %v %v", resp, err)
	}
	conn, _, err := h.dial(tok, testOrigin)
	if err != nil {
		t.Fatalf("token should still be usable: %v", err)
	}
	conn.CloseNow()
}

func TestTokenEndpointAuthentication(t *testing.T) {
	h := newHarness(t, nil)
	form := h.validForm()
	form.Set("securityToken", "wrong")
	if status, _ := h.requestToken(form); status != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", status)
	}
	form.Del("securityToken")
	if status, _ := h.requestToken(form); status != http.StatusUnauthorized {
		t.Fatalf("missing key: %d", status)
	}

	h2 := newHarness(t, map[string]string{"WHMCS_IPS": "192.0.2.10"})
	if status, body := h2.requestToken(h2.validForm()); status != http.StatusUnauthorized || body["errors"] == nil {
		t.Fatalf("caller outside WHMCS_IPS: %d %v", status, body)
	}

	resp, err := http.Get(h.srv.URL + "/token")
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /token: %v %v", resp, err)
	}
}

func TestTokenTargetValidation(t *testing.T) {
	h := newHarness(t, nil)
	port := strconv.Itoa(h.pve.port)
	cases := map[string]func(url.Values){
		"public host": func(f url.Values) { f.Set("URL", h.pveURL("8.8.8.8")) },
		"other port":  func(f url.Values) { f.Set("URL", strings.Replace(h.pveURL("127.0.0.1"), ":"+port+"/", ":22/", 1)) },
		"plain http":  func(f url.Values) { f.Set("URL", strings.Replace(h.pveURL("127.0.0.1"), "https://", "http://", 1)) },
		"api path": func(f url.Values) {
			f.Set("URL", "https://127.0.0.1:"+port+"/api2/json/access/ticket?port=5900&vncticket=x")
		},
		"path traversal": func(f url.Values) {
			f.Set("URL", "https://127.0.0.1:"+port+"/api2/json/nodes/pve1/qemu/101/../../../access/vncwebsocket?port=5900&vncticket=x")
		},
		"extra query": func(f url.Values) { f.Set("URL", h.pveURL("127.0.0.1")+"&node=x") },
		"missing ticket": func(f url.Values) {
			f.Set("URL", "https://127.0.0.1:"+port+"/api2/json/nodes/pve1/qemu/101/vncwebsocket?port=5900")
		},
		"userinfo": func(f url.Values) {
			f.Set("URL", strings.Replace(h.pveURL("127.0.0.1"), "https://", "https://a:b@", 1))
		},
		"cookie injection": func(f url.Values) { f.Set("COOKIE[PVEAuthCookie]", "x; other=1") },
		"cookie missing":   func(f url.Values) { f.Del("COOKIE[PVEAuthCookie]") },
		"bad client ip":    func(f url.Values) { f.Set("ip", "not-an-ip") },
		"zone in proxmox":  func(f url.Values) { f.Set("URL", h.pveURL("[fe80::1%25eth0]")) },
		"weird hostname":   func(f url.Values) { f.Set("URL", h.pveURL("pve_1.internal")) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := h.validForm()
			mutate(f)
			status, body := h.requestToken(f)
			if status != http.StatusUnprocessableEntity {
				t.Fatalf("status %d body %v", status, body)
			}
		})
	}
	if h.gw.tokens.Pending() != 0 {
		t.Fatal("rejected requests must not create tokens")
	}
}

func TestHostnameResolvingOutsideAllowedNetworksIsNotDialed(t *testing.T) {
	h := newHarness(t, map[string]string{"PVE_ALLOWED_NETWORKS": "10.0.0.0/8"})
	f := h.validForm()
	f.Set("URL", h.pveURL("localhost"))
	status, body := h.requestToken(f)
	if status != http.StatusCreated {
		t.Fatalf("hostname token: %d %v", status, body)
	}
	_, resp, err := h.dial(body["token"].(string), testOrigin)
	if err == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("dial outside allowed networks must fail, got %v %v", resp, err)
	}
}

func TestUpstreamRefusalIsBadGateway(t *testing.T) {
	h := newHarness(t, nil)
	f := h.validForm()
	f.Set("COOKIE[PVEAuthCookie]", "PVE:someone-else")
	_, body := h.requestToken(f)
	_, resp, err := h.dial(body["token"].(string), testOrigin)
	if err == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %v %v", resp, err)
	}
	if h.gw.sessions.Active() != 0 {
		t.Fatal("session slot leaked")
	}
}

func TestUntrustedProxmoxCertificateIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.gw.cfg.PVETLS.RootCAs = x509.NewCertPool()
	h.gw.dialer = NewDialer(h.gw.cfg)
	_, resp, err := h.dial(h.issue(), testOrigin)
	if err == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 on untrusted certificate, got %v %v", resp, err)
	}
}

func TestClientIPBinding(t *testing.T) {
	h := newHarness(t, map[string]string{"CLIENT_IP_VALIDATE": "on"})
	f := h.validForm()
	f.Set("ip", "203.0.113.5")
	_, body := h.requestToken(f)
	_, resp, err := h.dial(body["token"].(string), testOrigin)
	if err == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other client ip must be refused, got %v %v", resp, err)
	}
	conn, _, err := h.dial(h.issue(), testOrigin)
	if err != nil {
		t.Fatalf("matching client ip: %v", err)
	}
	conn.CloseNow()
}

func TestSessionLimitPerIP(t *testing.T) {
	h := newHarness(t, map[string]string{"MAX_SESSIONS_PER_IP": "1"})
	first, _, err := h.dial(h.issue(), testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseNow()
	_, resp, err := h.dial(h.issue(), testOrigin)
	if err == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second session must be refused, got %v %v", resp, err)
	}
	first.Close(websocket.StatusNormalClosure, "")
	waitFor(t, func() bool { return h.gw.sessions.Active() == 0 })
	again, _, err := h.dial(h.issue(), testOrigin)
	if err != nil {
		t.Fatalf("slot not released: %v", err)
	}
	again.CloseNow()
}

func TestPendingTokenCap(t *testing.T) {
	h := newHarness(t, map[string]string{"MAX_PENDING_TOKENS": "2"})
	h.issue()
	h.issue()
	if status, _ := h.requestToken(h.validForm()); status != http.StatusServiceUnavailable {
		t.Fatalf("cap not enforced: %d", status)
	}
}

func TestClientIPBehindTrustedProxy(t *testing.T) {
	cfg := &Config{}
	cfg.TrustedProxies, _ = parsePrefixes("10.0.0.0/8")
	s := &Server{cfg: cfg}
	req := func(remote string, xff ...string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		r    *http.Request
		want string
	}{
		{req("198.51.100.7:1234", "1.2.3.4"), "198.51.100.7"},
		{req("10.0.0.2:1234", "1.2.3.4"), "1.2.3.4"},
		{req("10.0.0.2:1234", "6.6.6.6, 1.2.3.4"), "1.2.3.4"},
		{req("10.0.0.2:1234", "1.2.3.4, 10.0.0.9"), "1.2.3.4"},
		{req("10.0.0.2:1234"), "10.0.0.2"},
		{req("[::ffff:10.0.0.2]:1234", "2001:db8::1"), "2001:db8::1"},
	}
	for i, c := range cases {
		if got := s.clientIP(c.r); got.String() != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]string{"API_KEY": testAPIKey, "WHMCS_IPS": "192.0.2.1", "PVE_ALLOWED_NETWORKS": "10.0.0.0/8"}
	load := func(over map[string]string) error {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range over {
			env[k] = v
		}
		_, err := LoadConfig(func(k string) string { return env[k] })
		return err
	}
	if err := load(nil); err != nil {
		t.Fatalf("base config: %v", err)
	}
	for name, over := range map[string]map[string]string{
		"short key":       {"API_KEY": "short"},
		"no whmcs":        {"WHMCS_IPS": ""},
		"no pve networks": {"PVE_ALLOWED_NETWORKS": ""},
		"bad network":     {"PVE_ALLOWED_NETWORKS": "10.0.0.0/99"},
		"bad origin":      {"ALLOWED_ORIGINS": "my.zenyx.eu"},
		"origin path":     {"ALLOWED_ORIGINS": "https://my.zenyx.eu/clientarea"},
		"bad bool":        {"CLIENT_IP_VALIDATE": "maybe"},
		"half tls":        {"TLS_CERT_FILE": "/x.pem"},
		"bad ttl":         {"TOKEN_TTL": "-5"},
	} {
		if load(over) == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestRandomToken(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		tok, err := randomToken(32)
		if err != nil || !validToken(tok) || seen[tok] {
			t.Fatalf("bad token %q %v", tok, err)
		}
		seen[tok] = true
	}
	if validToken("short") || validToken(strings.Repeat("a", 31)+"-") {
		t.Fatal("validToken accepts invalid input")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
