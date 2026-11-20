package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr         string
	TLSCertFile        string
	TLSKeyFile         string
	APIKey             string
	WHMCSNetworks      []netip.Prefix
	PVENetworks        []netip.Prefix
	PVEPorts           map[int]bool
	PVETLS             *tls.Config
	AllowedOrigins     map[string]bool
	ClientIPValidate   bool
	TrustedProxies     []netip.Prefix
	TokenTTL           time.Duration
	MaxPendingTokens   int
	MaxSessions        int
	MaxSessionsPerIP   int
	SessionMaxDuration time.Duration
	DialTimeout        time.Duration
	PingInterval       time.Duration
	ClientReadLimit    int64
}

func LoadConfig(getenv func(string) string) (*Config, error) {
	var errs []error
	c := &Config{
		ListenAddr:  envOr(getenv, "LISTEN_ADDR", ":8080"),
		TLSCertFile: getenv("TLS_CERT_FILE"),
		TLSKeyFile:  getenv("TLS_KEY_FILE"),
		APIKey:      getenv("API_KEY"),
	}

	if file := getenv("API_KEY_FILE"); file != "" && c.APIKey == "" {
		b, err := os.ReadFile(file)
		if err != nil {
			errs = append(errs, fmt.Errorf("API_KEY_FILE: %w", err))
		}
		c.APIKey = strings.TrimSpace(string(b))
	}
	if len(c.APIKey) < 32 {
		errs = append(errs, errors.New("API_KEY must be set and at least 32 characters long"))
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be set together"))
	}

	var err error
	if c.WHMCSNetworks, err = parsePrefixes(getenv("WHMCS_IPS")); err != nil {
		errs = append(errs, fmt.Errorf("WHMCS_IPS: %w", err))
	} else if len(c.WHMCSNetworks) == 0 {
		errs = append(errs, errors.New("WHMCS_IPS must list the WHMCS server addresses"))
	}
	if c.PVENetworks, err = parsePrefixes(getenv("PVE_ALLOWED_NETWORKS")); err != nil {
		errs = append(errs, fmt.Errorf("PVE_ALLOWED_NETWORKS: %w", err))
	} else if len(c.PVENetworks) == 0 {
		errs = append(errs, errors.New("PVE_ALLOWED_NETWORKS must list the networks of the Proxmox nodes"))
	}
	if c.TrustedProxies, err = parsePrefixes(getenv("TRUSTED_PROXIES")); err != nil {
		errs = append(errs, fmt.Errorf("TRUSTED_PROXIES: %w", err))
	}

	c.PVEPorts = map[int]bool{}
	for _, p := range splitList(envOr(getenv, "PVE_ALLOWED_PORTS", "8006")) {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			errs = append(errs, fmt.Errorf("PVE_ALLOWED_PORTS: invalid port %q", p))
			continue
		}
		c.PVEPorts[n] = true
	}

	c.AllowedOrigins = map[string]bool{}
	for _, o := range splitList(getenv("ALLOWED_ORIGINS")) {
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
			errs = append(errs, fmt.Errorf("ALLOWED_ORIGINS: invalid origin %q", o))
			continue
		}
		c.AllowedOrigins[strings.ToLower(u.Scheme+"://"+u.Host)] = true
	}

	if c.ClientIPValidate, err = parseBool(envOr(getenv, "CLIENT_IP_VALIDATE", "false")); err != nil {
		errs = append(errs, fmt.Errorf("CLIENT_IP_VALIDATE: %w", err))
	}

	c.PVETLS = &tls.Config{MinVersion: tls.VersionTLS12}
	insecure, err := parseBool(envOr(getenv, "PVE_TLS_INSECURE", "false"))
	if err != nil {
		errs = append(errs, fmt.Errorf("PVE_TLS_INSECURE: %w", err))
	}
	c.PVETLS.InsecureSkipVerify = insecure
	if file := getenv("PVE_CA_FILE"); file != "" {
		pem, err := os.ReadFile(file)
		if err != nil {
			errs = append(errs, fmt.Errorf("PVE_CA_FILE: %w", err))
		} else {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				errs = append(errs, errors.New("PVE_CA_FILE: no PEM certificate found"))
			}
			c.PVETLS.RootCAs = pool
		}
	}

	c.TokenTTL = durationEnv(getenv, "TOKEN_TTL", 60*time.Second, &errs)
	c.SessionMaxDuration = durationEnv(getenv, "SESSION_MAX_DURATION", 12*time.Hour, &errs)
	c.DialTimeout = durationEnv(getenv, "PVE_DIAL_TIMEOUT", 10*time.Second, &errs)
	c.PingInterval = durationEnv(getenv, "PING_INTERVAL", 25*time.Second, &errs)
	c.MaxPendingTokens = intEnv(getenv, "MAX_PENDING_TOKENS", 10000, &errs)
	c.MaxSessions = intEnv(getenv, "MAX_SESSIONS", 500, &errs)
	c.MaxSessionsPerIP = intEnv(getenv, "MAX_SESSIONS_PER_IP", 10, &errs)
	c.ClientReadLimit = int64(intEnv(getenv, "CLIENT_MESSAGE_LIMIT", 4<<20, &errs))

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func envOr(getenv func(string) string, key, def string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(s) {
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid network %q", item)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", item)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "1", "true", "on", "yes":
		return true, nil
	case "0", "false", "off", "no":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q", s)
}

func durationEnv(getenv func(string) string, key string, def time.Duration, errs *[]error) time.Duration {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		*errs = append(*errs, fmt.Errorf("%s: invalid duration %q", key, v))
		return def
	}
	return d
}

func intEnv(getenv func(string) string, key string, def int, errs *[]error) int {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		*errs = append(*errs, fmt.Errorf("%s: invalid positive integer %q", key, v))
		return def
	}
	return n
}

func containsAddr(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
