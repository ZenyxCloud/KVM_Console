package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var (
	wsPathRe   = regexp.MustCompile(`^/auth/([A-Za-z0-9]{32})/proxmox$`)
	pvePathRe  = regexp.MustCompile(`^/api2/json/nodes/([A-Za-z0-9][A-Za-z0-9.-]{0,62})/(qemu|lxc)/([0-9]{1,9})/vncwebsocket$`)
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\.?$`)
)

type Server struct {
	cfg      *Config
	tokens   *TokenStore
	log      *slog.Logger
	dialer   *Dialer
	sessions *SessionLimiter
}

func NewServer(cfg *Config, log *slog.Logger) *Server {
	return &Server{
		cfg:      cfg,
		tokens:   NewTokenStore(cfg.TokenTTL, cfg.MaxPendingTokens),
		log:      log,
		dialer:   NewDialer(cfg),
		sessions: NewSessionLimiter(cfg.MaxSessions, cfg.MaxSessionsPerIP),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/auth/", s.handleConsole)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErrors(w, http.StatusMethodNotAllowed, "Invalid HTTP method")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"sessions":       s.sessions.Active(),
		"pending_tokens": s.tokens.Pending(),
	})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrors(w, http.StatusMethodNotAllowed, "Invalid HTTP method")
		return
	}
	caller := s.clientIP(r)
	if !caller.IsValid() || !containsAddr(s.cfg.WHMCSNetworks, caller) {
		s.log.Warn("token request from address not in WHMCS_IPS", "remote", caller.String())
		writeErrors(w, http.StatusUnauthorized, fmt.Sprintf("The IP Address '%s' is not in whitelisted.", caller))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeErrors(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	key := r.PostForm.Get("securityToken")
	if subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.APIKey)) != 1 {
		s.log.Warn("token request with invalid API key", "remote", caller.String())
		writeErrors(w, http.StatusUnauthorized, "Parameter verification failed 'securityToken' is invalid")
		return
	}
	target, err := s.parseTarget(r.PostForm.Get("URL"), r.PostForm.Get("COOKIE[PVEAuthCookie]"), r.PostForm.Get("ip"))
	if err != nil {
		s.log.Warn("token request rejected", "remote", caller.String(), "reason", err.Error())
		writeErrors(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	tok, id, err := s.tokens.Issue(target)
	if err != nil {
		s.log.Error("token issue failed", "error", err.Error())
		writeErrors(w, http.StatusServiceUnavailable, "Console proxy is busy, try again later")
		return
	}
	s.log.Info("console token issued", "node", target.Node, "type", target.Kind, "vmid", target.VMID, "client_ip", target.ClientIP.String())
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "token": tok})
}

func (s *Server) parseTarget(rawURL, authToken, ip string) (Target, error) {
	var t Target
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil || u.Fragment != "" {
		return t, errors.New("The URL field is invalid.")
	}
	if u.Scheme != "https" && u.Scheme != "wss" {
		return t, errors.New("The URL must use https.")
	}
	host := u.Hostname()
	port := 443
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return t, errors.New("The URL port is invalid.")
		}
	}
	if !s.cfg.PVEPorts[port] {
		return t, errors.New("The URL port is not allowed.")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" || !containsAddr(s.cfg.PVENetworks, a) {
			return t, errors.New("The Proxmox host is not allowed.")
		}
	} else if !hostnameRe.MatchString(host) || len(host) > 253 {
		return t, errors.New("The Proxmox host is invalid.")
	}
	m := pvePathRe.FindStringSubmatch(u.EscapedPath())
	if m == nil {
		return t, errors.New("The URL path is not a Proxmox console websocket.")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return t, errors.New("The URL query is invalid.")
	}
	for k := range q {
		if k != "port" && k != "vncticket" {
			return t, errors.New("The URL query is invalid.")
		}
	}
	vncPort, err := strconv.Atoi(q.Get("port"))
	if err != nil || len(q["port"]) != 1 || vncPort < 1 || vncPort > 65535 {
		return t, errors.New("The console port is invalid.")
	}
	ticket := q.Get("vncticket")
	if len(q["vncticket"]) != 1 || ticket == "" || len(ticket) > 4096 {
		return t, errors.New("The console ticket is invalid.")
	}
	if !validCookieValue(authToken) {
		return t, errors.New("Auth Cookie is empty")
	}
	clientIP, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || clientIP.Zone() != "" {
		return t, errors.New("The ip field must be a valid IP address.")
	}
	canonicalHost := host
	if strings.Contains(host, ":") {
		canonicalHost = "[" + host + "]"
	}
	t.URL = "wss://" + canonicalHost + ":" + strconv.Itoa(port) + m[0] +
		"?port=" + strconv.Itoa(vncPort) + "&vncticket=" + url.QueryEscape(ticket)
	t.AuthToken = authToken
	t.Node, t.Kind, t.VMID = m[1], m[2], m[3]
	t.ClientIP = clientIP.Unmap()
	return t, nil
}

func validCookieValue(v string) bool {
	if v == "" || len(v) > 4096 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= 0x20 || c >= 0x7f || c == ';' || c == ',' || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func (s *Server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	remote = remote.Unmap()
	if len(s.cfg.TrustedProxies) == 0 || !containsAddr(s.cfg.TrustedProxies, remote) {
		return remote
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	if len(hops) == 0 {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-Ip"))); err == nil {
			return a.Unmap()
		}
		return remote
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			return remote
		}
		a = a.Unmap()
		if i == 0 || !containsAddr(s.cfg.TrustedProxies, a) {
			return a
		}
	}
	return remote
}

func (s *Server) originAllowed(r *http.Request) bool {
	if len(s.cfg.AllowedOrigins) == 0 {
		return true
	}
	return s.cfg.AllowedOrigins[strings.ToLower(r.Header.Get("Origin"))]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErrors(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"errors": []string{msg}})
}

type SessionLimiter struct {
	mu     sync.Mutex
	max    int
	perIP  int
	total  int
	byAddr map[netip.Addr]int
}

func NewSessionLimiter(max, perIP int) *SessionLimiter {
	return &SessionLimiter{max: max, perIP: perIP, byAddr: map[netip.Addr]int{}}
}

func (l *SessionLimiter) Acquire(a netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.max || l.byAddr[a] >= l.perIP {
		return false
	}
	l.total++
	l.byAddr[a]++
	return true
}

func (l *SessionLimiter) Release(a netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.byAddr[a]--; l.byAddr[a] <= 0 {
		delete(l.byAddr, a)
	}
}

func (l *SessionLimiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}
