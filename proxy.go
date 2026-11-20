package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

type Dialer struct {
	cfg    *Config
	client *http.Client
}

func NewDialer(cfg *Config) *Dialer {
	nd := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("refused upstream address %q", address)
			}
			if !containsAddr(cfg.PVENetworks, ap.Addr()) {
				return fmt.Errorf("upstream address %s is outside PVE_ALLOWED_NETWORKS", ap.Addr())
			}
			if !cfg.PVEPorts[int(ap.Port())] {
				return fmt.Errorf("upstream port %d is not allowed", ap.Port())
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         nd.DialContext,
		TLSClientConfig:     cfg.PVETLS.Clone(),
		TLSHandshakeTimeout: cfg.DialTimeout,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        0,
		DisableKeepAlives:   true,
	}
	return &Dialer{cfg: cfg, client: &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (d *Dialer) Dial(ctx context.Context, t Target, subprotocols []string) (*websocket.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, d.cfg.DialTimeout*2)
	defer cancel()
	h := http.Header{}
	h.Set("Cookie", "PVEAuthCookie="+t.AuthToken)
	conn, resp, err := websocket.Dial(ctx, t.URL, &websocket.DialOptions{
		HTTPClient:      d.client,
		HTTPHeader:      h,
		Subprotocols:    subprotocols,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("proxmox answered HTTP %d", resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
}

func (s *Server) handleConsole(w http.ResponseWriter, r *http.Request) {
	m := wsPathRe.FindStringSubmatch(r.URL.Path)
	if m == nil {
		writeErrors(w, http.StatusNotFound, "Invalid API endpoint")
		return
	}
	if r.Method != http.MethodGet {
		writeErrors(w, http.StatusMethodNotAllowed, "Invalid HTTP method")
		return
	}
	client := s.clientIP(r)
	if !client.IsValid() {
		writeErrors(w, http.StatusBadRequest, "Invalid client address")
		return
	}
	if !s.originAllowed(r) {
		s.log.Warn("console refused: origin not allowed", "client_ip", client.String(), "origin", r.Header.Get("Origin"))
		writeErrors(w, http.StatusForbidden, "Origin not allowed")
		return
	}
	if !validToken(m[1]) {
		writeErrors(w, http.StatusUnauthorized, "The token is invalid.")
		return
	}
	target, ok := s.tokens.Redeem(m[1])
	if !ok {
		s.log.Warn("console refused: unknown, used or expired token", "client_ip", client.String())
		writeErrors(w, http.StatusUnauthorized, "The token is invalid.")
		return
	}
	logger := s.log.With("node", target.Node, "type", target.Kind, "vmid", target.VMID, "client_ip", client.String())
	if s.cfg.ClientIPValidate && target.ClientIP != client {
		logger.Warn("console refused: client address differs from the WHMCS session", "expected_ip", target.ClientIP.String())
		writeErrors(w, http.StatusUnauthorized, fmt.Sprintf("The token and client IP Address: '%s' is invalid.", client))
		return
	}
	if !s.sessions.Acquire(client) {
		logger.Warn("console refused: session limit reached")
		writeErrors(w, http.StatusTooManyRequests, "Too many console sessions")
		return
	}
	defer s.sessions.Release(client)

	upstream, err := s.dialer.Dial(r.Context(), target, requestedSubprotocols(r))
	if err != nil {
		logger.Error("proxmox websocket connection failed", "error", err.Error())
		writeErrors(w, http.StatusBadGateway, "Console connection could not be established.")
		return
	}
	upstream.SetReadLimit(-1)

	var accepted []string
	if p := upstream.Subprotocol(); p != "" {
		accepted = []string{p}
	}
	downstream, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       accepted,
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		upstream.Close(websocket.StatusGoingAway, "client handshake failed")
		logger.Warn("client websocket handshake failed", "error", err.Error())
		return
	}
	downstream.SetReadLimit(s.cfg.ClientReadLimit)

	start := time.Now()
	logger.Info("console session opened")
	up, down, reason := s.relay(r.Context(), downstream, upstream)
	logger.Info("console session closed", "duration", time.Since(start).Round(time.Second).String(), "bytes_to_vm", up, "bytes_to_client", down, "reason", reason)
}

func requestedSubprotocols(r *http.Request) []string {
	var out []string
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func (s *Server) relay(parent context.Context, client, upstream *websocket.Conn) (int64, int64, string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.cfg.SessionMaxDuration)
	defer cancel()

	var toVM, toClient atomic.Int64
	type result struct {
		from string
		err  error
	}
	done := make(chan result, 2)
	go func() { done <- result{"client", copyMessages(ctx, upstream, client, &toVM)} }()
	go func() { done <- result{"proxmox", copyMessages(ctx, client, upstream, &toClient)} }()
	go keepAlive(ctx, client, s.cfg.PingInterval, cancel)
	go keepAlive(ctx, upstream, s.cfg.PingInterval, cancel)

	first := <-done
	reason := closeReason(first.from, first.err, ctx)
	code, text := forwardedClose(first.err)
	if first.from == "client" {
		upstream.Close(code, text)
		client.CloseNow()
	} else {
		if ctx.Err() == context.DeadlineExceeded {
			code, text = websocket.StatusPolicyViolation, "maximum session duration reached"
		}
		client.Close(code, text)
		upstream.CloseNow()
	}
	cancel()
	<-done
	return toVM.Load(), toClient.Load(), reason
}

func copyMessages(ctx context.Context, dst, src *websocket.Conn, counter *atomic.Int64) error {
	for {
		typ, r, err := src.Reader(ctx)
		if err != nil {
			return err
		}
		w, err := dst.Writer(ctx, typ)
		if err != nil {
			return err
		}
		n, err := io.Copy(w, r)
		counter.Add(n)
		if err != nil {
			w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
	}
}

func keepAlive(ctx context.Context, c *websocket.Conn, every time.Duration, fail context.CancelFunc) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, every)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					fail()
				}
				return
			}
		}
	}
}

func forwardedClose(err error) (websocket.StatusCode, string) {
	code := websocket.CloseStatus(err)
	switch code {
	case -1, websocket.StatusNoStatusRcvd, websocket.StatusAbnormalClosure, websocket.StatusTLSHandshake:
		return websocket.StatusNormalClosure, ""
	}
	var ce websocket.CloseError
	if errors.As(err, &ce) {
		reason := ce.Reason
		if len(reason) > 120 {
			reason = reason[:120]
		}
		return code, reason
	}
	return code, ""
}

func closeReason(from string, err error, ctx context.Context) string {
	if ctx.Err() == context.DeadlineExceeded {
		return "max_duration"
	}
	if ctx.Err() == context.Canceled {
		return "keepalive_timeout"
	}
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return from + "_closed"
	}
	if errors.Is(err, io.EOF) {
		return from + "_closed"
	}
	return from + "_error"
}
