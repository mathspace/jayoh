package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigUsesDefaultsAndFileValues(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configFile, []byte(`{
		"acl_file": "/tmp/acl.json",
		"server_key_file": "/tmp/server_key",
		"max_auth_tries": 2
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(configFile)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Listen != defaultConfig().Listen {
		t.Fatalf("listen = %q, want default %q", cfg.Listen, defaultConfig().Listen)
	}
	if cfg.MaxAuthTries != 2 {
		t.Fatalf("max auth tries = %d, want 2", cfg.MaxAuthTries)
	}
	if cfg.ConnKeepaliveMinutes != defaultConfig().ConnKeepaliveMinutes {
		t.Fatalf("keepalive = %d, want default %d", cfg.ConnKeepaliveMinutes, defaultConfig().ConnKeepaliveMinutes)
	}
}

func TestLoadConfigRejectsZeroKeepalive(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configFile, []byte(`{
		"acl_file": "/tmp/acl.json",
		"server_key_file": "/tmp/server_key",
		"connection_keepalive_minutes": 0
	}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := loadConfig(configFile); err == nil {
		t.Fatal("expected keepalive validation error")
	}
}

func TestApplySSHServerConfigUsesLoadedMaxAuthTries(t *testing.T) {
	originalMaxAuthTries := sshServerConfig.MaxAuthTries
	originalKex := append([]string(nil), sshServerConfig.KeyExchanges...)
	originalMACs := append([]string(nil), sshServerConfig.MACs...)
	t.Cleanup(func() {
		sshServerConfig.MaxAuthTries = originalMaxAuthTries
		sshServerConfig.KeyExchanges = originalKex
		sshServerConfig.MACs = originalMACs
	})

	cfg := defaultConfig()
	cfg.MaxAuthTries = 1
	applySSHServerConfig(cfg)

	if sshServerConfig.MaxAuthTries != 1 {
		t.Fatalf("max auth tries = %d, want 1", sshServerConfig.MaxAuthTries)
	}
}

func TestSetAndClearPreAuthDeadline(t *testing.T) {
	conn := &recordingConn{}

	before := time.Now()
	if err := setPreAuthDeadline(conn); err != nil {
		t.Fatalf("set pre-auth deadline: %v", err)
	}
	after := time.Now()

	minDeadline := before.Add(preAuthHandshakeTimeout)
	maxDeadline := after.Add(preAuthHandshakeTimeout)
	if conn.deadline.Before(minDeadline) || conn.deadline.After(maxDeadline) {
		t.Fatalf("deadline = %s, want between %s and %s", conn.deadline, minDeadline, maxDeadline)
	}

	if err := clearConnDeadline(conn); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	if !conn.deadline.IsZero() {
		t.Fatalf("deadline = %s, want zero time", conn.deadline)
	}
}

func TestDialTargetUsesContextAwareDialer(t *testing.T) {
	originalDialer := dialTargetContext
	t.Cleanup(func() {
		dialTargetContext = originalDialer
	})

	wantConn := &recordingConn{}
	type ctxKey string
	ctx := context.WithValue(context.Background(), ctxKey("request-id"), "123")

	var gotCtx context.Context
	var gotNetwork string
	var gotAddress string
	dialTargetContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		gotCtx = ctx
		gotNetwork = network
		gotAddress = address
		return wantConn, nil
	}

	conn, err := dialTarget(ctx, "example.com", 22)
	if err != nil {
		t.Fatalf("dial target: %v", err)
	}

	if conn != wantConn {
		t.Fatal("expected dialTarget to return the dialed connection")
	}
	if gotCtx != ctx {
		t.Fatal("dialTarget did not pass the caller context through")
	}
	if gotNetwork != "tcp" {
		t.Fatalf("network = %q, want tcp", gotNetwork)
	}
	if gotAddress != "example.com:22" {
		t.Fatalf("address = %q, want example.com:22", gotAddress)
	}
}

func TestAcceptLoopSkipsTemporaryErrors(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	fatalErr := errors.New("listener closed")
	listener := &stubListener{
		results: []acceptResult{
			{err: temporaryNetError{message: "temporary failure"}},
			{conn: serverConn},
			{err: fatalErr},
		},
	}

	handled := make(chan net.Conn, 1)
	err := acceptLoop(listener, func(conn net.Conn) {
		handled <- conn
		conn.Close()
	})
	if !errors.Is(err, fatalErr) {
		t.Fatalf("acceptLoop error = %v, want %v", err, fatalErr)
	}

	select {
	case gotConn := <-handled:
		if gotConn != serverConn {
			t.Fatal("acceptLoop handled unexpected connection")
		}
	case <-time.After(time.Second):
		t.Fatal("expected acceptLoop to handle a connection after the temporary error")
	}
}

type recordingConn struct {
	deadline time.Time
}

func (c *recordingConn) Read(_ []byte) (int, error)       { return 0, nil }
func (c *recordingConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return stubAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr             { return stubAddr("remote") }
func (c *recordingConn) SetDeadline(t time.Time) error    { c.deadline = t; return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type acceptResult struct {
	conn net.Conn
	err  error
}

type stubListener struct {
	results []acceptResult
}

func (l *stubListener) Accept() (net.Conn, error) {
	if len(l.results) == 0 {
		return nil, errors.New("no more accept results")
	}
	result := l.results[0]
	l.results = l.results[1:]
	return result.conn, result.err
}

func (l *stubListener) Close() error { return nil }
func (l *stubListener) Addr() net.Addr {
	return stubAddr("listener")
}

type temporaryNetError struct {
	message string
}

func (e temporaryNetError) Error() string   { return e.message }
func (e temporaryNetError) Timeout() bool   { return false }
func (e temporaryNetError) Temporary() bool { return true }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }
