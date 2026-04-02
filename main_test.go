package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mathspace/jayoh/acl"
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

	wantKex := []string{
		ssh.KeyExchangeMLKEM768X25519,
		ssh.KeyExchangeCurve25519,
	}
	if !slices.Equal(sshServerConfig.KeyExchanges, wantKex) {
		t.Fatalf("key exchanges = %v, want %v", sshServerConfig.KeyExchanges, wantKex)
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

func TestHandleConnSetsPreAuthDeadlineBeforeHandshake(t *testing.T) {
	originalNewSSHServerConn := newSSHServerConn
	t.Cleanup(func() {
		newSSHServerConn = originalNewSSHServerConn
	})

	config = defaultConfig()
	conn := &recordingConn{}
	called := false
	newSSHServerConn = func(conn net.Conn, _ *ssh.ServerConfig) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
		called = true
		recording, ok := conn.(*recordingConn)
		if !ok {
			t.Fatalf("unexpected connection type %T", conn)
		}
		if recording.deadline.IsZero() {
			t.Fatal("expected handleConn to set a pre-auth deadline before the SSH handshake")
		}
		return nil, nil, nil, errors.New("stop handshake")
	}

	handleConn(conn)

	if !called {
		t.Fatal("expected handleConn to invoke the SSH handshake")
	}
}

func TestHandleConnClearsPreAuthDeadlineAfterHandshake(t *testing.T) {
	originalNewSSHServerConn := newSSHServerConn
	t.Cleanup(func() {
		newSSHServerConn = originalNewSSHServerConn
	})

	config = defaultConfig()
	conn := &recordingConn{}
	reqs := make(chan *ssh.Request)
	close(reqs)
	chans := make(chan ssh.NewChannel)
	close(chans)
	newSSHServerConn = func(net.Conn, *ssh.ServerConfig) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
		return &ssh.ServerConn{Conn: sshConnStub{user: "mike", sessionID: []byte("session")}}, chans, reqs, nil
	}

	handleConn(conn)

	if !conn.deadline.IsZero() {
		t.Fatal("expected handleConn to clear the pre-auth deadline after a successful handshake")
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

func TestHandleDirectTCPUsesContextAwareDialer(t *testing.T) {
	originalDialer := dialTargetContext
	originalACL := accessControlList
	t.Cleanup(func() {
		dialTargetContext = originalDialer
		accessControlList = originalACL
	})

	allowedACL := &acl.ACL{}
	if err := allowedACL.Load(strings.NewReader(`{
		"users": {
			"mike": {
				"groups": ["dev"]
			}
		},
		"rules": {
			"dev": {
				"groups": ["dev"],
				"host_patterns": ["db.internal"]
			}
		}
	}`)); err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	accessControlList = allowedACL

	type ctxKey string
	ctx := context.WithValue(context.Background(), ctxKey("request-id"), "456")
	var gotCtx context.Context
	var gotAddress string
	dialTargetContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		gotCtx = ctx
		gotAddress = address
		return nil, errors.New("dial blocked for test")
	}

	newChan := &recordingNewChannel{
		channelType: "direct-tcpip",
		extraData: ssh.Marshal(directTCPIPPayload{
			Host:     "db.internal",
			HostPort: 5432,
		}),
	}

	handleDirectTCPWithSession(ctx, sshConnStub{user: "mike", sessionID: []byte("session")}, newChan)

	if gotCtx != ctx {
		t.Fatal("expected handleDirectTCP to pass the caller context to the dialer")
	}
	if gotAddress != "db.internal:5432" {
		t.Fatalf("address = %q, want db.internal:5432", gotAddress)
	}
	if newChan.rejectedReason != ssh.ConnectionFailed {
		t.Fatalf("reject reason = %v, want %v", newChan.rejectedReason, ssh.ConnectionFailed)
	}
}

func TestAcceptLoopSkipsTemporaryErrors(t *testing.T) {
	originalSleep := sleepBeforeAcceptRetry
	t.Cleanup(func() {
		sleepBeforeAcceptRetry = originalSleep
	})
	sleepBeforeAcceptRetry = func(time.Duration) {}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	fatalErr := net.ErrClosed
	listener := &stubListener{
		results: []acceptResult{
			{err: errors.New("temporary failure")},
			{conn: serverConn},
			{err: fatalErr},
		},
	}

	handled := make(chan net.Conn, 1)
	err := acceptLoop(listener, func(conn net.Conn) {
		handled <- conn
		conn.Close()
	})
	if err != nil {
		t.Fatalf("acceptLoop error = %v, want nil", err)
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

func TestAcceptLoopStopsOnClosedListener(t *testing.T) {
	listener := &stubListener{
		results: []acceptResult{
			{err: net.ErrClosed},
		},
	}

	if err := acceptLoop(listener, func(net.Conn) {}); err != nil {
		t.Fatalf("acceptLoop error = %v, want nil", err)
	}
}

func TestAMIProvisioningScriptUsesIMDSv2AndExplicitRegion(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("cloud", "ami.sh"))
	if err != nil {
		t.Fatalf("read ami script: %v", err)
	}

	content := string(script)
	for _, expected := range []string{
		"/latest/api/token",
		"X-aws-ec2-metadata-token",
		"/opt/get_own_region",
		"aws ssm get-parameter --region \"$(/opt/get_own_region)\"",
	} {
		if !strings.Contains(content, expected) {
			t.Fatalf("ami.sh is missing %q", expected)
		}
	}
}

func TestAMIProvisioningScriptParses(t *testing.T) {
	cmd := exec.Command("bash", "-n", filepath.Join("cloud", "ami.sh"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash -n cloud/ami.sh: %v\n%s", err, output)
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

type recordingNewChannel struct {
	channelType    string
	extraData      []byte
	rejectedReason ssh.RejectionReason
	rejectedMsg    string
}

func (c *recordingNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("unexpected accept")
}
func (c *recordingNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	c.rejectedReason = reason
	c.rejectedMsg = message
	return nil
}
func (c *recordingNewChannel) ChannelType() string { return c.channelType }
func (c *recordingNewChannel) ExtraData() []byte   { return c.extraData }

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

type sshConnStub struct {
	user      string
	sessionID []byte
}

func (c sshConnStub) User() string          { return c.user }
func (c sshConnStub) SessionID() []byte     { return c.sessionID }
func (c sshConnStub) ClientVersion() []byte { return []byte("SSH-2.0-test-client") }
func (c sshConnStub) ServerVersion() []byte { return []byte("SSH-2.0-test-server") }
func (c sshConnStub) RemoteAddr() net.Addr  { return stubAddr("remote") }
func (c sshConnStub) LocalAddr() net.Addr   { return stubAddr("local") }
func (c sshConnStub) SendRequest(string, bool, []byte) (bool, []byte, error) {
	return false, nil, errors.New("unexpected request")
}
func (c sshConnStub) OpenChannel(string, []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("unexpected channel open")
}
func (c sshConnStub) Close() error { return nil }
func (c sshConnStub) Wait() error  { return nil }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }
