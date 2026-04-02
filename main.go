// jayoh is a SSH jump server with intentionally limited functionality
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mathspace/jayoh/acl"
)

const (
	preAuthHandshakeTimeout = 5 * time.Second
	outboundDialTimeout     = 10 * time.Second
	acceptRetryDelay        = 50 * time.Millisecond
)

type serverConfig struct {
	ACLFile              string `json:"acl_file"`
	ServerKeyFile        string `json:"server_key_file"`
	Listen               string `json:"listen"`
	MaxAuthTries         int    `json:"max_auth_tries"`
	AuthFailureDelay     int    `json:"auth_failure_delay"`
	ConnKeepaliveMinutes uint   `json:"connection_keepalive_minutes"`
}

var (
	// Recommended key exchange algorithms, by ssh-audit
	recommendedKexAlgos = []string{
		"curve25519-sha256@libssh.org",
	}
	// Recommended MACs, by ssh-audit
	recommendedMACs = []string{
		"hmac-sha2-256-etm@openssh.com",
	}

	configPath = flag.String("config", "/etc/jayoh/config.json", "path to config file")
	config     = defaultConfig()

	sshServerConfig = &ssh.ServerConfig{
		PasswordCallback:  passwordCallback,
		PublicKeyCallback: publicKeyCallback,
	}

	accessControlList = &acl.ACL{}

	dialTargetContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: outboundDialTimeout}
		return dialer.DialContext(ctx, network, address)
	}
)

// directTCPIPPayload holds the extra payload of a direct-tcpip SSH
// new channel request.
type directTCPIPPayload struct {
	Host       string
	HostPort   uint32
	Origin     string
	OriginPort uint32
}

type sessionIDProvider interface {
	SessionID() []byte
}

type sshSession interface {
	sessionIDProvider
	User() string
}

// sessionID returns the session ID of the given SSH connection in hex string
func sessionID(c sessionIDProvider) string {
	return hex.EncodeToString(c.SessionID())
}

func defaultConfig() serverConfig {
	return serverConfig{
		Listen:               "127.0.0.1:2222",
		MaxAuthTries:         6,
		AuthFailureDelay:     5,
		ConnKeepaliveMinutes: 1,
	}
}

func loadConfig(path string) (serverConfig, error) {
	cfg := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return serverConfig{}, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return serverConfig{}, err
	}
	if err := validateConfig(cfg); err != nil {
		return serverConfig{}, err
	}
	return cfg, nil
}

func validateConfig(cfg serverConfig) error {
	switch {
	case cfg.ServerKeyFile == "":
		return fmt.Errorf("server_key_file is required")
	case cfg.ACLFile == "":
		return fmt.Errorf("acl_file is required")
	case cfg.Listen == "":
		return fmt.Errorf("listen is required")
	case cfg.MaxAuthTries < 1:
		return fmt.Errorf("max_auth_tries must be greater than 0")
	case cfg.AuthFailureDelay < 0:
		return fmt.Errorf("auth_failure_delay must be greater than or equal to 0")
	case cfg.ConnKeepaliveMinutes == 0:
		return fmt.Errorf("connection_keepalive_minutes must be greater than 0")
	default:
		return nil
	}
}

func applySSHServerConfig(cfg serverConfig) {
	sshServerConfig.KeyExchanges = recommendedKexAlgos
	sshServerConfig.MACs = recommendedMACs
	sshServerConfig.MaxAuthTries = cfg.MaxAuthTries
}

func setPreAuthDeadline(c net.Conn) error {
	return c.SetDeadline(time.Now().Add(preAuthHandshakeTimeout))
}

func clearConnDeadline(c net.Conn) error {
	return c.SetDeadline(time.Time{})
}

// passwordCallback is called when a password login is attempted
func passwordCallback(conn ssh.ConnMetadata, pwd []byte) (*ssh.Permissions, error) {
	if accessControlList.IsValidPassword(conn.User(), pwd) {
		log.Printf("remote %s: password login: succeeded for user \"%s\"", conn.RemoteAddr(), conn.User())
		return nil, nil
	}
	log.Printf("remote %s: password login: failed for user \"%s\"", conn.RemoteAddr(), conn.User())
	log.Printf("remote %s: delaying %d seconds before responding", conn.RemoteAddr(), config.AuthFailureDelay)
	time.Sleep(time.Second * time.Duration(config.AuthFailureDelay))
	return nil, fmt.Errorf("login failed")
}

// publicKeyCallback is called when a public key login is attempted
func publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if accessControlList.IsValidKey(conn.User(), key) {
		log.Printf("remote %s: public key login: succeeded for user \"%s\"", conn.RemoteAddr(), conn.User())
		return nil, nil
	}
	log.Printf("remote %s: public key login: failed for user \"%s\"", conn.RemoteAddr(), conn.User())
	log.Printf("remote %s: delaying %d seconds before responding", conn.RemoteAddr(), config.AuthFailureDelay)
	time.Sleep(time.Second * time.Duration(config.AuthFailureDelay))
	return nil, fmt.Errorf("login failed")
}

// isClientAlive sends a keep alive request to the client and return true
// if client responds in timely manner, false otherwise
func isClientAlive(ctx context.Context, conn ssh.Conn) bool {
	tCtx, cancelFn := context.WithTimeout(ctx, time.Second*15)
	defer cancelFn()
	clientResponse := make(chan bool, 1)
	go func() {
		if _, _, err := conn.SendRequest("keepalive@jayoh", true, nil); err != nil {
			clientResponse <- false
			return
		}
		clientResponse <- true
	}()
	select {
	case r := <-clientResponse:
		return r
	case <-tCtx.Done():
		return false
	}
}

// handleConn handles a new SSH connection
func handleConn(c net.Conn) {
	if c == nil {
		return
	}
	defer c.Close()

	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	log.Printf("remote %s: connected", c.RemoteAddr())
	if err := setPreAuthDeadline(c); err != nil {
		log.Printf("remote %s: failed to set handshake deadline: %s", c.RemoteAddr(), err)
		return
	}
	conn, chans, reqs, err := ssh.NewServerConn(c, sshServerConfig)
	if err != nil {
		log.Printf("remote %s: disconnected before authentication: %s", c.RemoteAddr(), err)
		return
	}
	defer conn.Close()
	if err := clearConnDeadline(c); err != nil {
		log.Printf("session %s: failed to clear handshake deadline: %s", sessionID(conn), err)
		return
	}
	log.Printf("remote %s: logged in to session %s as user \"%s\"", c.RemoteAddr(), sessionID(conn), conn.User())
	go ssh.DiscardRequests(reqs)

	// Periodic liveness checks
	go func() {
		ticker := time.NewTicker(time.Minute * time.Duration(config.ConnKeepaliveMinutes))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !isClientAlive(ctx, conn) {
					log.Printf("session %s: keep alive failed", sessionID(conn))
					cancelFn()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

NewChan:
	for {
		select {
		case newChan := <-chans:
			switch {

			case newChan == nil:
				break NewChan

			case newChan.ChannelType() == "direct-tcpip":
				go handleDirectTCP(ctx, conn, newChan)

			default:
				log.Printf("session %s: new channel \"%s\" not supported", sessionID(conn), newChan.ChannelType())
				go newChan.Reject(ssh.UnknownChannelType, "only tcp forwarding is supported")
			}
		case <-ctx.Done():
			break NewChan
		}
	}

	log.Printf("session %s: disconnected", sessionID(conn))
}

// handleDirectTCP handles request to setup new SSH port forwarding channel
func handleDirectTCP(ctx context.Context, conn *ssh.ServerConn, newChan ssh.NewChannel) {
	handleDirectTCPWithSession(ctx, conn, newChan)
}

func handleDirectTCPWithSession(ctx context.Context, conn sshSession, newChan ssh.NewChannel) {
	// Read out the destination host requested to connect to
	pl := directTCPIPPayload{}
	if err := ssh.Unmarshal(newChan.ExtraData(), &pl); err != nil {
		log.Printf("session %s: bad direct-tcpip payload", sessionID(conn))
		newChan.Reject(ssh.UnknownChannelType, "bad payload")
		return
	}

	if !accessControlList.IsAllowedHostAccess(conn.User(), pl.Host) {
		log.Printf("session %s: connection to \"%s\" is not allowed for user \"%s\"", sessionID(conn), pl.Host, conn.User())
		newChan.Reject(ssh.Prohibited, fmt.Sprintf("connection to \"%s\" is not allowed for user \"%s\"", pl.Host, conn.User()))
		return
	}

	// Connect to the remote host
	tcpConn, err := dialTarget(ctx, pl.Host, pl.HostPort)
	if err != nil {
		log.Printf("session %s: failed to connect to \"%s\" on port %d: %s", sessionID(conn), pl.Host, pl.HostPort, err)
		newChan.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	defer tcpConn.Close()

	log.Printf("session %s: successful TCP connection to \"%s\" on port %d", sessionID(conn), pl.Host, pl.HostPort)

	chans, reqs, err := newChan.Accept()
	if err != nil {
		log.Printf("session %s: failed to accept new connection request: %s", sessionID(conn), err)
		return
	}
	defer chans.Close()
	go ssh.DiscardRequests(reqs)

	connCtx, termConn := context.WithCancel(ctx)

	// Pipe data both ways between the SSH client and the remote host
	go func() {
		io.Copy(tcpConn, chans)
		termConn()
	}()
	go func() {
		io.Copy(chans, tcpConn)
		termConn()
	}()

	<-connCtx.Done()
	log.Printf("session %s TCP connection to \"%s\" on port %d terminated", sessionID(conn), pl.Host, pl.HostPort)
}

func reloadACL() error {
	f, err := os.Open(config.ACLFile)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := accessControlList.Load(f); err != nil {
		return err
	}
	return nil
}

func dialTarget(ctx context.Context, host string, port uint32) (net.Conn, error) {
	return dialTargetContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}

func acceptLoop(listener net.Listener, handler func(net.Conn)) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("accept failed: %s", err)
			time.Sleep(acceptRetryDelay)
			continue
		}
		if conn == nil {
			continue
		}
		go handler(conn)
	}
}

func run() error {

	flag.Parse()

	// Load config file
	{
		cfg, err := loadConfig(*configPath)
		if err != nil {
			return err
		}
		config = cfg
		applySSHServerConfig(config)
	}

	{
		b, err := os.ReadFile(config.ServerKeyFile)
		if err != nil {
			return err
		}
		serverKey, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return err
		}
		sshServerConfig.AddHostKey(serverKey)
	}

	if err := reloadACL(); err != nil {
		log.Printf("loading ACL failed - no access is allowed: %s", err.Error())
	}

	// Run SIGHUP handler for reloading config
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP)
	go func() {
		for range sigc {
			if err := reloadACL(); err != nil {
				log.Printf("reloading ACL failed: %s", err.Error())
			} else {
				log.Print("reloaded ACL")
			}
		}
	}()

	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("listening on %s for connections...", config.Listen)
	return acceptLoop(listener, handleConn)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
