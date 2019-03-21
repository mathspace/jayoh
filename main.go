// jayoh is a SSH jump server with intentionally limited functionality
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/oxplot/jayoh/acl"
)

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
	config     = struct {
		ACLFile       string `json:"acl_file"`
		ServerKeyFile string `json:"server_key_file"`
		Listen        string `json:"listen"`
		MaxAuthTries  int    `json:"max_auth_tries"`
	}{
		Listen:       "127.0.0.1:2222",
		MaxAuthTries: 4,
	}

	sshServerConfig = &ssh.ServerConfig{
		PasswordCallback:  passwordCallback,
		PublicKeyCallback: publicKeyCallback,
	}

	accessControlList = &acl.ACL{}
)

// directTCPIPPayload holds the extra payload of a direct-tcpip SSH
// new channel request.
type directTCPIPPayload struct {
	Host       string
	HostPort   uint32
	Origin     string
	OriginPort uint32
}

// sessionId returns the session ID of the given SSH connection in hex string
func sessionId(c ssh.Conn) string {
	return hex.EncodeToString(c.SessionID())
}

// passwordCallback is called when a password login is attempted
func passwordCallback(conn ssh.ConnMetadata, pwd []byte) (*ssh.Permissions, error) {
	if accessControlList.IsValidPassword(conn.User(), pwd) {
		log.Printf("remote %s: password login: succeeded for user \"%s\"", conn.RemoteAddr(), conn.User())
		return nil, nil
	}
	log.Printf("remote %s: password login: failed for user \"%s\"", conn.RemoteAddr(), conn.User())
	return nil, fmt.Errorf("login failed")
}

// publicKeyCallback is called when a public key login is attempted
func publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if accessControlList.IsValidKey(conn.User(), key) {
		log.Printf("remote %s: public key login: succeeded for user \"%s\"", conn.RemoteAddr(), conn.User())
		return nil, nil
	}
	log.Printf("remote %s: public key login: failed for user \"%s\"", conn.RemoteAddr(), conn.User())
	return nil, fmt.Errorf("login failed")
}

// handleConn handles a new SSH connection
func handleConn(c net.Conn) {
	log.Printf("remote %s: connected", c.RemoteAddr())
	conn, chans, reqs, err := ssh.NewServerConn(c, sshServerConfig)
	if err != nil {
		log.Print(err)
		return
	}
	log.Printf("remote %s: logged in to session %s", c.RemoteAddr(), sessionId(conn))
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {

		case "direct-tcpip":
			go handleDirectTCP(conn, newChan)

		default:
			log.Printf("session %s: new channel \"%s\" not supported", sessionId(conn), newChan.ChannelType())
			go newChan.Reject(ssh.UnknownChannelType, "only tcp forwarding is supported")

		}
	}
	log.Printf("session %s: disconnected", sessionId(conn))
}

// handleDirectTCP handles request to setup new SSH port forwarding channel
func handleDirectTCP(conn *ssh.ServerConn, newChan ssh.NewChannel) {

	// Read out the destination host requested to connect to
	pl := directTCPIPPayload{}
	if err := ssh.Unmarshal(newChan.ExtraData(), &pl); err != nil {
		log.Printf("session %s: bad direct-tcpip payload", sessionId(conn))
		newChan.Reject(ssh.UnknownChannelType, "bad payload")
		return
	}

	if !accessControlList.IsAllowedHostAccess(conn.User(), pl.Host) {
		newChan.Reject(ssh.Prohibited, fmt.Sprintf("connection to \"%s\" is not allowed for user \"%s\"", pl.Host, conn.User()))
		return
	}

	// Connect to the remote host
	tcpConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", pl.Host, pl.HostPort))
	if err != nil {
		log.Printf("session %s: %s", sessionId(conn), err)
		newChan.Reject(ssh.ConnectionFailed, err.Error())
	}

	log.Printf("session %s: successful TCP connection to \"%s\" on port %d", sessionId(conn), pl.Host, pl.HostPort)

	chans, reqs, err := newChan.Accept()
	if err != nil {
		log.Print(err)
		return
	}
	go ssh.DiscardRequests(reqs)

	// Pipe data both ways between the SSH client and the remote host
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		io.Copy(tcpConn, chans)
		wg.Done()
	}()

	go func() {
		io.Copy(chans, tcpConn)
		wg.Done()
	}()

	wg.Wait()
	tcpConn.Close()
	chans.Close()
	log.Printf("session %s TCP connection to \"%s\" on port %d terminated", sessionId(conn), pl.Host, pl.HostPort)
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

func run() error {

	flag.Parse()
	sshServerConfig.KeyExchanges = recommendedKexAlgos
	sshServerConfig.MACs = recommendedMACs
	sshServerConfig.MaxAuthTries = config.MaxAuthTries

	// Load config file
	{
		b, err := ioutil.ReadFile(*configPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &config); err != nil {
			return err
		}
		if config.ServerKeyFile == "" || config.ACLFile == "" {
			return fmt.Errorf("server_key_file and acl_file are required")
		}
	}

	{
		b, err := ioutil.ReadFile(config.ServerKeyFile)
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
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
		}
		go handleConn(conn)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
