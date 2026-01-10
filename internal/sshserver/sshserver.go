package sshserver

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/eventdata"
	"github.com/r-smith/deceptifeed/internal/proxyproto"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
	"golang.org/x/crypto/ssh"
)

// serverTimeout defines the duration after which connected clients are
// automatically disconnected, set to 30 seconds.
const serverTimeout = 30 * time.Second

// Start initializes and starts an SSH honeypot server. The SSH server is
// designed to log the usernames and passwords submitted in authentication
// requests. It is not possible for clients to log in to the honeypot server,
// as authentication is the only function handled by the server. Clients
// receive authentication failure responses for every login attempt.
// Interactions with the SSH server are sent to the threat feed.
func Start(cfg *config.Server) {
	fmt.Printf("Starting SSH server on port: %s\n", cfg.Port)
	sshConfig := &ssh.ServerConfig{}

	// Load or generate a private key and add it to the SSH configuration.
	privateKey, err := loadOrGeneratePrivateKey(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The SSH server on port %s has stopped: %v\n", cfg.Port, err)
		return
	}
	sshConfig.AddHostKey(privateKey)

	// If a banner string is provided in the configuration, use it as the SSH
	// server version string advertised to connecting clients. This allows
	// the honeypot server to mimic the appearance of other common SSH servers,
	// such as OpenSSH on Debian, Ubuntu, FreeBSD, or Raspberry Pi.
	if len(cfg.Banner) > 0 {
		sshConfig.ServerVersion = cfg.Banner
	} else {
		sshConfig.ServerVersion = config.DefaultBannerSSH
	}

	// Define the public key authentication callback function.
	sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		// This public key authentication function rejects all requests.
		// Currently, no data is logged. Useful information may include:
		// `key.Type()` and `ssh.FingerprintSHA256(key)`.

		// Short, intentional delay.
		time.Sleep(200 * time.Millisecond)

		// Reject the authentication request.
		return nil, fmt.Errorf("permission denied")
	}

	// Start the SSH server.
	listener, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The SSH server on port %s has stopped: %v\n", cfg.Port, err)
		return
	}
	defer listener.Close()

	// Listen for and accept incoming connections.
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleConnection(conn, sshConfig, cfg)
	}
}

// handleConnection manages incoming SSH client connections. It performs the
// handshake and handles authentication callbacks.
func handleConnection(conn net.Conn, baseConfig *ssh.ServerConfig, cfg *config.Server) {
	defer conn.Close()

	// Record connection details and handle Proxy Protocol if enabled.
	evt := eventdata.Connection{}
	evt.ServerIP, evt.ServerPort, _ = net.SplitHostPort(conn.LocalAddr().String())
	evt.SourceIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	if cfg.UseProxyProtocol {
		evt.ProxyIP = evt.SourceIP
		if extractedIP, err := proxyproto.ReadHeader(conn); err != nil {
			evt.ProxyError = err.Error()
		} else {
			evt.ProxyParsed = true
			evt.SourceIP = extractedIP
		}
	}

	logData := prepareLog(&evt, cfg)

	// Set a connection deadline.
	_ = conn.SetDeadline(time.Now().Add(serverTimeout))

	// Because we modify the callbacks, clone the config per each connection.
	sshConfig := *baseConfig

	// PasswordCallback is called during the SSH handshake when a client
	// requests password authentication. It logs the credentials, updates the
	// threat feed, then rejects the authentication attempt.
	sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		d := slog.Group("event_details",
			slog.String("username", conn.User()),
			slog.String("password", string(password)),
			slog.String("ssh_client", string(conn.ClientVersion())),
			slog.String("auth_method", "password"),
		)
		cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "ssh", append(logData, d)...)

		fmt.Printf("[SSH] %s Username: %q Password: %q\n", evt.SourceIP, conn.User(), string(password))

		if cfg.SendToThreatFeed {
			threatfeed.Update(evt.SourceIP)
		}

		// Insert a fixed delay, then reject the authentication attempt.
		time.Sleep(2 * time.Second)

		return nil, fmt.Errorf("invalid username or password")
	}

	// Perform the SSH handshake with authentication callbacks defined in
	// sshConfig. Since all authentication attempts are rejected (return an
	// error), NewServerConn always closes the connection and returns an error.
	// No further connection or channel handling is necessary.
	sshConn, _, _, err := ssh.NewServerConn(conn, &sshConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()
}

// preparelog builds structured log fields from network connection metadata.
func prepareLog(evt *eventdata.Connection, cfg *config.Server) []slog.Attr {
	d := make([]slog.Attr, 0, 8)
	d = append(d,
		slog.String("source_ip", evt.SourceIP),
	)
	if cfg.UseProxyProtocol {
		d = append(d,
			slog.Bool("source_ip_parsed", evt.ProxyParsed),
			slog.String("source_ip_error", evt.ProxyError),
			slog.String("proxy_ip", evt.ProxyIP),
		)
	}
	d = append(d,
		slog.String("server_ip", evt.ServerIP),
		slog.String("server_port", evt.ServerPort),
		slog.String("server_name", config.Hostname),
	)
	return d
}

// loadOrGeneratePrivateKey attempts to load a private key from the specified
// path. If the key does not exist, it generates a new private key, saves it to
// the specified path, and returns the generated key.
func loadOrGeneratePrivateKey(path string) (ssh.Signer, error) {
	if _, err := os.Stat(path); err == nil {
		// Load the specified file and return the parsed private key.
		privateKey, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key '%s': %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key '%s': %w", path, err)
		}
		return signer, nil
	} else if os.IsNotExist(err) {
		// Generate and return a new private key.
		_, privateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}

		// Save the private key to disk.
		if len(path) > 0 {
			// Silently ignore any potential errors and continue.
			_ = writePrivateKey(path, privateKey)
		}

		// Convert the key to ssh.Signer.
		signer, err := ssh.NewSignerFromKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert key to SSH signer: %w", err)
		}
		return signer, nil
	} else {
		return nil, err
	}
}

// writePrivateKey saves a private key in PEM format to the specified path.
func writePrivateKey(path string, privateKey any) error {
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	privPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, privPem)
}
