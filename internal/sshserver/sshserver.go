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
func handleConnection(conn net.Conn, sshConfig *ssh.ServerConfig, cfg *config.Server) {
	defer conn.Close()

	// Record connection details.
	dstIP, dstPort, _ := net.SplitHostPort(conn.LocalAddr().String())
	srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	var remIP string
	var errMsg string
	var parsed bool

	// If Proxy Protocol is enabled, set remIP to the remote IP and extract the
	// client IP from the proxy header into srcIP.
	if cfg.UseProxyProtocol {
		remIP = srcIP
		if clientIP, err := proxyproto.ReadHeader(conn); err != nil {
			errMsg = err.Error()
		} else {
			parsed = true
			srcIP = clientIP
		}
	}

	// Set a connection deadline.
	_ = conn.SetDeadline(time.Now().Add(serverTimeout))

	// Set the password authentication callback function. This function is
	// called after a successful SSH handshake. It logs the credentials,
	// updates the threat feed, then responds to the client that auth failed.
	sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		// Log the authentication attempt.
		logData := make([]slog.Attr, 0, 9)
		logData = append(logData,
			slog.String("event_type", "ssh"),
			slog.String("source_ip", srcIP),
		)
		if cfg.UseProxyProtocol {
			logData = append(logData,
				slog.Bool("source_ip_parsed", parsed),
				slog.String("source_ip_error", errMsg),
				slog.String("remote_ip", remIP),
			)
		}
		logData = append(logData,
			slog.String("server_ip", dstIP),
			slog.String("server_port", dstPort),
			slog.String("server_name", config.GetHostname()),
			slog.Group("event_details",
				slog.String("username", conn.User()),
				slog.String("password", string(password)),
				slog.String("ssh_client", string(conn.ClientVersion())),
			),
		)
		cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "", logData...)

		// Print a simplified version of the request to the console.
		fmt.Printf("[SSH] %s Username: %q Password: %q\n", srcIP, conn.User(), string(password))

		// Update the threat feed with srcIP. If Proxy Protocol is enabled,
		// srcIP is from the proxy header. Otherwise, it's the connecting IP.
		if cfg.SendToThreatFeed {
			threatfeed.Update(srcIP)
		}

		// Insert a fixed delay between authentication attempts.
		time.Sleep(2 * time.Second)

		// Reject the authentication request.
		return nil, fmt.Errorf("invalid username or password")
	}

	// Perform handshake and authentication. Authentication callbacks are
	// defined in the SSH server configuration. Since authentication requests
	// are always rejected, this function will consistently return an error,
	// and no further connection handling is necessary.
	sshConn, _, _, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()
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

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Limit key access to the owner only.
	_ = file.Chmod(0600)

	if err := pem.Encode(file, privPem); err != nil {
		return err
	}
	return nil
}
