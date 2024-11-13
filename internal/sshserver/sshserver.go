package sshserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
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

	// Define the password authentication callback function.
	sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		// Log the the username and password submitted by the client.
		dst_ip, dst_port, _ := net.SplitHostPort(conn.LocalAddr().String())
		src_ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		cfg.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
			slog.String("event_type", "ssh"),
			slog.String("source_ip", src_ip),
			slog.String("server_ip", dst_ip),
			slog.String("server_port", dst_port),
			slog.String("server_name", config.GetHostname()),
			slog.Group("event_details",
				slog.String("username", conn.User()),
				slog.String("password", string(password)),
				slog.String("ssh_client", string(conn.ClientVersion())),
			),
		)

		// Print a simplified version of the request to the console.
		fmt.Printf("[SSH] %s Username: %s Password: %s\n", src_ip, conn.User(), string(password))

		// Update the threat feed with the source IP address from the request.
		if cfg.SendToThreatFeed {
			threatfeed.Update(src_ip, cfg.ThreatScore)
		}

		// Insert fixed delay to mimic PAM.
		time.Sleep(2 * time.Second)

		// Reject the authentication request.
		return nil, fmt.Errorf("invalid username or password")
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

		go handleConnection(conn, sshConfig)
	}
}

// handleConnection manages incoming SSH client connections. It performs the
// handshake and handles authentication callbacks.
func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(serverTimeout))

	// Perform handshake and authentication. Authentication callbacks are
	// defined in the SSH server configuration. Since authentication requests
	// are always rejected, this function will consistently return an error,
	// and no further connection handling is necessary.
	sshConn, _, _, err := ssh.NewServerConn(conn, config)
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
			return nil, fmt.Errorf("failed to read private key from '%s': %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key '%s': %w", path, err)
		}
		return signer, nil
	} else if os.IsNotExist(err) {
		// Generate and return a new private key.
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA private key: %w", err)
		}

		// Save the private key to disk.
		if len(path) > 0 {
			_ = writePrivateKey(path, privateKey)
			// If saving fails, ignore the errors and use the in-memory private
			// key.
		}

		// Convert the key to ssh.Signer.
		signer, err := ssh.NewSignerFromKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert RSA key to SSH signer: %w", err)
		}
		return signer, nil
	} else {
		return nil, err
	}
}

// writePrivateKey saves a private key in PEM format to the specified file
// path.
func writePrivateKey(path string, privateKey *rsa.PrivateKey) error {
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
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
