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

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
	"golang.org/x/crypto/ssh"
)

// StartSSH serves as a wrapper to initialize and start an SSH honeypot server.
// The SSH server is designed to log the usernames and passwords submitted in
// authentication requests. It is not possible for clients to log in to the
// honeypot server, as authentication is the only function handled by the
// server. Clients receive authentication failure responses for every login
// attempt. This function calls the underlying startSSH function to perform the
// actual server startup.
func StartSSH(srv *config.Server) {
	fmt.Printf("Starting SSH server on port: %s\n", srv.Port)
	if err := startSSH(srv); err != nil {
		fmt.Fprintln(os.Stderr, "The SSH server has terminated:", err)
	}
}

// startSSH starts the SSH honeypot server. It handles the server's main loop,
// authentication callback, and logging.
func startSSH(srv *config.Server) error {
	// Create a new SSH server configuration.
	sshConfig := &ssh.ServerConfig{}

	// Load or generate a private key and add it to the SSH configuration.
	privateKey, err := loadOrGeneratePrivateKey(srv.KeyPath)
	if err != nil {
		return err
	}
	sshConfig.AddHostKey(privateKey)

	// If a banner string is provided in the configuration, use it as the SSH
	// server version string advertised to connecting clients. This allows
	// the honeypot server to mimic the appearance of other common SSH servers,
	// such as OpenSSH on Debian, Ubuntu, FreeBSD, or Raspberry Pi.
	if len(srv.Banner) > 0 {
		sshConfig.ServerVersion = srv.Banner
	} else {
		sshConfig.ServerVersion = config.DefaultBannerSSH
	}

	// Define the password callback function for the SSH server.
	sshConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		// Log the the username and password submitted by the client.
		dst_ip, dst_port, _ := net.SplitHostPort(conn.LocalAddr().String())
		src_ip, src_port, _ := net.SplitHostPort(conn.RemoteAddr().String())
		srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "",
			slog.String("event_type", "ssh"),
			slog.String("source_ip", src_ip),
			slog.String("source_port", src_port),
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
		if srv.SendToThreatFeed {
			threatfeed.UpdateIoC(src_ip)
		}

		// Return an invalid username or password error to the client.
		return nil, fmt.Errorf("invalid username or password")
	}

	// Start the SSH server.
	listener, err := net.Listen("tcp", ":"+srv.Port)
	if err != nil {
		return fmt.Errorf("failed to listen on port '%s': %w", srv.Port, err)
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
// handshake and establishes communication channels.
func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	// Perform handshake on incoming connection.
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	// Handle SSH requests and channels.
	go ssh.DiscardRequests(reqs)
	go handleChannels(chans)
}

// handleChannels processes SSH channels for the connected client.
func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		continue
	}
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
	file.Chmod(0600)

	if err := pem.Encode(file, privPem); err != nil {
		return err
	}
	return nil
}
