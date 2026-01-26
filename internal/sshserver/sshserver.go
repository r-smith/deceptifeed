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
	"strconv"
	"time"

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/eventdata"
	"github.com/r-smith/deceptifeed/internal/proxyproto"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
	"golang.org/x/crypto/ssh"
)

// Start launches an SSH honeypot server that logs credentials and reports
// activity to the threat feed. All authentication attempts are rejected. It is
// not possible to "login" to the server.
func Start(srv *config.Server) {
	fmt.Printf("Starting SSH server on port: %s\n", srv.Port)
	sshConfig := &ssh.ServerConfig{}

	// Load or generate a private key and add it to the SSH configuration.
	privateKey, err := loadOrGeneratePrivateKey(srv.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The SSH server on port %s has stopped: %v\n", srv.Port, err)
		return
	}
	sshConfig.AddHostKey(privateKey)

	// Set the SSH server identification string advertised to clients.
	if srv.Banner == "" {
		sshConfig.ServerVersion = config.DefaultBannerSSH
	} else {
		sshConfig.ServerVersion = srv.Banner
	}

	// Start the SSH server.
	listener, err := net.Listen("tcp", ":"+srv.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "The SSH server on port %s has stopped: %v\n", srv.Port, err)
		return
	}
	defer listener.Close()

	// Listen for and accept incoming connections.
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleConnection(conn, sshConfig, srv)
	}
}

// handleConnection manages incoming SSH client connections. It performs the
// handshake and handles authentication callbacks.
func handleConnection(conn net.Conn, baseConfig *ssh.ServerConfig, srv *config.Server) {
	defer conn.Close()

	// Capture connection metadata.
	evt := eventdata.Connection{}
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		evt.ServerIP = addr.AddrPort().Addr().Unmap()
		evt.ServerPort = addr.AddrPort().Port()
	}
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		evt.SourceIP = addr.AddrPort().Addr().Unmap()
	}

	// Handle Proxy Protocol.
	if srv.UseProxyProtocol {
		evt.ProxyIP = evt.SourceIP
		newConn, extractedIP, err := proxyproto.ReadHeader(conn)

		if newConn != nil {
			conn = newConn
		}

		if err != nil {
			evt.ProxyError = err.Error()
		} else {
			evt.ProxyParsed = true
			evt.SourceIP = extractedIP
		}
	}

	logData := prepareLog(&evt, srv)

	// Log and report the connection.
	if srv.LogConnections {
		srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "connection", logData...)
		fmt.Printf("[SSH] %s connected to port %d\n", evt.SourceIP, evt.ServerPort)
	}
	if srv.ReportConnections {
		threatfeed.Update(evt.SourceIP)
	}

	// Apply SessionTimeout as an absolute deadline for the connection.
	_ = conn.SetDeadline(time.Now().Add(time.Duration(srv.SessionTimeout) * time.Second))

	// Apply callbacks to config.
	sshConfig := configureCallbacks(baseConfig, srv, &evt, logData)

	// Perform the SSH handshake. Because all authentication attempts are
	// rejected (return an error), NewServerConn never opens a connection. No
	// further connection or channel handling is necessary.
	_, _, _, _ = ssh.NewServerConn(conn, sshConfig)
}

// prepareLog builds structured log fields from network connection metadata.
func prepareLog(evt *eventdata.Connection, srv *config.Server) []slog.Attr {
	d := make([]slog.Attr, 0, 8)
	d = append(d,
		slog.Any("source_ip", evt.SourceIP),
	)
	if srv.UseProxyProtocol {
		d = append(d,
			slog.Bool("source_ip_parsed", evt.ProxyParsed),
			slog.String("source_ip_error", evt.ProxyError),
			slog.Any("proxy_ip", evt.ProxyIP),
		)
	}
	d = append(d,
		slog.Any("server_ip", evt.ServerIP),
		slog.String("server_port", strconv.FormatUint(uint64(evt.ServerPort), 10)),
		slog.String("server_name", config.Hostname),
	)
	return d
}

// configureCallbacks attaches authentication callbacks to a base SSH config.
// The callbacks log authentication attempts and update the threat feed.
func configureCallbacks(base *ssh.ServerConfig, srv *config.Server, evt *eventdata.Connection, logData []slog.Attr) *ssh.ServerConfig {
	conf := *base

	// Password authentication: Log the credentials, update the threat feed,
	// then reject the attempt.
	conf.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if srv.LogInteractions {
			d := slog.Group("event_details",
				slog.String("username", conn.User()),
				slog.String("password", string(password)),
				slog.String("ssh_client", string(conn.ClientVersion())),
				slog.String("auth_method", "password"),
			)
			srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "ssh", append(logData, d)...)

			fmt.Printf("[SSH] %s Username: %q Password: %q\n", evt.SourceIP, conn.User(), string(password))
		}

		if srv.ReportInteractions {
			threatfeed.Update(evt.SourceIP)
		}

		// Insert a fixed delay, then reject the authentication attempt.
		time.Sleep(2 * time.Second)
		return nil, fmt.Errorf("invalid username or password")
	}

	// Publickey authentication: Log the key hash and username, update the
	// threat feed, then reject the attempt. Note: The logged key is unverified
	// because the login is rejected before the client proves key ownership.
	conf.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if srv.LogInteractions {
			d := slog.Group("event_details",
				slog.String("username", conn.User()),
				slog.String("ssh_client", string(conn.ClientVersion())),
				slog.String("auth_method", "publickey"),
				slog.Group("publickey",
					slog.String("type", key.Type()),
					slog.String("fingerprint_sha256", ssh.FingerprintSHA256(key)),
					slog.Bool("is_verified", false),
				),
			)
			srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "ssh", append(logData, d)...)

			fmt.Printf("[SSH] %s Username: %q (publickey authentication attempt)\n", evt.SourceIP, conn.User())
		}

		if srv.ReportInteractions {
			threatfeed.Update(evt.SourceIP)
		}

		// Reject the authentication attempt.
		return nil, fmt.Errorf("permission denied")
	}

	return &conf
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
		if path != "" {
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
