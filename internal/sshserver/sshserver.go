package sshserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/r-smith/deceptifeed/internal/certutil"
	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/console"
	"github.com/r-smith/deceptifeed/internal/eventdata"
	"github.com/r-smith/deceptifeed/internal/proxyproto"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
	"golang.org/x/crypto/ssh"
)

// Start launches an SSH honeypot server that logs credentials and reports
// activity to the threatfeed. All authentication attempts are rejected. It is
// not possible to "login" to the server.
func Start(srv *config.Server) {
	sshConfig := &ssh.ServerConfig{}

	// Load or generate a private key and add it to the SSH configuration.
	privateKey, err := loadOrCreateKey(srv.KeyPath)
	if err != nil {
		console.Error(console.SSH, "Failed to start honeypot on port %d: ssh key failure: %v", srv.Port, err)
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
	addr := net.JoinHostPort("", strconv.Itoa(int(srv.Port)))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		console.Error(console.SSH, "Failed to start honeypot on port %d: %v", srv.Port, err)
		return
	}

	if srv.UseProxyProtocol {
		listener = &proxyproto.Listener{Listener: listener}
	}
	defer listener.Close()
	console.Info(console.SSH, "Honeypot is active and listening on port %d", srv.Port)

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

	// If the connection is Proxy Protocol wrapped, extract the metadata.
	if pconn, ok := conn.(*proxyproto.Conn); ok {
		// Record the proxy's IP.
		if rawAddr, ok := pconn.Conn.RemoteAddr().(*net.TCPAddr); ok {
			evt.ProxyIP = rawAddr.AddrPort().Addr().Unmap()
		}

		// Record the parsing results.
		if extractedIP, err := pconn.ProxyData(); err == nil && extractedIP.IsValid() {
			evt.ProxyParsed = true
		} else if err != nil {
			evt.ProxyError = err.Error()
		}
	}

	logData := prepareLog(&evt, srv)

	// Log and report the connection.
	if srv.LogConnections {
		srv.Logger.LogAttrs(context.Background(), slog.LevelInfo, "connection", logData...)
		console.Debug(console.SSH, "%s connected to port %d", evt.SourceIP, evt.ServerPort)
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
			slog.Any("proxy_ip", evt.ProxyIP),
			slog.Bool("proxy_parsed", evt.ProxyParsed),
			slog.String("proxy_error", evt.ProxyError),
		)
	}
	d = append(d,
		slog.Any("server_ip", evt.ServerIP),
		slog.Uint64("server_port", uint64(evt.ServerPort)),
		slog.String("server_name", config.Hostname),
	)
	return d
}

// configureCallbacks attaches authentication callbacks to a base SSH config.
// The callbacks log authentication attempts and update the threatfeed.
func configureCallbacks(base *ssh.ServerConfig, srv *config.Server, evt *eventdata.Connection, logData []slog.Attr) *ssh.ServerConfig {
	conf := *base

	// Password authentication: Log the credentials, update the threatfeed,
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

			console.Debug(console.SSH, "%s → Username: %q Password: %q", evt.SourceIP, conn.User(), string(password))
		}

		if srv.ReportInteractions {
			threatfeed.Update(evt.SourceIP)
		}

		// Insert a fixed delay, then reject the authentication attempt.
		time.Sleep(2 * time.Second)
		return nil, fmt.Errorf("invalid username or password")
	}

	// Publickey authentication: Log the key hash and username, update the
	// threatfeed, then reject the attempt. Note: The logged key is unverified
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

			console.Debug(console.SSH, "%s → Username: %q (publickey authentication)", evt.SourceIP, conn.User())
		}

		if srv.ReportInteractions {
			threatfeed.Update(evt.SourceIP)
		}

		// Reject the authentication attempt.
		return nil, fmt.Errorf("permission denied")
	}

	return &conf
}

// loadOrCreateKey attempts to load an SSH private key from the given path.
// If the path is empty or the file doesn't exist, it generates a new Ed25519
// key, saves it (if a path is provided), and returns an ssh.Signer.
func loadOrCreateKey(path string) (ssh.Signer, error) {
	if path != "" {
		signer, err := loadKey(path)
		if err == nil {
			return signer, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	// Generate a new key because no existing key was found.
	return createKey(path)
}

// loadKey reads a private key from the filesystem and parses it into an
// ssh.Signer.
func loadKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// createKey generates a new Ed25519 key and converts it to an ssh.Signer. If a
// path is given, it attempts to save the key to disk.
func createKey(path string) (ssh.Signer, error) {
	console.Info(console.SSH, "Generating Ed25519 private key...")

	priv, err := certutil.GenerateEd25519Key(path)
	if err != nil {
		var saveError *certutil.SaveError
		if errors.As(err, &saveError) {
			console.Warning(console.SSH, "Failed to save SSH key to disk; generated key will not persist after restart: %v", err)
			return ssh.NewSignerFromKey(priv)
		}
		return nil, err
	}

	if path != "" {
		console.Info(console.SSH, "Private key saved to '%s'", path)
	}

	return ssh.NewSignerFromKey(priv)
}
