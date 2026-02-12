package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"syscall"

	"github.com/r-smith/deceptifeed/internal/config"
	"github.com/r-smith/deceptifeed/internal/console"
	"github.com/r-smith/deceptifeed/internal/httpserver"
	"github.com/r-smith/deceptifeed/internal/sshserver"
	"github.com/r-smith/deceptifeed/internal/tcpserver"
	"github.com/r-smith/deceptifeed/internal/threatfeed"
	"github.com/r-smith/deceptifeed/internal/udpserver"
)

func main() {
	// Initialize config structs for parsing command-line flags.
	cfg := config.Config{}
	http := config.Server{Type: config.HTTP}
	https := config.Server{Type: config.HTTPS}
	ssh := config.Server{Type: config.SSH}
	var httpPort, httpsPort, sshPort, threatPort uint

	// Parse command line flags.
	configPath := flag.String("config", "", "Path to optional XML configuration file")
	flag.BoolVar(&http.Enabled, "enable-http", config.DefaultEnableHTTP, "Enable HTTP server")
	flag.BoolVar(&https.Enabled, "enable-https", config.DefaultEnableHTTPS, "Enable HTTPS server")
	flag.BoolVar(&ssh.Enabled, "enable-ssh", config.DefaultEnableSSH, "Enable SSH server")
	flag.BoolVar(&cfg.ThreatFeed.Enabled, "enable-threatfeed", config.DefaultEnableThreatFeed, "Enable threatfeed server")
	flag.StringVar(&cfg.LogPath, "log", config.DefaultLogPath, "Path to log file")
	flag.StringVar(&cfg.ThreatFeed.DatabasePath, "threat-database", config.DefaultThreatDatabasePath, "Path to threatfeed database file")
	flag.IntVar(&cfg.ThreatFeed.ExpiryHours, "threat-expiry-hours", config.DefaultThreatExpiryHours, "Remove inactive IPs from threatfeed after specified hours")
	flag.BoolVar(&cfg.ThreatFeed.IsPrivateIncluded, "threat-include-private", config.DefaultThreatIncludePrivate, "Include private IPs in threatfeed")
	flag.StringVar(&http.HomePagePath, "html", config.DefaultHomePagePath, "Path to optional HTML file to serve")
	flag.UintVar(&httpPort, "port-http", config.DefaultPortHTTP, "Port number to listen on for HTTP server")
	flag.UintVar(&httpsPort, "port-https", config.DefaultPortHTTPS, "Port number to listen on for HTTPS server")
	flag.UintVar(&sshPort, "port-ssh", config.DefaultPortSSH, "Port number to listen on for SSH server")
	flag.UintVar(&threatPort, "port-threatfeed", config.DefaultPortThreatFeed, "Port number to listen on for threatfeed server")
	flag.StringVar(&https.CertPath, "https-cert", config.DefaultCertPathHTTPS, "Path to optional TLS public certificate")
	flag.StringVar(&https.KeyPath, "https-key", config.DefaultKeyPathHTTPS, "Path to optional TLS private key")
	flag.StringVar(&ssh.KeyPath, "ssh-key", config.DefaultKeyPathSSH, "Path to optional SSH private key")
	ver := flag.Bool("version", false, "Output the version number and exit")
	flag.Parse()

	// If the `-version` flag is provided, output the version number and exit.
	if *ver {
		fmt.Println(config.Version)
		return
	}

	// Assign 'port' flags to config structs.
	http.Port = uint16(httpPort)
	https.Port = uint16(httpsPort)
	ssh.Port = uint16(sshPort)
	cfg.ThreatFeed.Port = uint16(threatPort)

	version := ""
	if config.Version != "undefined" {
		version = " v" + config.Version
	}
	console.Info(console.Main, "Initializing Deceptifeed%s", version)

	// If the `-config` flag is not provided, try using "config.xml" from the
	// current directory.
	if *configPath == "" {
		if _, err := os.Stat("config.xml"); err == nil {
			*configPath = "config.xml"
		}
	}

	// If a config file is specified (via the `-config` flag or "config.xml"),
	// load it. Otherwise, configure the app using the command line flags and
	// default settings.
	if *configPath != "" {
		console.Info(console.Main, "Reading configuration file '%v'", *configPath)
		cfgFromFile, err := config.Load(*configPath)
		if err != nil {
			console.Errors(console.Cfg, "Config error → ", err)
			console.Info(console.Main, "Shutting down...")
			return
		}
		cfg = *cfgFromFile
	} else {
		https.HomePagePath = http.HomePagePath
		cfg.Servers = append(cfg.Servers, http, https, ssh)
		// Set defaults.
		for i := range cfg.Servers {
			s := &cfg.Servers[i]
			s.LogPath = cfg.LogPath
			s.LogInteractions = true
			s.ReportInteractions = true
			switch s.Type {
			case config.HTTP:
				s.SessionTimeout = config.DefaultSessionTimeoutHTTP
			case config.SSH:
				s.Banner = config.DefaultBannerSSH
				s.SessionTimeout = config.DefaultSessionTimeout
			default:
				s.SessionTimeout = config.DefaultSessionTimeout
			}
		}
	}

	// Update config paths with the cleaned and absolute path representations.
	if err := cfg.ResolvePaths(); err != nil {
		console.Error(console.Main, "Failed to resolve paths: %v", err)
		return
	}

	// Ensure directories exist and create directory structure if missing.
	if err := ensureDirs(&cfg); err != nil {
		console.Error(console.Main, "Directory setup failed: %v", err)
		return
	}

	// Initialize loggers.
	if err := cfg.InitLoggers(); err != nil {
		console.Error(console.Main, "Failed to initialize logging: %v", err)
		return
	}
	defer cfg.CloseLogs()

	// Sort servers by port number for consistent order when viewing config.
	slices.SortFunc(cfg.Servers, func(a, b config.Server) int {
		return cmp.Compare(a.Port, b.Port)
	})

	// Resolve the system's hostname for identification in logs.
	config.InitHostname()

	// Setup signal context. Note: Graceful shutdown is not yet implemented.
	// For now, only a shutdown message is printed before exiting.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start the threatfeed and honeypots.
	run(ctx, &cfg)
}

// run spawns the threatfeed and configured honeypot servers, and blocks until
// the program is terminated.
func run(ctx context.Context, cfg *config.Config) {
	var wg sync.WaitGroup

	// Start the threatfeed.
	if cfg.ThreatFeed.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			threatfeed.Start(cfg)
		}()
	}

	// Start the honeypots.
	for _, server := range cfg.Servers {
		if !server.Enabled {
			continue
		}

		wg.Add(1)
		go func(s config.Server) {
			defer wg.Done()

			switch s.Type {
			case config.HTTP, config.HTTPS:
				httpserver.Start(&s)
			case config.SSH:
				sshserver.Start(&s)
			case config.TCP:
				tcpserver.Start(&s)
			case config.UDP:
				udpserver.Start(&s)
			}
		}(server)
	}

	// Create a channel to signal if all servers stop.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Block until all servers stop naturally or interrupt signal is received.
	select {
	case <-done:
		console.Info(console.Main, "All servers stopped")
	case <-ctx.Done():
		console.Info(console.Main, "Shutting down...")
	}
}

// ensureDirs ensures the filesystem is ready by creating parent directories
// for file paths defined in the configuration. It skips empty paths and
// returns an error if a directory can't be created.
func ensureDirs(cfg *config.Config) error {
	for _, p := range cfg.ActivePaths() {
		if *p == "" {
			continue
		}
		dir := filepath.Dir(*p)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("couldn't create '%v': %w", dir, err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("couldn't access '%v': %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("path '%v' is not a directory", dir)
		}
	}
	return nil
}
