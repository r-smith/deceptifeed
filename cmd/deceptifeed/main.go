package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"syscall"

	"github.com/r-smith/deceptifeed/internal/config"
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

	// Parse command line flags.
	configPath := flag.String("config", "", "Path to optional XML configuration file")
	flag.BoolVar(&http.Enabled, "enable-http", config.DefaultEnableHTTP, "Enable HTTP server")
	flag.BoolVar(&https.Enabled, "enable-https", config.DefaultEnableHTTPS, "Enable HTTPS server")
	flag.BoolVar(&ssh.Enabled, "enable-ssh", config.DefaultEnableSSH, "Enable SSH server")
	flag.BoolVar(&cfg.ThreatFeed.Enabled, "enable-threatfeed", config.DefaultEnableThreatFeed, "Enable threat feed server")
	flag.StringVar(&cfg.LogPath, "log", config.DefaultLogPath, "Path to log file")
	flag.StringVar(&cfg.ThreatFeed.DatabasePath, "threat-database", config.DefaultThreatDatabasePath, "Path to threat feed database file")
	flag.IntVar(&cfg.ThreatFeed.ExpiryHours, "threat-expiry-hours", config.DefaultThreatExpiryHours, "Remove inactive IPs from threat feed after specified hours")
	flag.BoolVar(&cfg.ThreatFeed.IsPrivateIncluded, "threat-include-private", config.DefaultThreatIncludePrivate, "Include private IPs in threat feed")
	flag.StringVar(&http.HomePagePath, "html", config.DefaultHomePagePath, "Path to optional HTML file to serve")
	flag.StringVar(&http.Port, "port-http", config.DefaultPortHTTP, "Port number to listen on for HTTP server")
	flag.StringVar(&https.Port, "port-https", config.DefaultPortHTTPS, "Port number to listen on for HTTPS server")
	flag.StringVar(&ssh.Port, "port-ssh", config.DefaultPortSSH, "Port number to listen on for SSH server")
	flag.StringVar(&cfg.ThreatFeed.Port, "port-threatfeed", config.DefaultPortThreatFeed, "Port number to listen on for threat feed server")
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

	// If the `-config` flag is not provided, use "config.xml" from the current
	// directory if the file exists.
	if *configPath == "" {
		if _, err := os.Stat("config.xml"); err == nil {
			*configPath = "config.xml"
			fmt.Printf("Using configuration file: '%v'\n", *configPath)
		}
	}

	// If a config file is specified (via the `-config` flag or "config.xml"),
	// load it. Otherwise, configure the app using the command line flags and
	// default settings.
	if *configPath != "" {
		cfgFromFile, err := config.Load(*configPath)
		if err != nil {
			log.Fatalln("Failed to load configuration file:", err)
		}
		cfg = *cfgFromFile
	} else {
		https.HomePagePath = http.HomePagePath
		cfg.Servers = append(cfg.Servers, http, https, ssh)
		// Set defaults.
		for i := range cfg.Servers {
			cfg.Servers[i].LogPath = cfg.LogPath
			cfg.Servers[i].LogEnabled = true
			cfg.Servers[i].SendToThreatFeed = true
			if cfg.Servers[i].Type == config.SSH {
				cfg.Servers[i].Banner = config.DefaultBannerSSH
			}
		}
	}

	// Sort the servers by port number. This is for cosmetic reasons to format
	// the output when querying / viewing the active configuration.
	slices.SortFunc(cfg.Servers, func(a, b config.Server) int {
		p1, err := strconv.Atoi(a.Port)
		if err != nil {
			return 0
		}
		p2, err := strconv.Atoi(b.Port)
		if err != nil {
			return 0
		}
		return cmp.Compare(p1, p2)
	})

	// Initialize loggers.
	err := cfg.InitializeLoggers()
	if err != nil {
		log.Fatalln("Failed to initialize logging:", err)
	}
	defer cfg.CloseLogFiles()

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

	// Start the threat feed.
	if cfg.ThreatFeed.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			threatfeed.Start(cfg)
		}()
	}

	// Start the honeypots.
	for _, server := range cfg.Servers {
		if !server.Enabled || server.Port == "" {
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
		fmt.Println("All servers stopped.")
	case <-ctx.Done():
		fmt.Println("\nShutting down...")
	}
}
