package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

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
	flag.Parse()

	// If the `-config` flag is not provided, use "config.xml" from the current
	// directory if the file exists.
	if len(*configPath) == 0 {
		if _, err := os.Stat("config.xml"); err == nil {
			*configPath = "config.xml"
			fmt.Printf("Using configuration file: '%v'\n", *configPath)
		}
	}

	// If a config file is specified (via the `-config` flag or "config.xml"),
	// load it. Otherwise, configure the app using the command line flags and
	// default settings.
	if len(*configPath) > 0 {
		cfgFromFile, err := config.Load(*configPath)
		if err != nil {
			log.Fatalln("Shutting down. Failed to load configuration file:", err)
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

	// Initialize structured loggers for each honeypot server.
	err := cfg.InitializeLoggers()
	if err != nil {
		log.Fatalln("Shutting down. Failed to initialize logging:", err)
	}
	defer cfg.CloseLogFiles()

	// Initialize a WaitGroup, as each server operates in its own goroutine.
	// The WaitGroup counter is set to the number of configured honeypot
	// servers, plus one additional count for the threat feed server.
	var wg sync.WaitGroup
	wg.Add(len(cfg.Servers) + 1)

	// Start the threat feed.
	go func() {
		defer wg.Done()

		if !cfg.ThreatFeed.Enabled {
			return
		}

		threatfeed.Start(&cfg)
	}()

	// Start the honeypot servers.
	for _, server := range cfg.Servers {
		go func() {
			defer wg.Done()

			if !server.Enabled || len(server.Port) == 0 {
				return
			}

			switch server.Type {
			case config.HTTP, config.HTTPS:
				httpserver.Start(&server)
			case config.SSH:
				sshserver.Start(&server)
			case config.TCP:
				tcpserver.Start(&server)
			case config.UDP:
				udpserver.Start(&server)
			}
		}()
	}

	// Wait for all servers to end.
	wg.Wait()
}
