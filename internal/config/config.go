package config

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"github.com/r-smith/deceptifeed/internal/logrotate"
)

// Version stores Deceptifeed's version number. This variable is set at build
// time using the `-X` option with `-ldflags` and is assigned the latest Git
// tag. Refer to the Makefile in the project root for details on how it's set.
var Version = "undefined"

// This block of constants defines the default application settings when no
// configuration file is provided.
const (
	DefaultEnableHTTP           = true
	DefaultEnableHTTPS          = true
	DefaultEnableSSH            = true
	DefaultEnableThreatFeed     = true
	DefaultPortHTTP             = "8080"
	DefaultPortHTTPS            = "8443"
	DefaultPortSSH              = "2222"
	DefaultPortThreatFeed       = "9000"
	DefaultThreatExpiryHours    = 336
	DefaultThreatDatabasePath   = "deceptifeed-database.csv"
	DefaultThreatIncludePrivate = true
	DefaultLogPath              = "deceptifeed-log.txt"
	DefaultHomePagePath         = ""
	DefaultCertPathHTTPS        = "deceptifeed-https.crt"
	DefaultKeyPathHTTPS         = "deceptifeed-https.key"
	DefaultKeyPathSSH           = "deceptifeed-ssh.key"
	DefaultBannerSSH            = "SSH-2.0-OpenSSH_9.6"
)

// ServerType represents the different types of honeypot servers that can be
// deployed. Each type has its own specific handlers and behavior.
type ServerType int

const (
	HTTP ServerType = iota
	HTTPS
	SSH
	TCP
	UDP
)

// String returns a string represenation of ServerType.
func (t ServerType) String() string {
	return [...]string{"http", "https", "ssh", "tcp", "udp"}[t]
}

// UnmarshalXMLAttr unmarshals the XML 'type' attribute from 'server' elements
// into a ServerType.
//
// Example XML snippet:
// <server type="http"><enabled>true</enabled></server>
func (t *ServerType) UnmarshalXMLAttr(attr xml.Attr) error {
	switch attr.Value {
	case "http":
		*t = HTTP
	case "https":
		*t = HTTPS
	case "ssh":
		*t = SSH
	case "tcp":
		*t = TCP
	case "udp":
		*t = UDP
	default:
		return fmt.Errorf("invalid server type: %s", attr.Value)
	}
	return nil
}

// Config holds the configuration settings for the application. It contains the
// logger, settings for managing a threat feed, and the collection of honeypot
// servers that are configured to run.
type Config struct {
	LogPath    string     `xml:"defaultLogPath"`
	Servers    []Server   `xml:"honeypotServers>server"`
	ThreatFeed ThreatFeed `xml:"threatFeed"`
	FilePath   string     `xml:"-"`
}

// Server represents a honeypot server with its relevant settings.
type Server struct {
	Type             ServerType      `xml:"type,attr"`
	Enabled          bool            `xml:"enabled"`
	Port             string          `xml:"port"`
	CertPath         string          `xml:"certPath"`
	KeyPath          string          `xml:"keyPath"`
	HomePagePath     string          `xml:"homePagePath"`
	ErrorPagePath    string          `xml:"errorPagePath"`
	Banner           string          `xml:"banner"`
	Headers          []string        `xml:"headers>header"`
	Prompts          []Prompt        `xml:"prompts>prompt"`
	SendToThreatFeed bool            `xml:"sendToThreatFeed"`
	Rules            Rules           `xml:"rules"`
	SourceIPHeader   string          `xml:"sourceIpHeader"`
	LogPath          string          `xml:"logPath"`
	LogEnabled       bool            `xml:"logEnabled"`
	LogFile          *logrotate.File `xml:"-"`
	Logger           *slog.Logger    `xml:"-"`
}

type Rules struct {
	Include []Rule `xml:"include"`
	Exclude []Rule `xml:"exclude"`
}

type Rule struct {
	Target  string `xml:"target,attr"`
	Pattern string `xml:",chardata"`
	Negate  bool   `xml:"negate,attr"`
}

// Prompt represents a text prompt that can be displayed to connecting clients
// when using the TCP-type honeypot server. Each prompt waits for input and
// logs the response. A Server can include multiple prompts which are displayed
// one at a time. The optional Log field gives a description when logging the
// response.
type Prompt struct {
	Text string `xml:",chardata"`
	Log  string `xml:"log,attr"`
}

// ThreatFeed represents an optional HTTP server that serves a list of IP
// addresses observed interacting with your honeypot servers. This server
// outputs data in a format compatible with most enterprise firewalls, which
// can be configured to automatically block communication with IP addresses
// appearing in the threat feed.
type ThreatFeed struct {
	Enabled           bool   `xml:"enabled"`
	Port              string `xml:"port"`
	DatabasePath      string `xml:"databasePath"`
	ExpiryHours       int    `xml:"threatExpiryHours"`
	IsPrivateIncluded bool   `xml:"includePrivateIPs"`
	CustomThreatsPath string `xml:"customThreatsPath"`
	ExcludeListPath   string `xml:"excludeListPath"`
}

// Load reads an optional XML configuration file and unmarshals its contents
// into a Config struct. Any errors encountered opening or decoding the file
// are returned. When decoding is successful, the populated Config struct is
// returned.
func Load(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	absPath, err := filepath.Abs(filename)
	if err != nil {
		config.FilePath = filename
	} else {
		config.FilePath = absPath
	}

	xmlBytes, _ := io.ReadAll(file)
	err = xml.Unmarshal(xmlBytes, &config)
	if err != nil {
		return nil, err
	}

	for i := range config.Servers {
		// Use the global log path if the server log path is not specified.
		if len(config.Servers[i].LogPath) == 0 {
			config.Servers[i].LogPath = config.LogPath
		}

		// Validate regex rules.
		if err := validateRegexRules(config.Servers[i].Rules); err != nil {
			return nil, err
		}

		// Use the default SSH banner if no banner is specified.
		if config.Servers[i].Type == SSH && len(config.Servers[i].Banner) == 0 {
			config.Servers[i].Banner = DefaultBannerSSH
		}
	}

	return &config, nil
}

// validateRegexRules checks the validity of regex patterns in the rules.
func validateRegexRules(rules Rules) error {
	for _, rule := range rules.Include {
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %s", rule.Pattern)
		}
	}
	for _, rule := range rules.Exclude {
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %s", rule.Pattern)
		}
	}
	return nil
}

// InitializeLoggers creates structured loggers for each server. It opens log
// files using the server's specified log path, defaulting to the global log
// path if none is provided.
func (c *Config) InitializeLoggers() error {
	const maxSize = 50
	openedLogFiles := make(map[string]*slog.Logger)

	for i := range c.Servers {
		if !c.Servers[i].Enabled {
			continue
		}

		logPath := c.Servers[i].LogPath

		// If no log path is specified or if logging is disabled, discard logs.
		if len(logPath) == 0 || !c.Servers[i].LogEnabled {
			c.Servers[i].Logger = slog.New(slog.DiscardHandler)
			continue
		}

		// Check if this log path has already been opened. If so, reuse the
		// logger.
		if logger, exists := openedLogFiles[logPath]; exists {
			c.Servers[i].Logger = logger
			continue
		}

		// Open the specified log file.
		file, err := logrotate.OpenFile(logPath, maxSize)
		if err != nil {
			return err
		}

		// Create a new logger.
		logger := slog.New(slog.NewJSONHandler(file, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Remove 'message' and 'log level' fields from output.
				if a.Key == slog.MessageKey || a.Key == slog.LevelKey {
					return slog.Attr{}
				}
				return a
			},
		}))

		c.Servers[i].Logger = logger
		c.Servers[i].LogFile = file

		// Store the logger for reuse.
		openedLogFiles[logPath] = logger
	}

	return nil
}

// CloseLogFiles closes all open log file handles for the servers. This
// function should be called when the application is shutting down.
func (c *Config) CloseLogFiles() {
	for i := range c.Servers {
		if c.Servers[i].LogFile != nil {
			_ = c.Servers[i].LogFile.Close()
		}
	}
}
