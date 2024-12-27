package config

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
)

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
}

// Server represents a honeypot server with its relevant settings.
type Server struct {
	Type             ServerType   `xml:"type,attr"`
	Enabled          bool         `xml:"enabled"`
	Port             string       `xml:"port"`
	CertPath         string       `xml:"certPath"`
	KeyPath          string       `xml:"keyPath"`
	HomePagePath     string       `xml:"homePagePath"`
	ErrorPagePath    string       `xml:"errorPagePath"`
	Banner           string       `xml:"banner"`
	Headers          []string     `xml:"headers>header"`
	Prompts          []Prompt     `xml:"prompts>prompt"`
	SendToThreatFeed bool         `xml:"sendToThreatFeed"`
	ThreatScore      int          `xml:"threatScore"`
	Rules            Rules        `xml:"rules"`
	SourceIPHeader   string       `xml:"sourceIpHeader"`
	LogPath          string       `xml:"logPath"`
	LogEnabled       bool         `xml:"logEnabled"`
	LogFile          *os.File     `xml:"-"`
	Logger           *slog.Logger `xml:"-"`
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
	Enabled            bool   `xml:"enabled"`
	Port               string `xml:"port"`
	DatabasePath       string `xml:"databasePath"`
	ExpiryHours        int    `xml:"threatExpiryHours"`
	IsPrivateIncluded  bool   `xml:"includePrivateIPs"`
	MinimumThreatScore int    `xml:"minimumThreatScore"`
	CustomThreatsPath  string `xml:"customThreatsPath"`
	ExcludeListPath    string `xml:"excludeListPath"`
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
	xmlBytes, _ := io.ReadAll(file)
	err = xml.Unmarshal(xmlBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode XML file: %w", err)
	}

	for i := range config.Servers {
		// Ensure a minimum threat score of 0.
		if config.Servers[i].ThreatScore < 0 {
			config.Servers[i].ThreatScore = 0
		}

		// Validate regex rules.
		if err := validateRegexRules(config.Servers[i].Rules); err != nil {
			return nil, err
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
	openedLogFiles := make(map[string]*slog.Logger)

	for i := range c.Servers {
		if !c.Servers[i].Enabled {
			continue
		}

		// Use the global log path if the server log path is not specified.
		var logPath string
		if len(c.Servers[i].LogPath) > 0 {
			logPath = c.Servers[i].LogPath
		} else {
			logPath = c.LogPath
		}

		// If no log path is specified or if logging is disabled, discard logs.
		if len(logPath) == 0 || !c.Servers[i].LogEnabled {
			c.Servers[i].Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
			continue
		}

		// Check if this log path has already been opened. If so, reuse the
		// logger.
		if logger, exists := openedLogFiles[logPath]; exists {
			c.Servers[i].Logger = logger
			continue
		}

		// Open the specified log file.
		file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
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
