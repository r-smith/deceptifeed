package config

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"github.com/r-smith/deceptifeed/internal/logmonitor"
	"github.com/r-smith/deceptifeed/internal/logrotate"
)

// Version stores Deceptifeed's version number. This variable is set at build
// time using the `-X` option with `-ldflags` and is assigned the latest Git
// tag. Refer to the Makefile in the project root for details on how it's set.
var Version = "undefined"

// Hostname identifies the system running Deceptifeed and is primarily used
// with honeypot logs. It is set once at startup from the DECEPTIFEED_HOSTNAME
// environment variable or the OS-reported name.
var Hostname string

const (
	DefaultEnableHTTP           = true
	DefaultEnableHTTPS          = true
	DefaultEnableSSH            = true
	DefaultEnableThreatFeed     = true
	DefaultPortHTTP             = 8080
	DefaultPortHTTPS            = 8443
	DefaultPortSSH              = 2222
	DefaultPortThreatFeed       = 9000
	DefaultThreatExpiryHours    = 336
	DefaultThreatDatabasePath   = "deceptifeed-database.csv"
	DefaultThreatIncludePrivate = true
	DefaultHTTPErrorCode        = 404
	DefaultLogPath              = "deceptifeed-log.txt"
	DefaultHomePagePath         = ""
	DefaultCertPathHTTPS        = "deceptifeed-https.crt"
	DefaultKeyPathHTTPS         = "deceptifeed-https.key"
	DefaultKeyPathSSH           = "deceptifeed-ssh.key"
	DefaultBannerSSH            = "SSH-2.0-OpenSSH_9.9"
	DefaultSessionTimeout       = 30
	DefaultSessionTimeoutHTTP   = 5
)

// Config stores the application's settings. It includes honeypot configuration,
// threatfeed configuration, and loggers.
type Config struct {
	LogPath    string              `xml:"defaultLogPath"`
	Servers    []Server            `xml:"honeypotServers>server"`
	ThreatFeed ThreatFeed          `xml:"threatFeed"`
	FilePath   string              `xml:"-"`
	Monitor    *logmonitor.Monitor `xml:"-"`
}

// ThreatFeed defines the settings for the threatfeed server.
type ThreatFeed struct {
	Enabled           bool   `xml:"enabled"`
	Port              uint16 `xml:"port"`
	DatabasePath      string `xml:"databasePath"`
	ExpiryHours       int    `xml:"threatExpiryHours"`
	IsPrivateIncluded bool   `xml:"includePrivateIPs"`
	ExcludeListPath   string `xml:"excludeListPath"`
	EnableTLS         bool   `xml:"enableTLS"`
	CertPath          string `xml:"certPath"`
	KeyPath           string `xml:"keyPath"`
}

// Server defines the settings for honeypot servers.
type Server struct {
	Type               ServerType        `xml:"type,attr"`
	Enabled            bool              `xml:"enabled"`
	Port               uint16            `xml:"port"`
	LogPath            string            `xml:"logPath"`
	LogConnections     bool              `xml:"logConnections"`
	LogInteractions    bool              `xml:"logInteractions"`
	ReportConnections  bool              `xml:"reportConnections"`
	ReportInteractions bool              `xml:"reportInteractions"`
	SessionTimeout     int               `xml:"sessionTimeout"`
	UseProxyProtocol   bool              `xml:"useProxyProtocol"`
	SourceIPHeader     string            `xml:"sourceIpHeader"`
	CertPath           string            `xml:"certPath"`
	KeyPath            string            `xml:"keyPath"`
	HomePagePath       string            `xml:"homePagePath"`
	ErrorPagePath      string            `xml:"errorPagePath"`
	ErrorCode          int               `xml:"errorCode"`
	Headers            []string          `xml:"headers>header"`
	CustomHeaders      map[string]string `xml:"-"`
	Prompts            []Prompt          `xml:"prompts>prompt"`
	Rules              Rules             `xml:"rules"`
	Banner             string            `xml:"banner"`
	LogFile            *logrotate.File   `xml:"-"`
	Logger             *slog.Logger      `xml:"-"`
}

// Rules define the criteria for reporting client IPs to the threatfeed.
type Rules struct {
	Include []Rule `xml:"include"`
	Exclude []Rule `xml:"exclude"`
}

// Rule represents a regex pattern.
type Rule struct {
	Target  string         `xml:"target,attr"`
	Pattern string         `xml:",chardata"`
	Negate  bool           `xml:"negate,attr"`
	Re      *regexp.Regexp `xml:"-"`
}

// Prompt defines a text prompt used by TCP honeypots. It displays the message,
// waits for client input, and logs the response. If multiple prompts are
// configured, they are displayed sequentially.
type Prompt struct {
	Text string `xml:",chardata"`

	// Log is an optional label used when logging the client's response. When
	// set to "none", the response is not logged.
	Log string `xml:"log,attr"`
}

// ServerType identifies the protocol used by a honeypot server. It determines
// how the server listens, responds, and logs activity.
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

// UnmarshalXML is a custom unmarshaler for the Server struct. It provides
// backwards compatibility for deprecated XML tags.
func (s *Server) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type alias Server

	var aux struct {
		*alias
		Timeout *int  `xml:"sessionTimeout"`
		OldLog  *bool `xml:"logEnabled"`
		OldFeed *bool `xml:"sendToThreatFeed"`
	}
	aux.alias = (*alias)(s)

	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}

	// Capture the timeout value. Use -1 to identify when no value is provided.
	if aux.Timeout != nil {
		s.SessionTimeout = *aux.Timeout
	} else {
		s.SessionTimeout = -1 // Indicates "not set".
	}

	// Use the deprecated XML tags if they're provided.
	if aux.OldLog != nil {
		s.LogInteractions = *aux.OldLog
	}
	if aux.OldFeed != nil {
		s.ReportInteractions = *aux.OldFeed
	}

	return nil
}

// Load reads an XML configuration file, decodes it into a Config struct, and
// applies sever defaults.
func Load(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg Config

	// Resolve the absolute path.
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	cfg.FilePath = abs

	// Decode the XML.
	decoder := xml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}

	// Finalize honeypot configuration.
	if err := cfg.Prepare(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Prepare finalizes the configuration for each honeypot server. It applies
// defaults, ensures a log path is defined, and ensures rules are compiled.
func (c *Config) Prepare() error {
	var errs []error
	seenPorts := make(map[uint16]string)

	// Validate threatfeed port.
	if c.ThreatFeed.Port == 0 {
		errs = append(errs, fmt.Errorf("invalid <port> number for <threatFeed>; assign a port number between 1 and 65535"))
	} else {
		seenPorts[c.ThreatFeed.Port] = "threatfeed"
	}

	for i := range c.Servers {
		s := &c.Servers[i]

		// Validate port (skip remaining checks when invalid).
		if s.Port == 0 {
			errs = append(errs, fmt.Errorf("invalid <port> number for honeypot #%d (%s); assign a port number between 1 and 65535", i+1, s.Type))
			continue
		}

		// Duplicate port check.
		if svc, exists := seenPorts[s.Port]; exists {
			errs = append(errs, fmt.Errorf("<port> %d is used by both %s and honeypot #%d (%s)", s.Port, svc, i+1, s.Type))
		} else {
			seenPorts[s.Port] = fmt.Sprintf("honeypot #%d (%s)", i+1, s.Type)
		}

		// Use the global log path if the server log path is not specified.
		if s.LogPath == "" {
			s.LogPath = c.LogPath
		}

		// Use the default SSH banner if no banner is specified.
		if s.Type == SSH && s.Banner == "" {
			s.Banner = DefaultBannerSSH
		}

		// Explicitly disable threatfeed for UDP honeypots.
		if s.Type == UDP {
			s.LogConnections = false
			s.ReportConnections = false
			s.ReportInteractions = false
		}

		// Apply default SessionTimeout if unset or out of range. Unset values
		// are set to -1 by UnmarshalXML. The valid range is 0-60 for TCP and
		// 1-60 for all other honeypot types.
		if s.SessionTimeout < 0 || s.SessionTimeout > 60 || (s.SessionTimeout == 0 && s.Type != TCP) {
			if s.Type == HTTP || s.Type == HTTPS {
				s.SessionTimeout = DefaultSessionTimeoutHTTP
			} else {
				s.SessionTimeout = DefaultSessionTimeout
			}
		}

		// Parse headers to a map[string]string (used by http.Header().Set()).
		s.CustomHeaders = parseCustomHeaders(s.Headers)

		// Validate and compile regex rules.
		if err := s.compileRules(); err != nil {
			errs = append(errs, fmt.Errorf("invalid <rules> defined for honeypot #%d (%s/%d): %w", i+1, s.Type, s.Port, err))
		}

		// Ensure only one proxy method is used.
		if (s.Type == HTTP || s.Type == HTTPS) && (s.UseProxyProtocol && s.SourceIPHeader != "") {
			errs = append(errs, fmt.Errorf("conflicting proxy settings defined for honeypot #%d (%s/%d); choose either <useProxyProtocol> or <sourceIpHeader>", i+1, s.Type, s.Port))
		}
	}

	return errors.Join(errs...)
}

// InitLoggers creates structured loggers for each server. It opens log files
// using the server's specified log path, defaulting to the global log path if
// none is provided.
func (c *Config) InitLoggers() error {
	const maxSize = 50
	c.Monitor = logmonitor.New()
	openedLogFiles := make(map[string]*slog.Logger)

	for i := range c.Servers {
		if !c.Servers[i].Enabled {
			continue
		}

		logPath := c.Servers[i].LogPath

		// If no log path is specified or logging is disabled, write to a log
		// monitor for live monitoring. No log data is written to disk.
		if logPath == "" || (!c.Servers[i].LogInteractions && !c.Servers[i].LogConnections) {
			c.Servers[i].Logger = slog.New(slog.NewJSONHandler(c.Monitor, nil))
			continue
		}

		// Reuse the logger if this log path has already been opened.
		if logger, exists := openedLogFiles[logPath]; exists {
			c.Servers[i].Logger = logger
			continue
		}

		// Open the specified log file.
		file, err := logrotate.OpenFile(logPath, maxSize)
		if err != nil {
			return err
		}

		// Create a JSON logger with two writers: one writes to disk using file
		// rotation, the other writes to a channel for live monitoring.
		logger := slog.New(
			slog.NewJSONHandler(
				io.MultiWriter(file, c.Monitor),
				&slog.HandlerOptions{
					ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
						switch a.Key {
						case slog.MessageKey:
							// Rename the default 'msg' field to 'event_type'.
							return slog.String("event_type", a.Value.String())
						case slog.LevelKey:
							// Remove the default 'level' field.
							return slog.Attr{}
						}
						return a
					},
				},
			),
		)

		c.Servers[i].Logger = logger
		c.Servers[i].LogFile = file

		// Store the logger for reuse.
		openedLogFiles[logPath] = logger
	}

	return nil
}

// CloseLogs closes all open log file handles. This function should be called
// when the application is shutting down.
func (c *Config) CloseLogs() {
	for i := range c.Servers {
		if c.Servers[i].LogFile != nil {
			_ = c.Servers[i].LogFile.Close()
		}
	}
}

// ResolvePaths updates all config paths with the cleaned and absolute
// representation of the path. Disabled components and empty paths are skipped.
func (c *Config) ResolvePaths() error {
	// Update the config struct with the cleaned and absolute paths.
	for _, p := range c.ActivePaths() {
		if *p == "" {
			continue
		}

		abs, err := filepath.Abs(*p)
		if err != nil {
			return fmt.Errorf("couldn't resolve '%v': %w", *p, err)
		}

		*p = abs
	}

	return nil
}

// ActivePaths returns a slice of pointers to all configuration paths for
// components that are currently enabled.
func (c *Config) ActivePaths() []*string {
	// Start with global log path.
	paths := []*string{&c.LogPath}

	// Collect threatfeed paths.
	if c.ThreatFeed.Enabled {
		paths = append(paths,
			&c.ThreatFeed.DatabasePath,
			&c.ThreatFeed.ExcludeListPath,
		)
		if c.ThreatFeed.EnableTLS {
			paths = append(paths,
				&c.ThreatFeed.CertPath,
				&c.ThreatFeed.KeyPath,
			)
		}
	}

	// Collect honeypot paths.
	for i := range c.Servers {
		s := &c.Servers[i]
		if !s.Enabled {
			continue
		}
		paths = append(paths,
			&s.LogPath,
			&s.CertPath,
			&s.KeyPath,
			&s.HomePagePath,
			&s.ErrorPagePath,
		)
	}

	return paths
}
