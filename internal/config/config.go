package config

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/r-smith/deceptifeed/internal/logmonitor"
	"github.com/r-smith/deceptifeed/internal/logrotate"
)

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
	DefaultReportDay            = time.Monday
	DefaultReportHour           = 9
)

var (
	// Version stores Deceptifeed's version number. This variable is set at
	// build time using the `-X` option with `-ldflags` and is assigned the
	// latest Git tag. Refer to the Makefile in the project root for details on
	// how it's set.
	Version = "undefined"

	// Hostname identifies the system running Deceptifeed and is primarily used
	// with honeypot logs. It is set once at startup from the
	// DECEPTIFEED_HOSTNAME environment variable or the OS-reported name.
	Hostname string
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

	// Finalize the configuration.
	if err := cfg.Prepare(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Prepare finalizes the threatfeed and honeypot server configuration. It
// applies defaults, performs validation, and ensures settings are initialized.
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

		// Parse custom HTTP response headers.
		s.parseHeaders()

		// Validate and compile regex rules.
		if err := s.compileRules(); err != nil {
			errs = append(errs, fmt.Errorf("invalid <rules> defined for honeypot #%d (%s/%d): %w", i+1, s.Type, s.Port, err))
		}

		// Ensure only one proxy method is used.
		if (s.Type == HTTP || s.Type == HTTPS) && (s.UseProxyProtocol && s.SourceIPHeader != "") {
			errs = append(errs, fmt.Errorf("conflicting proxy settings defined for honeypot #%d (%s/%d); choose either <useProxyProtocol> or <sourceIpHeader>", i+1, s.Type, s.Port))
		}
	}

	// Initialize reporting fields.
	if err := c.ThreatFeed.Reporting.Daily.init(); err != nil {
		errs = append(errs, fmt.Errorf("invalid <daily> schedule: %w", err))
	}
	if err := c.ThreatFeed.Reporting.Weekly.init(); err != nil {
		errs = append(errs, fmt.Errorf("invalid <weekly> schedule: %w", err))
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
			&c.ThreatFeed.Reporting.HistoryPath,
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

// GetHostIP returns the local IP address of the system, defaulting to
// "127.0.0.1" if it cannot be determined. If there is more than one active IP
// address on the system, only the first found is returned.
func GetHostIP() string {
	const failedLookup = "127.0.0.1"

	interfaces, err := net.Interfaces()
	if err != nil {
		return failedLookup
	}

	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			return failedLookup
		}

		for _, addr := range addrs {
			if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback() {
				if ip.IP.To4() != nil {
					return ip.IP.String()
				}
			}
		}
	}
	return failedLookup
}

// InitHostname resolves the system's hostname and stores it in the global
// Hostname variable. It should be called once during application startup.
func InitHostname() {
	Hostname = getHostname()
}

// getHostname returns the system's hostname. It first checks for a value
// provided via environment variable, then falls back to the name reported by
// the OS.
func getHostname() string {
	if h, ok := os.LookupEnv("DECEPTIFEED_HOSTNAME"); ok {
		return h
	}

	if h, err := os.Hostname(); err == nil {
		return h
	}

	return ""
}
