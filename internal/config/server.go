package config

import (
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/r-smith/deceptifeed/internal/logrotate"
)

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

// compileRules pre-compiles and stores Include and Exclude rules that may
// appear in a honeypot configuration. It also converts rule Targets to
// canonical format ("path" to "Path", "user-agent" to "User-Agent").
func (s *Server) compileRules() error {
	// Include rules.
	for i := range s.Rules.Include {
		rule := &s.Rules.Include[i]

		// Canonicalize `Target`.
		rule.Target = http.CanonicalHeaderKey(rule.Target)

		// Compile.
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %s", rule.Pattern)
		}
		rule.Re = re
	}

	// Exclude rules.
	for i := range s.Rules.Exclude {
		rule := &s.Rules.Exclude[i]

		// Canonicalize `Target`.
		rule.Target = http.CanonicalHeaderKey(rule.Target)

		// Compile.
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %s", rule.Pattern)
		}
		rule.Re = re
	}
	return nil
}

// parseHeaders converts the Headers slice (strings in "Key: Value" format)
// into the CustomHeaders map. The Headers slice is used for loading the
// strings from the configuration file, while the resulting CustomHeaders map
// provides efficient access for using the headers in HTTP honeypots.
func (s *Server) parseHeaders() {
	result := make(map[string]string)

	for _, header := range s.Headers {
		kv := strings.SplitN(header, ":", 2)
		if len(kv) == 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	s.CustomHeaders = result
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
