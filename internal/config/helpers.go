package config

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

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

// parseCustomHeaders takes a slice of header strings in the format of
// "Name: Value", and returns a map of the Name-Value pairs. For example, given
// the input:
// `[]{"Server: Microsoft-IIS/8.5", "X-Powered-By: ASP.NET"}`, the function
// would return a map with "Server" and "X-Powered-By" as keys, each linked to
// their corresponding values.
func parseCustomHeaders(headers []string) map[string]string {
	result := make(map[string]string)

	for _, header := range headers {
		kv := strings.SplitN(header, ":", 2)
		if len(kv) == 2 {
			result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return result
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
