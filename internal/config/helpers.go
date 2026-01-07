package config

import (
	"net"
	"os"
)

// GetHostname returns the system's hostname. It first checks for a value
// provided via environment variable, then falls back to the name reported by
// the OS.
func GetHostname() string {
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
