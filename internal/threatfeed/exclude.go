package threatfeed

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// excludeHeader is the default content written to a new exclude list file.
const excludeHeader = `# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# Deceptifeed: Threatfeed exclude list
#
# Entries in this file are ignored and filtered out of the threatfeed.
# Changes are detected automatically while Deceptifeed is running.
#
# FORMAT:
# - Single IP: 192.168.1.100
# - Network:   172.16.0.0/24 (CIDR notation)
#
# COMMENTS:
# - Use '#' for comments (can be at the start or middle of a line).
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-


# Example entries:
# 192.168.0.15     # Ignore attack surface management platform
# 10.0.50.0/24     # Ignore search engine crawler network
`

var (
	// excludeMu protects access to the exclude list (excludeIPs/excludeCIDRs).
	excludeMu sync.RWMutex

	// excludeIPs stores IP addresses to exclude from the threatfeed.
	excludeIPs = make(map[netip.Addr]struct{})

	// excludeCIDRs stores network ranges to exclude from the threatfeed.
	excludeCIDRs = []netip.Prefix{}

	// excludeModTime tracks the last modification time of the exclude file.
	excludeModTime time.Time
)

// initExcludeList checks for the existence of an exclude list file and creates
// it with a default header if it's missing.
func initExcludeList(path string) error {
	if path == "" {
		return nil
	}

	_, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return os.WriteFile(path, []byte(excludeHeader), 0644)
	}
	return err
}

// parseExcludeList reads IP addresses and CIDR ranges from the specified file.
// It returns a map of IP addresses and a slice of network prefixes to ignore.
// The file supports single IP addresses and CIDR notation. Comments can appear
// anywhere on a line using '#' and whitespace is stripped.
func parseExcludeList(path string) (map[netip.Addr]struct{}, []netip.Prefix, error) {
	if path == "" {
		return nil, nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	// `ips` stores individual IPs to exclude, and `cidr` stores CIDR networks
	// to exclude.
	ips := make(map[netip.Addr]struct{})
	cidr := []netip.Prefix{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Remove comments and trim.
		if i := strings.IndexByte(line, '#'); i != -1 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse as CIDR.
		if prefix, err := netip.ParsePrefix(line); err == nil {
			// Ensure canonical form (eg: 192.168.1.7/24 -> 192.168.1.0/24).
			prefix = prefix.Masked()

			// If it's a single IP expressed as CIDR, store as a single IP.
			// Otherwise, store as CIDR.
			if prefix.IsSingleIP() {
				ips[prefix.Addr().Unmap()] = struct{}{}
			} else {
			cidr = append(cidr, prefix)
			}
			continue
		}

		// Try to parse as single IP.
		if addr, err := netip.ParseAddr(line); err == nil {
			ips[addr.Unmap()] = struct{}{}
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return ips, cidr, nil
}

// reloadExcludeList checks if the exclude list file has been modified since
// the last load. If newer, it parses the file and updates the in-memory
// exclude list.
func reloadExcludeList(path string) {
	if path == "" {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	if !info.ModTime().After(excludeModTime) {
		return
	}

	// File has changed. Parse the file and update the in-memory list.
	ips, cidrs, err := parseExcludeList(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reloading exclude list:", err)
		return
	}

	excludeMu.Lock()
	excludeIPs = ips
	excludeCIDRs = cidrs
	excludeMu.Unlock()

	if !excludeModTime.IsZero() {
		fmt.Printf("Exclude list updated: %d IPs, %d CIDRs\n", len(ips), len(cidrs))
	}

	// Update last modified timestamp.
	excludeModTime = info.ModTime()
}

// isExcluded returns whether the provided IP address is in the exclude list.
func isExcluded(ip netip.Addr) bool {
	excludeMu.RLock()
	defer excludeMu.RUnlock()

	if _, found := excludeIPs[ip.Unmap()]; found {
		return true
	}

	for _, prefix := range excludeCIDRs {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
