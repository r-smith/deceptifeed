package threatfeed

import (
	"bufio"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"strings"
)

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

// parseExcludeList reads IP addresses and CIDR ranges from a file. Each line
// should contain an IP address or CIDR. It returns a map of the unique IPs and
// a slice of the CIDR ranges found in the file. The file may include comments
// using "#". The "#" symbol on a line and everything after is ignored.
func parseExcludeList(filepath string) (map[netip.Addr]struct{}, []netip.Prefix, error) {
	if len(filepath) == 0 {
		return nil, nil, nil
	}

	f, err := os.Open(filepath)
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
		if len(line) == 0 {
			continue
		}

		// Try to parse as CIDR.
		if prefix, err := netip.ParsePrefix(line); err == nil {
			cidr = append(cidr, prefix)
			continue
		}

		// Try to parse as single IP.
		if addr, err := netip.ParseAddr(line); err == nil {
			ips[addr.Unmap()] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return ips, cidr, nil
}
