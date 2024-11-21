package threatfeed

import (
	"bufio"
	"bytes"
	"cmp"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
)

type feed []net.IP

// sortMethod represents the method used for sorting the threat feed.
type sortMethod int

// Constants representing the possible values for sortMethod.
const (
	byIP sortMethod = iota
	byLastSeen
	byAdded
	byThreatScore
)

// sortDirection represents the direction of sorting (ascending or descending).
type sortDirection int

// Constants representing the possible values for sortDirection.
const (
	ascending sortDirection = iota
	descending
)

// feedOptions define configurable options for serving the threat feed.
type feedOptions struct {
	sortMethod    sortMethod
	sortDirection sortDirection
	seenAfter     time.Time
	limit         int
	page          int
}

// prepareFeed filters, processes, and sorts IP addresses from the threat feed.
// The resulting slice of `net.IP` represents the current threat feed to be
// served to clients.
func prepareFeed(options ...feedOptions) feed {
	// Set default feed options.
	opt := feedOptions{
		sortMethod:    byIP,
		sortDirection: ascending,
	}
	// Override default options if provided.
	if len(options) > 0 {
		opt = options[0]
	}

	excludedIPs, excludedCIDR, err := parseExcludeList(configuration.ExcludeListPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read threat feed exclude list:", err)
	}

	// Parse and filter IPs from iocData into the threat feed.
	mutex.Lock()
	threats := make(feed, 0, len(iocData))
loop:
	for ip, ioc := range iocData {
		if ioc.expired() || ioc.ThreatScore < configuration.MinimumThreatScore || !ioc.LastSeen.After(opt.seenAfter) {
			continue
		}

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil || (parsedIP.IsPrivate() && !configuration.IsPrivateIncluded) {
			continue
		}

		for _, ipnet := range excludedCIDR {
			if ipnet.Contains(parsedIP) {
				continue loop
			}
		}

		if _, found := excludedIPs[ip]; found {
			continue
		}

		threats = append(threats, parsedIP)
	}
	mutex.Unlock()

	threats.applySort(opt.sortMethod, opt.sortDirection)

	return threats
}

// parseExcludeList reads IP addresses and CIDR ranges from a file. Each line
// should contain an IP address or CIDR. It returns a map of the unique IPs and
// a slice of the CIDR ranges found in the file.
func parseExcludeList(filepath string) (map[string]struct{}, []*net.IPNet, error) {
	if len(filepath) == 0 {
		return map[string]struct{}{}, []*net.IPNet{}, nil
	}

	file, err := os.Open(filepath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	// `ips` stores individual IPs to exclude, and `cidr` stores CIDR networks
	// to exclude.
	ips := make(map[string]struct{})
	cidr := []*net.IPNet{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 {
			if _, ipnet, err := net.ParseCIDR(line); err == nil {
				cidr = append(cidr, ipnet)
			} else {
				ips[line] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return ips, cidr, nil
}

// applySort sorts the threat feed based on the specified sort method and
// direction.
func (f feed) applySort(method sortMethod, direction sortDirection) {
	switch method {
	case byIP:
		slices.SortFunc(f, func(a, b net.IP) int {
			return bytes.Compare(a, b)
		})
	case byLastSeen:
		mutex.Lock()
		slices.SortFunc(f, func(a, b net.IP) int {
			return iocData[a.String()].LastSeen.Compare(iocData[b.String()].LastSeen)
		})
		mutex.Unlock()
	case byAdded:
		mutex.Lock()
		slices.SortFunc(f, func(a, b net.IP) int {
			return iocData[a.String()].Added.Compare(iocData[b.String()].Added)
		})
		mutex.Unlock()
	case byThreatScore:
		mutex.Lock()
		slices.SortFunc(f, func(a, b net.IP) int {
			return cmp.Compare(iocData[a.String()].ThreatScore, iocData[b.String()].ThreatScore)
		})
		mutex.Unlock()
	}
	if direction == descending {
		slices.Reverse(f)
	}
}

// convertToIndicators converts IP addresses from the threat feed into a
// collection of STIX Indicator objects.
func (f feed) convertToIndicators() []stix.Object {
	if len(f) == 0 {
		return []stix.Object{}
	}

	const indicator = "indicator"
	result := make([]stix.Object, 0, len(f)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All IP addresses in the collection will reference this identity as
	// the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, ip := range f {
		if ioc, found := iocData[ip.String()]; found {
			pattern := "[ipv4-addr:value = '"
			if strings.Contains(ip.String(), ":") {
				pattern = "[ipv6-addr:value = '"
			}
			pattern = pattern + ip.String() + "']"

			// Fixed expiration: 2 months since last seen.
			validUntil := new(time.Time)
			*validUntil = ioc.LastSeen.AddDate(0, 2, 0).UTC()

			// Generate a deterministic identifier for each IP address in the
			// threat feed using the STIX IP pattern represented as a JSON
			// string. For example: {"pattern":"[ipv4-addr:value='127.0.0.1']"}
			patternJSON := fmt.Sprintf("{\"pattern\":\"%s\"}", pattern)

			result = append(result, stix.Indicator{
				Type:           indicator,
				SpecVersion:    stix.SpecVersion,
				ID:             stix.DeterministicID(indicator, patternJSON),
				IndicatorTypes: []string{"malicious-activity"},
				Pattern:        pattern,
				PatternType:    "stix",
				Created:        ioc.Added.UTC(),
				Modified:       ioc.LastSeen.UTC(),
				ValidFrom:      ioc.Added.UTC(),
				ValidUntil:     validUntil,
				Name:           "Honeypot interaction: " + ip.String(),
				Description:    "This IP was observed interacting with a honeypot server.",
				KillChains:     []stix.KillChain{{KillChain: "mitre-attack", Phase: "reconnaissance"}},
				Lang:           "en",
				Labels:         []string{"honeypot"},
				CreatedByRef:   stix.DeceptifeedID,
			})
		}
	}
	return result
}

// convertToObservables converts IP addresses from the threat feed into a
// collection of STIX Cyber-observable Objects.
func (f feed) convertToObservables() []stix.Object {
	if len(f) == 0 {
		return []stix.Object{}
	}

	result := make([]stix.Object, 0, len(f)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All IP addresses in the collection will reference this identity as
	// the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, ip := range f {
		if _, found := iocData[ip.String()]; found {
			t := "ipv4-addr"
			if strings.Contains(ip.String(), ":") {
				t = "ipv6-addr"
			}

			// Generate a deterministic identifier for each IP address in the
			// threat feed using the IP value represented as a JSON string. For
			// example: {"value":"127.0.0.1"}
			result = append(result, stix.ObservableIP{
				Type:         t,
				SpecVersion:  stix.SpecVersion,
				ID:           stix.DeterministicID(t, "{\"value\":\""+ip.String()+"\"}"),
				Value:        ip.String(),
				CreatedByRef: stix.DeceptifeedID,
			})
		}
	}
	return result
}
