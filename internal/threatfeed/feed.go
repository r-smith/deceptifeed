package threatfeed

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
)

// sortMethod is a type representing threat feed sorting methods.
type sortMethod int

const (
	byIP sortMethod = iota
	byLastSeen
)

// feedOptions define configurable options for serving the threat feed.
type feedOptions struct {
	sortMethod sortMethod
	seenAfter  time.Time
}

// option defines a function type for configuring `feedOptions`.
type option func(*feedOptions)

// sortByLastSeen returns an option that sets the sort method in `feedOptions`
// to sort the threat feed by the last seen time.
func sortByLastSeen() option {
	return func(o *feedOptions) {
		o.sortMethod = byLastSeen
	}
}

// seenAfter returns an option that sets the the `seenAfter` time in
// `feedOptions`. This filters the feed to include only entries seen after the
// specified timestamp.
func seenAfter(after time.Time) option {
	return func(o *feedOptions) {
		o.seenAfter = after
	}
}

// prepareFeed filters, processes, and sorts IP addresses from the threat feed.
// The resulting slice of `net.IP` represents the current threat feed to be
// served to clients.
func prepareFeed(options ...option) []net.IP {
	opt := feedOptions{
		sortMethod: byIP,
		seenAfter:  time.Time{},
	}
	for _, o := range options {
		o(&opt)
	}

	// Parse IPs from iocData to net.IP. Skip IPs that are expired, below the
	// minimum threat score, or are private, based on the configuration.
	mutex.Lock()
	netIPs := make([]net.IP, 0, len(iocData))
	for ip, ioc := range iocData {
		if ioc.expired() || ioc.ThreatScore < configuration.MinimumThreatScore || !ioc.LastSeen.After(opt.seenAfter) {
			continue
		}

		ipParsed := net.ParseIP(ip)
		if ipParsed == nil {
			continue
		}
		if !configuration.IsPrivateIncluded && ipParsed.IsPrivate() {
			continue
		}
		netIPs = append(netIPs, ipParsed)
	}
	mutex.Unlock()

	// If an exclude list is provided, filter the IP list.
	if len(configuration.ExcludeListPath) > 0 {
		ipsToRemove, err := parseExcludeList(configuration.ExcludeListPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read threat feed exclude list:", err)
		} else {
			netIPs = filterIPs(netIPs, ipsToRemove)
		}
	}

	// Apply sorting.
	switch opt.sortMethod {
	case byIP:
		slices.SortFunc(netIPs, func(a, b net.IP) int {
			return bytes.Compare(a, b)
		})
	case byLastSeen:
		mutex.Lock()
		slices.SortFunc(netIPs, func(a, b net.IP) int {
			// Sort by LastSeen date, and if equal, sort by IP.
			dateCompare := iocData[a.String()].LastSeen.Compare(iocData[b.String()].LastSeen)
			if dateCompare != 0 {
				return dateCompare
			}
			return bytes.Compare(a, b)
		})
		mutex.Unlock()

	}

	return netIPs
}

// parseExcludeList reads IP addresses and CIDR ranges from a file. Each line
// should contain an IP address or CIDR. It returns a map of the unique IPs and
// CIDR ranges found in the file.
func parseExcludeList(filepath string) (map[string]struct{}, error) {
	ips := make(map[string]struct{})

	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 {
			ips[line] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ips, nil
}

// filterIPs removes IPs from ipList that are found in the ipsToRemove map. The
// keys in ipsToRemove may be single IP addresses or CIDR ranges. If a key is a
// CIDR range, an IP will be removed if it falls within that range.
func filterIPs(ipList []net.IP, ipsToRemove map[string]struct{}) []net.IP {
	if len(ipsToRemove) == 0 {
		return ipList
	}

	cidrNetworks := []*net.IPNet{}
	for cidr := range ipsToRemove {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			cidrNetworks = append(cidrNetworks, ipnet)
		}
	}

	i := 0
	for _, ip := range ipList {
		if _, found := ipsToRemove[ip.String()]; found {
			continue
		}

		contains := false
		for _, ipnet := range cidrNetworks {
			if ipnet.Contains(ip) {
				contains = true
				break
			}
		}
		if !contains {
			ipList[i] = ip
			i++
		}
	}
	return ipList[:i]
}

// convertToIndicators converts IP addresses from the threat feed into a
// collection of STIX Indicator objects.
func convertToIndicators(ips []net.IP) []stix.Object {
	if len(ips) == 0 {
		return []stix.Object{}
	}

	const indicator = "indicator"
	result := make([]stix.Object, 0, len(ips)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All IP addresses in the collection will reference this identity as
	// the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, ip := range ips {
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
func convertToObservables(ips []net.IP) []stix.Object {
	if len(ips) == 0 {
		return []stix.Object{}
	}

	result := make([]stix.Object, 0, len(ips)+1)

	// Add the Deceptifeed `Identity` as the first object in the collection.
	// All IP addresses in the collection will reference this identity as
	// the creator.
	result = append(result, stix.DeceptifeedIdentity())

	for _, ip := range ips {
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
