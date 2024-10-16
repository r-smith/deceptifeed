package threatfeed

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/r-smith/cti-honeypot/internal/config"
)

var (
	// iocMap stores the Indicator of Compromise (IoC) entries which makes up
	// the threat feed database. It is initially populated by loadIoC if an
	// existing JSON database file is provided. The map is subsequently updated
	// by UpdateIoC whenever a client interacts with a honeypot server. This
	// map is accessed and served by the threat feed HTTP server.
	iocMap = make(map[string]*IoC)

	// isPrivateIncluded indicates whether private IP addresses are included in
	// the threat feed database. It is set once by loadIoC according to the
	// threat feed configuration.
	isPrivateIncluded bool

	// jsonFile holds the path to the JSON file used to save IoC data to disk.
	// It is set once by loadIoC according to the threat feed configuration.
	// This file ensures the threat feed database persists across server
	// restarts.
	jsonFile string

	// expiryHours specifies the duration after which an IoC entry is
	// considered expired based on its last seen date. It is set once by
	// loadIoC according to the threat feed configuration.
	expiryHours uint

	// mutex is to ensure thread-safe access to iocMap.
	mutex sync.Mutex
)

// IoC represents an Indicator of Compromise (IoC) entry in the threat feed
// database. The database is formatted as JSON, where each IP address serves as
// a key. Each IP entry includes the date the IP was added and the date it was
// last seen.
//
// Example database:
//
// {
// "127.0.14.54":
// {
// "added": "2024-10-13T17:35:04.8199165-00:00",
// "last_seen": "2024-10-16T08:07:17.6370403-00:00"
// },
// "127.19.201.8":
// {
// "added": "2024-10-16T04:27:58.301360933-00:00",
// "last_seen": "2024-10-16T05:57:37.646377358-00:00"
// }
// }
type IoC struct {
	Added    time.Time `json:"added"`
	LastSeen time.Time `json:"last_seen"`
}

// loadIoC reads IoC data from an existing JSON database. If found, it
// populates iocMap. This function is called once during the initialization of
// the threat feed server.
func loadIoC(threatFeed *config.ThreatFeed) error {
	jsonFile = threatFeed.DatabasePath
	expiryHours = threatFeed.ExpiryHours
	isPrivateIncluded = threatFeed.IsPrivateIncluded

	file, err := os.Open(jsonFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	jsonBytes, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	if len(jsonBytes) == 0 {
		return nil
	}

	return json.Unmarshal(jsonBytes, &iocMap)
}

// UpdateIoC updates the IoC map. This function is called by honeypot servers
// each time a client interacts with the honeypot. The modified IoC map is then
// saved back to the JSON database.
func UpdateIoC(ip string) {
	mutex.Lock()
	defer mutex.Unlock()

	// Check if the given IP string is a private address. The threat feed may
	// be configured to include or exclude private IPs.
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return
	}
	if !isPrivateIncluded && netIP.IsPrivate() {
		return
	}

	now := time.Now()
	if ioc, exists := iocMap[ip]; exists {
		// Update existing entry.
		ioc.LastSeen = now
	} else {
		// Create a new entry.
		iocMap[ip] = &IoC{
			Added:    now,
			LastSeen: now,
		}
	}

	// Remove expired entries from iocMap.
	removeExpired()

	// Write the updated map back to the JSON file.
	if err := saveIoC(); err != nil {
		fmt.Fprintln(os.Stderr, "Error saving Threat Feed database:", err)
	}
}

// removeExpired checks the IoC map for entries that have expired based on
// their last seen date and the configured expiry hours. It deletes any expired
// entries from the map. This function should be called exclusively by
// UpdateIoC, which manages the mutex lock.
func removeExpired() {
	// If expiryHours is set to 0, entries never expire and will remain
	// indefinitely.
	if expiryHours <= 0 {
		return
	}

	var iocToRemove []string
	expirtyTime := time.Now().Add(-time.Hour * time.Duration(expiryHours))

	for key, value := range iocMap {
		if value.LastSeen.Before(expirtyTime) {
			iocToRemove = append(iocToRemove, key)
		}
	}

	for _, key := range iocToRemove {
		delete(iocMap, key)
	}
}

// saveIoC writes the current IoC map to the JSON file. This function is called
// after modifications to the IoC map. The file ensures the threat feed
// database persists across server restarts. This function should be called
// exclusively by UpdateIoC, which manages the mutex lock.
func saveIoC() error {
	file, err := os.Create(jsonFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(iocMap)
}
