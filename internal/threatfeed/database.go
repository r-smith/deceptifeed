package threatfeed

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// IoC represents an Indicator of Compromise (IoC) entry in the threat feed
// database. The database is formatted as JSON, where each IP address serves as
// a key. Each IP entry includes the date the IP was last seen.
//
// Example database:
//
// {
// "127.0.14.54":
// {
// "last_seen": "2024-10-16T08:07:17.6370403-00:00"
// },
// "127.19.201.8":
// {
// "last_seen": "2024-10-16T05:57:37.646377358-00:00"
// }
// }
type IoC struct {
	LastSeen time.Time `json:"last_seen"`
}

// loadIoC reads IoC data from an existing JSON database. If found, it
// populates iocMap. This function is called once during the initialization of
// the threat feed server.
func loadIoC() error {
	file, err := os.Open(configuration.DatabasePath)
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
	if !configuration.IsPrivateIncluded && netIP.IsPrivate() {
		return
	}

	now := time.Now()
	if ioc, exists := iocMap[ip]; exists {
		// Update existing entry.
		ioc.LastSeen = now
	} else {
		// Create a new entry.
		iocMap[ip] = &IoC{
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
	if configuration.ExpiryHours <= 0 {
		return
	}

	var iocToRemove []string
	expirtyTime := time.Now().Add(-time.Hour * time.Duration(configuration.ExpiryHours))

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
	file, err := os.Create(configuration.DatabasePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(iocMap)
}
