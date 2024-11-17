package threatfeed

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
	"github.com/r-smith/deceptifeed/internal/taxii"
)

// handlePlain handles HTTP requests to serve the threat feed in plain text. It
// returns a list of IP addresses that interacted with the honeypot servers.
// This is the default catch-all route handler.
func handlePlain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	for _, ip := range prepareFeed() {
		_, err := w.Write([]byte(ip.String() + "\n"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to serve threat feed:", err)
			return
		}
	}

	// If a custom threat file is supplied in the configuration, append the
	// contents of the file to the HTTP response. To allow for flexibility, the
	// contents of the file are not parsed or validated.
	if len(configuration.CustomThreatsPath) > 0 {
		data, err := os.ReadFile(configuration.CustomThreatsPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read custom threats file:", err)
			return
		}
		_, err = w.Write(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to serve threat feed:", err)
		}
	}
}

// handleJSON handles HTTP requests to serve the full threat feed in JSON
// format. It returns a JSON array containing all IoC data (IP addresses and
// their associated data).
func handleJSON(w http.ResponseWriter, r *http.Request) {
	type iocDetailed struct {
		IP          string    `json:"ip"`
		Added       time.Time `json:"added"`
		LastSeen    time.Time `json:"last_seen"`
		ThreatScore int       `json:"threat_score"`
	}

	ipData := prepareFeed()
	result := make([]iocDetailed, 0, len(ipData))
	for _, ip := range ipData {
		if ioc, found := iocData[ip.String()]; found {
			result = append(result, iocDetailed{
				IP:          ip.String(),
				Added:       ioc.Added,
				LastSeen:    ioc.LastSeen,
				ThreatScore: ioc.ThreatScore,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(map[string]interface{}{"threat_feed": result}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to JSON:", err)
	}
}

// handleJSONSimple handles HTTP requests to serve a simplified version of the
// threat feed in JSON format. It returns a JSON array containing only the IP
// addresses from the threat feed.
func handleJSONSimple(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(map[string]interface{}{"threat_feed": prepareFeed()}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to JSON:", err)
	}
}

// handleCSV handles HTTP requests to serve the full threat feed in CSV format.
// It returns a CSV file containing all IoC data (IP addresses and their
// associated data).
func handleCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"threat-feed-"+time.Now().Format("20060102-150405")+".csv\"")

	c := csv.NewWriter(w)
	if err := c.Write(csvHeader); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
		return
	}

	for _, ip := range prepareFeed() {
		if ioc, found := iocData[ip.String()]; found {
			if err := c.Write([]string{
				ip.String(),
				ioc.Added.Format(dateFormat),
				ioc.LastSeen.Format(dateFormat),
				strconv.Itoa(ioc.ThreatScore),
			}); err != nil {
				fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
				return
			}
		}
	}

	c.Flush()
	if err := c.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
	}
}

// handleCSVSimple handles HTTP requests to serve a simplified version of the
// threat feed in CSV format. It returns a CSV file containing only the IP
// addresses of the threat feed.
func handleCSVSimple(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"threat-feed-ips-"+time.Now().Format("20060102-150405")+".csv\"")

	c := csv.NewWriter(w)
	if err := c.Write([]string{"ip"}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
		return
	}

	for _, ip := range prepareFeed() {
		if err := c.Write([]string{ip.String()}); err != nil {
			fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
			return
		}
	}

	c.Flush()
	if err := c.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
	}
}

// handleSTIX2 handles HTTP requests to serve the full threat feed in STIX 2
// format. The response includes all IoC data (IP addresses and their
// associated data). The response is structured as a STIX Bundle containing
// `Indicators` (STIX Domain Objects) for each IP address in the threat feed.
func handleSTIX2(w http.ResponseWriter, r *http.Request) {
	const bundle = "bundle"
	result := stix.Bundle{
		Type:    bundle,
		ID:      stix.NewID(bundle),
		Objects: convertToIndicators(prepareFeed()),
	}

	w.Header().Set("Content-Type", stix.ContentType)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to STIX:", err)
	}
}

// handleSTIX2Simple handles HTTP requests to serve a simplified version of the
// threat feed in STIX 2 format. The response is structured as a STIX Bundle,
// with each IP address in the threat feed included as a STIX Cyber-observable
// Object.
func handleSTIX2Simple(w http.ResponseWriter, r *http.Request) {
	const bundle = "bundle"
	result := stix.Bundle{
		Type:    bundle,
		ID:      stix.NewID(bundle),
		Objects: convertToObservables(prepareFeed()),
	}

	w.Header().Set("Content-Type", stix.ContentType)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to STIX:", err)
	}
}

// handleTAXIINotFound returns a 404 Not Found response. This is the default
// response for the /taxii2/... endpoint when a request is made outside the
// defined API.
func handleTAXIINotFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

// handleTAXIIDiscovery handles the TAXII server discovery endpoint, defined as
// `/taxii2/`. It returns a list of API root URLs available on the TAXII server.
// Deceptifeed has a single API root at `/taxii2/api/`
func handleTAXIIDiscovery(w http.ResponseWriter, r *http.Request) {
	result := taxii.DiscoveryResource{
		Title:       "Deceptifeed TAXII Server",
		Description: "This TAXII server contains IP addresses observed interacting with honeypots",
		Default:     taxii.APIRoot,
		APIRoots:    []string{taxii.APIRoot},
	}

	w.Header().Set("Content-Type", taxii.ContentType)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(result); err != nil {
		http.Error(w, "Error encoding TAXII response", http.StatusInternalServerError)
	}
}

// handleTAXIIRoot returns general information about the requested API root.
func handleTAXIIRoot(w http.ResponseWriter, r *http.Request) {
	result := taxii.APIRootResource{
		Title:            "Deceptifeed TAXII Server",
		Versions:         []string{taxii.ContentType},
		MaxContentLength: 1,
	}

	w.Header().Set("Content-Type", taxii.ContentType)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(result); err != nil {
		http.Error(w, "Error encoding TAXII response", http.StatusInternalServerError)
	}
}

// handleTAXIICollections returns details about available TAXII collections
// hosted under the API root. Requests for `{api-root}/collections/` return a
// list of all available collections. Requests for
// `{api-root}/collections/{id}/` return information about the requested
// collection ID.
func handleTAXIICollections(w http.ResponseWriter, r *http.Request) {
	// Depending on the request, the result may be a single Collection or a
	// slice of Collections.
	var result any
	collections := taxii.ImplementedCollections()
	id := r.PathValue("id")

	if len(id) > 0 {
		found := false
		for i, c := range collections {
			if id == c.ID || id == c.Alias {
				found = true
				result = collections[i]
				break
			}
		}
		if !found {
			handleTAXIINotFound(w, r)
			return
		}
	} else {
		result = map[string]interface{}{"collections": collections}
	}

	w.Header().Set("Content-Type", taxii.ContentType)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(result); err != nil {
		http.Error(w, "Error encoding TAXII response", http.StatusInternalServerError)
	}
}

// handleTAXIIObjects returns the threat feed as STIX objects. The objects are
// structured according to the requested TAXII collection and wrapped in a
// TAXII Envelope. Request URL format: `{api-root}/collections/{id}/objects/`.
func handleTAXIIObjects(w http.ResponseWriter, r *http.Request) {
	// Get the added_after value, defaulting to the zero value for time.Time{}
	// if parsing fails or the value is not present.
	after, _ := time.Parse(time.RFC3339, r.URL.Query().Get("added_after"))

	result := taxii.Envelope{}
	id := r.PathValue("id")
	switch id {
	case taxii.IndicatorsID, taxii.IndicatorsAlias:
		result.Objects = convertToIndicators(prepareFeed(sortByLastSeen(), seenAfter(after)))
	case taxii.ObservablesID, taxii.ObservablesAlias:
		result.Objects = convertToObservables(prepareFeed(sortByLastSeen(), seenAfter(after)))
	default:
		handleTAXIINotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", taxii.ContentType)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(result); err != nil {
		http.Error(w, "Error encoding TAXII response", http.StatusInternalServerError)
	}
}

// handleEmpty handles HTTP requests to /empty. It returns an empty body with
// status code 200. This endpoint is useful for temporarily clearing the threat
// feed data in firewalls.
func handleEmpty(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}
