package threatfeed

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
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
		Objects: prepareFeed().convertToIndicators(),
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
		Objects: prepareFeed().convertToObservables(),
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

	if id := r.PathValue("id"); len(id) > 0 {
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
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Ensure a minimum page number of 1.
	if opt.page < 1 {
		opt.page = 1
	}

	// Build the requested collection.
	result := taxii.Envelope{}
	switch r.PathValue("id") {
	case taxii.IndicatorsID, taxii.IndicatorsAlias:
		result.Objects = prepareFeed(opt).convertToIndicators()
	case taxii.ObservablesID, taxii.ObservablesAlias:
		result.Objects = prepareFeed(opt).convertToObservables()
	default:
		handleTAXIINotFound(w, r)
		return
	}

	// Paginate. result.Objects may be resliced depending on the requested
	// limit and page number.
	result.Objects, result.More = paginate(result.Objects, opt.limit, opt.page)

	// If more results are available, include the `next` property in the
	// response with the next page number.
	if result.More {
		if opt.page+1 > 0 {
			result.Next = strconv.Itoa(opt.page + 1)
		}
	}

	// Get the `last seen` timestamps of the first and last objects in the
	// results for setting `X-TAXII-Date-Added-` headers.
	first := time.Time{}
	last := time.Time{}
	objectCount := len(result.Objects)
	if objectCount > 0 {
		// Loop twice: the first iteration accesses the first element of the
		// Objects slice, and the second iteration accesses the last element.
		for i := 0; i < 2; i++ {
			element := 0
			if i == 1 {
				element = len(result.Objects) - 1
			}
			timestamp := time.Time{}
			switch v := result.Objects[element].(type) {
			case stix.Indicator:
				timestamp = v.Modified
			case stix.ObservableIP:
				if ioc, found := iocData[v.Value]; found {
					timestamp = ioc.LastSeen
				}
			case stix.Identity:
				timestamp = v.Created
			}
			if i == 0 {
				first = timestamp
			} else {
				last = timestamp
			}
		}
	}

	w.Header().Set("Content-Type", taxii.ContentType)
	if objectCount > 0 {
		w.Header()["X-TAXII-Date-Added-First"] = []string{first.UTC().Format(time.RFC3339)}
		w.Header()["X-TAXII-Date-Added-Last"] = []string{last.UTC().Format(time.RFC3339)}
	}
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, "Error encoding TAXII response", http.StatusInternalServerError)
	}
}

// paginate returns a slice of stix.Objects for the requested page, based on
// the provided limit and page numbers. It also returns whether more items are
// available.
func paginate(items []stix.Object, limit int, page int) ([]stix.Object, bool) {
	if limit <= 0 {
		return items, false
	}
	if page < 1 {
		page = 1
	}

	// Determine the start index. Return an empty collection if out of bounds
	// or if the calculation overflows.
	start := (page - 1) * limit
	if start >= len(items) || start < 0 {
		return []stix.Object{}, false
	}

	// Determine the end index and whether more items are remaining.
	end := start + limit
	more := end < len(items)
	if end > len(items) {
		end = len(items)
	}

	return items[start:end], more
}

// parseParams extracts HTTP query parameters and maps them to options for
// controlling the threat feed output.
func parseParams(r *http.Request) (feedOptions, error) {
	opt := feedOptions{}

	// Handle TAXII parameters.
	if strings.HasPrefix(r.URL.Path, taxii.APIRoot) {
		// TAXII requires results to be sorted by object creation date.
		// However, since IPs in the threat feed may have their `LastSeen` date
		// updated after being added, it makes more sense to sort by the last
		// seen date instead. Otherwise, clients may miss updates if they are
		// only looking for newly added results.
		opt.sortMethod = byLastSeen

		var err error
		if len(r.URL.Query().Get("added_after")) > 0 {
			opt.seenAfter, err = time.Parse(time.RFC3339, r.URL.Query().Get("added_after"))
			if err != nil {
				return feedOptions{}, err
			}
		}
		if len(r.URL.Query().Get("limit")) > 0 {
			opt.limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
			if err != nil {
				return feedOptions{}, err
			}
		}
		if len(r.URL.Query().Get("next")) > 0 {
			opt.page, err = strconv.Atoi(r.URL.Query().Get("next"))
			if err != nil {
				return feedOptions{}, err
			}
		}
		return opt, nil
	}

	switch r.URL.Query().Get("sort") {
	case "last_seen":
		opt.sortMethod = byLastSeen
	case "added":
		opt.sortMethod = byAdded
	case "threat_score":
		opt.sortMethod = byThreatScore
	default:
		opt.sortMethod = byIP
	}

	return opt, nil
}

// handleEmpty handles HTTP requests to /empty. It returns an empty body with
// status code 200. This endpoint is useful for temporarily clearing the threat
// feed data in firewalls.
func handleEmpty(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}
