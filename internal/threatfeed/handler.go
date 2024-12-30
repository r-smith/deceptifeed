package threatfeed

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/r-smith/deceptifeed/internal/stix"
	"github.com/r-smith/deceptifeed/internal/taxii"
)

// templates embeds .html and template files in the `./templates/` folder.
//
//go:embed templates
var templates embed.FS

// handlePlain handles HTTP requests to serve the threat feed in plain text. It
// returns a list of IP addresses that interacted with the honeypot servers.
func handlePlain(w http.ResponseWriter, r *http.Request) {
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	for _, entry := range prepareFeed(opt) {
		_, err := w.Write([]byte(entry.IP + "\n"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to serve threat feed:", err)
			return
		}
	}

	// If a custom threat file is supplied in the configuration, append the
	// contents of the file to the HTTP response. To allow for flexibility, the
	// contents of the file are not parsed or validated.
	if len(cfg.ThreatFeed.CustomThreatsPath) > 0 {
		data, err := os.ReadFile(cfg.ThreatFeed.CustomThreatsPath)
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
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(map[string]interface{}{"threat_feed": prepareFeed(opt)}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to JSON:", err)
		return
	}
}

// handleCSV handles HTTP requests to serve the full threat feed in CSV format.
// It returns a CSV file containing all IoC data (IP addresses and their
// associated data).
func handleCSV(w http.ResponseWriter, r *http.Request) {
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"threat-feed-"+time.Now().Format("20060102-150405")+".csv\"")

	c := csv.NewWriter(w)
	if err := c.Write(csvHeader); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
		return
	}

	for _, entry := range prepareFeed(opt) {
		if err := c.Write([]string{
			entry.IP,
			entry.Added.Format(dateFormat),
			entry.LastSeen.Format(dateFormat),
			strconv.Itoa(entry.ThreatScore),
		}); err != nil {
			fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
			return
		}
	}

	c.Flush()
	if err := c.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
	}
}

// handleSTIX handles HTTP requests to serve the full threat feed in STIX 2.1
// format. The response includes all IoC data (IP addresses and their
// associated data). The response is structured as a STIX Bundle containing
// `Indicators` (STIX Domain Objects) for each IP address in the threat feed.
func handleSTIX(w http.ResponseWriter, r *http.Request) {
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	const bundle = "bundle"
	result := stix.Bundle{
		Type:    bundle,
		ID:      stix.NewID(bundle),
		Objects: prepareFeed(opt).convertToIndicators(),
	}

	w.Header().Set("Content-Type", stix.ContentType)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to STIX:", err)
	}
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
			handleNotFound(w, r)
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
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	case taxii.SightingsID, taxii.SightingsAlias:
		result.Objects = prepareFeed(opt).convertToSightings()
	default:
		handleNotFound(w, r)
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
			case stix.Sighting:
				timestamp = v.LastSeen
			case stix.ObservableIP:
				if ioc, found := iocData[v.Value]; found {
					timestamp = ioc.lastSeen
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

// handleHome serves as the default landing page for the threat feed. It
// delivers a static HTML document with information on accessing the threat
// feed.
func handleHome(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(templates, "templates/home.html"))
	err := tmpl.Execute(w, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse home page template:", err)
		return
	}
}

// handleHTML returns the threat feed as a web page for viewing in a browser.
func handleHTML(w http.ResponseWriter, r *http.Request) {
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Set default sort if no query parameters are provided.
	if len(r.URL.Query()) == 0 {
		opt.sortMethod = byLastSeen
		opt.sortDirection = descending
	}

	var d string
	switch opt.sortDirection {
	case ascending:
		d = "asc"
	case descending:
		d = "desc"
	}
	var m string
	switch opt.sortMethod {
	case byIP:
		m = "ip"
	case byAdded:
		m = "added"
	case byLastSeen:
		m = "last_seen"
	case byThreatScore:
		m = "threat_score"
	}

	tmpl := template.Must(template.ParseFS(templates, "templates/htmlfeed.html"))
	err = tmpl.Execute(w, map[string]interface{}{"Data": prepareFeed(opt), "SortDirection": d, "SortMethod": m})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to HTML:", err)
		return
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
		// While TAXII requires sorting by creation date, we sort by `LastSeen`
		// instead. This is because the threat feed is dynamic and IPs may be
		// updated. This ensures clients don't miss updates if they are only
		// looking for new entries.
		opt.sortMethod = byLastSeen

		var err error
		if len(r.URL.Query().Get("added_after")) > 0 {
			opt.seenAfter, err = time.Parse(time.RFC3339, r.URL.Query().Get("added_after"))
			if err != nil {
				return feedOptions{}, fmt.Errorf("invalid 'added_after' value")
			}
		}
		if len(r.URL.Query().Get("limit")) > 0 {
			opt.limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
			if err != nil {
				return feedOptions{}, fmt.Errorf("invalid 'limit' value")
			}
		}
		if len(r.URL.Query().Get("next")) > 0 {
			opt.page, err = strconv.Atoi(r.URL.Query().Get("next"))
			if err != nil {
				return feedOptions{}, fmt.Errorf("invalid 'next' value")
			}
		}
		return opt, nil
	}

	switch r.URL.Query().Get("sort") {
	case "ip":
		opt.sortMethod = byIP
	case "last_seen":
		opt.sortMethod = byLastSeen
	case "added":
		opt.sortMethod = byAdded
	case "threat_score":
		opt.sortMethod = byThreatScore
	case "":
		// No sort option specified.
	default:
		return feedOptions{}, fmt.Errorf("invalid 'sort' value")
	}

	switch r.URL.Query().Get("direction") {
	case "asc":
		opt.sortDirection = ascending
	case "desc":
		opt.sortDirection = descending
	case "":
		// No direction option specified.
	default:
		return feedOptions{}, fmt.Errorf("invalid 'direction' value")
	}

	if len(r.URL.Query().Get("last_seen_hours")) > 0 {
		hours, err := strconv.Atoi(r.URL.Query().Get("last_seen_hours"))
		if err != nil {
			return feedOptions{}, fmt.Errorf("invalid 'last_seen_hours' value")
		}
		opt.seenAfter = time.Now().Add(-time.Hour * time.Duration(hours))
	}

	return opt, nil
}

// handleNotFound returns a 404 Not Found response. This is the default
// response when a request is made outside the defined API.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}
