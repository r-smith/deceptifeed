package threatfeed

import (
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

// handlePlain handles HTTP requests to serve the threat feed in plain text. It
// returns a list of IP addresses that interacted with the honeypot servers.
// This is the default catch-all route handler.
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

// handleJSONSimple handles HTTP requests to serve a simplified version of the
// threat feed in JSON format. It returns a JSON array containing only the IP
// addresses from the threat feed.
func handleJSONSimple(w http.ResponseWriter, r *http.Request) {
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ips := make([]string, 0, len(iocData))
	for _, entry := range prepareFeed(opt) {
		ips = append(ips, entry.IP)
	}
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	if err := e.Encode(map[string]interface{}{"threat_feed": ips}); err != nil {
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

// handleCSVSimple handles HTTP requests to serve a simplified version of the
// threat feed in CSV format. It returns a CSV file containing only the IP
// addresses of the threat feed.
func handleCSVSimple(w http.ResponseWriter, r *http.Request) {
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"threat-feed-ips-"+time.Now().Format("20060102-150405")+".csv\"")

	c := csv.NewWriter(w)
	if err := c.Write([]string{"ip"}); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to encode threat feed to CSV:", err)
		return
	}

	for _, entry := range prepareFeed(opt) {
		if err := c.Write([]string{entry.IP}); err != nil {
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

// handleSTIX2Simple handles HTTP requests to serve a simplified version of the
// threat feed in STIX 2 format. The response is structured as a STIX Bundle,
// with each IP address in the threat feed included as a STIX Cyber-observable
// Object.
func handleSTIX2Simple(w http.ResponseWriter, r *http.Request) {
	opt, err := parseParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	const bundle = "bundle"
	result := stix.Bundle{
		Type:    bundle,
		ID:      stix.NewID(bundle),
		Objects: prepareFeed(opt).convertToObservables(),
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

	tmpl, err := template.New("table").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title>Deceptifeed</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			background-color: #080808;
			color: #e0e0e0;
			margin: 0;
			padding: 0;
		}

		table {
			border-collapse: collapse;
			margin: 25px auto;
			font-size: 1em;
			font-family: sans-serif;
			min-width: 400px;
			box-shadow: 0 2px 20px rgba(0, 0, 0, 0.5);
			overflow: auto;
		}

		thead tr {
			background-color: #000000;
			color: #ffffff;
			text-align: left;
			font-weight: bold;
			font-size: 1.1em;
			position: sticky;
			top: 0;
			z-index: 1;
		}

		svg {display: block; margin-left: auto; margin-right: auto; margin-top: 48px; margin-bottom: 30px;}
				
		th, td  { padding: 14px 25px; }
		td      { font-family: 'Roboto Mono', 'Consolas', 'Courier New', Courier, monospace; }
		a       { text-decoration: none; color: inherit; }
		a:hover { color: #00FA9A; }
		tbody tr                 { border-bottom: 0.5px solid #28283d; }
		tbody tr:nth-child(even) { background-color: #070a0f; }
		tbody tr:nth-child(odd)  { background-color: #0e1015; }
		tbody tr:hover           { background-color: #1a1d22; }
		tbody tr:last-of-type    { border-bottom: 3px solid #000000; }
		tbody td:nth-child(1)    { color: #48E3FF; }
		tbody td:nth-child(2)    { color: #8b949e; }
		tbody td:nth-child(3)    { color: #c8e1ff; }
		tbody td:nth-child(4)    { color: #fd005c; text-align: right }
		.sort-arrow  { font-size: 0.8em; margin-left: 5px; }
        .asc::after  { content: "▲"; }
        .desc::after { content: "▼"; }

		@media (max-width: 600px) {
			table {
				width: 100%;
			}
			th, td {
				font-size: 14px;
				padding: 8px;
			}
		}
	</style>
</head>
<body>
	<svg width="370" height="63" viewBox="0 0 370 63" fill="none" xmlns="http://www.w3.org/2000/svg">
		<path d="M0.312 49V44.998H7.212V4.702H0.312V0.699997H18.666C24.968 0.699997 29.867 2.31 33.363 5.53C36.905 8.704 38.676 13.672 38.676 20.434V29.335C38.676 36.097 36.905 41.065 33.363 44.239C29.867 47.413 24.968 49 18.666 49H0.312ZM11.628 44.998H18.666C23.726 44.998 27.59 43.779 30.258 41.341C32.926 38.903 34.26 34.97 34.26 29.542V20.227C34.26 14.753 32.926 10.82 30.258 8.428C27.59 5.99 23.726 4.771 18.666 4.771H11.628V44.998ZM60.0735 49.966C56.6235 49.966 53.6105 49.253 51.0345 47.827C48.5045 46.355 46.5265 44.308 45.1005 41.686C43.6745 39.064 42.9615 36.051 42.9615 32.647V31.819C42.9615 28.369 43.6745 25.356 45.1005 22.78C46.5265 20.158 48.4815 18.134 50.9655 16.708C53.4955 15.236 56.3705 14.5 59.5905 14.5C62.7185 14.5 65.4785 15.167 67.8705 16.501C70.3085 17.789 72.2175 19.675 73.5975 22.159C74.9776 24.597 75.6676 27.518 75.6676 30.922V33.13H47.1015C47.2395 37.316 48.5045 40.559 50.8965 42.859C53.3345 45.113 56.3935 46.24 60.0735 46.24C63.2015 46.24 65.6165 45.527 67.3185 44.101C69.0665 42.675 70.4005 40.927 71.3205 38.857L75.0466 40.513C74.3565 42.031 73.3905 43.526 72.1485 44.998C70.9525 46.424 69.3885 47.62 67.4565 48.586C65.5245 49.506 63.0635 49.966 60.0735 49.966ZM47.1705 29.542H71.4585C71.2745 25.908 70.1015 23.125 67.9395 21.193C65.7775 19.215 62.9945 18.226 59.5905 18.226C56.2325 18.226 53.4495 19.215 51.2415 21.193C49.0335 23.125 47.6765 25.908 47.1705 29.542ZM97.0338 49.966C93.7678 49.966 90.8468 49.276 88.2708 47.896C85.7408 46.47 83.7398 44.446 82.2678 41.824C80.7958 39.202 80.0598 36.12 80.0598 32.578V31.888C80.0598 28.3 80.7958 25.218 82.2678 22.642C83.7398 20.02 85.7408 18.019 88.2708 16.639C90.8468 15.213 93.7678 14.5 97.0338 14.5C100.254 14.5 102.968 15.121 105.176 16.363C107.43 17.559 109.178 19.146 110.42 21.124C111.708 23.056 112.513 25.103 112.835 27.265L108.764 28.093C108.534 26.299 107.959 24.666 107.039 23.194C106.119 21.676 104.831 20.48 103.175 19.606C101.519 18.686 99.4718 18.226 97.0338 18.226C94.5958 18.226 92.4108 18.801 90.4788 19.951C88.5468 21.055 87.0058 22.642 85.8558 24.712C84.7518 26.736 84.1998 29.151 84.1998 31.957V32.509C84.1998 35.315 84.7518 37.753 85.8558 39.823C87.0058 41.847 88.5468 43.434 90.4788 44.584C92.4108 45.688 94.5958 46.24 97.0338 46.24C100.714 46.24 103.52 45.297 105.452 43.411C107.384 41.479 108.58 39.133 109.04 36.373L113.111 37.201C112.697 39.363 111.823 41.433 110.489 43.411C109.201 45.343 107.43 46.93 105.176 48.172C102.968 49.368 100.254 49.966 97.0338 49.966ZM134.607 49.966C131.157 49.966 128.144 49.253 125.568 47.827C123.038 46.355 121.06 44.308 119.634 41.686C118.208 39.064 117.495 36.051 117.495 32.647V31.819C117.495 28.369 118.208 25.356 119.634 22.78C121.06 20.158 123.015 18.134 125.499 16.708C128.029 15.236 130.904 14.5 134.124 14.5C137.252 14.5 140.012 15.167 142.404 16.501C144.842 17.789 146.751 19.675 148.131 22.159C149.511 24.597 150.201 27.518 150.201 30.922V33.13H121.635C121.773 37.316 123.038 40.559 125.43 42.859C127.868 45.113 130.927 46.24 134.607 46.24C137.735 46.24 140.15 45.527 141.852 44.101C143.6 42.675 144.934 40.927 145.854 38.857L149.58 40.513C148.89 42.031 147.924 43.526 146.682 44.998C145.486 46.424 143.922 47.62 141.99 48.586C140.058 49.506 137.597 49.966 134.607 49.966ZM121.704 29.542H145.992C145.808 25.908 144.635 23.125 142.473 21.193C140.311 19.215 137.528 18.226 134.124 18.226C130.766 18.226 127.983 19.215 125.775 21.193C123.567 23.125 122.21 25.908 121.704 29.542ZM156.249 62.8V15.466H160.251V21.607H161.079C162.045 19.767 163.54 18.134 165.564 16.708C167.634 15.236 170.509 14.5 174.189 14.5C177.179 14.5 179.893 15.213 182.331 16.639C184.769 18.019 186.701 19.997 188.127 22.573C189.599 25.149 190.335 28.231 190.335 31.819V32.647C190.335 36.189 189.622 39.271 188.196 41.893C186.77 44.469 184.838 46.47 182.4 47.896C179.962 49.276 177.225 49.966 174.189 49.966C171.751 49.966 169.658 49.644 167.91 49C166.208 48.31 164.805 47.436 163.701 46.378C162.643 45.32 161.815 44.239 161.217 43.135H160.389V62.8H156.249ZM173.223 46.24C177.041 46.24 180.123 45.021 182.469 42.583C184.861 40.145 186.057 36.787 186.057 32.509V31.957C186.057 27.679 184.861 24.321 182.469 21.883C180.123 19.445 177.041 18.226 173.223 18.226C169.451 18.226 166.369 19.445 163.977 21.883C161.585 24.321 160.389 27.679 160.389 31.957V32.509C160.389 36.787 161.585 40.145 163.977 42.583C166.369 45.021 169.451 46.24 173.223 46.24ZM207.378 49C205.584 49 204.227 48.54 203.307 47.62C202.433 46.7 201.996 45.412 201.996 43.756V19.192H191.232V15.466H201.996V2.908H206.136V15.466H217.866V19.192H206.136V43.204C206.136 44.584 206.826 45.274 208.206 45.274H216.072V49H207.378ZM222.966 49V15.466H227.106V49H222.966ZM225.036 9.67C224.024 9.67 223.173 9.325 222.483 8.635C221.793 7.945 221.448 7.094 221.448 6.082C221.448 5.024 221.793 4.173 222.483 3.529C223.173 2.839 224.024 2.494 225.036 2.494C226.094 2.494 226.945 2.839 227.589 3.529C228.279 4.173 228.624 5.024 228.624 6.082C228.624 7.094 228.279 7.945 227.589 8.635C226.945 9.325 226.094 9.67 225.036 9.67Z" fill="#FE1133"/>
		<path d="M240.488 49V21.952H231.794V14.776H240.488V8.428C240.488 6.082 241.178 4.219 242.558 2.839C243.984 1.413 245.824 0.699997 248.078 0.699997H257.048V7.876H251.114C249.826 7.876 249.182 8.566 249.182 9.946V14.776H258.152V21.952H249.182V49H240.488ZM276.571 49.966C273.167 49.966 270.154 49.253 267.532 47.827C264.956 46.355 262.932 44.308 261.46 41.686C260.034 39.018 259.321 35.89 259.321 32.302V31.474C259.321 27.886 260.034 24.781 261.46 22.159C262.886 19.491 264.887 17.444 267.463 16.018C270.039 14.546 273.029 13.81 276.433 13.81C279.791 13.81 282.712 14.569 285.196 16.087C287.68 17.559 289.612 19.629 290.992 22.297C292.372 24.919 293.062 27.978 293.062 31.474V34.441H268.153C268.245 36.787 269.119 38.696 270.775 40.168C272.431 41.64 274.455 42.376 276.847 42.376C279.285 42.376 281.079 41.847 282.229 40.789C283.379 39.731 284.253 38.558 284.851 37.27L291.958 40.996C291.314 42.192 290.371 43.503 289.129 44.929C287.933 46.309 286.323 47.505 284.299 48.517C282.275 49.483 279.699 49.966 276.571 49.966ZM268.222 27.955H284.23C284.046 25.977 283.241 24.39 281.815 23.194C280.435 21.998 278.618 21.4 276.364 21.4C274.018 21.4 272.155 21.998 270.775 23.194C269.395 24.39 268.544 25.977 268.222 27.955ZM313.634 49.966C310.23 49.966 307.217 49.253 304.595 47.827C302.019 46.355 299.995 44.308 298.523 41.686C297.097 39.018 296.384 35.89 296.384 32.302V31.474C296.384 27.886 297.097 24.781 298.523 22.159C299.949 19.491 301.95 17.444 304.526 16.018C307.102 14.546 310.092 13.81 313.496 13.81C316.854 13.81 319.775 14.569 322.259 16.087C324.743 17.559 326.675 19.629 328.055 22.297C329.435 24.919 330.125 27.978 330.125 31.474V34.441H305.216C305.308 36.787 306.182 38.696 307.838 40.168C309.494 41.64 311.518 42.376 313.91 42.376C316.348 42.376 318.142 41.847 319.292 40.789C320.442 39.731 321.316 38.558 321.914 37.27L329.021 40.996C328.377 42.192 327.434 43.503 326.192 44.929C324.996 46.309 323.386 47.505 321.362 48.517C319.338 49.483 316.762 49.966 313.634 49.966ZM305.285 27.955H321.293C321.109 25.977 320.304 24.39 318.878 23.194C317.498 21.998 315.681 21.4 313.427 21.4C311.081 21.4 309.218 21.998 307.838 23.194C306.458 24.39 305.607 25.977 305.285 27.955ZM348.904 49.966C346.19 49.966 343.637 49.299 341.245 47.965C338.899 46.585 337.013 44.584 335.587 41.962C334.161 39.34 333.448 36.166 333.448 32.44V31.336C333.448 27.61 334.161 24.436 335.587 21.814C337.013 19.192 338.899 17.214 341.245 15.88C343.591 14.5 346.144 13.81 348.904 13.81C350.974 13.81 352.699 14.063 354.079 14.569C355.505 15.029 356.655 15.627 357.529 16.363C358.403 17.099 359.07 17.881 359.53 18.709H360.772V0.699997H369.466V49H360.91V44.86H359.668C358.886 46.148 357.667 47.321 356.011 48.379C354.401 49.437 352.032 49.966 348.904 49.966ZM351.526 42.376C354.194 42.376 356.425 41.525 358.219 39.823C360.013 38.075 360.91 35.545 360.91 32.233V31.543C360.91 28.231 360.013 25.724 358.219 24.022C356.471 22.274 354.24 21.4 351.526 21.4C348.858 21.4 346.627 22.274 344.833 24.022C343.039 25.724 342.142 28.231 342.142 31.543V32.233C342.142 35.545 343.039 38.075 344.833 39.823C346.627 41.525 348.858 42.376 351.526 42.376Z" fill="#FFAC11"/>
	</svg>
	<table>
		<thead>
			<tr>
			<th><a href="?sort=ip&direction={{if and (eq .SortMethod "ip") (eq .SortDirection "asc")}}desc{{else}}asc{{end}}">
				IP{{if eq .SortMethod "ip"}}<span class="sort-arrow {{if eq .SortDirection "asc"}}asc{{else}}desc{{end}}"></span>{{end}}</a>
			</th>
			<th><a href="?sort=added&direction={{if and (eq .SortMethod "added") (eq .SortDirection "asc")}}desc{{else}}asc{{end}}">
				Added{{if eq .SortMethod "added"}}<span class="sort-arrow {{if eq .SortDirection "asc"}}asc{{else}}desc{{end}}"></span>{{end}}</a>
			</th>
			<th><a href="?sort=last_seen&direction={{if and (eq .SortMethod "last_seen") (eq .SortDirection "asc")}}desc{{else}}asc{{end}}">
				Last Seen{{if eq .SortMethod "last_seen"}}<span class="sort-arrow {{if eq .SortDirection "asc"}}asc{{else}}desc{{end}}"></span>{{end}}</a>
			</th>
			<th><a href="?sort=threat_score&direction={{if and (eq .SortMethod "threat_score") (eq .SortDirection "asc")}}desc{{else}}asc{{end}}">
				Threat Score{{if eq .SortMethod "threat_score"}}<span class="sort-arrow {{if eq .SortDirection "asc"}}asc{{else}}desc{{end}}"></span>{{end}}</a>
			</th>
			</tr>
		</thead>
		<tbody>
		{{range .Data}}<tr><td>{{.IP}}</td><td>{{.Added.Format "2006-01-02 15:04:05"}}</td><td>{{.LastSeen.Format "2006-01-02 15:04:05"}}</td><td>{{.ThreatScore}}</td></tr>
		{{end}}
		</tbody>
	</table>
</body>
</html>`)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

// handleEmpty handles HTTP requests to /empty. It returns an empty body with
// status code 200. This endpoint is useful for temporarily clearing the threat
// feed data in firewalls.
func handleEmpty(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}
