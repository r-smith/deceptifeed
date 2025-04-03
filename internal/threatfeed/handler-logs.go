package threatfeed

import (
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"os"
	"slices"
	"time"
)

// handleLogsMain serves a static page listing honeypot logs available for
// viewing.
func handleLogsMain(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(templates, "templates/logs.html"))
	_ = tmpl.Execute(w, nil)
}

// handleLogs directs the request to the appropriate log parser based on the
// request path.
func handleLogs(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("logtype") {
	case "http":
		handleLogHTTP(w)
	case "ssh":
		handleLogSSH(w)
	default:
		handleNotFound(w, r)
	}
}

// handleLogSSH serves the SSH honeypot logs as a web page. It opens the
// honeypot log files, parses the data to JSON, and passes the result to an
// HTML template for rendering.
func handleLogSSH(w http.ResponseWriter) {
	l := logFiles{}
	reader, err := l.open()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tmpl := template.Must(template.ParseFS(templates, "templates/logs-error.html"))
		_ = tmpl.Execute(w, err)
		return
	}
	defer l.close()

	type Log struct {
		Time      time.Time `json:"time"`
		EventType string    `json:"event_type"`
		SourceIP  string    `json:"source_ip"`
		Details   struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"event_details"`
	}

	const maxResults = 25_000
	d := json.NewDecoder(reader)
	data := make([]Log, 0, maxResults+1)
	for d.More() {
		var entry Log
		if err := d.Decode(&entry); err != nil {
			continue
		}
		if entry.EventType == "ssh" {
			data = append(data, entry)
			if len(data) > maxResults {
				data = data[1:]
			}
		}
	}
	slices.Reverse(data)

	tmpl := template.Must(template.ParseFS(templates, "templates/logs-ssh.html"))
	_ = tmpl.Execute(w, data)
}

// handleLogHTTP serves the HTTP honeypot logs as a web page. It opens the
// honeypot log files, parses the data to JSON, and passes the result to an
// HTML template for rendering.
func handleLogHTTP(w http.ResponseWriter) {
	l := logFiles{}
	reader, err := l.open()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tmpl := template.Must(template.ParseFS(templates, "templates/logs-error.html"))
		_ = tmpl.Execute(w, err)
		return
	}
	defer l.close()

	type Log struct {
		Time      time.Time `json:"time"`
		EventType string    `json:"event_type"`
		SourceIP  string    `json:"source_ip"`
		Details   struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"event_details"`
	}

	const maxResults = 25_000
	d := json.NewDecoder(reader)
	data := make([]Log, 0, maxResults+1)
	for d.More() {
		var entry Log
		if err := d.Decode(&entry); err != nil {
			continue
		}
		if entry.EventType == "http" {
			data = append(data, entry)
			if len(data) > maxResults {
				data = data[1:]
			}
		}
	}
	slices.Reverse(data)

	tmpl := template.Must(template.ParseFS(templates, "templates/logs-http.html"))
	_ = tmpl.Execute(w, data)
}

// logFiles represents open honeypot log files and their associate io.Reader.
type logFiles struct {
	files   []*os.File
	readers []io.Reader
}

// open opens all honeypot log files and returns an io.MultiReader that
// combines all of the logs.
func (l *logFiles) open() (io.Reader, error) {
	paths := []string{}
	seenPaths := make(map[string]bool)

	// Helper function to ensure only unique paths are added to the slice.
	add := func(p string) {
		if seenPaths[p] {
			return
		}
		// New path. Add both the path and the path with ".1" to the slice.
		paths = append(paths, p+".1", p)
		seenPaths[p] = true
	}

	for _, s := range cfg.Servers {
		add(s.LogPath)
	}

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		l.files = append(l.files, f)
	}

	for _, f := range l.files {
		l.readers = append(l.readers, f)
	}

	return io.MultiReader(l.readers...), nil
}

// close closes all honeypot log files.
func (l *logFiles) close() {
	for _, f := range l.files {
		_ = f.Close()
	}
}
