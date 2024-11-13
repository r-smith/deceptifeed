package threatfeed

import (
	"net"
	"net/http"
)

// enforcePrivateIP is a middleware that restricts access to the HTTP server
// based on the client's IP address. It allows only requests from private IP
// addresses. Any other requests are denied with a 403 Forbidden error.
func enforcePrivateIP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Could not get IP", http.StatusInternalServerError)
			return
		}

		if netIP := net.ParseIP(ip); !netIP.IsPrivate() && !netIP.IsLoopback() {
			http.Error(w, "", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// disableCache is a middleware that sets HTTP response headers to prevent
// clients from caching the threat feed.
func disableCache(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		next.ServeHTTP(w, r)
	}
}
