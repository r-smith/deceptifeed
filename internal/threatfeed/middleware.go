package threatfeed

import (
	"net"
	"net/http"
	"net/netip"
)

// enforcePrivateIP restricts access to private, loopback, and link-local IP
// addresses. Note: This restriction can be bypassed if the threatfeed is
// behind a proxy.
func enforcePrivateIP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		addr, err := netip.ParseAddr(host)
		if err != nil || (!addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast()) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// disableCache is a middleware that sets HTTP response headers to prevent
// clients from caching the threatfeed.
func disableCache(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		next.ServeHTTP(w, r)
	}
}
