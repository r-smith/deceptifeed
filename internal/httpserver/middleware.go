package httpserver

import (
	"net/http"
)

// withCustomError is a middleware that intercepts 4xx/5xx HTTP error responses
// and replaces them with a custom error response.
func withCustomError(next http.Handler, errorPath string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := &errorInterceptor{origWriter: w, origRequest: r, errorPath: errorPath}
		next.ServeHTTP(e, r)
	})
}

// errorInterceptor intercepts HTTP responses to override error status codes
// and to serve a custom error response.
type errorInterceptor struct {
	origWriter  http.ResponseWriter
	origRequest *http.Request
	overridden  bool
	errorPath   string
}

// WriteHeader intercepts error response codes (4xx or 5xx) to serve a custom
// error response.
func (e *errorInterceptor) WriteHeader(statusCode int) {
	if statusCode >= 400 && statusCode <= 599 {
		e.overridden = true
		serveErrorPage(e.origWriter, e.origRequest, e.errorPath)
		return
	}
	e.origWriter.WriteHeader(statusCode)
}

// Write writes the response body only if the response code was not overridden.
// Otherwise, the body is discarded.
func (e *errorInterceptor) Write(b []byte) (int, error) {
	if !e.overridden {
		return e.origWriter.Write(b)
	}
	return 0, nil
}

// Header returns the response headers from the original ResponseWriter.
func (e *errorInterceptor) Header() http.Header {
	return e.origWriter.Header()
}
