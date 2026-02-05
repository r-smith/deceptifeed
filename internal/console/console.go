// Package console provides a simple, human-readable logging interface.
package console

import (
	"fmt"
	"io"
	"os"
)

// Component represents a specific subsystem of Deceptifeed.
type Component string

const (
	Main Component = "MAIN"
	Cfg  Component = "CFG"
	TCP  Component = "TCP"
	UDP  Component = "UDP"
	SSH  Component = "SSH"
	HTTP Component = "HTTP"
	Feed Component = "FEED"
)

// Info logs a general informational message to stdout.
func Info(c Component, msg string, args ...any) {
	print(os.Stdout, "INFO", c, msg, args...)
}

// Warning logs a non-critical issue to stderr.
func Warning(c Component, msg string, args ...any) {
	print(os.Stderr, "WARN", c, msg, args...)
}

// Error logs an error message to stderr.
func Error(c Component, msg string, args ...any) {
	print(os.Stderr, "ERROR", c, msg, args...)
}

// Debug logs a verbose diagnostic message to stdout.
func Debug(c Component, msg string, args ...any) {
	print(os.Stdout, "DEBUG", c, msg, args...)
}

// Errors logs one or more errors with a custom prefix. If the error contains
// multiple joined errors, each is unwrapped and logged as a separate entry.
func Errors(c Component, prefix string, err error) {
	if err == nil {
		return
	}

	// Unwrap joined errors.
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range u.Unwrap() {
			Error(c, "%s%v", prefix, e)
		}
		return
	}

	// If couldn't unwrap, log the single error.
	Error(c, "%s%v", prefix, err)
}

func print(w io.Writer, level string, c Component, msg string, args ...any) {
	userMsg := fmt.Sprintf(msg, args...)
	fmt.Fprintf(w, "%-5s | %-4s | %s\n", level, c, userMsg)
}
