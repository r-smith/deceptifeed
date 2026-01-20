package logmonitor

import (
	"bytes"
	"io"
)

// Compile-time check to ensure Monitor staisfies the io.Writer interface.
var _ io.Writer = (*Monitor)(nil)

// Monitor is an io.Writer that sends bytes written to its Write method to an
// underlying byte channel. This allows other packages to receive the data from
// the channel. Writes are non-blocking. If there is no receiver, the data is
// silently discarded.
//
// Monitor does not implement io.Closer. Once initialized, it is meant to run
// for the duration of the program. If needed, manually close `Channel` when
// finished.
type Monitor struct {
	Channel chan []byte
}

// New creates a new Monitor ready for I/O operations. The underlying `Channel`
// should have a receiver to capture and process the data.
func New() *Monitor {
	return &Monitor{
		Channel: make(chan []byte, 10),
	}
}

// Write sends the bytes from p to the underlying channel. If there is no
// active receiver, the data is discarded to prevent blocking. Write always
// returns n = len(p) and err = nil.
func (m *Monitor) Write(p []byte) (n int, err error) {
	select {
	case m.Channel <- bytes.Clone(p):
	default:
	}

	return len(p), nil
}
