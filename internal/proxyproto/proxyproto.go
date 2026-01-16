package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// v1Signature is the byte representation of "PROXY ", which is the start of a
// Proxy Protocol v1 header.
var v1Signature = []byte("PROXY ")

// v2Signature is a 12-byte constant which is the start of a Proxy Protocol v2
// header.
var v2Signature = []byte{
	0x0D, 0x0A, 0x0D, 0x0A,
	0x00, 0x0D, 0x0A, 0x51,
	0x55, 0x49, 0x54, 0x0A,
}

// serverTimeout defines the duration after which connected clients are
// automatically disconnected, set to 2 seconds.
const serverTimeout = 2 * time.Second

// Conn wraps a net.Conn and a bufio.Reader to ensure data read by Proxy
// Protocol handling remains accessible.
type Conn struct {
	net.Conn
	r *bufio.Reader
}

// Ensure Conn satisfies the net.Conn interface.
var _ net.Conn = (*Conn)(nil)

// Read overrides the underlying net.Conn.Read to read from the internal
// buffered reader instead of the underlying connection.
func (c *Conn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// ReadHeader reads and parses a Proxy Protocol v1 or v2 header from conn. It
// extracts and returns the client IP address from the header. It sets a
// 2-second deadline on conn. If parsing fails, it returns an error. Callers
// should reset the deadline after this function returns to extend the timeout.
func ReadHeader(conn net.Conn) (net.Conn, netip.Addr, error) {
	_ = conn.SetDeadline(time.Now().Add(serverTimeout))

	reader := bufio.NewReader(conn)
	c := &Conn{Conn: conn, r: reader}

	peek, err := reader.Peek(12)
	if err != nil {
		return c, netip.Addr{}, errors.New("failed to read proxy header data")
	}

	var clientIP netip.Addr

	// Determine the Proxy Protocol version and parse accordingly.
	if bytes.Equal(peek, v2Signature) {
		// Proxy Protocol version 2.
		clientIP, err = parseVersion2(reader)
		if err != nil {
			return c, netip.Addr{}, fmt.Errorf("proxy protocol v2: %w", err)
		}
	} else if bytes.HasPrefix(peek, v1Signature) {
		// Proxy Protocol version 1.
		clientIP, err = parseVersion1(reader)
		if err != nil {
			return c, netip.Addr{}, fmt.Errorf("proxy protocol v1: %w", err)
		}
	} else {
		// Not a Proxy Protocol header.
		return c, netip.Addr{}, errors.New("invalid or missing proxy protocol header")
	}

	// Ensure the header data was provided by a private IP address.
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP := addr.AddrPort().Addr().Unmap()
		if !remoteIP.IsPrivate() && !remoteIP.IsLoopback() {
			return c, netip.Addr{}, errors.New("proxy connection must originate from a private IP address")
		}
	} else {
		return c, netip.Addr{}, errors.New("could not resolve proxy IP address")
	}

	return c, clientIP, nil
}

// parseVersion1 reads and parses a Proxy Protocol version 1 text header and
// returns the extracted source IP address.
func parseVersion1(r *bufio.Reader) (netip.Addr, error) {
	// Proxy Protocol v1 ends with a CRLF (\r\n) and contains no more than 108
	// bytes (including the CRLF). Read up to the newline. The presence of a
	// carriage return before the newline is not validated.
	buf := make([]byte, 0, 108)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("can't read header: %w", err)
		}
		buf = append(buf, b)
		if b == '\n' {
			break
		}
		if len(buf) == 108 {
			return netip.Addr{}, errors.New("invalid header")
		}
	}

	// Strict CRLF validation.
	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		return netip.Addr{}, errors.New("invalid header terminator (expected CRLF)")
	}

	// Split into parts. Exactly 6 parts are expected. Other formats are not
	// supported by this package.
	parts := strings.Fields(string(buf))
	if len(parts) != 6 {
		return netip.Addr{}, errors.New("invalid or unsupported format")
	}

	// TCP4 and TCP6 addresses are expected. Other address formats are not
	// supported by this package.
	if parts[1] != "TCP4" && parts[1] != "TCP6" {
		return netip.Addr{}, errors.New("invalid or unsupported proxied protocol")
	}

	// Parse the IP.
	ip, err := netip.ParseAddr(parts[2])
	if err != nil {
		return netip.Addr{}, errors.New("invalid source address")
	}
	ip = ip.Unmap()

	// Verify protcol and address match.
	if parts[1] == "TCP4" && !ip.Is4() || (parts[1] == "TCP6" && !ip.Is6()) {
		return netip.Addr{}, errors.New("protocol/address version mismatch")
	}

	// Return the IP.
	return ip, nil
}

// parseVersion2 reads and parses a Proxy Protocol version 2 binary header and
// returns the extracted source IP address.
func parseVersion2(r *bufio.Reader) (netip.Addr, error) {
	// Read the first 16 bytes.
	// Bytes 1-12:  Proxy Protocol v2 signature.
	// Byte 13:     Protocol version and command.
	// Byte 14:     Transport protocol and address family.
	// Bytes 15-16: Length of the remaining header.
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return netip.Addr{}, fmt.Errorf("can't read header: %w", err)
	}

	// The 13th byte must be 0x21. The high bits are the version (2), low bits
	// are the command (1 = PROXY).
	if header[12] != 0x21 {
		return netip.Addr{}, errors.New("unsupported proxy command or version data")
	}

	// The 15th and 16th bytes specify the remaining header length. This
	// includes the address data and optional Type-Length-Value (TLV) vectors.
	// Cap this at a sensible 2KB for security, then read the remaining data.
	addrLen := binary.BigEndian.Uint16(header[14:16])
	if addrLen > 2048 {
		return netip.Addr{}, errors.New("proxy header too large")
	}
	addresses := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addresses); err != nil {
		return netip.Addr{}, fmt.Errorf("can't read address information: %w", err)
	}

	// The 14th byte is the transport protocol and address family. Only TCP/UDP
	// over IPv4 and IPv6 are supported by this package.
	addrType := header[13]

	// Extract and return the source IP address.
	// TCP over IPv4 = 0x11, UDP over IPv4 = 0x12.
	// 12 bytes is the size needed for IPv4 address data.
	if (addrType == 0x11 || addrType == 0x12) && len(addresses) >= 12 {
		ip, ok := netip.AddrFromSlice(addresses[0:4])
		if !ok || !ip.IsValid() {
			return netip.Addr{}, errors.New("invalid ipv4 source address")
		}
		return ip.Unmap(), nil
	}
	// TCP over IPv6 = 0x21, UDP over IPv6 = 0x22.
	// 36 bytes is the size needed for IPv6 address data.
	if (addrType == 0x21 || addrType == 0x22) && len(addresses) >= 36 {
		ip, ok := netip.AddrFromSlice(addresses[0:16])
		if !ok || !ip.IsValid() {
			return netip.Addr{}, errors.New("invalid ipv6 source address")
		}
		return ip.Unmap(), nil
	}

	return netip.Addr{}, errors.New("unsupported transport protocol or address family")
}
