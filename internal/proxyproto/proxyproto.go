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
	// bytes (including the CRLF). Read up to the newline.
	var buf [108]byte
	n := 0

	for {
		b, err := r.ReadByte()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("can't read proxy v1 header: %w", err)
		}

		buf[n] = b
		n++

		if b == '\n' {
			break
		}
		if n == 108 {
			return netip.Addr{}, errors.New("proxy v1 header exceeds 108-byte limit")
		}
	}

	line := buf[:n]

	// Strict CRLF validation.
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return netip.Addr{}, errors.New("proxy v1 header missing CRLF")
	}

	// Trim the CRLF.
	header := line[:len(line)-2]

	// Split into space-separated parts. Exactly 6 parts are expected.
	parts := bytes.Split(header, []byte(" "))
	if len(parts) != 6 {
		return netip.Addr{}, errors.New("invalid proxy v1 header format")
	}

	// Protocol and address family validation. Must be TCP4 or TCP6.
	isIPv4 := bytes.Equal(parts[1], []byte("TCP4"))
	isIPv6 := bytes.Equal(parts[1], []byte("TCP6"))
	if !isIPv4 && !isIPv6 {
		return netip.Addr{}, errors.New("unsupported proxy v1 address family")
	}

	// Parse the IP.
	ip, err := netip.ParseAddr(string(parts[2]))
	if err != nil {
		return netip.Addr{}, errors.New("invalid proxy v1 source address")
	}
	ip = ip.Unmap()

	// Verify the protocol and address match.
	if (isIPv4 && !ip.Is4()) || (isIPv6 && !ip.Is6()) {
		return netip.Addr{}, errors.New("proxy v1 protocol/address mismatch")
	}

	// Return the IP.
	return ip, nil
}

// parseVersion2 reads and parses a Proxy Protocol version 2 binary header and
// returns the extracted source IP address.
func parseVersion2(r *bufio.Reader) (netip.Addr, error) {
	// Read the first 16 bytes.
	// Bytes 0-11:  Proxy Protocol v2 signature.
	// Byte 12:     Protocol version and command.
	// Byte 13:     Transport protocol and address family.
	// Bytes 14-15: Length of the remaining header (addresses + TLVs).
	var header [16]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return netip.Addr{}, fmt.Errorf("failed to read proxy v2 header: %w", err)
	}

	// Bytes 14-15 specify the remaining header length. This includes the
	// address data and optional Type-Length-Value (TLV) vectors. We enforce a
	// sensible 512-byte limit on the total header. Since the fixed portion is
	// 16 bytes, the remaining header must not exceed 496 bytes.
	remainingLen := int(binary.BigEndian.Uint16(header[14:16]))
	if remainingLen > 496 {
		return netip.Addr{}, errors.New("proxy v2 header exceeds 512-byte limit")
	}

	// Byte 12 is the protocol version and command. The highest four bits is
	// the protocol version (must be 0x2). The lowest four bits is the command
	// (0x0 = LOCAL, 0x1 = PROXY).
	switch header[12] {
	case 0x20:
		// Version 2 + Command = LOCAL. Discard the remaining header and use
		// the real connection endpoints.
		_, _ = io.CopyN(io.Discard, r, int64(remainingLen))
		return netip.Addr{}, nil
	case 0x21:
		// Version 2 + Command = PROXY. Continue to address parsing.
	default:
		// Per spec, receivers must drop connections with unexpected values.
		_, _ = io.CopyN(io.Discard, r, int64(remainingLen))
		return netip.Addr{}, errors.New("unsupported proxy v2 command or version")
	}

	// Byte 13 is the transport protocol and address family. Only TCP/UDP over
	// IPv4 or IPv6 are supported by this package.
	addrType := header[13]
	var addrLen int
	var ipOffset int

	switch addrType {
	case 0x11, 0x12:
		// TCP or UDP over IPv4:
		// 4 (src) + 4 (dst) + 2 (src port) + 2 (dst port) = 12 bytes.
		addrLen = 12
		ipOffset = 4
	case 0x21, 0x22:
		// TCP or UDP over IPv6:
		// 16 (src) + 16 (dst) + 2 (src port) + 2 (dst port) = 36 bytes.
		addrLen = 36
		ipOffset = 16
	default:
		// For all other types, consume and discard remainingLen bytes and
		// return an error.
		_, _ = io.CopyN(io.Discard, r, int64(remainingLen))
		return netip.Addr{}, errors.New("unsupported proxy v2 address family")
	}

	if remainingLen < addrLen {
		_, _ = io.CopyN(io.Discard, r, int64(remainingLen))
		return netip.Addr{}, errors.New("header length too short for address family")
	}

	// Read the address data.
	var addrBuf [36]byte
	if _, err := io.ReadFull(r, addrBuf[:addrLen]); err != nil {
		return netip.Addr{}, fmt.Errorf("failed to read address data: %w", err)
	}

	// Discard the TLVs (the remaining bytes).
	tlvLen := int64(remainingLen - addrLen)
	if tlvLen > 0 {
		_, _ = io.CopyN(io.Discard, r, tlvLen)
	}

	// Extract and validate the source IP.
	ip, ok := netip.AddrFromSlice(addrBuf[:ipOffset])
		if !ok || !ip.IsValid() {
		return netip.Addr{}, errors.New("invalid proxy v2 source address")
		}

		return ip.Unmap(), nil
}
