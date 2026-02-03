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

// readHeaderTimeout defines the time limit for receiving and parsing a Proxy
// Protocol header before the connection is closed.
const readHeaderTimeout = 2 * time.Second

// Listener wraps a net.Listener to automatically parse Proxy Protocol headers
// from incoming connections.
type Listener struct {
	net.Listener
}

// Ensure Listener satisfies the net.Listener interface.
var _ net.Listener = (*Listener)(nil)

// Accept waits for and returns the next connection to the listener. Proxy
// Protocol headers are automatically parsed from incoming connections.
func (l *Listener) Accept() (net.Conn, error) {
	rawConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	wrappedConn := &Conn{
		Conn: rawConn,
		r:    bufio.NewReaderSize(rawConn, 512),
	}

	// Parse the Proxy Protocol header (with a set deadline).
	_ = rawConn.SetDeadline(time.Now().Add(readHeaderTimeout))
	wrappedConn.readHeader()
	_ = rawConn.SetDeadline(time.Time{})

	return wrappedConn, nil
}

// Conn wraps a net.Conn and a bufio.Reader to ensure data read by Proxy
// Protocol handling remains accessible.
type Conn struct {
	net.Conn
	r           *bufio.Reader
	extractedIP netip.Addr
	proxyErr    error
}

// Ensure Conn satisfies the net.Conn interface.
var _ net.Conn = (*Conn)(nil)

// Read overrides the underlying net.Conn.Read to read from the internal
// buffered reader instead of the underlying connection.
func (c *Conn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// RemoteAddr returns the original client's network address. If Proxy Protocol
// parsing fails, it returns the underlying connection's remote address.
func (c *Conn) RemoteAddr() net.Addr {
	if !c.extractedIP.IsValid() {
		return c.Conn.RemoteAddr()
	}

	// Return the extracted client IP with the original connection's port and
	// zone.
	if addr, ok := c.Conn.RemoteAddr().(*net.TCPAddr); ok {
		return &net.TCPAddr{
			IP:   net.IP(c.extractedIP.AsSlice()),
			Port: addr.Port,
			Zone: addr.Zone,
		}
	}

	return c.Conn.RemoteAddr()
}

// ProxyData returns the source IP address extracted from the Proxy Protocol
// header and any error encountered during parsing.
func (c *Conn) ProxyData() (netip.Addr, error) {
	return c.extractedIP, c.proxyErr
}

// readHeader reads and parses a Proxy Protocol version 1 or 2 header from the
// connection. The extracted client IP and any parsing errors are stored within
// the Conn.
func (c *Conn) readHeader() {
	peek, err := c.r.Peek(12)
	if err != nil {
		c.proxyErr = errors.New("failed to read proxy header data")
		return
	}

	var clientIP netip.Addr

	// Determine the Proxy Protocol version and parse accordingly.
	if bytes.Equal(peek, v2Signature) {
		clientIP, err = parseVersion2(c.r)
	} else if bytes.HasPrefix(peek, v1Signature) {
		clientIP, err = parseVersion1(c.r)
	} else {
		c.proxyErr = errors.New("invalid or missing proxy protocol header")
		return
	}

	if err != nil {
		c.proxyErr = err
		return
	}

	// Restrict Proxy Protocol usage to private IP addresses.
	if addr, ok := c.Conn.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP := addr.AddrPort().Addr().Unmap()
		if !remoteIP.IsPrivate() && !remoteIP.IsLoopback() {
			c.proxyErr = errors.New("proxy connection must originate from a private IP address")
			return
		}
	}

	c.extractedIP = clientIP
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
