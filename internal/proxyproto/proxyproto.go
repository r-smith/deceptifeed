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
var v1Signature = []byte{
	0x50, 0x52, 0x4F, 0x58, 0x59, 0x20,
}

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

// ReadHeader reads and parses a Proxy Protocol v1 or v2 header from conn. It
// extracts and returns the client IP address from the header. It sets a
// 2-second deadline on conn. If parsing fails, it returns an error. Callers
// should reset the deadline after this function returns to extend the timeout.
func ReadHeader(conn net.Conn) (netip.Addr, error) {
	_ = conn.SetDeadline(time.Now().Add(serverTimeout))

	reader := bufio.NewReader(conn)
	peek, err := reader.Peek(12)
	if err != nil {
		return netip.Addr{}, errors.New("failed to read proxy header data")
	}

	var clientIP netip.Addr

	// Determine the Proxy Protocol version and parse accordingly.
	if bytes.Equal(peek, v2Signature) {
		// Proxy Protocol version 2.
		clientIP, err = parseVersion2(reader)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("proxy protocol v2: %w", err)
		}
	} else if bytes.HasPrefix(peek, v1Signature) {
		// Proxy Protocol version 1.
		clientIP, err = parseVersion1(reader)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("proxy protocol v1: %w", err)
		}
	} else {
		// Not a Proxy Protocol header.
		return netip.Addr{}, errors.New("invalid or missing proxy protocol header")
	}

	// Ensure the header data was provided by a private IP address.
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if ip, err := netip.ParseAddr(host); err != nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
		return netip.Addr{}, errors.New("proxy connection must originate from a private IP address")
	}

	return clientIP, nil
}

// parseVersion1 reads and parses a Proxy Protocol vesion 1 text header and
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

	// Split into space-delimited parts. When address information is provided,
	// this should be exactly 6 parts. Other formats are not supported.
	parts := strings.Fields(string(buf))
	if len(parts) != 6 {
		return netip.Addr{}, errors.New("invalid or unsupported format")
	}

	// TCP4 and TCP6 addresses are supported by this package. Other address
	// formats are rejected.
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

// parseVersion2 reads and parses a Proxy Protocol vesion 2 binary header and
// returns the extracted source IP address.
func parseVersion2(r *bufio.Reader) (netip.Addr, error) {
	// Read the first 16 bytes into a buffer. The first 12 bytes is the Proxy
	// Protocol v2 signature. Byte 13 is the protocol version and command. Byte
	// 14 is the transport protocol and address family. Bytes 15-16 is the
	// length of the address data.
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return netip.Addr{}, fmt.Errorf("can't read header: %w", err)
	}

	// Byte 13 must be 0x21. The upper four bits represent the proxy protocol
	// version, which must be 0x2. The lower four bits specify the command -
	// 0x1 (PROXY) is the only supported command in this implementation.
	if header[12] != 0x21 {
		return netip.Addr{}, errors.New("unsupported proxy command or version data")
	}

	// Read bytes 15-16, which specify the length (in bytes) of the address
	// data in big-endian format. The address data includes source/destination
	// IPs and ports. Read the specified number of bytes into a buffer. The
	// length may indicate that additional bytes are part of the header beyond
	// the address data. These are Type-Length-Value (TLV) vectors, which are
	// read, but ignored by this implementation.
	addresses := make([]byte, binary.BigEndian.Uint16(header[14:16]))
	if _, err := io.ReadFull(r, addresses); err != nil {
		return netip.Addr{}, fmt.Errorf("can't read address information: %w", err)
	}

	// Byte 14 is the transport protocol and address family. Only TCP/UDP
	// over IPv4 and IPv6 are supported in this implementation.
	addrType := header[13]

	// Extract, parse, validate, and return the source IP address.
	// TCP over IPv4 = 0x11, UDP over IPv4 = 0x12.
	if (addrType == 0x11 || addrType == 0x12) && len(addresses) >= 12 {
		ip, ok := netip.AddrFromSlice(addresses[0:4])
		if !ok || !ip.IsValid() {
			return netip.Addr{}, errors.New("invalid ipv4 source address")
		}
		return ip.Unmap(), nil
	}
	// TCP over IPv6 = 0x21, UDP over IPv6 = 0x22.
	if (addrType == 0x21 || addrType == 0x22) && len(addresses) >= 36 {
		ip, ok := netip.AddrFromSlice(addresses[0:16])
		if !ok || !ip.IsValid() {
			return netip.Addr{}, errors.New("invalid ipv6 source address")
		}
		return ip.Unmap(), nil
	}

	return netip.Addr{}, errors.New("unsupported transport protocol or address family")
}
