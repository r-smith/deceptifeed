package eventdata

// Connection describes network metadata for incoming honeypot connections.
type Connection struct {
	// SourceIP is the client IP address interacting with the honeypot. When
	// the honeypot is configured to run behind a proxy and the proxy header is
	// successfully parsed, this field contains the client IP extracted from
	// the header.
	SourceIP string

	// ServerIP is the IP address of the honeypot server that accepted the
	// connection.
	ServerIP string

	// ServerPort is the TCP or UDP port of the honeypot server that received
	// the connection.
	ServerPort string

	// ProxyIP is the IP address of the upstream proxy that forwarded the
	// connection to the honeypot. It is only set when the the honeypot is
	// configured to run behind a proxy.
	ProxyIP string

	// ProxyParsed indicates whether a client IP was successfully extracted
	// from a proxy header.
	ProxyParsed bool

	// ProxyError describes any error encountered while parsing a proxy header.
	// It is only set when parsing fails.
	ProxyError string
}
