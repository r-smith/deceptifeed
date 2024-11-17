package taxii

import "github.com/r-smith/deceptifeed/internal/stix"

const (
	// APIRoot is the part of the URL that makes up the TAXII API root.
	APIRoot = "/taxii2/api/"

	// ContentType is the `Content-Type` HTTP response header used when
	// returning TAXII responses.
	ContentType = "application/taxii+json;version=2.1"

	// IndicatorsID is a fixed (random) identifier for the indicators
	// collection.
	IndicatorsID = "2cc72f88-8d92-4745-9c00-ea0deac18163"

	// IndicatorsAlias is the friendly alias for the indicators collection.
	IndicatorsAlias = "deceptifeed-indicators"

	// ObservablesID is a fixed (random) identifier for the observables
	// collection.
	ObservablesID = "8aaff655-40de-41e2-9064-3dc1620d6420"

	// ObservablesAlias is the friendly alias for the observables collection.
	ObservablesAlias = "deceptifeed-observables"
)

// ImplementedCollections returns the collections that are available for use.
func ImplementedCollections() []Collection {
	return []Collection{
		{
			ID:          IndicatorsID,
			Title:       "Deceptifeed Indicators",
			Description: "This collection contains IP addresses represented as STIX Indicators",
			Alias:       IndicatorsAlias,
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{ContentType},
		},
		{
			ID:          ObservablesID,
			Title:       "Deceptifeed Observables",
			Description: "This collection contains IP addresses represented as STIX Observables",
			Alias:       ObservablesAlias,
			CanRead:     true,
			CanWrite:    false,
			MediaTypes:  []string{ContentType},
		},
	}
}

// Envelope represents a TAXII envelope resource, which is a simple wrapper for
// STIX 2 content.
type Envelope struct {
	More    bool          `json:"more"`           // Optional
	Next    string        `json:"next,omitempty"` // Optional
	Objects []stix.Object `json:"objects"`        // Optional
}

// Collection represents a TAXII collection resource, which contains general
// information about a collection.
type Collection struct {
	ID          string   `json:"id"`                    // Required
	Title       string   `json:"title"`                 // Required
	Description string   `json:"description,omitempty"` // Optional
	Alias       string   `json:"alias,omitempty"`       // Optional
	CanRead     bool     `json:"can_read"`              // Required
	CanWrite    bool     `json:"can_write"`             // Required
	MediaTypes  []string `json:"media_types,omitempty"` // Optional
}

// DiscoveryResource represents a TAXII discovery resource, which contains
// information about a TAXII server.
type DiscoveryResource struct {
	Title       string   `json:"title"`                 // Required
	Description string   `json:"description,omitempty"` // Optional
	Default     string   `json:"default,omitempty"`     // Optional
	APIRoots    []string `json:"api_roots,omitempty"`   // Optional
}

// APIRootResource represents a TAXII api-root resource, which contains general
// information about the API root.
type APIRootResource struct {
	Title            string   `json:"title"`              // Required
	Versions         []string `json:"versions"`           // Required
	MaxContentLength int      `json:"max_content_length"` // Required
}
