package stix

import (
	"time"
)

const (
	// DeceptifeedID is a deterministic identifier for the Deceptifeed Identity
	// object. STIX objects should reference this ID using the `created_by_ref`
	// property to show the object was created by Deceptifeed. This constant is
	// the result of:
	// DeterministicID("identity", "{"identity_class":"system","name":"deceptifeed"}")
	DeceptifeedID = "identity--370c0cfb-3203-5ca4-b8a9-b1aeef9d6fb3"

	// SpecVersion is the version of the STIX specification being implemented.
	SpecVersion = "2.1"

	// ContentType is the `Content-Type` HTTP response header used when
	// returning STIX objects.
	ContentType = "application/stix+json;version=2.1"
)

// Object represents a STIX Object, a general term for a STIX Domain Object
// (SDO), STIX Cyber-observable Object (SCO), STIX Relationship Object (SRO),
// or STIX Meta Object.
type Object interface{}

// Bundle represents a STIX Bundle Object. A Bundle is a collection of
// arbitrary STIX Objects grouped together in a single container.
type Bundle struct {
	Type    string   `json:"type"`              // Required
	ID      string   `json:"id"`                // Required
	Objects []Object `json:"objects,omitempty"` // Optional
}

// Indicator represents a STIX Indicator SDO.
type Indicator struct {
	Type           string      `json:"type"`                        // Required
	SpecVersion    string      `json:"spec_version"`                // Required
	ID             string      `json:"id"`                          // Required
	IndicatorTypes []string    `json:"indicator_types"`             // Required
	Pattern        string      `json:"pattern"`                     // Required
	PatternType    string      `json:"pattern_type"`                // Required
	Created        time.Time   `json:"created"`                     // Required
	Modified       time.Time   `json:"modified"`                    // Required
	ValidFrom      time.Time   `json:"valid_from"`                  // Required
	ValidUntil     *time.Time  `json:"valid_until,omitempty"`       // Optional
	Name           string      `json:"name,omitempty"`              // Optional
	Description    string      `json:"description,omitempty"`       // Optional
	KillChains     []KillChain `json:"kill_chain_phases,omitempty"` // Optional
	Labels         []string    `json:"labels,omitempty"`            // Optional
	Lang           string      `json:"lang,omitempty"`              // Optional
	CreatedByRef   string      `json:"created_by_ref,omitempty"`    // Optional
}

// KillChain represents a STIX `kill-chain-phase` type, which represents a
// phase in a kill chain.
type KillChain struct {
	KillChain string `json:"kill_chain_name"` // Required
	Phase     string `json:"phase_name"`      // Required
}

// ObservableIP represents a STIX IP Address SCO.
type ObservableIP struct {
	Type         string `json:"type"`                     // Required
	SpecVersion  string `json:"spec_version,omitempty"`   // Optional
	ID           string `json:"id"`                       // Required
	Value        string `json:"value"`                    // Required
	CreatedByRef string `json:"created_by_ref,omitempty"` // Optional
}

// Identity represents a STIX Identity SDO, used to represent individuals,
// organizations, groups, or systems.
type Identity struct {
	Type        string    `json:"type"`                          // Required
	SpecVersion string    `json:"spec_version"`                  // Required
	ID          string    `json:"id"`                            // Required
	Class       string    `json:"identity_class"`                // Required
	Name        string    `json:"name"`                          // Required
	Description string    `json:"description,omitempty"`         // Optional
	Contact     string    `json:"contact_information,omitempty"` // Optional
	Created     time.Time `json:"created"`                       // Required
	Modified    time.Time `json:"modified"`                      // Required
}

// DeceptifeedIdentity returns a STIX Identity object representing the
// Deceptifeed application.
func DeceptifeedIdentity() Identity {
	const initialCommitTime = "2024-10-16T18:48:00.000Z"
	created, err := time.Parse(time.RFC3339, initialCommitTime)
	if err != nil {
		created = time.Now()
	}

	return Identity{
		Type:        "identity",
		SpecVersion: SpecVersion,
		ID:          DeceptifeedID,
		Class:       "system",
		Name:        "Deceptifeed",
		Description: "Deceptifeed is a defense system that combines honeypot servers with an integrated threat feed.",
		Contact:     "deceptifeed.com",
		Created:     created,
		Modified:    created,
	}
}
