package threatfeed

import (
	"net/netip"
	"time"
)

type alertCategory int

const (
	alertUnknown = iota
	alertExcessiveHits
)

func (a alertCategory) String() string {
	switch a {
	case alertExcessiveHits:
		return "excessive hits"
	default:
		return "unknown alert"
	}
}

// alert represents a notable security event detected by the threatfeed.
type alert struct {
	Timestamp time.Time      `json:"timestamp"`
	IP        netip.Addr     `json:"ip"`
	Category  alertCategory  `json:"category"`
	Data      map[string]any `json:"data"`
}
