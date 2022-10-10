package fleetlock

import (
	"context"
	"encoding/json"
	"regexp"
	"time"
)

// The core operations implemented by a FleetLock backend
// https://coreos.github.io/zincati/development/fleetlock/protocol/#overview
type FleetLocker interface {
	RecursiveLock(ctx context.Context, id string) error
	UnlockIfHeld(ctx context.Context, id string) error
	Group() string
	LockStatus(ctx context.Context) (LockStatus, error)
}

// https://coreos.github.io/zincati/development/fleetlock/protocol/#body
// Client group is a mandatory textual label, conforming to the regexp ^[a-zA-Z0-9.-]+$
var ValidGroup = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

// The error format expected for FleetLock requests
// https://coreos.github.io/zincati/development/fleetlock/protocol/#errors
type FleetLockError struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// The HTTP body format expected for FleetLock requests
// https://coreos.github.io/zincati/development/fleetlock/protocol/#body
type FleetLockBody struct {
	ClientParams clientParams `json:"client_params"`
}

// https://coreos.github.io/zincati/development/fleetlock/protocol/#body
type clientParams struct {
	ID    string `json:"id"`
	Group string `json:"group"`
}

// Returns status information regarding the lock. Useful for monitoring
// but is not part of the FleetLock protocol
type LockStatus struct {
	TotalSlots int      `json:"total_slots"`
	Holders    []Holder `json:"holders"`
}

type Holder struct {
	ID       string    `json:"id"`
	LockTime time.Time `json:"lock_time"`
	StaleAge Duration  `json:"stale_age"`
}

// Create a custom time.Duration wrapping struct so we can get a more
// easily readable JSON field for the data.
// Standard time.Duration: "stale_age": 10000000000
// With this Duration:     "stale_age": "10s"
type Duration struct {
	time.Duration
}

// Implement json.Unmarshaler interface
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	var err error
	if err = json.Unmarshal(b, &s); err != nil {
		return err
	}

	d.Duration, err = time.ParseDuration(s)
	if err != nil {
		return err
	}

	return nil
}

// Implement json.Marshaler interface
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}
