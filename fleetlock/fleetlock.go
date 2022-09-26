package fleetlock

import (
	"context"
	"regexp"
)

// The core operations implemented by a FleetLock backend
// https://coreos.github.io/zincati/development/fleetlock/protocol/#overview
type FleetLocker interface {
	RecursiveLock(ctx context.Context, id string) error
	UnlockIfHeld(ctx context.Context, id string) error
	Group() string
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
