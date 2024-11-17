package fleetlock

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/SUNET/knubbis-fleetlock/hashing"
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
	ClientParams ClientParams `json:"client_params"`
}

// https://coreos.github.io/zincati/development/fleetlock/protocol/#body
type ClientParams struct {
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

// Type that satisfies the "error" interface. If the caller gets this
// type of error it can trust the message in clientMsg is safe to send to the
// client as-is in a FleetLockError value.
type RecursiveLockError struct {
	ClientMsg     string
	AllSlotsTaken bool
}

func (le *RecursiveLockError) Error() string {
	return le.ClientMsg
}

type FleetLockConfig map[string]GroupSettings

// Settings that look the same before and after hashing
type CommonGroupSettings struct {
	TotalSlots int      `json:"total_slots" example:"1"`
	StaleAge   Duration `json:"stale_age" swaggertype:"string" example:"1h"`
}

// "example" and "swaggerype" tags are used by swaggo/swag for creating
// docs
type GroupSettings struct {
	CommonGroupSettings
	Permissions map[string]string `json:"permissions" example:"*:changeme"`
}

type FleetLockHashedConfig map[string]HashedGroupSettings

type HashedGroupSettings struct {
	CommonGroupSettings
	HashedPermissions map[string]hashing.HashedPassword `json:"permissions" example:"*:changeme"`
}

type HashedPassword struct {
	Hash []byte
	Salt []byte
}

type FleetLockConfiger interface {
	GetConfig(ctx context.Context) (FleetLockHashedConfig, error)
	GetLockers(ctx context.Context) (map[string]FleetLocker, error)
	GetNotifierChan(ctx context.Context) (interface{}, error)
	AddGroup(ctx context.Context, group string, totalSlots int, staleAge Duration, permissions map[string]string) error
	DelGroup(ctx context.Context, group string) error
}

func NewHashedConfig(flc FleetLockConfig, argonSettings hashing.ArgonSettings) (FleetLockHashedConfig, error) {
	flhc := map[string]HashedGroupSettings{}

	for group, settings := range flc {
		hashedPerms, err := hashing.HashPermissionPasswords(settings.Permissions, argonSettings)
		if err != nil {
			return FleetLockHashedConfig{}, fmt.Errorf("newFlcStorage: %w", err)
		}

		flhc[group] = HashedGroupSettings{
			CommonGroupSettings: CommonGroupSettings{
				TotalSlots: settings.TotalSlots,
				StaleAge:   settings.StaleAge,
			},
			HashedPermissions: hashedPerms,
		}
	}

	return flhc, nil
}
