package etcd3

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/SUNET/knubbis-fleetlock/fleetlock"
	"github.com/SUNET/knubbis-fleetlock/hashing"
	"github.com/rs/zerolog"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/exp/slices"
)

const groupPrefix = "se.sunet.knubbis/fleetlock/groups"
const groupSuffix = "v1/semaphore"

func groupSemaphorePath(group string) string {
	return fmt.Sprintf("%s/%s/%s", groupPrefix, group, groupSuffix)
}

type semaphore struct {
	TotalSlots int                `json:"total_slots"`
	Holders    []fleetlock.Holder `json:"holders"`
}

// Type implementing the FleetLock interface using etcd3 as a backend
type Etcd3Backend struct {
	client     *clientv3.Client
	key        string
	totalSlots int
	group      string
	staleAge   fleetlock.Duration
}

// Type implementing the FleetLockConfiger interface using etcd3 as a backend
type Etcd3Config struct {
	client        *clientv3.Client
	key           string
	argonSettings hashing.ArgonSettings
}

func newLocker(client *clientv3.Client, group string, totalSlots int, staleAge fleetlock.Duration) (*Etcd3Backend, error) {

	if !fleetlock.ValidGroup.MatchString(group) {
		return nil, fmt.Errorf("group name '%s' is not valid", group)
	}
	return &Etcd3Backend{
		client:     client,
		group:      group,
		key:        groupSemaphorePath(group),
		totalSlots: totalSlots,
		staleAge:   staleAge,
	}, nil
}

func (eb *Etcd3Backend) Key() string {
	return eb.key
}

func (eb *Etcd3Backend) RecursiveLock(ctx context.Context, id string) error {
	// Fetch semaphore data (which may not exist yet)
	s, err := eb.client.Get(ctx, eb.key)
	if err != nil {
		return fmt.Errorf("RecursiveLock: Get key: %w", err)
	}

	logger := zerolog.Ctx(ctx)

	switch numKvs := len(s.Kvs); numKvs {
	case 0:
		// The semaphore data does not exist, create it
		sNew := semaphore{
			TotalSlots: eb.totalSlots,
			Holders: []fleetlock.Holder{
				{
					ID:       id,
					LockTime: time.Now(),
					StaleAge: eb.staleAge,
				},
			},
		}

		// Version 0 requires that the key does not exist
		err := eb.atomicWrite(sNew, 0)
		if err != nil {
			return fmt.Errorf("RecursiveLock: %w", err)
		}
	case 1:
		// The semaphore data exists: add id as a holder if it
		// is not alreay in it and there is room
		sData := semaphore{}
		err := json.Unmarshal(s.Kvs[0].Value, &sData)
		if err != nil {
			return fmt.Errorf("RecursiveLock: unable to marshal KV value: %w", err)
		}

		for _, holder := range sData.Holders {
			if holder.ID == id {
				logger.Print("already holds a lock")
				return nil
			}
		}

		if len(sData.Holders) >= sData.TotalSlots {
			return &fleetlock.RecursiveLockError{
				ClientMsg:     fmt.Sprintf("all %d slots are currently taken", sData.TotalSlots),
				AllSlotsTaken: true,
			}
		}

		// Add requested id as holder, keeping the slice sorted
		index := sort.Search(len(sData.Holders), func(i int) bool { return sData.Holders[i].ID >= id })
		sData.Holders = slices.Insert(
			sData.Holders,
			index,
			fleetlock.Holder{
				ID:       id,
				LockTime: time.Now(),
				StaleAge: eb.staleAge,
			},
		)

		// Write updated semaphore to etcd
		err = eb.atomicWrite(sData, s.Kvs[0].Version)
		if err != nil {
			return fmt.Errorf("RecursiveLock: failed writing to etcd: %w", err)
		}
	default:
		return fmt.Errorf("RecursiveLock: unexpected number KVs in response: %d", len(s.Kvs))
	}

	return nil
}

func (eb *Etcd3Backend) UnlockIfHeld(ctx context.Context, id string) error {
	s, err := eb.client.Get(ctx, eb.key)
	if err != nil {
		return fmt.Errorf("UnlockIfHeld: Get key: %w", err)
	}

	logger := zerolog.Ctx(ctx)

	switch numKvs := len(s.Kvs); numKvs {
	case 0:
		// The semaphore data does not exist, create it in an
		// empty state
		sNew := semaphore{
			TotalSlots: eb.totalSlots,
			Holders:    []fleetlock.Holder{},
		}

		// Version 0 requires that the key does not exist
		err := eb.atomicWrite(sNew, 0)
		if err != nil {
			return fmt.Errorf("UnlockIfHeld: %w", err)
		}
	case 1:
		// The semaphore data exists: remove the id if present
		sData := semaphore{}
		err := json.Unmarshal(s.Kvs[0].Value, &sData)
		if err != nil {
			return fmt.Errorf("UnlockIfHeld: unable to marshal KV value: %w", err)
		}

		lockFound := false
		for _, holder := range sData.Holders {
			if holder.ID == id {
				lockFound = true
				break
			}
		}
		if !lockFound {
			logger.Printf("lock is not held by this ID")
			return nil
		}

		// Remove requested id
		index := sort.Search(len(sData.Holders), func(i int) bool { return sData.Holders[i].ID >= id })
		sData.Holders = slices.Delete(sData.Holders, index, index+1)

		// Write updated semaphore to etcd
		err = eb.atomicWrite(sData, s.Kvs[0].Version)
		if err != nil {
			return fmt.Errorf("UnlockIfHeld: failed writing to etcd: %w", err)
		}
	default:
		return fmt.Errorf("UnlockIfHeld: unexpected number KVs in response: %d", len(s.Kvs))
	}

	return nil
}

func (eb *Etcd3Backend) LockStatus(ctx context.Context) (fleetlock.LockStatus, error) {
	logger := zerolog.Ctx(ctx)

	logger.Info().Msgf("LockStatus: getting status for key: '%s'", eb.key)

	s, err := eb.client.Get(ctx, eb.key)
	if err != nil {
		return fleetlock.LockStatus{}, fmt.Errorf("LockStatus: Get key: %w", err)
	}

	switch numKvs := len(s.Kvs); numKvs {
	case 0:
		// The semaphore data does not exist, synthesize empty
		// status
		logger.Debug().Msg("LockStatus: returning empty status")
		return fleetlock.LockStatus{
			TotalSlots: eb.totalSlots,
			Holders:    []fleetlock.Holder{},
		}, nil
	case 1:
		// The semaphore data exists: return the information
		sData := semaphore{}
		err := json.Unmarshal(s.Kvs[0].Value, &sData)
		if err != nil {
			return fleetlock.LockStatus{}, fmt.Errorf("LockStatus: unable to marshal KV value: %w", err)
		}

		logger.Debug().Msg("LockStatus: returning status")
		return fleetlock.LockStatus{
			TotalSlots: eb.totalSlots,
			Holders:    sData.Holders,
		}, nil
	default:
		return fleetlock.LockStatus{}, fmt.Errorf("LockStatus: unexpected number KVs in response: %d", len(s.Kvs))
	}
}

func (eb *Etcd3Backend) Group() string {
	return eb.group
}

// atomicWrite creates or overwrites the existing semaphore value in
// etcd, requiring that the value being overwritten is currently at the
// supplied version number. This ensures that two simultanous writers
// will not overwrite eachother. Only the one handled first will
// succeed, and the other one will fail as its version is no longer
// valid, requring a new read of the value.
func (eb *Etcd3Backend) atomicWrite(sData semaphore, version int64) error {
	b, err := json.Marshal(sData)
	if err != nil {
		return fmt.Errorf("atomicWrite: unable to marshal JSON: %w", err)
	}

	txnResp, err := eb.client.Txn(context.Background()).
		If(clientv3.Compare(clientv3.Version(eb.key), "=", version)).
		Then(clientv3.OpPut(eb.key, string(b))).
		Commit()
	if err != nil {
		return fmt.Errorf("atomicWrite: unable to commit semaphore key '%s': %w", eb.key, err)
	}

	if !txnResp.Succeeded {
		return fmt.Errorf("atomicWrite: transaction initializing semaphore failed")
	}
	return nil
}

func NewConfiger(client *clientv3.Client, configName string, argonSettings hashing.ArgonSettings) (*Etcd3Config, error) {
	return &Etcd3Config{
		client:        client,
		key:           fmt.Sprintf("se.sunet.knubbis/fleetlock/config/%s/v1/data", configName),
		argonSettings: argonSettings,
	}, nil
}

// atomicConfigWrite creates or overwrites the existing config value in
// etcd, requiring that the value being overwritten is currently at the
// supplied version number. This ensures that two simultanous writers
// will not overwrite eachother. Only the one handled first will
// succeed, and the other one will fail as its version is no longer
// valid, requring a new read of the value. The handler also supports
// cleaning up a related semaphore when removing a group, if the string
// is not empty
func (ec *Etcd3Config) atomicConfigWrite(ctx context.Context, logger *zerolog.Logger, flhc fleetlock.FleetLockHashedConfig, version int64, delSemKey string) error {
	b, err := json.Marshal(flhc)
	if err != nil {
		return fmt.Errorf("atomicConfigWrite: unable to marshal JSON: %w", err)
	}

	txn := ec.client.Txn(ctx)
	txn = txn.If(clientv3.Compare(clientv3.Version(ec.key), "=", version))

	// If a semaphore key was supplied we delete this inside the
	// same transaction
	if delSemKey != "" {
		txn = txn.Then(clientv3.OpPut(ec.key, string(b)), clientv3.OpDelete(delSemKey))
	} else {
		txn = txn.Then(clientv3.OpPut(ec.key, string(b)))
	}

	txnResp, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("atomicConfigWrite: unable to commit config key '%s': %w", ec.key, err)
	}

	if !txnResp.Succeeded {
		return fmt.Errorf("atomicConfigWrite: transaction writing config failed")
	}

	// Do some extra verification for the responses
	for _, response := range txnResp.Responses {
		switch op := response.Response.(type) {
		case *etcdserverpb.ResponseOp_ResponsePut:
		case *etcdserverpb.ResponseOp_ResponseDeleteRange:
			// If no locks have been taken in the group
			// there is no semaphore key to delete because
			// it has not been created yet, but more than 1
			// is strange:
			if op.ResponseDeleteRange.Deleted > 1 {
				return fmt.Errorf("atomicConfigWrite: unexpected number of keys deleted: %d", op.ResponseDeleteRange.Deleted)
			}
		default:
			return fmt.Errorf("found unexpected op type '%T'", op)
		}

	}
	return nil
}

func (ec *Etcd3Config) GetConfig(ctx context.Context) (fleetlock.FleetLockHashedConfig, error) {
	// Fetch config data (which may not exist yet)
	s, err := ec.client.Get(ctx, ec.key)
	if err != nil {
		return fleetlock.FleetLockHashedConfig{}, fmt.Errorf("GetConfig: Get key: %w", err)
	}

	logger := zerolog.Ctx(ctx)

	switch numKvs := len(s.Kvs); numKvs {
	case 0:
		// No config exists, return empty config
		logger.Info().Msg("returning empty config from etcd3")
		return fleetlock.FleetLockHashedConfig{}, nil
	case 1:
		// The config data exists, return it
		flhc := fleetlock.FleetLockHashedConfig{}
		err := json.Unmarshal(s.Kvs[0].Value, &flhc)
		if err != nil {
			return fleetlock.FleetLockHashedConfig{}, fmt.Errorf("GetConfig: unable to marshal KV storage value: %w", err)
		}

		logger.Info().Msg("returning config from etcd3")
		return flhc, nil
	default:
		return fleetlock.FleetLockHashedConfig{}, fmt.Errorf("RecursiveLock: unexpected number KVs in response: %d", len(s.Kvs))
	}
}

func (ec *Etcd3Config) GetLockers(ctx context.Context) (map[string]fleetlock.FleetLocker, error) {
	logger := zerolog.Ctx(ctx)

	logger.Info().Msg("getting lockers")

	lockers := map[string]fleetlock.FleetLocker{}

	config, err := ec.GetConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetLockers: unable to GetConfig: %w", err)
	}

	for group, groupSettings := range config {
		backend, err := newLocker(ec.client, group, groupSettings.TotalSlots, groupSettings.StaleAge)
		if err != nil {
			return nil, fmt.Errorf("GetLockers: unable to create locker backend: %w", err)
		}
		lockers[group] = backend
	}

	return lockers, nil
}

func (ec *Etcd3Config) AddGroup(ctx context.Context, group string, totalSlots int, staleAge fleetlock.Duration, permissions map[string]string) error {

	if !fleetlock.ValidGroup.MatchString(group) {
		return fmt.Errorf("AddGroup: group name '%s' is not valid", group)
	}
	// Fetch config data (which may not exist yet)
	s, err := ec.client.Get(ctx, ec.key)
	if err != nil {
		return fmt.Errorf("AddGroup: Get key: %w", err)
	}

	logger := zerolog.Ctx(ctx)

	switch numKvs := len(s.Kvs); numKvs {
	case 0:
		// No config exists, create new one
		logger.Info().Msgf("adding group '%s' to config", group)
		flc := fleetlock.FleetLockConfig{
			group: fleetlock.GroupSettings{
				CommonGroupSettings: fleetlock.CommonGroupSettings{
					TotalSlots: totalSlots,
					StaleAge:   staleAge,
				},
				Permissions: permissions,
			},
		}

		flhc, err := fleetlock.NewHashedConfig(flc, ec.argonSettings)
		if err != nil {
			return fmt.Errorf("AddGroup: %w", err)
		}

		// We expect the value to be created (version 0)
		err = ec.atomicConfigWrite(ctx, logger, flhc, 0, "")
		if err != nil {
			return fmt.Errorf("AddGroup: error creating config: %w", err)
		}

		return nil
	case 1:
		// The config data exists, add the group if it does
		// not exist in the data
		flhc := fleetlock.FleetLockHashedConfig{}
		err := json.Unmarshal(s.Kvs[0].Value, &flhc)
		if err != nil {
			return fmt.Errorf("AddGroup: unable to marshal KV value: %w", err)
		}

		_, exists := flhc[group]

		if exists {
			return fmt.Errorf("AddGroup: group '%s' already exists", group)
		}

		hashedPerms, err := hashing.HashPermissionPasswords(permissions, ec.argonSettings)
		if err != nil {
			return fmt.Errorf("AddGroup: unable to hash perms: %w", err)
		}

		// Add the group config
		flhc[group] = fleetlock.HashedGroupSettings{
			CommonGroupSettings: fleetlock.CommonGroupSettings{
				TotalSlots: totalSlots,
				StaleAge:   staleAge,
			},
			HashedPermissions: hashedPerms,
		}

		err = ec.atomicConfigWrite(ctx, logger, flhc, s.Kvs[0].Version, "")
		if err != nil {
			return fmt.Errorf("AddGroup: error adding group '%s' to config: %w", group, err)
		}
		return nil
	default:
		return fmt.Errorf("AddGroup: unexpected number KVs in response: %d", len(s.Kvs))
	}
}

func (ec *Etcd3Config) DelGroup(ctx context.Context, group string) error {
	if !fleetlock.ValidGroup.MatchString(group) {
		return fmt.Errorf("DelGroup: group name '%s' is not valid", group)
	}
	// Fetch config data (which may not exist yet)
	s, err := ec.client.Get(ctx, ec.key)
	if err != nil {
		return fmt.Errorf("DelGroup: Get key: %w", err)
	}

	logger := zerolog.Ctx(ctx)

	switch numKvs := len(s.Kvs); numKvs {
	case 0:
		// No config exists, error out
		logger.Info().Msgf("trying to delete group '%s' from empty config", group)
		return fmt.Errorf("DelGroup: unable to delete group '%s' from empty config: %w", group, err)
	case 1:
		// The config data exists, delete the group if it exists
		// in the data
		flhc := fleetlock.FleetLockHashedConfig{}
		err := json.Unmarshal(s.Kvs[0].Value, &flhc)
		if err != nil {
			return fmt.Errorf("DelGroup: unable to marshal KV value: %w", err)
		}

		_, exists := flhc[group]

		if !exists {
			return fmt.Errorf("DelGroup: group '%s' does not exist", group)
		}

		// Delete the group config
		delete(flhc, group)

		// Cleanup related semaphore
		semaphoreKey := groupSemaphorePath(group)

		err = ec.atomicConfigWrite(ctx, logger, flhc, s.Kvs[0].Version, semaphoreKey)
		if err != nil {
			return fmt.Errorf("DelGroup: error deleting group '%s' from config: %w", group, err)
		}

		return nil
	default:
		return fmt.Errorf("DelGroup: unexpected number KVs in response: %d", len(s.Kvs))
	}
}

func (ec *Etcd3Config) GetNotifierChan(ctx context.Context) (interface{}, error) {
	rch := ec.client.Watch(ctx, ec.key)

	return rch, nil
}

func (ec *Etcd3Config) Key() string {

	return ec.key
}
