package etcd3

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/SUNET/knubbis-fleetlock/fleetlock"
	"github.com/rs/zerolog"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/exp/slices"
)

type semaphore struct {
	TotalSlots int                `json:"total_slots"`
	Holders    []fleetlock.Holder `json:"holders"`
}

// The type implementing the FleetLock interface using etcd3 as a
// backend
type Etcd3Backend struct {
	client     *clientv3.Client
	key        string
	totalSlots int
	group      string
	staleAge   fleetlock.Duration
}

func NewLocker(client *clientv3.Client, group string, totalSlots int, staleAge time.Duration) (*Etcd3Backend, error) {

	fld := fleetlock.Duration{
		Duration: staleAge,
	}

	if !fleetlock.ValidGroup.MatchString(group) {
		return nil, fmt.Errorf("group name '%s' is not valid", group)
	}
	return &Etcd3Backend{
		client:     client,
		group:      group,
		key:        fmt.Sprintf("se.sunet.knubbis/fleetlock/groups/%s/v1/semaphore", group),
		totalSlots: totalSlots,
		staleAge:   fld,
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
