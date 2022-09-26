package etcd3storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/rs/zerolog"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// Etcd3Storage is used for persisting ACME assets in etcd3.
//
// Locks are created using etcd3 as well, where the automatically added
// TTL on the lock lease will make sure things are eventually cleaned up
// if a lock holder crashes or is otherwise unable to handle the
// Unlock() itself.
//
// There are known shortcomings of "distributed locking", namely that
// the TTL on an acquired lock depends on the server and client being in
// sync. If the client experiences prolonged pauses in execution due to
// GC or something else it can believe it is holding a valid lock when
// in reality the lock has expired on the server (or worse, been locked by
// someone else after expiration). The solution to this is fencing
// tokens, as mentioned below in the comment for Lock(), which
// fortunately can be implemented on top of etcd3, see Lock() for
// current status on the use of fencing tokens.
type Etcd3Storage struct {
	basePath string // We store all data in keys under this base path in etcd3
	client   *clientv3.Client
	locks    map[string]*concurrency.Mutex // We store the etcd3 mutex in this map for use in Unlock()
	logger   zerolog.Logger
	mapMutex *sync.RWMutex // Protects reads and writes to the locks map in this struct
	aesKey   []byte
}

// We wrap certmagic data in this struct so that we can also store a
// "modified" time used in the Stat() call
type storageData struct {
	Value    []byte    `json:"value"`
	Modified time.Time `json:"modified"`
}

// Interface guard, make sure *Etcd3Storage implements the
// certmagic.Storage interface:
var _ certmagic.Storage = (*Etcd3Storage)(nil)

func New(client *clientv3.Client, basePath string, aesKey []byte, logger zerolog.Logger) *Etcd3Storage {
	return &Etcd3Storage{
		aesKey:   aesKey,
		basePath: basePath,
		client:   client,
		locks:    map[string]*concurrency.Mutex{},
		logger:   logger,
		mapMutex: &sync.RWMutex{},
	}
}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// The Load, Delete, List, and Stat methods should return
// fs.ErrNotExist if the key does not exist.

// basePrefix return the given string prefixed with the base path we use in etcd3
func (s *Etcd3Storage) basePrefix(key string) string {
	return s.basePath + "/" + key
}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// Exists returns true if the key exists
// and there was no error checking.
func (s *Etcd3Storage) Exists(ctx context.Context, key string) bool {

	keyPath := s.basePrefix(key)

	s.logger.Debug().Msgf("Exists(): keyPath: %s", keyPath)

	getResp, err := s.client.Get(ctx, keyPath, clientv3.WithCountOnly())
	if err != nil {
		return false
	}

	if getResp.Count > 1 {
		s.logger.Error().Msgf("Exists(): keyPath: '%s', unexpected number of results: %d", keyPath, getResp.Count)
		return false
	}

	s.logger.Debug().Msgf("Exists(): keyPath: '%s', count: %d", keyPath, getResp.Count)
	return (getResp.Count == 1)
}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// Store puts value at key.
func (s *Etcd3Storage) Store(ctx context.Context, key string, value []byte) error {

	keyPath := s.basePrefix(key)

	s.logger.Debug().Msgf("Store(): keyPath: %s", keyPath)

	sd := storageData{
		Value:    value,
		Modified: time.Now(),
	}

	plaintextBytes, err := json.Marshal(sd)
	if err != nil {
		return err
	}

	// Encrypt the data before storing it, using AES256-GCM
	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		s.logger.Debug().Msgf("Store(): keyPath: %s, unable to create cipher", keyPath)
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		s.logger.Debug().Msgf("Store(): keyPath: %s, unable to create GCM", keyPath)
		return err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		s.logger.Debug().Msgf("Store(): keyPath: %s, unable to initialize nonce", keyPath)
		return err
	}

	// By using "nonce" as dst argument we get a secret that is
	// nonce+ciphertext. This way the decryption in Load()
	// automatically has access to the nonce without us needing to
	// store it separately
	encryptedMsg := aesgcm.Seal(nonce, nonce, plaintextBytes, nil)

	_, err = s.client.Put(ctx, keyPath, string(encryptedMsg))
	if err != nil {
		s.logger.Debug().Msgf("Store(): keyPath: %s, etcd3 Put() failed", keyPath)
		return err
	}

	s.logger.Debug().Msgf("Store(): wrote data for keyPath: %s", keyPath)
	return nil
}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// Load retrieves the value at key.
func (s *Etcd3Storage) Load(ctx context.Context, key string) ([]byte, error) {

	keyPath := s.basePrefix(key)

	s.logger.Debug().Msgf("Load(): keyPath: %s", keyPath)

	getResp, err := s.client.Get(ctx, keyPath)
	if err != nil {
		return nil, err
	}

	if getResp.Count == 0 {
		return nil, fs.ErrNotExist
	}

	if getResp.Count != 1 {
		return nil, fmt.Errorf("Load: unexpected key count: %d", getResp.Count)
	}

	plaintextBytes, err := s.decryptStorageData(keyPath, getResp.Kvs[0].Value)
	if err != nil {
		return nil, err
	}

	sd := storageData{}
	err = json.Unmarshal(plaintextBytes, &sd)
	if err != nil {
		s.logger.Debug().Msgf("Load(): keyPath: %s, unable to unmarshal decrypted etcd3 JSON", keyPath)
		return nil, err
	}

	s.logger.Debug().Msgf("Load(): returning data for keyPath: %s", keyPath)
	return sd.Value, nil
}

func (s *Etcd3Storage) decryptStorageData(keyPath string, encryptedMsg []byte) ([]byte, error) {
	// Decrypt data and return the value
	block, err := aes.NewCipher(s.aesKey)
	if err != nil {
		s.logger.Debug().Msgf("decryptStorageData(): keyPath: %s, unable to create cipher", keyPath)
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		s.logger.Debug().Msgf("decryptStorageData(): keyPath: %s, unable to create GCM", keyPath)
		return nil, err
	}

	// The encrypted value in etcd3 is stored as nonce+ciphertext,
	// split them out:
	nonce, ciphertext := encryptedMsg[:aesgcm.NonceSize()], encryptedMsg[aesgcm.NonceSize():]

	plaintextBytes, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		s.logger.Debug().Msgf("decryptStorageData(): keyPath: %s, unable to decrypt etcd3 value", keyPath)
		return nil, err
	}

	return plaintextBytes, nil
}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// Delete deletes key. An error should be
// returned only if the key still exists
// when the method returns.
func (s *Etcd3Storage) Delete(ctx context.Context, key string) error {

	keyPath := s.basePrefix(key)

	s.logger.Debug().Msgf("Delete(): keyPath: %s", keyPath)

	delResp, err := s.client.Delete(ctx, keyPath)
	if err != nil {
		return err
	}

	if delResp.Deleted == 0 {
		return fs.ErrNotExist
	}

	s.logger.Debug().Msgf("Delete(): keyPath: %s deleted", keyPath)
	return nil
}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// List returns all keys that match prefix.
// If recursive is true, non-terminal keys
// will be enumerated (i.e. "directories"
// should be walked); otherwise, only keys
// prefixed exactly by prefix will be listed.
func (s *Etcd3Storage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	prefixPath := s.basePrefix(prefix)

	s.logger.Debug().Msgf("List(): prefixPath: %s", prefixPath)

	listResp, err := s.client.Get(ctx, prefixPath, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, err
	}

	if listResp.Count == 0 {
		return nil, fs.ErrNotExist
	}

	var keys []string

	for _, kv := range listResp.Kvs {
		// We want to store the supplied prefix + key, but exclude
		// our basePath
		key := strings.TrimPrefix(string(kv.Key), s.basePath+"/")
		keys = append(keys, key)
	}

	// Return all keys if recursive is requested
	if recursive {
		s.logger.Debug().Msgf("List(): returning all results for prefixPath: %s", prefixPath)
		return keys, nil
	}

	// If recursive is not requested we need to filter out keys that
	// include "/" in the string following the prefix, as well as
	// combining potential duplicate entries (directory names) into
	// one:
	// prefix/file1
	// prefix/file2
	// prefix/dir1/file1
	// prefix/dir1/file2
	// prefix/dir2/file1
	//
	// Should result in:  "file1, file2, dir1, dir2"

	// The value of the map is never used, so just set it to an
	// empty struct.
	combinedKeys := map[string]struct{}{}
	for _, key := range keys {
		// prefix/dir1/file1 -> dir1/file1
		noPrefixKey := strings.TrimPrefix(key, prefix+"/")
		// dir1/file1 -> dir1
		part := strings.Split(noPrefixKey, "/")[0]

		combinedKeys[part] = struct{}{}
	}

	cKeys := []string{}
	for key := range combinedKeys {
		cKeys = append(cKeys, path.Join(prefix, key))
	}

	s.logger.Debug().Msgf("List(): returning combined 'directory' results for prefixPath: %s", prefixPath)
	return cKeys, nil
}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// Stat returns information about key.
func (s *Etcd3Storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	keyPath := s.basePrefix(key)

	s.logger.Debug().Msgf("Stat(): keyPath: %s", keyPath)

	getResp, err := s.client.Get(ctx, keyPath)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	// If the get found a response the specific key name exists and is a "file"
	if getResp.Count == 1 {
		plaintextBytes, err := s.decryptStorageData(keyPath, getResp.Kvs[0].Value)
		if err != nil {
			return certmagic.KeyInfo{}, err
		}

		sd := storageData{}
		err = json.Unmarshal(plaintextBytes, &sd)
		if err != nil {
			s.logger.Debug().Msgf("Stat(): unable to unmarshal json for keyPath: %s", keyPath)
			return certmagic.KeyInfo{}, err
		}

		modified := sd.Modified
		size := int64(len(sd.Value)) // The etcd3 "Value" is a []byte so len() should be a good tool for size
		s.logger.Debug().Msgf("Stat(): returning 'file' result for keyPath: %s, modified: %s, size: %d", keyPath, modified, size)
		return certmagic.KeyInfo{
			Key:        key,
			Modified:   modified,
			Size:       size, // The etcd3 "Value" is a []byte so len() should be a good tool for size
			IsTerminal: true, // This is a "file", not a "directory"
		}, nil
	}

	// If we did not find a key, try looking for a "directory", that
	// is, do a prefix get for keys named like "key/". Do a "Count
	// only" search since we set size to 0 in the returned data for
	// now anyway
	dirPath := keyPath + "/"

	s.logger.Debug().Msgf("Stat(): attemptingg to treat key as 'directory': %s", dirPath)

	listResp, err := s.client.Get(ctx, dirPath, clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	if listResp.Count == 0 {
		s.logger.Debug().Msgf("Stat(): returning fs.ErrNotExist for keyPath: %s", keyPath)
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}

	s.logger.Debug().Msgf("Stat(): returning 'directory' result for dirPath: %s", dirPath)
	return certmagic.KeyInfo{
		Key:        key,
		Modified:   time.Time{}, // "Modified" is optional and it is unclear what modification time we should make up for this "directory" which does not correspond to an actual key in etcd3
		Size:       0,           // "Size" is optional, and like for "Modified" it is unclear what the size of this made up "directory" should be
		IsTerminal: false,       // There were results found under the prefix "key/" so treat this like a "directory"
	}, nil

}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// Lock acquires the lock for name, blocking until the lock
// can be obtained or an error is returned. Note that, even
// after acquiring a lock, an idempotent operation may have
// already been performed by another process that acquired
// the lock before - so always check to make sure idempotent
// operations still need to be performed after acquiring the
// lock.
//
// The actual implementation of obtaining of a lock must be
// an atomic operation so that multiple Lock calls at the
// same time always results in only one caller receiving the
// lock at any given time.
//
// To prevent deadlocks, all implementations should put a
// reasonable expiration on the lock in case Unlock is unable
// to be called due to some sort of network failure or system
// crash. Additionally, implementations should honor context
// cancellation as much as possible (in case the caller wishes
// to give up and free resources before the lock can be obtained).
//
// Additionally, implementations may wish to support fencing
// tokens (https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html)
// in order to be robust against long process pauses, extremely
// high network latency (or other factors that get in the way of
// renewing lock leases).
func (s *Etcd3Storage) Lock(ctx context.Context, name string) error {
	lockKey := s.lockKeyPath(name)

	s.logger.Debug().Msgf("Lock(): lockKey '%s'", lockKey)

	// If we already hold the lock we just return
	s.mapMutex.RLock()
	_, lockExists := s.locks[lockKey]
	s.mapMutex.RUnlock()
	if lockExists {
		s.logger.Debug().Msgf("Lock(): we already hold the lock for lockKey '%s', doing nothing", lockKey)
		return nil
	}

	// The session defaults to a TTL of 60 seconds, so this should
	// automatically clean up any stale locks from crashed clients
	session, err := concurrency.NewSession(s.client, concurrency.WithContext(ctx))
	if err != nil {
		return err
	}

	mutex := concurrency.NewMutex(session, lockKey)

	// Take the lock, potentially waiting on existing lock holder
	err = mutex.Lock(session.Client().Ctx())
	if err != nil {
		s.logger.Debug().Msgf("Lock(): attempt to aquire lock failed for lockKey '%s': %s", lockKey, err)
		return err
	}

	// TODO(patlu): Use the mutex.Header().Revision (or maybe the
	// etcd3 lock key version is better?) as a fencing
	// token when performing calls like Store() and Delete() to
	// ensure the lock has not expired. At this point there is no
	// way to know what lock is related to a given Store() request,
	// see https://github.com/caddyserver/certmagic/issues/205
	//
	// Some more information on fencing token use in etcd3 is
	// available in https://jepsen.io/analyses/etcd-3.4.3
	s.logger.Debug().Msgf("Lock(): aquired lockKey '%s', lease ID: %x, lock revision: %d", lockKey, session.Lease(), mutex.Header().Revision)

	// Store the lock in our Etcd3Storage struct so we can fetch it
	// in Unlock(). We use the mapMutex to make sure we only write
	// to the s.locks map one at a time.
	s.mapMutex.Lock()
	s.locks[lockKey] = mutex
	s.mapMutex.Unlock()

	s.logger.Debug().Msgf("Lock(): done for '%s'", lockKey)
	return nil
}

// From https://github.com/caddyserver/certmagic/blob/master/storage.go:
//
// Unlock releases the lock for name. This method must ONLY be
// called after a successful call to Lock, and only after the
// critical section is finished, even if it errored or timed
// out. Unlock cleans up any resources allocated during Lock.
func (s *Etcd3Storage) Unlock(ctx context.Context, name string) error {
	lockKey := s.lockKeyPath(name)

	s.logger.Debug().Msgf("Unlock(): lockKey '%s'", lockKey)

	// Make sure the s.locks map is not modified while we read from
	// it
	s.mapMutex.RLock()
	mutex := s.locks[lockKey]
	s.mapMutex.RUnlock()

	err := mutex.Unlock(ctx)
	if err != nil {
		s.logger.Debug().Msgf("Unlock(): failed releasing lockKey '%s', ", lockKey)
		// TODO(patlu): Not sure if we should clean up map here
		// or leave it. The documentation comment above states
		// "Unlock cleans up any resources allocated during
		// Lock" without regard for success or error, so for
		// now clean it up, but it also means the caller can not
		// retry Unlock() requests that failed.
		s.deleteLockFromMap(lockKey)
		return err
	}
	s.logger.Debug().Msgf("Unlock(): released lockKey '%s'", lockKey)

	// Cleanup the map entry
	s.deleteLockFromMap(lockKey)

	s.logger.Debug().Msgf("Unlock(): done for '%s'", lockKey)
	return nil
}

func (s *Etcd3Storage) deleteLockFromMap(lockKey string) {
	s.mapMutex.Lock()
	delete(s.locks, lockKey)
	s.mapMutex.Unlock()
}

func (s *Etcd3Storage) String() string {
	return "Etcd3Storage:" + s.basePath
}

func (s *Etcd3Storage) lockKeyPath(name string) string {
	return path.Join(s.lockPath(), certmagic.StorageKeys.Safe(name)+"-lock")
}

func (s *Etcd3Storage) lockPath() string {
	return path.Join(s.basePath, "locks")
}
