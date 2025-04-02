package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // #nosec G108 -- pprofServer is only bound to 127.0.0.1:6060
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/SUNET/knubbis-fleetlock/backends/etcd3"
	"github.com/SUNET/knubbis-fleetlock/certmagic/etcd3storage"
	"github.com/SUNET/knubbis-fleetlock/fleetlock"
	"github.com/SUNET/knubbis-fleetlock/hashing"
	"github.com/SUNET/knubbis-fleetlock/server/docs"
	"github.com/caddyserver/certmagic"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	"github.com/libdns/acmedns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	httpSwagger "github.com/swaggo/http-swagger"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/time/rate"
)

// Automatically call swag when running "go generate"
//go:generate swag fmt -g server.go
//go:generate swag init --parseDependency -g server.go

// annotations for generating swagger docs:
//
//	@title						Swagger Knubbis FleetLock API
//	@version					0.0.1
//	@description				This API is used for managing FleetLock groups.
//	@contact.name				Patrik Lundin
//	@contact.url				https://www.sunet.se
//	@contact.email				patlu@sunet.se
//	@license.name				BSD 2-Clause
//	@license.url				https://github.com/SUNET/knubbis-fleetlock/blob/main/LICENSE
//	@host						localhost:8443
//	@BasePath					/api/v1
//	@securityDefinitions.basic	BasicAuth
//	@Security					BasicAuth

// version set at build time with -ldflags="-X github.com/SUNET/knubbis-fleetlock/server.version=v0.0.1"
var version = "unspecified"

// Some constant values
const (
	groupDoesNotExistMsg  string = "group does not exist in config"
	failedGettingLockMsg  string = "failed getting lock"
	fleetLockProtocolName string = "fleet-lock-protocol"
	contentTypeString     string = "application/json; charset=utf-8"
)

// configCache struct is used for storing config settings stored in a
// backend and can be dynamically updated at runtime. The mutex is used
// to protect writes and reads to the different maps. The expectation is
// that struct methods take suitable locks when doing operations.
type configCache struct {
	flMap          map[string]fleetlock.FleetLocker
	flattenedPerms map[string]hashing.HashedPassword
	mutex          *sync.RWMutex
}

func newConfigCache(ctx context.Context, flConfiger fleetlock.FleetLockConfiger) (*configCache, error) {
	flc, err := flConfiger.GetLockers(ctx)
	if err != nil {
		return nil, fmt.Errorf("newConfigCache: unable to get lockers: %w", err)
	}

	flp, err := getFlattenedPerms(ctx, flConfiger)
	if err != nil {
		return nil, fmt.Errorf("newConfigCache: unable to get flattened perms: %w", err)
	}

	return &configCache{
		flMap:          flc,
		flattenedPerms: flp,
		mutex:          &sync.RWMutex{},
	}, nil
}

// runs in a go routine in the background and updates the configCache struct
// if something changes
func configCacheUpdater(cc *configCache, flConfiger fleetlock.FleetLockConfiger, logger zerolog.Logger, loginCache *lru.Cache[string, bool]) {
	chanInterface, err := flConfiger.GetNotifierChan(context.Background())
	if err != nil {
		logger.Err(err).Msg("unable to get notifier, not starting cache updater")
		return
	}

	for {
		// Since GetNotifier returns an interface we need to find out
		// what we are actually working with.
		switch ch := chanInterface.(type) {
		case clientv3.WatchChan:
			res := <-ch
			logger.Info().Msgf("notified by '%s' event on etcd3 watcher, updating config cache", res.Events[0].Type)
			err := updateConfigCache(cc, logger, flConfiger, loginCache)
			if err != nil {
				logger.Err(err).Msg("unable to update config cache")
			}
		default:
			logger.Error().Msg("unsupported notifier type, not starting cache updated")
			return
		}
	}
}

func updateConfigCache(cc *configCache, logger zerolog.Logger, flConfiger fleetlock.FleetLockConfiger, loginCache *lru.Cache[string, bool]) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	flc, err := flConfiger.GetLockers(ctx)
	if err != nil {
		return fmt.Errorf("unable to get lockers: %w", err)
	}

	flp, err := getFlattenedPerms(ctx, flConfiger)
	if err != nil {
		return fmt.Errorf("unable to get flattened perms: %w", err)
	}

	cc.setLockerMap(flc)
	cc.setPerms(flp)

	// Purge login cache in case password hashes has been updated in
	// the config (should not collide since hashes will have
	// changed due to a new randomized salt even if setting the same
	// password for a key), but makes sense to be careful
	lenBefore := loginCache.Len()
	loginCache.Purge()
	lenAfter := loginCache.Len()
	logger.Info().Msgf("purged login cache due to config reload, keys before: %d, keys after: %d", lenBefore, lenAfter)

	return nil
}

func (cc *configCache) setLockerMap(flm map[string]fleetlock.FleetLocker) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.flMap = flm
}

func (cc *configCache) setPerms(flattenedPerms map[string]hashing.HashedPassword) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.flattenedPerms = flattenedPerms
}

func (cc *configCache) getPerms() map[string]hashing.HashedPassword {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	// Create copy while holding the lock
	mCopy := map[string]hashing.HashedPassword{}
	for k, v := range cc.flattenedPerms {
		mCopy[k] = v
	}

	return mCopy
}

func (cc *configCache) getGroupLocker(group string) (fleetlock.FleetLocker, bool) {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	groupLocker, groupExists := cc.flMap[group]

	return groupLocker, groupExists
}

func (cc *configCache) getMap() map[string]fleetlock.FleetLocker {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	// Create a copy of the map while we hold the read lock, this way
	// the returned map is consistent if something modified the map
	// stored in lrs while the caller of this function was still
	// using it
	mCopy := map[string]fleetlock.FleetLocker{}
	for k, v := range cc.flMap {
		mCopy[k] = v
	}

	return mCopy
}

// https://pkg.go.dev/github.com/burntSushi/toml#readme-examples
// Used to be able to automatically parse duration strings like "10s" in
// the TOML config:
type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

// serverConfig is the main config struct filled in by parsing a TOML
// file
type serverConfig struct {
	Server     serverSettings
	Ratelimit  ratelimitSettings
	Pprof      pprofSettings
	Prometheus prometheusSettings
	Etcd3      etcd3config
	CertMagic  certMagicConfig
	AcmeDNS    acmeDNSConfig
	Monitoring monitoringConfig
	API        apiConfig
}

type serverSettings struct {
	Listen        string
	ExposedPort   int `toml:"exposed_port"`
	Backend       string
	ReadTimeout   duration `toml:"read_timeout"`
	WriteTimeout  duration `toml:"write_timeout"`
	ShutdownDelay duration `toml:"shutdown_delay"`
}

type ratelimitSettings struct {
	Rate  rate.Limit
	Burst int
}

type pprofSettings struct {
	ReadTimeout  duration `toml:"read_timeout"`
	WriteTimeout duration `toml:"write_timeout"`
}

type prometheusSettings struct {
	Listen       string
	ReadTimeout  duration `toml:"read_timeout"`
	WriteTimeout duration `toml:"write_timeout"`
}

type monitoringConfig struct {
	Username string
	Password string
}

type apiConfig struct {
	Username string
	Password string
}

type etcd3config struct {
	Endpoints          []string
	CertFile           string `toml:"cert_file"`
	KeyFile            string `toml:"key_file"`
	Username           string
	Password           string
	InsecureSkipVerify bool   `toml:"insecure_skip_verify"`
	RootCAPath         string `toml:"root_ca_path"`
}

type certMagicConfig struct {
	Salt            string
	ArgonTime       uint32 `toml:"argon_time"`
	ArgonMemory     uint32 `toml:"argon_memory"`
	ArgonThreads    uint8  `toml:"argon_threads"`
	Password        string
	Etcd3Path       string `toml:"etcd3_path"`
	LetsEncryptProd bool   `toml:"letsencrypt_prod"`
	Email           string
	Domains         []string
}

type acmeDNSConfig map[string]acmeDNSDomainSettings

type acmeDNSDomainSettings struct {
	Username   string
	Password   string
	Subdomain  string
	FullDomain string `toml:"full_domain"`
	ServerURL  string `toml:"server_url"`
}

// apiSendError is used to return error data to a client interacting
// with the group management API
func apiSendError(w http.ResponseWriter, message string, statusCode int) error {
	fle := apiError{
		StatusCode: statusCode,
		Message:    message,
	}

	b, err := json.Marshal(fle)
	if err != nil {
		return fmt.Errorf("apiSendError: failed creating API error response: %w", err)
	}
	err = writeNewlineJSON(w, b, statusCode)
	if err != nil {
		return fmt.Errorf("apiSendError: %w", err)
	}

	return nil
}

func fleetLockSendError(kind, value string, statusCode int, w http.ResponseWriter) error {
	fle := fleetlock.FleetLockError{
		Kind:  kind,
		Value: value,
	}

	b, err := json.Marshal(fle)
	if err != nil {
		return fmt.Errorf("fleetLockSendError: failed creating FleetLock error response: %w", err)
	}
	err = writeNewlineJSON(w, b, statusCode)
	if err != nil {
		return fmt.Errorf("fleetLockSendError: %w", err)
	}

	return nil
}

func handlePreRebootLockError(logger *zerolog.Logger, err error, w http.ResponseWriter) {
	logger.Err(err).Msg(failedGettingLockMsg)

	// Set default error content and status
	msg := failedGettingLockMsg
	errStatus := http.StatusInternalServerError

	// If specific type of error we trust that the
	// string returned can be sent to the client
	// as-is
	if rlerr, ok := err.(*fleetlock.RecursiveLockError); ok {
		msg = rlerr.Error()
		if rlerr.AllSlotsTaken {
			errStatus = http.StatusConflict
		}
	}

	err = fleetLockSendError("failed_lock", msg, errStatus, w)
	if err != nil {
		logger.Err(err).Msg("failed sending RecursiveLock error")
		return
	}
}

// handler called when clients requests to take a lock
func preRebootFunc(cc *configCache, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("fleetlock_op", "recursivelock")
		})

		// Fetch FleetLock data validated in middleware
		fld := r.Context().Value(keyFleetLockBody).(fleetlock.FleetLockBody)

		groupLocker, groupExists := cc.getGroupLocker(fld.ClientParams.Group)
		if !groupExists {
			logger.Error().Msg(groupDoesNotExistMsg)

			err := fleetLockSendError("failed_lock", groupDoesNotExistMsg, http.StatusInternalServerError, w)
			if err != nil {
				logger.Err(err).Msgf("failed sending RecursiveLock error: %s", err)
			}
			return
		}

		lockerCtx, lockerCancel := context.WithTimeout(r.Context(), timeout)
		defer lockerCancel()

		logger.Info().Msg("aquiring lock")

		err := groupLocker.RecursiveLock(lockerCtx, fld.ClientParams.ID)
		if err != nil {
			handlePreRebootLockError(logger, err, w)
			return
		}

		// At this point everything is OK. Calling WriteHeader is not strictly
		// needed but it makes sure the zerolog JSON contains
		// "status":200 instead of "status":0
		w.WriteHeader(http.StatusOK)
	}
}

// handler called when clients request to release a lock
func steadyStateFunc(cc *configCache, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("fleetlock_op", "unlockifheld")
		})

		// Fetch FleetLock data validated in middleware
		fld := r.Context().Value(keyFleetLockBody).(fleetlock.FleetLockBody)

		groupLocker, groupExists := cc.getGroupLocker(fld.ClientParams.Group)
		if !groupExists {
			logger.Error().Msg(groupDoesNotExistMsg)

			err := fleetLockSendError("failed_lock", groupDoesNotExistMsg, http.StatusInternalServerError, w)
			if err != nil {
				logger.Err(err).Msg("failed sending nonexistant group error")
			}
			return
		}

		lockerCtx, lockerCancel := context.WithTimeout(r.Context(), timeout)
		defer lockerCancel()

		logger.Info().Msg("releasing lock")

		err := groupLocker.UnlockIfHeld(lockerCtx, fld.ClientParams.ID)
		if err != nil {
			logger.Err(err).
				Msg(failedGettingLockMsg)

			err = fleetLockSendError("failed_unlock", http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, w)
			if err != nil {
				logger.Err(err).Msg("failed sending UnlockIfHeld error")
			}
			return
		}

		// At this point everything is OK. Calling WriteHeader is not strictly
		// needed but it makes sure the zerolog JSON contains
		// "status":200 instead of "status":0
		w.WriteHeader(http.StatusOK)
	}
}

type lockStatusData struct {
	Groups map[string]fleetlock.LockStatus `json:"groups"`
}

func getLockStatus(ctx context.Context, timeout time.Duration, cc *configCache, logger *zerolog.Logger) (lockStatusData, error) {
	lsd := lockStatusData{
		Groups: map[string]fleetlock.LockStatus{},
	}

	lockerCtx, lockerCancel := context.WithTimeout(ctx, timeout)
	defer lockerCancel()

	for group, locker := range cc.getMap() {
		ls, err := locker.LockStatus(lockerCtx)
		if err != nil {
			logger.Err(err).Msgf("unable to get LockStatus for group '%s'", group)
			return lockStatusData{}, err
		}
		lsd.Groups[group] = ls
	}

	return lsd, nil
}

// handler called when clients request lock status
func lockStatusFunc(cc *configCache, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		lsd, err := getLockStatus(r.Context(), timeout, cc, logger)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		b, err := json.Marshal(lsd)
		if err != nil {
			logger.Err(err).Msg("unable to marshal locksStatusData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = writeNewlineJSON(w, b, http.StatusOK)
		if err != nil {
			logger.Err(err).Msg("failed writing lockStatusData")
			return
		}
	}
}

type staleLocksData struct {
	StaleLocks bool                `json:"stale_locks"`
	Groups     map[string][]string `json:"groups"`
}

type apiError struct {
	StatusCode int    `json:"status_code" example:"400"`
	Message    string `json:"message" example:"status bad request"`
}

// addGroupModel is the expected structure of JSON sent to the addGroup
// API hander
type addGroupModel struct {
	fleetlock.GroupSettings
	Name string `json:"name" example:"workers"`
}

// Annotations for generating swagger docs:
//
//	@Summary		Get groups
//	@Description	Get the current available groups
//	@Tags			groups
//	@Success		200
//	@Failure		400	{object}	apiError
//	@Router			/groups [get]
func getGroups(ctx context.Context, timeout time.Duration, cc *configCache, logger *zerolog.Logger) (lockStatusData, error) {
	lsd, err := getLockStatus(ctx, timeout, cc, logger)
	if err != nil {
		return lockStatusData{}, err
	}
	return lsd, nil
}

// Annotations for generating swagger docs:
//
//	@Summary		Add a group
//	@Description	Add a new FleetLock group
//	@Tags			groups
//	@Accept			json
//	@Param			group	body	addGroupModel	true	"Add group"
//	@Success		200
//	@Failure		400	{object}	apiError
//	@Router			/groups [post]
func addGroup(ctx context.Context, flConfiger fleetlock.FleetLockConfiger, agd addGroupModel) error {
	err := flConfiger.AddGroup(ctx, agd.Name, agd.TotalSlots, agd.StaleAge, agd.Permissions)
	if err != nil {
		return fmt.Errorf("addGroup: %w", err)
	}

	return nil
}

// Annotations for generating swagger docs:
//
//	@Summary		Delete a group
//	@Description	Delete a FleetLock group
//	@Tags			groups
//	@Accept			json
//	@Param			group	path	string	true	"Group name"
//	@Success		200
//	@Failure		404	{object}	apiError
//	@Router			/groups/{group} [delete]
func delGroup(ctx context.Context, flConfiger fleetlock.FleetLockConfiger, group string) error {
	err := flConfiger.DelGroup(ctx, group)
	if err != nil {
		return fmt.Errorf("delGroup: %w", err)
	}

	return nil
}

func apiHandleGet(logger *zerolog.Logger, cc *configCache, timeout time.Duration, w http.ResponseWriter, r *http.Request) bool {
	lsd, err := getGroups(r.Context(), timeout, cc, logger)
	if err != nil {
		message := "unable to get lock status"
		logger.Err(err).Msg(message)
		err := apiSendError(w, message, http.StatusBadRequest)
		if err != nil {
			logger.Err(err).Msgf("unable to send API GET error")
		}
		return false
	}

	b, err := json.Marshal(lsd)
	if err != nil {
		logger.Err(err).Msg("unable to marshal locksStatusData in API GET")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return false
	}

	err = writeNewlineJSON(w, b, http.StatusOK)
	if err != nil {
		logger.Err(err).Msg("failed writing lockStatusData in API GET")
		return false
	}

	return true
}

func apiHandlePost(logger *zerolog.Logger, timeout time.Duration, flConfiger fleetlock.FleetLockConfiger, w http.ResponseWriter, r *http.Request) bool {
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	agd := addGroupModel{}
	err := json.NewDecoder(r.Body).Decode(&agd)
	if err != nil {
		if err == io.EOF {
			logger.Error().Msg("API body is empty")
			err = apiSendError(w, "API body is empty", http.StatusBadRequest)
			if err != nil {
				logger.Err(err).Msgf("unable to send API error")
			}
		} else {
			logger.Err(err).Msg("failed decoding API body")
			err = apiSendError(w, "failed decoding API body", http.StatusBadRequest)
			if err != nil {
				logger.Err(err).Msgf("unable to send API error")
			}
		}
		return false
	}

	err = addGroup(ctx, flConfiger, agd)
	if err != nil {
		message := fmt.Sprintf("unable to add group '%s'", agd.Name)
		logger.Err(err).Msg(message)
		err := apiSendError(w, message, http.StatusBadRequest)
		if err != nil {
			logger.Err(err).Msgf("unable to send group add error")
		}

		return false
	}
	return true
}

func apiHandleDelete(logger *zerolog.Logger, timeout time.Duration, flConfiger fleetlock.FleetLockConfiger, w http.ResponseWriter, r *http.Request) bool {
	params := httprouter.ParamsFromContext(r.Context())

	group := params.ByName("group")
	if !fleetlock.ValidGroup.MatchString(group) {
		logger.Error().Msg("invalid group name")
		http.Error(w, "invalid group name", http.StatusBadRequest)
		return false
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	err := delGroup(ctx, flConfiger, group)
	if err != nil {
		message := fmt.Sprintf("unable to delete group '%s'", group)
		logger.Err(err).Msg(message)
		err := apiSendError(w, message, http.StatusInternalServerError)
		if err != nil {
			logger.Err(err).Msg("unable to send group add error response")
		}
		return false
	}

	return true
}

// apiFunc is the gateway to calling other API functions, this way we do
// not need to create one middleware chain per request type.
func apiFunc(cc *configCache, timeout time.Duration, flConfiger fleetlock.FleetLockConfiger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		switch r.Method {
		case "GET":
			if !apiHandleGet(logger, cc, timeout, w, r) {
				return
			}
		case "POST":
			if !apiHandlePost(logger, timeout, flConfiger, w, r) {
				return
			}
		case "DELETE":
			if !apiHandleDelete(logger, timeout, flConfiger, w, r) {
				return
			}
		default:
			message := fmt.Sprintf("unsupported HTTP method: '%s'", r.Method)
			logger.Error().Msg(message)
			err := apiSendError(w, message, http.StatusInternalServerError)
			if err != nil {
				logger.Err(err).Msg("unable to send group del error response")
			}
			return
		}

		// At this point everything is OK. Calling WriteHeader is not strictly
		// needed but it makes sure the zerolog JSON contains
		// "status":200 instead of "status":0
		w.WriteHeader(http.StatusOK)
	}
}

func getStaleLocksData(logger *zerolog.Logger, timeout time.Duration, cc *configCache, w http.ResponseWriter, r *http.Request) (staleLocksData, error) {
	sld := staleLocksData{
		Groups: map[string][]string{},
	}

	lockerCtx, lockerCancel := context.WithTimeout(r.Context(), timeout)
	defer lockerCancel()

	for group, locker := range cc.getMap() {
		ls, err := locker.LockStatus(lockerCtx)
		if err != nil {
			logger.Err(err).Msgf("unable to get LockStatus for group '%s'", group)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return staleLocksData{}, err
		}
		for _, holder := range ls.Holders {
			if time.Since(holder.LockTime) > holder.StaleAge.Duration {
				sld.StaleLocks = true
				sld.Groups[group] = append(sld.Groups[group], holder.ID)
			}
		}
	}

	return sld, nil
}

func staleLocksFunc(cc *configCache, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)

		sld, err := getStaleLocksData(logger, timeout, cc, w, r)
		if err != nil {
			return
		}

		b, err := json.Marshal(sld)
		if err != nil {
			logger.Err(err).Msg("unable to marshal staleLocksData")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = writeNewlineJSON(w, b, http.StatusOK)
		if err != nil {
			logger.Err(err).Msg("failed writing staleLocksData")
			return
		}
	}
}

func methodNotAllowedFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func notFoundFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}
}

func writeNewlineJSON(w http.ResponseWriter, b []byte, statusCode int) error {
	w.Header().Set("content-type", contentTypeString)
	w.WriteHeader(statusCode)
	// Include newline since this JSON can be returned to curl
	// requests and similar where the prompt gets messed up without
	// it.
	_, err := fmt.Fprintf(w, "%s\n", b)
	if err != nil {
		return err
	}

	return nil
}

func allowedByLimiter(logger *zerolog.Logger, rl *rateLimiter, addrPort netip.AddrPort, conf serverConfig, w http.ResponseWriter) bool {
	// Because both nonexisting and existing IP
	// addresses requires writes to contents of the
	// map (either creation of
	// a new IP key or update of lastSeen on an
	// existing one) we keep a write lock over
	// the whole operation
	rl.mutex.Lock()
	ipl, exists := rl.ipLimiterMap[addrPort.Addr()]
	if exists {
		// Just update timestamp
		ipl.lastSeen = time.Now()
	} else {
		// Create new limiter
		ipl = &ipLimiter{
			lastSeen: time.Now(),
			limiter:  rate.NewLimiter(conf.Ratelimit.Rate, conf.Ratelimit.Burst),
		}
		rl.ipLimiterMap[addrPort.Addr()] = ipl
	}
	if !ipl.limiter.Allow() {
		rl.mutex.Unlock()

		err := fleetLockSendError("request_ratelimit", "you hit a ratelimit, try again later", http.StatusTooManyRequests, w)
		if err != nil {
			logger.Err(err).Msg("failed sending ratelimit FleetLock error to client")
			return false
		}
		return false
	}
	// Important to release the lock before calling
	// followup middleware
	rl.mutex.Unlock()
	return true
}

func ratelimitMiddleware(conf serverConfig, rl *rateLimiter) alice.Constructor {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
			if err != nil {
				logger.Err(err).Msg("ratelimitMiddleware: unable to parse RemoteAddr")

				err := fleetLockSendError("server_error", "unable to parse remote address", http.StatusInternalServerError, w)
				if err != nil {
					logger.Err(err).Msg("failed sending RemoteAddr FleetLock error to client")
					return
				}
				return
			}

			if !allowedByLimiter(logger, rl, addrPort, conf, w) {
				return
			}

			h.ServeHTTP(w, r)
		})
	}
}

// ratelimitCleaner runs in a goroutine and cleans up old entries when
// they are too old
func ratelimitCleaner(logger zerolog.Logger, rl *rateLimiter) {
	for {
		time.Sleep(time.Second * 60)
		rl.mutex.Lock()
		for ipKey, ipLimiter := range rl.ipLimiterMap {
			if time.Since(ipLimiter.lastSeen) > time.Second*10 {
				logger.Debug().Msgf("cleanup ip %s", ipKey.String())
				delete(rl.ipLimiterMap, ipKey)
			}
		}
		rl.mutex.Unlock()
	}
}

func createLoginCacheKey(key string, expectedPasswordHash hashing.HashedPassword, password string) string {
	var loginCacheKey []byte
	loginCacheKey = append(loginCacheKey, key...)
	loginCacheKey = append(loginCacheKey, expectedPasswordHash.Hash...)
	loginCacheKey = append(loginCacheKey, expectedPasswordHash.Salt...)
	loginCacheKey = append(loginCacheKey, password...)
	hashedCacheKeyBytes := sha256.Sum256(loginCacheKey)
	hashedCacheKey := hex.EncodeToString(hashedCacheKeyBytes[:])

	return hashedCacheKey
}

func getCachedKeys(logger *zerolog.Logger, loginCache *lru.Cache[string, bool], keys []string, flattenedPerms map[string]hashing.HashedPassword, password string) (bool, []string) {
	validLogin := false

	foundKeys := []string{}

	for _, key := range keys {
		expectedPasswordHash, ok := flattenedPerms[key]

		if !ok {
			// The key does not exist, try with the next one
			continue
		}

		foundKeys = append(foundKeys, key)

		hashedCacheKey := createLoginCacheKey(key, expectedPasswordHash, password)

		if _, ok = loginCache.Get(hashedCacheKey); ok {
			logger.Info().Msgf("login cache hit for key '%s'", key)
			validLogin = true
		} else {
			logger.Info().Msgf("login cache miss for key '%s'", key)
		}
	}

	return validLogin, foundKeys
}

func keyHashComparision(logger *zerolog.Logger, foundKeys []string, flattenedPerms map[string]hashing.HashedPassword, loginCache *lru.Cache[string, bool], password string) bool {
	validLogin := false
	for _, key := range foundKeys {
		expectedPasswordHash, ok := flattenedPerms[key]

		if !ok {
			// The key does not exist, try with the next one
			logger.Info().Msgf("should have found key '%s' since it was found previously, please investigate", key)
			continue
		}

		logger.Info().Msgf("calculating hash for '%s'", key)

		argonSettings := hashing.NewArgonSettings(
			expectedPasswordHash.ArgonTime,
			expectedPasswordHash.ArgonMemory,
			expectedPasswordHash.ArgonThreads,
			expectedPasswordHash.ArgonHashSize,
		)

		// The API passwords in the config are
		// stored argon2 hashed in the database.
		// Now hash the client supplied password
		// so we can compare strings of equal
		// length with
		// subtle.ConstantTimeCompare()
		hashedPassword := hashing.GetHashedPassword(
			password,
			expectedPasswordHash.Salt,
			argonSettings,
		)

		// Use subtle.ConstantTimeCompare() in an attempt to
		// not leak password contents via timing attack
		passwordMatch := (subtle.ConstantTimeCompare(hashedPassword.Hash, expectedPasswordHash.Hash) == 1)
		if passwordMatch {
			validLogin = true
			hashedCacheKey := createLoginCacheKey(key, expectedPasswordHash, password)
			evicted := loginCache.Add(hashedCacheKey, true)
			if evicted {
				logger.Info().Msg("adding key to loginCache resulted in eviction")
			}
			break
		}

	}

	return validLogin
}

func flBasicAuthMiddleware(cc *configCache, loginCache *lru.Cache[string, bool], argon2Mutex *sync.Mutex) alice.Constructor {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			realm := "fleetlock"

			// Since we pair passwords with FleetLock
			// group + ID we have no need for the username,
			// so just ignore it for now.
			_, password, ok := r.BasicAuth()
			if !ok {
				logger.Info().Msg("invalid or missing Authorization header")
				sendUnauthorizedResponse(logger, w, realm, true)
				return
			}

			// Fetch FleetLock data validated in middleware
			fld := r.Context().Value(keyFleetLockBody).(fleetlock.FleetLockBody)

			// Given FleetLock data attempting to lock or unlock the group "workers"
			// with id "server01" we compare the supplied password
			// aginst both a wildcard "workers-*" key as well as a
			// group+id specific "workers-server01" key
			groupWildcardKey := fld.ClientParams.Group + "-*"
			groupIDKey := fld.ClientParams.Group + "-" + fld.ClientParams.ID

			keys := []string{groupWildcardKey, groupIDKey}

			flattenedPerms := cc.getPerms()

			// Check if we have a cache hit for any of the keys
			// first
			validLogin, foundKeys := getCachedKeys(logger, loginCache, keys, flattenedPerms, password)

			// If successful login was not found in cache, but we
			// did find a matching key, do hash comparision:
			if !validLogin && len(foundKeys) > 0 {
				// Protect concurrent access to memory intensive argon2
				// operation to be less susceptible to OOM
				// conditions if many requests are coming in at
				// the same time.
				argon2Mutex.Lock()
				// Do a second check in the cache in case
				// another request has updated it while
				// we were waiting on the lock.
				validLogin, foundKeys = getCachedKeys(logger, loginCache, keys, flattenedPerms, password)
				if !validLogin && len(foundKeys) > 0 {
					validLogin = keyHashComparision(logger, foundKeys, flattenedPerms, loginCache, password)
				}
				argon2Mutex.Unlock()
			}

			if validLogin {
				logger.Info().Msg("successful authentication")
				h.ServeHTTP(w, r)
				return
			}

			logger.Info().Msg("invalid credentials in Authorization header")
			sendUnauthorizedResponse(logger, w, realm, true)
		})
	}
}

func monitorBasicAuthMiddleware(username, password string) alice.Constructor {
	// Calculate hashes for strings in config at startup
	expectedUsernameHash := sha256.Sum256([]byte(username))
	expectedPasswordHash := sha256.Sum256([]byte(password))
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			realm := "monitoring"

			username, password, ok := r.BasicAuth()
			if !ok {
				logger.Info().Msg("invalid or missing Authorization header")
				sendUnauthorizedResponse(logger, w, realm, false)
				return
			}

			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				logger.Info().Msg("successful authentication")
				h.ServeHTTP(w, r)
				return
			}

			logger.Info().Msg("invalid credentials in Authorization header")
			sendUnauthorizedResponse(logger, w, realm, false)
		})
	}
}

func sendUnauthorizedResponse(logger *zerolog.Logger, w http.ResponseWriter, realm string, flEndpoint bool) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="utf-8"`, realm))

	// Return FleetLock formatted JSON if this authentication error
	// was made on a FleetLock endpoint
	if flEndpoint {
		err := fleetLockSendError("unauthorized_request", "you need to authenticate to acquire or release a lock", http.StatusUnauthorized, w)
		if err != nil {
			logger.Err(err).Msg("failed sending FleetLock error to client")
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// key is used to get unique keys for use in the net/http context that
// is passed between middleware handlers
type key int

const (
	keyFleetLockBody key = iota
)

type rateLimiter struct {
	mutex        sync.Mutex
	ipLimiterMap map[netip.Addr]*ipLimiter
}

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func validFleetLockHeader(logger *zerolog.Logger, w http.ResponseWriter, r *http.Request) bool {
	// Verify that a valid FleetLock header is present
	// https://coreos.github.io/zincati/development/fleetlock/protocol/#headers
	// Returns true if all is good, otherwise false
	if r.Header.Get(fleetLockProtocolName) != "true" {
		logger.Warn().
			Msgf("missing '%s' header", fleetLockProtocolName)

		err := fleetLockSendError("invalid_fleetlock_header", fmt.Sprintf("'%s' header must be set to 'true'", fleetLockProtocolName), http.StatusBadRequest, w)
		if err != nil {
			logger.Err(err).Msg("failed sending FleetLock error to client")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		return false
	}

	return true
}

func decodeFleetLockBody(logger *zerolog.Logger, w http.ResponseWriter, r *http.Request) (fleetlock.FleetLockBody, error) {
	fld := fleetlock.FleetLockBody{}

	err := json.NewDecoder(r.Body).Decode(&fld)
	if err != nil {
		if err == io.EOF {
			logger.Error().Msg("FleetLock body is empty")
			err := fleetLockSendError("empty_fleetlock_body", "body is empty", http.StatusBadRequest, w)
			if err != nil {
				logger.Err(err).Msg("failed sending empty body error to client")
				return fleetlock.FleetLockBody{}, err
			}
		} else {
			logger.Err(err).Msg("failed decoding FleetLock body")
			err := fleetLockSendError("bad_fleetlock_body", "body must contain valid data", http.StatusBadRequest, w)
			if err != nil {
				logger.Err(err).Msg("failed sending invalid body error to client")
				return fleetlock.FleetLockBody{}, err
			}
		}
		return fleetlock.FleetLockBody{}, err
	}

	return fld, nil
}

func validFleetLockGroupName(logger *zerolog.Logger, fld fleetlock.FleetLockBody, w http.ResponseWriter) bool {
	// The spec does not specify a maximum length
	// for the group name but it seems reasonable to
	// not accept an unlimited length. Below we set
	// a 253 characters limit for ID based on the
	// maximume length of a hostname, for now just
	// reuse this here, since it should fit most
	// group names you would come up with.
	if len(fld.ClientParams.Group) > 253 {
		logger.Error().Msg("FleetLock group name too long")

		err := fleetLockSendError("invalid_group", "group name is too long", http.StatusBadRequest, w)
		if err != nil {
			logger.Err(err).Msg("failed sending FleetLock group name too long error to client")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
	}

	if !fleetlock.ValidGroup.MatchString(fld.ClientParams.Group) {
		logger.Error().Msg("group is not a valid name")

		err := fleetLockSendError("invalid_group", "group name is not valid", http.StatusBadRequest, w)
		if err != nil {
			logger.Err(err).Msg("failed sending FleetLock invalid group name error to client")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		return false
	}
	return true
}

func validFleetLockID(logger *zerolog.Logger, fld fleetlock.FleetLockBody, w http.ResponseWriter) bool {
	// The spec does not specify a maximum length
	// for the ID but it seems reasonable to
	// not accept an unlimited length. The examples
	// given for ID at
	// https://coreos.github.io/zincati/development/fleetlock/protocol/#body
	// are "node name or UUID". A UUID is 36
	// characters long in the "canonical textual
	// representation":
	// https://en.wikipedia.org/wiki/Universally_unique_identifier
	// ... while a maximum hostname is 253
	// characters:
	// https://en.wikipedia.org/wiki/Hostname
	// so set the limit at 253 characters for now
	if len(fld.ClientParams.ID) > 253 {
		logger.Error().Msg("FleetLock ID too long")

		err := fleetLockSendError("invalid_id", "ID is too long", http.StatusBadRequest, w)
		if err != nil {
			logger.Err(err).Msg("failed sending FleetLock ID too long error to client")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		return false
	}

	// Even tough the spec mentions nothing
	// regarding allowed characters in IDs, since
	// the examples are UUID and node name we can
	// reuse the group name filter which is general
	// enough to fit any valid characters in those
	// usages, can be changed later if we need to
	// support more characters.
	if !fleetlock.ValidGroup.MatchString(fld.ClientParams.ID) {
		logger.Error().Msg("FleetLock ID is invalid")

		err := fleetLockSendError("invalid_id", "ID is not valid", http.StatusBadRequest, w)
		if err != nil {
			logger.Err(err).Msg("failed sending FleetLock invalid ID error to client")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		return false
	}
	return true
}

func fleetLockValidatorMiddleware() alice.Constructor {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			if !validFleetLockHeader(logger, w, r) {
				return
			}

			fld, err := decodeFleetLockBody(logger, w, r)
			if err != nil {
				return
			}

			if !validFleetLockGroupName(logger, fld, w) {
				return
			}

			if !validFleetLockID(logger, fld, w) {
				return
			}

			// At this point we trust the contents of the ID
			// and Group fields, so attach the information
			// to our log messages. See:
			// https://pkg.go.dev/github.com/rs/zerolog#Logger.WithContext
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str("fleetlock_id", fld.ClientParams.ID)
			})
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str("fleetlock_group", fld.ClientParams.Group)
			})

			// Add validated fleetlock data to the context
			// for use in later handler
			ctx := context.WithValue(r.Context(), keyFleetLockBody, fld)
			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Small struct that implements io.Writer so we can pass it to net/http server for error
// logging
type zerologErrorWriter struct {
	logger *zerolog.Logger
}

func (zew *zerologErrorWriter) Write(p []byte) (n int, err error) {
	zew.logger.Error().Msg(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

func defaultServerConfig() serverConfig {
	return serverConfig{
		Server: serverSettings{
			Listen:  "127.0.0.1:8443",
			Backend: "etcd3",
			ReadTimeout: duration{
				Duration: time.Duration(10 * time.Second),
			},
			WriteTimeout: duration{
				Duration: time.Duration(10 * time.Second),
			},
			ShutdownDelay: duration{
				Duration: time.Duration(5 * time.Second),
			},
		},
		Ratelimit: ratelimitSettings{
			Rate:  1,
			Burst: 3,
		},
		Monitoring: monitoringConfig{
			Username: "monitor",
			Password: "changeme",
		},
		Pprof: pprofSettings{
			ReadTimeout: duration{
				Duration: time.Duration(10 * time.Second),
			},
			WriteTimeout: duration{
				Duration: time.Duration(31 * time.Second),
			},
		},
		Prometheus: prometheusSettings{
			Listen: "127.0.0.1:2222",
			ReadTimeout: duration{
				Duration: time.Duration(10 * time.Second),
			},
			WriteTimeout: duration{
				Duration: time.Duration(10 * time.Second),
			},
		},
		Etcd3: etcd3config{
			Endpoints:          []string{"https://localhost:2379"},
			Username:           "knubbis-fleetlock",
			Password:           "changeme",
			InsecureSkipVerify: false,
			RootCAPath:         "",
		},
		CertMagic: certMagicConfig{
			Salt:            "changeme",
			Password:        "changeme",
			Etcd3Path:       "com.example.fleetlock/certmagic",
			LetsEncryptProd: false,
			Email:           "someone@example.com",
			Domains:         []string{"fleetlock.example.com"},
		},
		AcmeDNS: acmeDNSConfig{
			"fleetlock.example.com": acmeDNSDomainSettings{
				Username:   "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				Password:   "changeme",
				Subdomain:  "eeeeeeee-dddd-cccc-bbbb-aaaaaaaaaaaa",
				FullDomain: "eeeeeeee-dddd-cccc-bbbb-aaaaaaaaaaaa.acme-dns.example.com",
				ServerURL:  "https://acme-dns.example.com",
			},
		},
	}
}

func newConfig(configFile string) (serverConfig, error) {
	conf := serverConfig{}
	if _, err := toml.DecodeFile(configFile, &conf); err != nil {
		return serverConfig{}, fmt.Errorf("newConfig: %w", err)
	}

	return conf, nil
}

// Flatten permissions from "group" => "id" => "password" to "group-id"
// => "[]byte(sha256(password))" for easier lookup, and also hash the
// password for later constant time comparision
func getFlattenedPerms(ctx context.Context, flc fleetlock.FleetLockConfiger) (map[string]hashing.HashedPassword, error) {
	flConfig, err := flc.GetConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize FleetLock config")
	}

	flattenedPerms := map[string]hashing.HashedPassword{}

	for group, groupSettings := range flConfig {
		for id, hashedPassword := range groupSettings.HashedPermissions {
			flattenedPerms[group+"-"+id] = hashedPassword
		}
	}

	return flattenedPerms, nil
}

func newLogger(service, hostname string) zerolog.Logger {
	return zerolog.New(os.Stderr).With().
		Timestamp().
		Str("service", service).
		Str("hostname", hostname).
		Str("server_version", version).
		Str("go_version", runtime.Version()).
		Logger()
}

func newIPLimiter() *rateLimiter {
	return &rateLimiter{
		ipLimiterMap: map[netip.Addr]*ipLimiter{},
	}
}

func setupEtcd3Client(logger zerolog.Logger, conf serverConfig) *clientv3.Client {
	etcd3TLSConfig := &tls.Config{InsecureSkipVerify: conf.Etcd3.InsecureSkipVerify} // #nosec this is configurable for testing

	if conf.Etcd3.RootCAPath != "" {
		logger.Info().Msgf("using etcd3 root ca file: %s", conf.Etcd3.RootCAPath)
		caPEMBytes, err := os.ReadFile(conf.Etcd3.RootCAPath)
		if err != nil {
			logger.Fatal().Err(err).Msgf("unable to read etcd3 root ca: %s", conf.Etcd3.RootCAPath)
		}
		etcd3TLSConfig.RootCAs = x509.NewCertPool()
		etcd3TLSConfig.RootCAs.AppendCertsFromPEM(caPEMBytes)
	}

	// Use TLS client authentication if a cert and key is configured
	if conf.Etcd3.CertFile != "" && conf.Etcd3.KeyFile != "" {
		logger.Info().Msgf("using etcd3 client cert authentication via cert: %s, key: %s", conf.Etcd3.CertFile, conf.Etcd3.KeyFile)
		etcd3ClientCert, err := tls.LoadX509KeyPair(conf.Etcd3.CertFile, conf.Etcd3.KeyFile)
		if err != nil {
			logger.Fatal().Err(err).Msgf("unable to setup etcd3 client certificates")
		}

		etcd3TLSConfig.Certificates = []tls.Certificate{etcd3ClientCert}
	}

	etcd3Client, err := newEtcd3Client(conf.Etcd3, etcd3TLSConfig)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("cannot create etcd3 client")
	}

	return etcd3Client
}

func getEncryptionKey(logger zerolog.Logger, conf serverConfig) []byte {
	if len(conf.CertMagic.Salt) != 32 {
		logger.Fatal().
			Err(errors.New("invalid salt")).
			Msg("certmagic salt must be 32 hex characters long")
	}
	salt, err := hashing.SaltFromHex(conf.CertMagic.Salt)
	if err != nil {
		logger.Fatal().Err(err).Msg("cannot decode salt hex")
	}

	// AES-256 needs a 32 byte-key
	AESKeyLen := uint32(32)
	aes256ArgonSettings := hashing.NewArgonSettings(conf.CertMagic.ArgonTime, conf.CertMagic.ArgonMemory, conf.CertMagic.ArgonThreads, AESKeyLen)

	hashedPassword := hashing.GetHashedPassword(
		conf.CertMagic.Password,
		salt,
		aes256ArgonSettings,
	)

	return hashedPassword.Hash
}

func setupACME(logger zerolog.Logger, conf serverConfig, service string) *tls.Config {
	// We only expect to use the DNS challenge as this service is
	// not exposed to the internet.
	certmagic.DefaultACME.DisableTLSALPNChallenge = true

	acmednsProvider := &acmedns.Provider{Configs: map[string]acmedns.DomainConfig{}}

	for domain, domainSettings := range conf.AcmeDNS {
		logger.Info().Msgf("configuring acme-dns settings for domain '%s'", domain)
		acmednsProvider.Configs[domain] = acmedns.DomainConfig{
			Username:   domainSettings.Username,
			Password:   domainSettings.Password,
			Subdomain:  domainSettings.Subdomain,
			FullDomain: domainSettings.FullDomain,
			ServerURL:  domainSettings.ServerURL,
		}
	}

	// Enable DNS challenge
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: acmednsProvider,
		},
	}

	if !conf.CertMagic.LetsEncryptProd {
		logger.Info().Msg("using LetsEncrypt Staging CA, TLS certificates will not be trusted")
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}

	// read and agree to your CA's legal documents
	certmagic.DefaultACME.Agreed = true

	// provide an email address
	certmagic.DefaultACME.Email = conf.CertMagic.Email

	tlsConfig, err := certmagic.TLS(conf.CertMagic.Domains)
	if err != nil {
		logger.Fatal().
			Err(err).
			Msgf("cannot create tlsconfig %s", service)
	}

	return tlsConfig
}

func buildServiceURL(logger zerolog.Logger, conf serverConfig) string {
	_, listenPort, err := net.SplitHostPort(conf.Server.Listen)
	if err != nil {
		logger.Fatal().Err(err).Msgf("unable to split out port from listen address '%s'", conf.Server.Listen)
	}

	listenPortInt, err := strconv.Atoi(listenPort)
	if err != nil {
		logger.Fatal().Err(err).Msgf("unable to convert listening port to int: '%s'", listenPort)
	}

	// Default to using the same port as the process is listening on
	servicePort := listenPort

	// If the service is running in a container and clients reach the
	// service on another port than the process is listening on we need
	// to advertise the port exposed to clients, not the port the process
	// is listening on.
	if conf.Server.ExposedPort != 0 && conf.Server.ExposedPort != listenPortInt {
		servicePort = strconv.Itoa(conf.Server.ExposedPort)
	}

	serviceURLString := conf.CertMagic.Domains[0]

	// Only include the :port if non-default for HTTPS
	if servicePort != "443" {
		serviceURLString = serviceURLString + ":" + servicePort
	}

	return serviceURLString
}

func buildSwaggerURL(logger zerolog.Logger, conf serverConfig) *url.URL {
	serviceURLString := buildServiceURL(logger, conf)

	// This path is expected by the http-swagger module
	swaggerURLString := serviceURLString + "/swagger/doc.json"
	swaggerURLString = "https://" + swaggerURLString

	// Override default Host string from comments above with where
	// the server is actually serving the API
	docs.SwaggerInfo.Host = serviceURLString

	swaggerURL, err := url.Parse(swaggerURLString)
	if err != nil {
		logger.Fatal().Err(err).Msgf("unable to parse swagger URL string: '%s'", swaggerURLString)
	}

	logger.Info().Msgf("using swagger URL '%s'", swaggerURL)

	return swaggerURL
}

func startGracefulShutdowner(logger zerolog.Logger, conf serverConfig, srv *http.Server, idleConnsClosed chan struct{}) {
	go func(logger zerolog.Logger, shutdownDelay time.Duration) {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		s := <-sigChan

		logger.Info().Msgf("received '%s' signal, sleeping for %s then calling Shutdown()", s, shutdownDelay)
		time.Sleep(shutdownDelay)
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Err(err).Msg("HTTP server Shutdown failure")
		}
		close(idleConnsClosed)
	}(logger, conf.Server.ShutdownDelay.Duration)
}

func Run(configPath string) {
	service := "knubbis-fleetlock"

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to get hostname, can not setup logging")
		os.Exit(1)
	}

	logger := newLogger(service, hostname)

	logger.Info().Msgf("starting server")

	conf, err := newConfig(configPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to create server config")
	}

	etcd3Client := setupEtcd3Client(logger, conf)

	// Timeout when interacting with backend like locking/unlocking
	// a semaphore or other operations.
	timeout, err := time.ParseDuration("10s")
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("cannot parse duration")
	}

	flConfigName := "default"

	configArgonSettings := hashing.NewArgonDefaultSettings()

	flConfiger, err := etcd3.NewConfiger(etcd3Client, flConfigName, configArgonSettings)
	if err != nil {
		logger.Fatal().Err(err).Msgf("cannot create FleetLockConfig for '%s'", flConfigName)
	}

	logger.Info().Msgf("using etcd3 config cache key '%s'", flConfiger.Key())

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cc, err := newConfigCache(ctx, flConfiger)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to initialize config cache")
	}

	// LRU cache used for storing successful authentications on the
	// FleetLock endpoints. Without this we need to compute
	// expensive argon2 hashes for each request taking or releasing
	// a lock.
	loginCache, err := lru.New[string, bool](128)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to initialize password LRU cache")
	}

	// run background config cache updater
	go configCacheUpdater(cc, flConfiger, logger, loginCache)

	limiter := newIPLimiter()

	logger.Info().Msgf("rate limiter rate: %.2f, burst: %d", conf.Ratelimit.Rate, conf.Ratelimit.Burst)

	// Start background job that continously cleans old per-IP rate
	// limiters
	go ratelimitCleaner(logger, limiter)

	// We always want to call these middlwares first, so we get
	// logging for the requests
	hlogMiddlewares := newHlogMiddlewareChain(logger)

	// Use the same middleware function for ratelimiting all endpoints
	ratelimitingMiddleware := ratelimitMiddleware(conf, limiter)

	// Create middleware chain used for the FleetLock endpoints.
	var argon2Mutex sync.Mutex
	fleetLockMiddlewares := newFleetLockMiddlewareChain(hlogMiddlewares, ratelimitingMiddleware, cc, loginCache, &argon2Mutex)

	// Create middleware chain used for monitoring endpoints
	monitoringMiddlewares := newMonitoringMiddlewareChain(hlogMiddlewares, ratelimitingMiddleware, conf.Monitoring)

	// Create middleware chain used for API endpoints
	apiMiddlewares := newAPIMiddlewareChain(hlogMiddlewares, ratelimitingMiddleware, conf.API)

	// Create middleware chain used for swagger docs endpoint
	swaggerMiddlewares := newSwaggerMiddlewareChain(hlogMiddlewares)

	// Create middleware chain used for unhandled requests
	unhandledMiddlewares := newUnhandledChain(hlogMiddlewares)

	preRebootChain := alice.New(fleetLockMiddlewares...).Then(preRebootFunc(cc, timeout))
	steadyStateChain := alice.New(fleetLockMiddlewares...).Then(steadyStateFunc(cc, timeout))

	lockStatusChain := alice.New(monitoringMiddlewares...).Then(lockStatusFunc(cc, timeout))
	staleLocksChain := alice.New(monitoringMiddlewares...).Then(staleLocksFunc(cc, timeout))

	apiChain := alice.New(apiMiddlewares...).Then(apiFunc(cc, timeout, flConfiger))

	key := getEncryptionKey(logger, conf)

	// Persist certmagic data in etcd3
	cmStorage := etcd3storage.New(etcd3Client, conf.CertMagic.Etcd3Path, key, logger)
	certmagic.Default.Storage = cmStorage

	tlsConfig := setupACME(logger, conf, service)

	swaggerURL := buildSwaggerURL(logger, conf)

	swaggerChain := alice.New(swaggerMiddlewares...).Then(httpSwagger.Handler(httpSwagger.URL(swaggerURL.String())))

	methodNotAllowedChain := alice.New(unhandledMiddlewares...).Then(methodNotAllowedFunc())
	notFoundChain := alice.New(unhandledMiddlewares...).Then(notFoundFunc())

	router := newRouter(methodNotAllowedChain, notFoundChain, preRebootChain, steadyStateChain, lockStatusChain, staleLocksChain, apiChain, swaggerChain)

	srv := &http.Server{
		Addr:         conf.Server.Listen,
		Handler:      router,
		ReadTimeout:  conf.Server.ReadTimeout.Duration,
		WriteTimeout: conf.Server.WriteTimeout.Duration,
		TLSConfig:    tlsConfig,
		ErrorLog:     log.New(&zerologErrorWriter{&logger}, "", 0),
	}

	// Handle graceful shutdown of HTTP server when receiving signal
	idleConnsClosed := make(chan struct{})

	startGracefulShutdowner(logger, conf, srv, idleConnsClosed)

	pprofServer := &http.Server{
		Addr:         "127.0.0.1:6060",
		ReadTimeout:  conf.Pprof.ReadTimeout.Duration,
		WriteTimeout: conf.Pprof.WriteTimeout.Duration,
	}

	go func() {
		logger.Fatal().
			Err(pprofServer.ListenAndServe()).
			Str("pprof listener", service).Msgf("cannot start %s", service)
	}()

	promMux := http.NewServeMux()

	promMux.Handle("/metrics", promhttp.Handler())

	promServer := &http.Server{
		Addr:         conf.Prometheus.Listen,
		Handler:      promMux,
		ReadTimeout:  conf.Prometheus.ReadTimeout.Duration,
		WriteTimeout: conf.Prometheus.WriteTimeout.Duration,
	}

	go func() {
		logger.Fatal().
			Err(promServer.ListenAndServe()).
			Str("prom listener", service).Msgf("cannot start %s", service)
	}()

	err = srv.ListenAndServeTLS("", "")
	if err != nil {
		if err == http.ErrServerClosed {
			logger.Info().Msg("server is shutting down gracefully")
		} else {
			logger.Fatal().Err(err).Msg("server failed")
		}
	}

	// ListenAndServe and ListenAndServeTLS immediately return
	// ErrServerClosed when Shutdown is called. Make sure the
	// program doesn't exit until Shutdown() has finished:
	<-idleConnsClosed
}

func newHlogMiddlewareChain(logger zerolog.Logger) []alice.Constructor {
	hlogMiddlewares := []alice.Constructor{
		// hlog handlers based on example from https://github.com/rs/zerolog#integration-with-nethttp
		hlog.NewHandler(logger),
		hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
			hlog.FromRequest(r).Info().
				Str("method", r.Method).
				Stringer("url", r.URL).
				Int("status", status).
				Int("size", size).
				Dur("duration", duration).
				Msg("")
		}),
		hlog.RemoteAddrHandler("ip"),
		hlog.UserAgentHandler("user_agent"),
		hlog.RefererHandler("referer"),
		hlog.RequestIDHandler("req_id", "Request-Id"),
	}

	return hlogMiddlewares
}

func newFleetLockMiddlewareChain(hlogMiddlewares []alice.Constructor, ratelimitingMiddleware alice.Constructor, cc *configCache, loginCache *lru.Cache[string, bool], argon2Mutex *sync.Mutex) []alice.Constructor {
	// Create middleware chain used for the FleetLock endpoints.
	fleetLockMiddlewares := []alice.Constructor{}
	fleetLockMiddlewares = append(fleetLockMiddlewares, hlogMiddlewares...)
	fleetLockMiddlewares = append(fleetLockMiddlewares, ratelimitingMiddleware)
	fleetLockMiddlewares = append(fleetLockMiddlewares, fleetLockValidatorMiddleware())
	fleetLockMiddlewares = append(fleetLockMiddlewares, flBasicAuthMiddleware(cc, loginCache, argon2Mutex))

	return fleetLockMiddlewares
}

func newMonitoringMiddlewareChain(hlogMiddlewares []alice.Constructor, ratelimitingMiddleware alice.Constructor, mc monitoringConfig) []alice.Constructor {
	monitoringMiddlewares := []alice.Constructor{}
	monitoringMiddlewares = append(monitoringMiddlewares, hlogMiddlewares...)
	monitoringMiddlewares = append(monitoringMiddlewares, ratelimitingMiddleware)
	monitoringMiddlewares = append(monitoringMiddlewares, monitorBasicAuthMiddleware(mc.Username, mc.Password))

	return monitoringMiddlewares
}

func newAPIMiddlewareChain(hlogMiddlewares []alice.Constructor, ratelimitingMiddleware alice.Constructor, ac apiConfig) []alice.Constructor {
	apiMiddlewares := []alice.Constructor{}
	apiMiddlewares = append(apiMiddlewares, hlogMiddlewares...)
	apiMiddlewares = append(apiMiddlewares, ratelimitingMiddleware)
	apiMiddlewares = append(apiMiddlewares, monitorBasicAuthMiddleware(ac.Username, ac.Password))

	return apiMiddlewares
}

func newSwaggerMiddlewareChain(hlogMiddlewares []alice.Constructor) []alice.Constructor {
	swaggerMiddlewares := []alice.Constructor{}
	swaggerMiddlewares = append(swaggerMiddlewares, hlogMiddlewares...)

	return swaggerMiddlewares
}

func newUnhandledChain(hlogMiddlewares []alice.Constructor) []alice.Constructor {
	unhandledMiddlewares := []alice.Constructor{}
	unhandledMiddlewares = append(unhandledMiddlewares, hlogMiddlewares...)

	return unhandledMiddlewares
}

func newEtcd3Client(conf etcd3config, tlsConfig *tls.Config) (*clientv3.Client, error) {
	etcd3Config := clientv3.Config{
		Endpoints:   conf.Endpoints,
		DialTimeout: 5 * time.Second,
	}

	// It is possible we are using client cert auth, then a username and
	// password is not needed.
	// From https://etcd.io/docs/v3.5/op-guide/authentication/rbac/:
	// ===
	// Note that if both of 1. --client-cert-auth=true is passed and CN is
	// provided by the client, and 2. username and password are provided by
	// the client, the username and password based authentication is
	// prioritized.
	// ===
	if conf.Username != "" && conf.Password != "" {
		etcd3Config.Username = conf.Username
		etcd3Config.Password = conf.Password
	}

	etcd3Config.TLS = tlsConfig

	etcd3Client, err := clientv3.New(etcd3Config)
	if err != nil {
		return nil, err
	}

	return etcd3Client, nil
}

func newRouter(methodNotAllowedChain, notFoundChain, preRebootChain, steadyStateChain, lockStatusChain, staleLocksChain, apiChain http.Handler, swaggerChain http.Handler) *httprouter.Router {
	router := httprouter.New()
	router.MethodNotAllowed = methodNotAllowedChain
	router.NotFound = notFoundChain

	router.Handler("POST", "/v1/pre-reboot", preRebootChain)
	router.Handler("POST", "/v1/steady-state", steadyStateChain)
	router.Handler("GET", "/lock-status", lockStatusChain)
	router.Handler("GET", "/stale-locks", staleLocksChain)
	router.Handler("GET", "/api/v1/groups", apiChain)
	router.Handler("POST", "/api/v1/groups", apiChain)
	router.Handler("DELETE", "/api/v1/groups/:group", apiChain)
	router.Handler("GET", "/swagger/*any", swaggerChain)
	router.Handler("GET", "/", http.RedirectHandler("/swagger/index.html", http.StatusFound))

	return router
}
