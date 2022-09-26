package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/SUNET/knubbis-fleetlock/backends/etcd3"
	"github.com/SUNET/knubbis-fleetlock/certmagic/etcd3storage"
	"github.com/SUNET/knubbis-fleetlock/fleetlock"
	"github.com/caddyserver/certmagic"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	"github.com/libdns/acmedns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/time/rate"
)

// version set at build time with -ldflags "-X main.version=v0.0.1"
var version = "unspecified"

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
	Server      serverSettings
	Ratelimit   ratelimitSettings
	Prometheus  prometheusSettings
	Permissions serverPermissions
	Etcd3       etcd3config
	FleetLock   fleetLockConfig
	CertMagic   certMagicConfig
	AcmeDNS     acmeDNSConfig
}

type serverSettings struct {
	Listen        string
	Backend       string
	ReadTimeout   duration
	WriteTimeout  duration
	ShutdownDelay duration
}

type ratelimitSettings struct {
	Rate  rate.Limit
	Burst int
}

type prometheusSettings struct {
	Listen       string
	ReadTimeout  duration
	WriteTimeout duration
}

type serverPermissions map[string]map[string]string

type fleetLockConfig map[string]groupSettings

type etcd3config struct {
	Endpoints          []string
	Username           string
	Password           string
	InsecureSkipVerify bool
}

type groupSettings struct {
	TotalSlots int
}

type certMagicConfig struct {
	Salt            string
	Password        string
	Etcd3Path       string
	LetsEncryptProd bool
	Email           string
	Domains         []string
}

type acmeDNSConfig map[string]acmeDNSDomainSettings

type acmeDNSDomainSettings struct {
	Username   string
	Password   string
	Subdomain  string
	FullDomain string
	ServerURL  string
}

func fleetLockSendError(fle fleetlock.FleetLockError, statusCode int, w http.ResponseWriter) error {
	b, err := json.Marshal(fle)
	if err != nil {
		return fmt.Errorf("fleetLockSendError: failed creating FleetLock error response: %w", err)
	}
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	// Include newline since this JSON can be returned to curl
	// requests and similar where the prompt gets messed up without
	// it.
	_, err = fmt.Fprintf(w, "%s\n", b)
	if err != nil {
		return fmt.Errorf("fleetLockSendError: %w", err)
	}

	return nil
}

// handler called when clients requests to take a lock
func preRebootFunc(flMap map[string]fleetlock.FleetLocker, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("fleetlock_op", "reqursivelock")
		})

		// Fetch FleetLock data validated in middleware
		fld := r.Context().Value(keyFleetLockBody).(fleetlock.FleetLockBody)

		groupLocker, groupExists := flMap[fld.ClientParams.Group]
		if !groupExists {
			logger.Error().
				Msg("group does not exist in config")

			fle := fleetlock.FleetLockError{
				Kind:  "failed_lock",
				Value: "group does not exist in config",
			}
			err := fleetLockSendError(fle, http.StatusInternalServerError, w)
			if err != nil {
				logger.Error().
					Msgf("failed sending RecursiveLock error: %s", err)
			}
			return
		}

		lockerCtx, lockerCancel := context.WithTimeout(r.Context(), timeout)
		defer lockerCancel()

		logger.Info().Msg("aquiring lock")

		err := groupLocker.RecursiveLock(lockerCtx, fld.ClientParams.ID)
		if err != nil {
			logger.Error().
				Msg("failed getting lock")

			fle := fleetlock.FleetLockError{
				Kind:  "failed_lock",
				Value: err.Error(),
			}
			err = fleetLockSendError(fle, http.StatusInternalServerError, w)
			if err != nil {
				logger.Error().
					Msgf("failed sending RecursiveLock error: %s", err)
			}
			return
		}

		// At this point everything is OK. Calling WriteHeader is not strictly
		// needed but it makes sure the zerolog JSON contains
		// "status":200 instead of "status":0
		w.WriteHeader(http.StatusOK)
	}
}

// handler called when clients request to release a lock
func steadyStateFunc(flMap map[string]fleetlock.FleetLocker, timeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := hlog.FromRequest(r)
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("fleetlock_op", "unlockifheld")
		})

		// Fetch FleetLock data validated in middleware
		fld := r.Context().Value(keyFleetLockBody).(fleetlock.FleetLockBody)

		groupLocker, groupExists := flMap[fld.ClientParams.Group]
		if !groupExists {
			logger.Error().
				Msg("group does not exist in config")

			fle := fleetlock.FleetLockError{
				Kind:  "failed_lock",
				Value: "group does not exist in config",
			}
			err := fleetLockSendError(fle, http.StatusInternalServerError, w)
			if err != nil {
				logger.Error().
					Msgf("failed sending RecursiveLock error: %s", err)
			}
			return
		}

		lockerCtx, lockerCancel := context.WithTimeout(r.Context(), timeout)
		defer lockerCancel()

		logger.Info().Msg("releasing lock")

		err := groupLocker.UnlockIfHeld(lockerCtx, fld.ClientParams.ID)
		if err != nil {
			logger.Error().
				Msg("failed getting lock")

			fle := fleetlock.FleetLockError{
				Kind:  "failed_unlock",
				Value: err.Error(),
			}
			err = fleetLockSendError(fle, http.StatusInternalServerError, w)
			if err != nil {
				logger.Error().
					Msgf("failed sending RecursiveLock error: %s", err)
			}
			return
		}

		// At this point everything is OK. Calling WriteHeader is not strictly
		// needed but it makes sure the zerolog JSON contains
		// "status":200 instead of "status":0
		w.WriteHeader(http.StatusOK)
	}
}

func ratelimitMiddleware(conf serverConfig, rl *rateLimiter) alice.Constructor {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
			if err != nil {
				logger.Err(err).Msg("ratelimitMiddleware: unable to parse RemoteAddr")
				//http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusInternalServerError)
				//return
				fle := fleetlock.FleetLockError{
					Kind:  "server_error",
					Value: "unable to parse remote address",
				}

				err := fleetLockSendError(fle, http.StatusInternalServerError, w)
				if err != nil {
					logger.Err(err).Msg("failed sending RemoteAddr FleetLock error to client")
					return
				}
				return
			}

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
				fle := fleetlock.FleetLockError{
					Kind:  "request_ratelimit",
					Value: "you hit a ratelimit, try again later",
				}

				err := fleetLockSendError(fle, http.StatusTooManyRequests, w)
				if err != nil {
					logger.Error().Msg("failed sending ratelimit FleetLock error to client")
					return
				}
				return
			}
			// Important to release the lock before calling
			// followup middleware
			rl.mutex.Unlock()
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

func basicAuthMiddleware(flattenedPerms map[string][]byte) alice.Constructor {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)

			// Since we pair passwords with FleetLock
			// group + ID we have no need for the username,
			// so just ignore it for now.
			_, password, ok := r.BasicAuth()
			if !ok {
				logger.Info().Msg("invalid or missing Authorization header")
				sendUnauthorizedResponse(w)
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

			validLogin := false
			for _, key := range keys {
				expectedPasswordHash, ok := flattenedPerms[key]

				if !ok {
					// The key does not exist, try with the next one
					continue
				}

				// The API passwords in the config are hashed at
				// startup, now hash the client supplied password so
				// we can compare strings of equal length with
				// subtle.ConstantTimeCompare()
				passwordHash := sha256.Sum256([]byte(password))

				// Use subtle.ConstantTimeCompare() in an attempt to
				// not leak password contents via timing attack
				passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash) == 1)

				if passwordMatch {
					validLogin = true
					break
				}

			}

			if validLogin {
				logger.Info().Msg("successful authentication")
				h.ServeHTTP(w, r)
				return
			}

			logger.Info().Msg("invalid credentials in Authorization header")
			sendUnauthorizedResponse(w)
		})
	}
}

func sendUnauthorizedResponse(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="utf-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

func fleetLockValidatorMiddleware() alice.Constructor {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := hlog.FromRequest(r)
			// Verify that a valid FleetLock header is present
			// https://coreos.github.io/zincati/development/fleetlock/protocol/#headers
			if r.Header.Get("fleet-lock-protocol") != "true" {
				logger.Warn().
					Msg("missing 'fleet-lock-protocol' header")
				fle := fleetlock.FleetLockError{
					Kind:  "invalid_fleetlock_header",
					Value: "'fleet-lock-protocol' header must be set to 'true'",
				}

				err := fleetLockSendError(fle, http.StatusBadRequest, w)
				if err != nil {
					logger.Error().Msg("failed sending FleetLock error to client")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				return
			}
			fld := fleetlock.FleetLockBody{}

			err := json.NewDecoder(r.Body).Decode(&fld)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// The spec does not specify a maximum length
			// for the group name but it seems reasonable to
			// not accept an unlimited length. Below we set
			// a 253 characters limit for ID based on the
			// maximume length of a hostname, for now just
			// reuse this here, since it should fit most
			// group names you would come up with.
			if len(fld.ClientParams.Group) > 253 {
				logger.Error().Msg("FleetLock group name too long")
				fle := fleetlock.FleetLockError{
					Kind:  "invalid_group",
					Value: "group name is too long",
				}

				err := fleetLockSendError(fle, http.StatusBadRequest, w)
				if err != nil {
					logger.Error().Msg("failed sending FleetLock group name too long error to client")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}

			if !fleetlock.ValidGroup.MatchString(fld.ClientParams.Group) {
				logger.Error().Msg("group is not a valid name")
				fle := fleetlock.FleetLockError{
					Kind:  "invalid_group",
					Value: "group name is not valid",
				}

				err := fleetLockSendError(fle, http.StatusBadRequest, w)
				if err != nil {
					logger.Error().Msg("failed sending FleetLock invalid group name error to client")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				return
			}

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
				fle := fleetlock.FleetLockError{
					Kind:  "invalid_id",
					Value: "ID is too long",
				}

				err := fleetLockSendError(fle, http.StatusBadRequest, w)
				if err != nil {
					logger.Error().Msg("failed sending FleetLock ID too long error to client")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				return
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
				fle := fleetlock.FleetLockError{
					Kind:  "invalid_id",
					Value: "ID is not valid",
				}

				err := fleetLockSendError(fle, http.StatusBadRequest, w)
				if err != nil {
					logger.Error().Msg("failed sending FleetLock invalid ID error to client")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
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
func flattenPermissions(confPerms serverPermissions) map[string][]byte {

	flattenedPerms := map[string][]byte{}

	for group, idMap := range confPerms {
		for id, password := range idMap {
			// We convert the plaintext password to a sha256 hash
			// because subtle.ConstantTimeCompare requires the input
			// strings being compared to be of the same length.
			hashedPassword := sha256.Sum256([]byte(password))
			// subtle.ConstantTimeCompare also requires a
			// []byte slice while sha256.Sum256() returns a
			// [32]byte array, so create a slice based on
			// the array:
			flattenedPerms[group+"-"+id] = hashedPassword[:]
		}
	}

	return flattenedPerms
}

func Run(configPath string) {

	host, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to get hostname, can not setup logging")
		os.Exit(1)
	}

	service := "knubbis-fleetlock"

	logger := zerolog.New(os.Stderr).With().
		Timestamp().
		Str("service", service).
		Str("host", host).
		Str("server_version", version).
		Str("go_version", runtime.Version()).
		Logger()

	logger.Info().Msgf("starting server")

	conf, err := newConfig(configPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to create server config")
	}

	flattenedPerms := flattenPermissions(conf.Permissions)

	router := httprouter.New()

	etcd3Config := clientv3.Config{
		Endpoints:   conf.Etcd3.Endpoints,
		DialTimeout: 5 * time.Second,
		Username:    conf.Etcd3.Username,
		Password:    conf.Etcd3.Password,
		//TLS: &tls.Config{
		//	InsecureSkipVerify: conf.Etcd3.InsecureSkipVerify,
		//},
	}

	etcd3Config.TLS = &tls.Config{InsecureSkipVerify: conf.Etcd3.InsecureSkipVerify} // #nosec this is configurable for testing

	etcd3Client, err := clientv3.New(etcd3Config)
	if err != nil {
		logger.Fatal().
			Err(err).
			Str("service", service).
			Msg("cannot create etcd3 client")
	}

	flMap := map[string]fleetlock.FleetLocker{}

	for group, settings := range conf.FleetLock {
		logger.Info().Msgf("configuring group '%s' with total slots: %d", group, settings.TotalSlots)
		el, err := etcd3.NewLocker(etcd3Client, group, settings.TotalSlots)
		if err != nil {
			logger.Fatal().
				Err(err).
				Str("service", service).
				Msg("cannot create etcd3 locker")
		}
		flMap[group] = el
	}

	limiter := &rateLimiter{
		ipLimiterMap: map[netip.Addr]*ipLimiter{},
	}

	logger.Info().Msgf("rate limiter rate: %.2f, burst: %d", conf.Ratelimit.Rate, conf.Ratelimit.Burst)

	// Start background job that continously cleans old per-IP rate
	// limiters
	go ratelimitCleaner(logger, limiter)

	commonMiddlewares := []alice.Constructor{
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
		fleetLockValidatorMiddleware(),
		ratelimitMiddleware(conf, limiter),
		basicAuthMiddleware(flattenedPerms),
	}

	// Timeout when aquiring or releasing a lock
	timeout, err := time.ParseDuration("10s")
	if err != nil {
		logger.Fatal().
			Err(err).
			Msg("cannot parse duration")
	}

	preRebootChain := alice.New(commonMiddlewares...).Then(preRebootFunc(flMap, timeout))
	steadyStateChain := alice.New(commonMiddlewares...).Then(steadyStateFunc(flMap, timeout))

	router.Handler("POST", "/v1/pre-reboot", preRebootChain)
	router.Handler("POST", "/v1/steady-state", steadyStateChain)

	// https://datatracker.ietf.org/doc/rfc9106/
	// Nonce S, which is a salt for password hashing applications.
	// It MUST have a length not greater than 2^(32)-1 bytes.  16
	// bytes is RECOMMENDED for password hashing.  The salt SHOULD
	// be unique for each password
	//salt, err := hex.DecodeString("287c5a555f4ce4e2c86cca3887ba02b8")
	if len(conf.CertMagic.Salt) != 32 {
		logger.Fatal().
			Err(errors.New("invalid salt")).
			Msg("certmagic salt must be 32 hex characters long")
	}
	salt, err := hex.DecodeString(conf.CertMagic.Salt)
	if err != nil {
		logger.Fatal().Err(err).Msg("cannot decode salt hex")
	}

	// https://datatracker.ietf.org/doc/rfc9106/
	// The Argon2id variant with t=1 and 2 GiB memory is the FIRST
	// RECOMMENDED option and is suggested as a default setting for
	// all environments.  This setting is secure against
	// side-channel attacks and maximizes adversarial costs on
	// dedicated brute-force hardware. The Argon2id variant with t=3
	// and 64 MiB memory is the SECOND RECOMMENDED option and is
	// suggested as a default setting for memory- constrained
	// environments.
	//
	// AES-256 needs a 32 byte-key

	// I guess it is possible to run on a machine with over 255
	// cores these days, so just be sure we do not wrap the uint8:
	var argonThreads uint8
	if runtime.NumCPU() > 255 {
		argonThreads = 255
	} else {
		argonThreads = uint8(runtime.NumCPU())
	}

	key := argon2.IDKey([]byte(conf.CertMagic.Password), salt, 3, 64*1024, argonThreads, 32)

	// Persist certmagic data in etcd3
	cmStorage := etcd3storage.New(etcd3Client, conf.CertMagic.Etcd3Path, key, logger)
	certmagic.Default.Storage = cmStorage

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
		DNSProvider: acmednsProvider,
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
			Str("service", service).
			Msgf("cannot create tlsconfig %s", service)
	}

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