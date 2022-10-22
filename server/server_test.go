package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SUNET/knubbis-fleetlock/fleetlock"
	"github.com/justinas/alice"
	"golang.org/x/time/rate"
	//"go.etcd.io/etcd/client/v3/mock/mockserver"
)

var update = flag.Bool("update", false, "update golden files")

// Satisfy the fleetlock.FleetLocker interface
type testLocker struct {
	group            string
	recursiveLockErr error
	unlockIfHeldErr  error
	lockStatus       fleetlock.LockStatus
}

func (ts testLocker) RecursiveLock(ctx context.Context, id string) error {
	return ts.recursiveLockErr
}

func (ts testLocker) UnlockIfHeld(ctx context.Context, id string) error {
	return ts.unlockIfHeldErr
}

func (ts testLocker) Group() string {
	return ts.group
}

func (ts testLocker) LockStatus(ctx context.Context) (fleetlock.LockStatus, error) {
	return fleetlock.LockStatus{}, nil
}

func TestFleetLockHandlers(t *testing.T) {
	t.Parallel()

	flb := fleetlock.FleetLockBody{
		ClientParams: fleetlock.ClientParams{
			ID:    "test-worker01.example.com",
			Group: "workers",
		},
	}

	flBodyBytes, err := json.Marshal(flb)
	if err != nil {
		t.Errorf("unable to JSON marshal FleetLockBody: %s", err)
	}

	preRebootURL := "http://example.com/v1/pre-reboot"
	steadyStateURL := "http://example.com/v1/steady-state"

	tests := []struct {
		name                 string
		flMap                map[string]fleetlock.FleetLocker
		flBody               []byte
		fleetLockHeaderName  string
		fleetLockHeaderValue string
		authPassword         string
		expectedStatusCode   int
		expectedContentType  string
		expectedBody         []byte
		url                  string
	}{
		{
			name: "prereboot-lock-successful",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: nil,
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:               flBodyBytes,
			fleetLockHeaderName:  "fleet-lock-protocol",
			fleetLockHeaderValue: "true",
			authPassword:         "changeme",
			expectedStatusCode:   http.StatusOK,
			url:                  preRebootURL,
		},
		{
			name: "prereboot-lock-all-slots-taken",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: &fleetlock.RecursiveLockError{ClientMsg: "all slots are taken", AllSlotsTaken: true},
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:               flBodyBytes,
			fleetLockHeaderName:  "fleet-lock-protocol",
			fleetLockHeaderValue: "true",
			authPassword:         "changeme",
			expectedStatusCode:   http.StatusConflict,
			expectedContentType:  "application/json; charset=utf-8",
			url:                  preRebootURL,
		},
		{
			name: "prereboot-lock-missing-header",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: nil,
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:              flBodyBytes,
			expectedStatusCode:  http.StatusBadRequest,
			expectedContentType: "application/json; charset=utf-8",
			url:                 preRebootURL,
		},
		{
			name: "prereboot-lock-empty-body",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: nil,
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:               nil,
			fleetLockHeaderName:  "fleet-lock-protocol",
			fleetLockHeaderValue: "true",
			authPassword:         "changeme",
			expectedStatusCode:   http.StatusBadRequest,
			expectedContentType:  "application/json; charset=utf-8",
			url:                  preRebootURL,
		},
		{
			name: "prereboot-lock-missing-authentication",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: nil,
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:               flBodyBytes,
			fleetLockHeaderName:  "fleet-lock-protocol",
			fleetLockHeaderValue: "true",
			expectedStatusCode:   http.StatusUnauthorized,
			expectedContentType:  "application/json; charset=utf-8",
			url:                  preRebootURL,
		},
		{
			name: "steadystate-lock-successful",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: nil,
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:               flBodyBytes,
			fleetLockHeaderName:  "fleet-lock-protocol",
			fleetLockHeaderValue: "true",
			authPassword:         "changeme",
			expectedStatusCode:   http.StatusOK,
			url:                  steadyStateURL,
		},
		{
			name: "steadystate-lock-missing-header",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: nil,
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:              flBodyBytes,
			expectedStatusCode:  http.StatusBadRequest,
			expectedContentType: "application/json; charset=utf-8",
			url:                 steadyStateURL,
		},
		{
			name: "steadystate-lock-empty-body",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: nil,
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:               nil,
			fleetLockHeaderName:  "fleet-lock-protocol",
			fleetLockHeaderValue: "true",
			authPassword:         "changeme",
			expectedStatusCode:   http.StatusBadRequest,
			expectedContentType:  "application/json; charset=utf-8",
			url:                  steadyStateURL,
		},
		{
			name: "steadystate-lock-missing-authentication",
			flMap: map[string]fleetlock.FleetLocker{
				"workers": testLocker{
					group:            "workers",
					recursiveLockErr: nil,
					unlockIfHeldErr:  nil,
					lockStatus: fleetlock.LockStatus{
						TotalSlots: 1,
						Holders:    []fleetlock.Holder{},
					},
				},
			},
			flBody:               flBodyBytes,
			fleetLockHeaderName:  "fleet-lock-protocol",
			fleetLockHeaderValue: "true",
			expectedStatusCode:   http.StatusUnauthorized,
			expectedContentType:  "application/json; charset=utf-8",
			url:                  steadyStateURL,
		},
	}

	logger := newLogger("test-service", "test-hostname")

	hlogMiddlewares := newHlogMiddlewareChain(logger)
	limiter := newIPLimiter()
	conf := defaultServerConfig()
	flattenedPerms := flattenFleetLockPermissions(conf.FleetLock)

	// Disable rate limit check so that the tests do not trip the
	// rate limiter, returning 429 responses.
	conf.Ratelimit.Rate = rate.Inf

	ratelimitingMiddleware := ratelimitMiddleware(conf, limiter)
	fleetLockMiddlewares := newFleetLockMiddlewareChain(hlogMiddlewares, ratelimitingMiddleware, flattenedPerms)
	timeout := time.Second * 3

	for _, test := range tests {

		preRebootChain := alice.New(fleetLockMiddlewares...).Then(preRebootFunc(test.flMap, timeout))
		steadyStateChain := alice.New(fleetLockMiddlewares...).Then(steadyStateFunc(test.flMap, timeout))
		bodyReader := bytes.NewReader(test.flBody)
		req := httptest.NewRequest("GET", test.url, bodyReader)
		if test.fleetLockHeaderName != "" {
			req.Header.Add(test.fleetLockHeaderName, test.fleetLockHeaderValue)
		}

		// Username is not used for the FleetLock endpoints since we use
		// the group name in the POST body as the username.
		if test.authPassword != "" {
			req.SetBasicAuth("", test.authPassword)
		}

		w := httptest.NewRecorder()

		switch url := test.url; url {
		case preRebootURL:
			preRebootChain.ServeHTTP(w, req)
		case steadyStateURL:
			steadyStateChain.ServeHTTP(w, req)
		default:
			t.Fatalf("unknown URL: %s", url)
		}

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != test.expectedStatusCode {
			t.Errorf("unexpected status code, got: %d, want: %d", resp.StatusCode, test.expectedStatusCode)
		}

		if resp.Header.Get("Content-Type") != test.expectedContentType {
			t.Errorf("unexpected Content-Type header, got: '%s', want: '%s'", resp.Header.Get("Content-Type"), test.expectedContentType)
		}

		goldenFn := test.name + ".golden"
		golden := filepath.Join("test-fixtures", goldenFn)
		if *update {
			os.WriteFile(golden, body, 0644)
		}

		expectedBody, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("unable to read golden file: '%s', re-run with '-update'?", err)
		}

		if !bytes.Equal(expectedBody, body) {
			t.Errorf("unexpected body (%s), got: '%s', want: '%s'", goldenFn, string(body), string(expectedBody))
		}
	}
}
