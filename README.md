# knubbis-fleetlock
This is an implementation of a [FleetLock](https://coreos.github.io/zincati/development/fleetlock/protocol/) server.

It currently supports using [etcd3](https://etcd.io) as a backend for
the semaphore that is used for handing out locks, but is written with
the intention that additional backends could be added if needed. The
format of the semaphore JSON data is the same as is used by the
[Airlock](https://github.com/coreos/airlock) server.

## Knubbis?
This is just a swedish translation of the name 'Chubby', the lock
service used at Google, see: [The Chubby lock service for loosely-coupled distributed systems](https://static.googleusercontent.com/media/research.google.com/en//archive/chubby-osdi06.pdf)

## Features
* BasicAuth for restricting who can take a lock in a given group.
* Automatic ACME TLS handling via [CertMagic](https://github.com/caddyserver/certmagic).
* Ratelimits requests per IP with a configurable rate and burst limit.
* Structured JSON logging.
* Exposes metrics via Prometheus endpoint.
* Client responses include a `request-id` HTTP header which is also present in log messages related to that request.

## Building
### Basic binary
The server version is expected to be supplied at build time (otherwise
it will just use the version tag "unspecified"):
```
CGO_ENABLED=0 go build -ldflags="-X 'github.com/SUNET/knubbis-fleetlock/server.version=v0.0.1'"
```
### Docker
```
VERSION=v0.0.1
docker build -t knubbis-fleetlock:$VERSION --build-arg VERSION=$VERSION .
```

## CertMagic details
The server uses [CertMagic](https://github.com/caddyserver/certmagic) for automatic handling of ACME certificates. This repo contains a etcd3 backend for CertMagic so that certificate storage can be handled by the same etcd3 cluster that stores the FleetLock semaphore. The backend stores all ACME data using AES256-GCM encryption.

Currently the only enabled ACME solver is DNS that requires an existing [acme-dns](https://github.com/joohoi/acme-dns) server.

## Preparation
### Configuration
It is probably easiest to copy the `knubbis-fleetlock.toml.sample` to
`knubbis-fleetlock.toml` and modify as necessary.

### CertMagic backend encryption
The etcd3 CertMagic backend requires you to create a random password and
salt and enter it into knubbis-fleetlock.toml prior to startup. The
password selection is up to you, but the salt must be 32 hexadecimal
characters, can be generated via for example:
```
openssl rand -hex 16
```
These values are then configured inside the `[certmagic]` stanza of
`knubbis-fleetlock.toml`.

### CertMagic acme-dns credentials
You need to make sure you have registered an endpoint in your [acme-dns](https://github.com/joohoi/acme-dns)
server and added the returned information to `knubbis-fleetlock.toml`.
This is needed for the CertMagic integration to be able to handle ACME
challanges.

Remember to also set up a CNAME for the service name you expect to use
pointing to the domain created in the registration process, something
like:
```
_acme-challenge.fleetlock-svc.example.com. IN CNAME aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.acme-dns.example.com.
```

### etcd3 permissions
The server expects etcd3 to run with HTTPS endpoints and authentication enabled, so make sure a user and role exists that gives permissions that the server needs:
```
etcdctl --user root user add knubbis-fleetlock
etcdctl --user root role add knubbis-fleetlock-role
etcdctl --user root role grant-permission --prefix=true knubbis-fleetlock-role readwrite se.sunet.knubbis/fleetlock/groups/
etcdctl --user root role grant-permission --prefix=true knubbis-fleetlock-role readwrite se.sunet.knubbis/certmagic/
etcdctl --user root user grant-role knubbis-fleetlock knubbis-fleetlock-role
```

## Development
### Formatting and linting
When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:
* `go fmt ./...`
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))

### CLI (flags)
The CLI and flag handling is managed with [Cobra](https://github.com/spf13/cobra). If you want to add additional subcommands this can be done using `cobra-cli`, see for example [Cobra Generator](https://github.com/spf13/cobra-cli/blob/main/README.md)
