# Sample docker-compose file and helper tools
This repo contains sample files for setting up a single node `knubbis-fleetlock`
service where the backend `etcd` server runs on the same node.

Keep in mind that this expects that you have prepopulated the
/opt/knubbis-fleetlock directory with the respective contents as mounted by the
docker compose file beforehand, see below.

## Certificates
The sample compose file uses cfssl tools to create a CA cert and `etcd` server
cert signed by that CA everytime the compose file is started. It will make the
generated `ca.pem` file available in `/opt/knubbis-fleetlock/cert-bootstrap-ca` for
consumption by the `knubis-fleetlock-server` server. It will make the `etcd` server cert
and private key available in `/opt/knubbis-fleetlock/cert-bootstrap-etcd` for use
by the `etcd` process. The CA private key is not saved because it will be
regenerated at next startup anyway.

The input `bootstrap.sh`, `ca.json` and `csr.json` files need to be added to
`/opt/knubbis-fleetlock/cert-bootstrap`, but the directory can be read-only
from the container perspective, e.g.:
```
mkdir -p /opt/knubbis-fleetlock/cert-bootstrap
cp cert-bootstrap/bootstrap.sh cert-bootstrap/ca.json cert-bootstrap/csr.json /opt/knubbis-fleetlock/cert-bootstrap
```

The following cert directories need to exist but can be empty initially, e.g:
```
mkdir -p /opt/knubbis-fleetlock/cert-bootstrap-ca
chown 1000000000:1000000000 /opt/knubbis-fleetlock/cert-bootstrap-ca
mkdir -p /opt/knubbis-fleetlock/cert-bootstrap-etcd
chown 1000000000:1000000000 /opt/knubbis-fleetlock/cert-bootstrap-etcd
```

## etcd
Except for mounting the above mentioned `cert-bootstrap-etcd` directory for
getting access to its private key and cert file `etcd` also needs to store its
data somewhere, and we use `/opt/knubbis-fleetlock/etcd-data` for that. It
therefore needs to be writeable by the uid used by the `etcd` server, and should
also have strict permissions since otherwise `etcd` will complain about the
permissions at startup, e.g.:
```
mkdir -p /opt/knubbis-fleetlock/etcd-data
chown 1000000000:1000000000 /opt/knubbis-fleetlock/etcd-data
chmod 0700 /opt/knubbis-fleetlock/etcd-data
```

Also, since we want to populate the `etcd` database on first use there is also a
bootstrap container that will run after starting `etcd` but before starting
`knubbis-fleetlock`, and it needs an input bootstrap script e.g.:
```
mkdir -p /opt/knubbis-fleetlock/bootstrap-etcd
cp bootstrap-etcd/bootstrap.sh /opt/knubbis-fleetlock/bootstrap-etcd
```

The bootstrap script also expects a password for the `root` and
`knubbis-fleetlock` user, e.g.:
```
echo "somethingsecret" > /opt/knubbis-fleetlock/bootstrap-etcd/password-root
echo "somethingelsesecret" > /opt/knubbis-fleetlock/bootstrap-etcd/password-knubbis-fleetlock
```

## knubbis-fleetlock
The knubbis fleetlock server needs read access to
`/opt/knubbis-fleetlock/cert-bootstrap-ca` to be able to trust the connection
to `etcd`, and also read access to its own config file in
`/opt/knubbis-fleetlock/conf/knubbis-fleetlock.toml`

E.g.:
```
mkdir /opt/knubbis-fleetlock/conf
$EDITOR /opt/knubbis-fleetlock/conf/knubbis-fleetlock.toml
```

After this you can start the containers:
```
docker-compose up
```
