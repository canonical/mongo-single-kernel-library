# Mongos Snap
[![.github/workflows/publish.yaml](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml)

This repository contains the packaging metadata for creating a snap of Mongos built from the official Percona Debian repositories. Mongos is the MongoDB sharded cluster query router.

This snap installs only the `mongos` query router. For a complete sharded cluster deployment, use the [`mongodb-server-sharded`](https://snapcraft.io/mongodb-server-sharded) snap. For replica set deployments, use the [`mongodb-server-replicaset`](https://snapcraft.io/mongodb-server-replicaset) snap.

## Installing the snap
The snap can be installed directly from the Snap Store.

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/mongos)

or:

```bash
sudo snap install mongos --channel=8/edge
```

## Using the snap

### Overview
`mongos` is the MongoDB query router for sharded clusters. It connects client requests to
the config server replica set and routes operations to shards.

### Configuration files
The snap stores the `mongos` configuration file at:

- `/var/snap/mongos/current/etc/mongod/mongos.conf`

Extra MongoDB arguments are passed through `mongos-args`. You can read more about the available
options in the [`mongos`](https://www.mongodb.com/docs/manual/reference/program/mongos/) documentation.

### Internal authentication keyfile

`mongos` requires the same shared keyfile used by the other sharded cluster components.

Retrive the key file from your config server using:

```
key="$(sudo snap run mongodb-server-sharded.get-keyfile)"
```

Set the keyfile in `mongos`:

```bash
sudo snap run mongos.set-keyfile "$key"
```

You can also pipe the key directly between machines. For example, with Multipass
VMs named `config-server` and `mongos`:

```bash
multipass exec config-server -- sudo snap run mongodb-server-sharded.get-keyfile | multipass exec mongos -- sudo snap run mongos.set-keyfile
```

The keyfile is stored securely at `/var/snap/mongos/current/etc/mongodb-keyfile`.
The `mongos.conf` already reference this keyfile, so it does not need to be set using the `mongos-args`.

### Configure `mongos`
Set the `mongos` runtime arguments using `snap set`:

```bash
sudo snap set mongos mongos-args="--configdb configrs/<CONFIG_SERVER_IP>:27019 --bind_ip 127.0.0.1 --port 27018"
```

Replace `configrs/<CONFIG_SERVER_IP>:27019` with your actual config server replica set name and members.

### Start the service

```bash
sudo snap start mongos.mongos
```

### Check service status

```bash
snap services mongos
```

You should see output similar to:

```text
Service         Startup   Current  Notes
mongos.mongos   disabled  active   -
```

## Available apps
This snap includes the following apps:

- `mongos.mongodump`
- `mongos.mongoexport`
- `mongos.mongofiles`
- `mongos.mongoimport`
- `mongos.mongorestore`
- `mongos.mongosh`
- `mongos.mongostat`
- `mongos.mongotop`

Use `snap run` with the app name. For example:

```bash
snap run mongos.mongosh --port 27018
```

## Getting command help
To see more information about a service or app, run it with `--help`. For example:

```bash
sudo snap run mongos.mongosh --help
```

You can use this pattern for any of the included apps.

## Logs
Logs are stored in:

- `/var/snap/mongos/common/var/log/mongodb/mongos.log`

## Configuration files
The snap stores the `mongos` configuration file at:

- `/var/snap/mongos/current/etc/mongod/mongos.conf`

## Contributing
Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues and pull requests.

## License
The Mongos Snap is free software, distributed under the Apache Software License, version 2.0. See [LICENSE](LICENSE) for more information.

## Trademark Notice
MongoDB is a trademark or registered trademark of MongoDB, Inc.
Percona is a trademark or registered trademark of Percona LLC.
Other trademarks are property of their respective owners.
