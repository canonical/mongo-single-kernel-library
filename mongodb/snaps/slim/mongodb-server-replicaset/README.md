# MongoDB server replica set snap
[![.github/workflows/publish.yaml](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml)

This repository contains the packaging metadata for creating a snap of MongoDB built from the official Percona Debian repositories. For more information on snaps, visit [snapcraft.io](https://snapcraft.io/).

This snap is intended to be run as a MongoDB replica set deployment. For sharded deployments,
see the [`mongodb-server-sharded`](https://snapcraft.io/mongodb-server-sharded) snap and the [`mongos`](https://snapcraft.io/mongos) snaps.


## Installing the snap
The snap can be installed directly from the Snap Store.

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/mongodb-server-replicaset)


or:

```bash
sudo snap install mongodb-server-replicaset --channel=8/edge
```

## Using the MongoDB replicaset server snap

This snap delivers `mongod` components for a replica set deployment. 

### Configuration files
The snap stores the MongoDB configuration file at:

- `/var/snap/mongodb-server-replicaset/current/etc/mongod/mongod.conf`

Extra MongoDB arguments are passed through `mongod-args`. You can read more about the available
options in the [`mongod`](https://www.mongodb.com/docs/manual/reference/program/mongod/).

### Start the mongod service

Configure the `mongod` service using the `mongod-args`.

```bash
sudo snap set mongodb-server-replicaset mongod-args="--port <PORT>"
```

Start the service:

```bash
sudo snap start mongodb-server-replicaset.mongod
```

Check MongoDB service status:

```bash
snap services mongodb-server-replicaset
```

You should see:
```
Service                           Startup   Current  Notes
mongodb-server-replicaset.mongod  disabled  active   -
```

## Available apps
This snap provides the following apps:

- `mongodb-server-replicaset.get-keyfile`
- `mongodb-server-replicaset.set-keyfile`
- `mongodb-server-replicaset.mongobridge`
- `mongodb-server-replicaset.mongod-cli`
- `mongodb-server-replicaset.mongodump`
- `mongodb-server-replicaset.mongoexport`
- `mongodb-server-replicaset.mongofiles`
- `mongodb-server-replicaset.mongoimport`
- `mongodb-server-replicaset.mongorestore`
- `mongodb-server-replicaset.mongosh`
- `mongodb-server-replicaset.mongostat`
- `mongodb-server-replicaset.mongotop`

Use `snap run` with the app name. For example:

```bash
snap run mongodb-server-replicaset.mongosh
```

## Internal Authentication Keyfile

Replica set members must share the same MongoDB internal-authentication keyfile.
The snap automatically generates a keyfile and provides two helper apps for storing
and retrieving that key securely at:
`/var/snap/mongodb-server-replicaset/current/etc/mongodb-keyfile`.

Retrieve the stored keyfile value:

```bash
key="$(sudo snap run mongodb-server-replicaset.get-keyfile)"
```

Set the keyfile from a shell value:

```bash
sudo snap run mongodb-server-replicaset.set-keyfile "$key"
```

You can also pipe the key directly between machines. For example, with Multipass
VMs named `replica-1` and `replica-2`:

```bash
multipass exec replica-1 -- sudo snap run mongodb-server-replicaset.get-keyfile | multipass exec replica-2 -- sudo snap run mongodb-server-replicaset.set-keyfile
```

The stored keyfile is owned by `snap_daemon` and has `400` permissions.

## Getting command help
To see more information about a service or app, run it with `--help`. For example:

```bash
sudo snap run mongodb-server-replicaset.mongod --help
```
You can use this pattern for any of the included apps.

## Logs
Logs are stored in:

- `/var/snap/mongodb-server-replicaset/common/var/log/mongodb/mongod.log`

## Contributing
Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues and pull requests.

## License
The MongoDB Replicaset Server Snap is free software, distributed under the Apache Software License,
version 2.0. See [LICENSE](LICENSE) for more information.

## Trademark Notice
MongoDB is a trademark or registered trademark of MongoDB, Inc.
Percona is a trademark or registered trademark of Percona LLC.
Other trademarks are property of their respective owners.
