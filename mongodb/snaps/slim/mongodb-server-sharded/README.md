# Sharded MongoDB Server Snap
[![.github/workflows/publish.yaml](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml)

This repository contains the packaging metadata for creating a snap of Sharded MongoDB built from the official Percona Debian repositories. For more information on snaps, visit [snapcraft.io](https://snapcraft.io/).

This snap is intended to be run as a MongoDB sharded deployment. It delivers both `mongod` and `mongos` components for a complete sharded cluster. If you only need the query router, standalone [`mongos`](https://snapcraft.io/mongos) snap available.

For replica set deployments, see the [`mongodb-server-replicaset`](https://snapcraft.io/mongodb-server-replicaset) snap.

## Installing the Snap
The snap can be installed directly from the Snap Store. Follow the link below for more information.
<br>

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/mongodb-server-sharded)

or:

```bash
sudo snap install mongodb-server-sharded --channel=8/edge
```

## Using Sharded MongoDB server

### Deployment topology

This snap only allows a single `mongod` service per machine. A sharded cluster
is therefore spread across several machines:

- The **config server** runs `mongod` on its own machine.
- **Each shard** runs `mongod` on its own separate machine.
- The **query router** (`mongos`) can run alongside the config server, or on a
  separate machine. You can also use standalone [`mongos`](https://snapcraft.io/mongos)
  snap in a separate machine.

Make sure the machines can reach each other over the MongoDB ports they are
configured to use.

The example below sets up a minimal sharded cluster with one config server, one
query router, and one shard. The table summarizes the roles, ports, and other
details used throughout this guide:

| Component         | Service  | Snap argument | Role flag     | Replica set | Port    | Bind IP     |
|-------------------|----------|---------------|---------------|-------------|---------|-------------|
| Config server     | `mongod` | `mongod-args` | `--configsvr` | `configrs`  | `27019` | `127.0.0.1` |
| Query router      | `mongos` | `mongos-args` | _n/a_         | _n/a_       | `27018` | `127.0.0.1` |
| Shard server      | `mongod` | `mongod-args` | `--shardsvr`  | `shard1rs`  | `27020` | `0.0.0.0`   |


### Configuration files
The snap stores the MongoDB configuration files at:

- `/var/snap/mongodb-server-sharded/current/etc/mongod/mongod.conf`
- `/var/snap/mongodb-server-sharded/current/etc/mongod/mongos.conf`

Extra MongoDB arguments are passed through `mongod-args` and `mongos-args`. You can read more about the available
options in the [`mongod`](https://www.mongodb.com/docs/manual/reference/program/mongod/) and
[`mongos`](https://www.mongodb.com/docs/manual/reference/program/mongos/) documentation.

### Configure internal authentication

MongoDB sharded clusters use a shared keyfile for internal authentication between config servers,
shard servers, and query routers (`mongos`).

### Get and set a keyfile

The snap includes two helper apps to manage the shared internal authentication keyfile:

- `mongodb-server-sharded.get-keyfile` prints the stored keyfile value to standard output.
- `mongodb-server-sharded.set-keyfile` stores a specific keyfile value.

On install, the snap automatically generates a keyfile at `/var/snap/mongodb-server-sharded/current/etc/mongodb-keyfile`.
The stored keyfile is owned by the `snap_daemon` user (UID `584788`) and is set to `400` permissions,
which is required by MongoDB for internal authentication.

1. Retrieve the generated keyfile from one machine:

```bash
key="$(sudo snap run mongodb-server-sharded.get-keyfile)"
```

2. Store that same key on every other machine in the sharded cluster:

```bash
sudo snap run mongodb-server-sharded.set-keyfile "$key"
```

You can also pipe the key directly between machines. For example, with Multipass
VMs named `config-server` and `mongos`:

```bash
multipass exec config-server -- sudo snap run mongodb-server-sharded.get-keyfile | multipass exec mongos -- sudo snap run mongos.set-keyfile
```

The `mongod.conf` and `mongos.conf` already reference this keyfile,
so it does not need to be set in the `mongod-args` or `mongos-args`.

### Configure the config server and query router

Configure `mongod` service:

```bash
sudo snap set mongodb-server-sharded mongod-args="--configsvr --replSet configrs --port 27019 --bind_ip 127.0.0.1"
```

Configure `mongos`:
```bash
sudo snap set mongodb-server-sharded mongos-args="--configdb configrs/127.0.0.1:27019 --port 27018 --bind_ip 127.0.0.1"
```

### Start the services
```bash
sudo snap start mongodb-server-sharded.mongod
sudo snap start mongodb-server-sharded.mongos
```

### Check service status
```bash
snap services mongodb-server-sharded
```

You should see both `mongodb-server-sharded.mongod` and `mongodb-server-sharded.mongos` listed and active.

### Initialize the config server replica set

Connect to the config server instance:

```bash
snap run mongodb-server-sharded.mongosh --port 27019
```

Initialize the replica set

```javascript
rs.initiate({
  _id: "configrs",
  configsvr: true,
  members: [
    { _id: 0, host: "<CONFIG_IP>:27019" }
  ]
})
```

Verify that the replica set has elected a primary:

```javascript
rs.status()
```

### Create an admin user

Create an admin user before running cluster administration commands:

```javascript
use admin

db.createUser({
  user: "admin",
  pwd: "<ADMIN_PASSWORD>",
  roles: [
    { role: "root", db: "admin" }
  ]
})
```

### Configure shard servers

In the shard machine, configure a shard server:

```bash
sudo snap set mongodb-server-sharded mongod-args="--shardsvr --replSet shard1rs --port 27020 --bind_ip 0.0.0.0"
```

Set the shared keyfile:

```bash
sudo snap run mongodb-server-sharded.set-keyfile "$key"
```

Start the service:

``` bash
sudo snap start mongodb-server-sharded.mongod
```

### Initialize the shard replica set

Connect to the shard instance:

```bash
snap run mongodb-server-sharded.mongosh --port 27020
```

Initialize the replica set:

```javascript
rs.initiate({
  _id: "shard1rs",
  members: [
    { _id: 0, host: "<SHARD_MACHINE_IP>:27020" }
  ]
})
```

Verify that the replica set has elected a primary:

```javascript
rs.status()
```

### Add the shard to the cluster

Connect to the query router (`mongos`) using the admin user:

```bash
snap run mongodb-server-sharded.mongosh "mongodb://admin:<ADMIN_PASSWORD>@127.0.0.1:27018/admin"
```

Add the shard replica set to the cluster:

```javascript
sh.addShard("shard1rs/<SHARD_MACHINE_IP>:27020")
```

You should see

```javascript
{
  shardAdded: 'shard1rs',
  ok: 1,
  '$clusterTime': {
    clusterTime: Timestamp({ t: 1780386971, i: 18 }),
    signature: {
      hash: Binary.createFromBase64('5iVqusjnRn483j8ppWPLve0DLQ4=', 0),
      keyId: Long('7646701044415594519')
    }
  },
  operationTime: Timestamp({ t: 1780386971, i: 18 })
}
```

### Verify the cluster configuration

List the registered shards:

```javascript
sh.status()
```

The output should show the newly added shard replica set.

### Shard the test collection

Create the required shard-key index:

```javascript
use testdb
db.test.createIndex({ _id: "hashed" })
```

Shard the collection:

```javascript
sh.shardCollection("testdb.test", { _id: "hashed" })
```

Verify shard distribution:

```javascript
db.test.getShardDistribution()
```

Add documents to the collection:

```javascript
for (let i = 0; i < 1000; i++) {
  db.test.insertOne({ value: i })
}
```

Check the number of documents:

```javascript
db.test.countDocuments()
```

Check the distribution:

```javascript
db.test.getShardDistribution()
```

The output should show the data is stored in `shard1rs`

## Available snap apps
The snap includes the following command-line tools:

- `mongodb-server-sharded.get-keyfile`
- `mongodb-server-sharded.set-keyfile`
- `mongodb-server-sharded.mongosh`
- `mongodb-server-sharded.mongobridge`
- `mongodb-server-sharded.mongod-cli`
- `mongodb-server-sharded.mongodump`
- `mongodb-server-sharded.mongoexport`
- `mongodb-server-sharded.mongofiles`
- `mongodb-server-sharded.mongoimport`
- `mongodb-server-sharded.mongorestore`
- `mongodb-server-sharded.mongostat`
- `mongodb-server-sharded.mongotop`

Use `snap run` with the app name, for example:
```bash
snap run mongodb-server-sharded.mongosh --port 27019
```

## Getting command help
To see more information about a service or app, run it with `--help`. For example:
```bash
sudo snap run mongodb-server-sharded.mongod --help
sudo snap run mongodb-server-sharded.mongos --help
```
You can use this pattern for any of the included apps.

## Logs
Logs are stored in:

- `/var/snap/mongodb-server-sharded/common/var/log/mongodb/mongod.log`
- `/var/snap/mongodb-server-sharded/common/var/log/mongodb/mongos.log`

## Contributing
Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues and pull requests.

## License
The Sharded MongoDB Server Snap is free software, distributed under the Apache
Software License, version 2.0. See [LICENSE](LICENSE) for more information.

## Trademark Notice
MongoDB is a trademark or registered trademark of MongoDB, Inc.
Percona is a trademark or registered trademark of Percona LLC.
Other trademarks are property of their respective owners.
