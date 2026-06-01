# MongoDB Snap
[![.github/workflows/publish.yaml](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml)

This repository contains the packaging metadata for creating a snap of MongoDB built from the official Percona Debian repositories. For more information on snaps, visit [snapcraft.io](https://snapcraft.io/).

## Installing the snap
The snap can be installed directly from the Snap Store.

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/mongodb)

## Building the snap
### Clone repository
```bash
git clone https://github.com/canonical/mongodb-artifacts.git
cd mongodb-artifacts/mongodb/snaps/slim/mongodb
```

### Install prerequisites
```bash
sudo snap install snapcraft --classic
sudo snap install lxd
sudo lxd init --auto
```

### Pack and install
```bash
snapcraft pack
sudo snap install ./mongodb*.snap --devmode
```

## Start the MongoDB service
```bash
sudo snap start mongodb.mongod
```

## Check MongoDB service status
```bash
snap services mongodb
```

You should see:
```
Service         Startup   Current  Notes
mongodb.mongod  disabled  active   -
```

## Available apps
This snap provides the following apps:

- `mongodb.mongobridge`
- `mongodb.mongod-cli`
- `mongodb.mongodump`
- `mongodb.mongoexport`
- `mongodb.mongofiles`
- `mongodb.mongoimport`
- `mongodb.mongorestore`
- `mongodb.mongosh`
- `mongodb.mongostat`
- `mongodb.mongotop`

Use `snap run` with the app name. For example:
```bash
snap run mongodb.mongosh
```

## Config server mode
To run `mongod` as a config server, set runtime arguments using `snap set`:

```bash
sudo snap set mongodb mongod-args="--configsvr --replSet configrs --port 27019 --bind_ip 127.0.0.1"
```

Then start the service:
```bash
sudo snap start mongodb.mongod
```

Connect with `mongosh`:
```bash
sudo snap run mongodb.mongosh --port 27019
```

Initialize the replica set:
```js
rs.initiate({
  _id: "configrs",
  configsvr: true,
  members: [
    { _id: 0, host: "127.0.0.1:27019" }
  ]
})
```

Verify the replica set status:
```js
rs.status()
```

## Logs
Logs are stored in:

- `/var/snap/mongodb/common/var/log/mongodb/mongod.log`

## License
The MongoDB Snap is free software, distributed under the Apache Software License, version 2.0. See [LICENSE](LICENSE) for more information.

## Trademark Notice
MongoDB is a trademark or registered trademark of MongoDB, Inc.
Percona is a trademark or registered trademark of Percona LLC.
Other trademarks are property of their respective owners.

