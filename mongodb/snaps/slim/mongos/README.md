# Mongos Snap
[![.github/workflows/publish.yaml](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml)

This repository contains the packaging metadata for creating a snap of Mongos built from the official Percona Debian repositories. Mongos is the MongoDB sharded cluster query router.

## Installing the snap
The snap can be installed directly from the Snap Store.

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/mongos)

## Building the snap
### Clone repository
```bash
git clone https://github.com/canonical/mongodb-artifacts.git
cd mongodb-artifacts/mongodb/snaps/slim/mongos
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
sudo snap install ./mongos*.snap --devmode
```

## Running mongos
Before starting the service, configure the query router to connect to your config server replica set.

```bash
sudo snap set mongos mongos-args="--configdb configrs/127.0.0.1:27019 --bind_ip 127.0.0.1 --port 27018"
```

Start the service:

```bash
sudo snap start mongos.mongos
```

## Check service status
```bash
snap services mongos
```

You should see:
```
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

## Logs
Logs are stored in:

- `/var/snap/mongodb/common/var/log/mongodb/mongos.log`

## License
The Mongos Snap is free software, distributed under the Apache Software License, version 2.0. See [LICENSE](LICENSE) for more information.

## Trademark Notice
MongoDB is a trademark or registered trademark of MongoDB, Inc.
Percona is a trademark or registered trademark of Percona LLC.
Other trademarks are property of their respective owners.

