# Sharded MongoDB Snap
[![.github/workflows/publish.yaml](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml)

This repository contains the packaging metadata for creating a snap of Sharded MongoDB built from the official Percona Debian repositories. For more information on snaps, visit [snapcraft.io](https://snapcraft.io/).

## Installing the Snap
The snap can be installed directly from the Snap Store. Follow the link below for more information.
<br>

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/sharded-mongodb)

## Building the Snap
### Clone Repository
```bash
git clone https://github.com/canonical/mongodb-artifacts.git
cd mongodb-artifacts/mongodb/snaps/slim/sharded-mongodb
```

### Installing and Configuring Prerequisites
```bash
sudo snap install snapcraft --classic
sudo snap install lxd
sudo lxd init --auto
```

### Packing and Installing the Snap
```bash
snapcraft pack
sudo snap install ./sharded-mongodb*.snap --devmode
```

## Running Sharded MongoDB
This snap delivers both `mongod` and `mongos` components for a sharded cluster deployment. Use `snap set` to configure runtime arguments for each daemon before starting them.

### Configure the config server and query router
```bash
sudo snap set sharded-mongodb mongod-args="--configsvr --replSet configrs --port 27019 --bind_ip 127.0.0.1"
sudo snap set sharded-mongodb mongos-args="--configdb configrs/127.0.0.1:27019 --bind_ip 127.0.0.1 --port 27018"
```

### Start the services
```bash
sudo snap start sharded-mongodb.mongod
sudo snap start sharded-mongodb.mongos
```

### Check service status
```bash
snap services sharded-mongodb
```

You should see both `sharded-mongodb.mongod` and `sharded-mongodb.mongos` listed.


## Available snap apps
The snap includes the following command-line tools:

- `sharded-mongodb.mongosh`
- `sharded-mongodb.mongobridge`
- `sharded-mongodb.mongod-cli`
- `sharded-mongodb.mongodump`
- `sharded-mongodb.mongoexport`
- `sharded-mongodb.mongofiles`
- `sharded-mongodb.mongoimport`
- `sharded-mongodb.mongorestore`
- `sharded-mongodb.mongostat`
- `sharded-mongodb.mongotop`

Use `snap run` with the app name, for example:
```bash
snap run sharded-mongodb.mongosh --port 27018
```

## Logs
Logs are stored in:

- `/var/snap/sharded-mongodb/common/var/log/mongodb/mongod.log`
- `/var/snap/sharded-mongodb/common/var/log/mongodb/mongos.log`

## License
The Sharded MongoDB Snap is free software, distributed under the Apache
Software License, version 2.0. See [LICENSE](LICENSE) for more information.

## Trademark Notice
MongoDB is a trademark or registered trademark of MongoDB, Inc.
Percona is a trademark or registered trademark of Percona LLC.
Other trademarks are property of their respective owners.

