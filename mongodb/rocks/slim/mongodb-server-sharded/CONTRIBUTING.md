# Contributing

## Install prerequisites
```bash
sudo snap install rockcraft --classic
sudo snap install docker
```

By default, Docker is only accessible with root privileges (sudo). We want to be able to use Docker commands as a regular user:

```bash
sudo addgroup --system docker
sudo adduser $USER docker
newgrp docker
```

Restart Docker

```bash
sudo snap disable docker
sudo snap enable docker
```

## Clone repository
```bash
git clone https://github.com/canonical/mongodb-artifacts.git
cd mongodb-artifacts/mongodb/rocks/slim/mongodb-server-sharded
```

## Packing the rock
```bash
rockcraft pack
```

## Run lint
```bash
tox -e lint
```

## Testing

The integration tests are [spread](https://github.com/canonical/spread) tasks
that exercise the rock through Docker. `rockcraft test` packs the rock, loads it
into Docker, and runs every task under `spread/tests/`.

Run all tests:
```bash
rockcraft test
```

Run a single suite (for example only the smoke task):
```bash
rockcraft test craft:ubuntu-24.04:spread/tests/smoke
```

The suites are:

- `spread/tests/smoke` — fast checks: mongod starts and accepts connections,
  the keyfile is auto-generated, `get-keyfile` / `set-keyfile` work, and the
  config / PID-file paths are correct.
- `spread/tests/cluster` — a full sharded cluster (config server, shard, and
  query router) with keyfile authentication, ending in a write and read through
  `mongos`.

Each task manages its own containers and cleans them up in its `restore`
section, so they do not interfere with any cluster you run by hand.
