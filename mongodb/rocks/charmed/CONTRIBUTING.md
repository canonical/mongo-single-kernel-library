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
cd mongodb-artifacts/mongodb/rocks/charmed/
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
that exercise the rock through the Charmed MongoDB Kubernetes operator.
`rockcraft test` packs the rock, clones the operator branch configured in
`spread.yaml`, patches the operator charm to use the rock built from this
repository, packs the charm, and runs the operator integration tests.

Run all tests:
```bash
rockcraft test
```

Run a single suite (for example only the replica set task):
```bash
rockcraft test craft:ubuntu-24.04:spread/tests/replica-set
```

The suites are:

- `spread/tests/replica-set` — runs the operator replica set integration test
  from `tests/integration/test_charm.py`.
- `spread/tests/sharding` — runs the operator sharding integration test from
  `tests/integration/test_sharding.py`.

Each task imports the current rock image into MicroK8s and cleans up its Juju
model/controller after it runs.