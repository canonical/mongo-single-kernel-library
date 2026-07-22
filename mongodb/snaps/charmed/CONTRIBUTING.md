# Contributing

## Install prerequisites
```bash
sudo snap install snapcraft --classic
sudo snap install lxd
sudo lxd init --auto
```

## Clone repository
```bash
git clone https://github.com/canonical/mongodb-artifacts.git
cd mongodb-artifacts/mongodb/snaps/charmed/
```

## Pack and install
```bash
snapcraft pack
sudo snap install ./charmed-mongodb*.snap --devmode
```

## Run lint
```bash
tox -e lint
```

## Run tests
```bash
tox -e smoke
```

Note that the this command assumes that the snap was already packed.

## Check the journal logs

```
sudo sysctl -w kernel.printk_ratelimit=0 ; journalctl --follow | grep charmed-mongodb
```

## Check the snap logs

```
sudo snap logs charmed-mongodb
```