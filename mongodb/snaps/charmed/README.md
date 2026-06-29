# Charmed MongoDB Snap
[![.github/workflows/publish.yaml](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/mongodb-artifacts/actions/workflows/publish.yaml)

This repository contains the packaging metadata for creating a snap of Charmed MongoDB built from the official
percona debian repositories. For more information on snaps, visit [snapcraft.io](https://snapcraft.io/). 

This snap is intended to be used by the [Charmed MongoDB operator](https://charmhub.io/mongodb).

For standard MongoDB snaps see:
- [`mongodb-server-sharded`](https://snapcraft.io/mongodb-server-sharded)
- [`mongodb-server-replicaset`](https://snapcraft.io/mongodb-server-replicaset)
- [`mongos`](https://snapcraft.io/mongos)


## Installing the snap
The snap can be installed directly from the Snap Store.

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/charmed-mongodb)

or:

```bash
sudo snap install charmed-mongodb --channel=8/edge
```

## Contributing
Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues and pull requests.

## License
The MongoDB Replicaset Server Snap is free software, distributed under the Apache Software License,
version 2.0. See [LICENSE](LICENSE) for more information.

## Trademark Notice
MongoDB is a trademark or registered trademark of MongoDB, Inc.
Percona is a trademark or registered trademark of Percona LLC.
Other trademarks are property of their respective owners.
