(revision-YYY)=

# Revision YYY

<sub>NN October 2026</sub>

Charmed MongoDB Revision YYY has been deployed to the [`6/stable` channel](https://charmhub.io/mongodb?channel=6/stable) on Charmhub.
It pairs with Charmed Mongos revision ZZZ that has been release to the [`6/stable` channel](https://charmhub.io/mongos?channel=6/stable) on Charmhub.

## Highlights

* Patch for a few CVEs on MongoDB.
* Dependencies upgrades

### Other features

* GCS Backup support

## Bug Fixes

* Stability improvements

## Requirements and compatibility

* Juju `3.6`

See {ref}`system-requirements` for more information about software and hardware prerequisites.

## Integrations

See the [Integrations page](https://charmhub.io/mongodb/integrations) for a list of all interfaces and compatible charms.

## Software contents

This charm is based on the Canonical [charmed-mongodb-snap](https://github.com/canonical/charmed-mongodb-snap/?channel=6/stable). It packages:

* Percona Server for MongoDB `v6.0.28-22`
* MongoDB Exporter `v0.51.0`
* mongosh `v2.9.2`
* Percona Backup for MongoDB `v2.10.0`

## Known issues and limitations

The following issues are known.

* Restores on backups with old passwords will leave clients / operator user locked out of the DB.
* Sharding cluster cannot drain jumbo chunks - draining jumbo chunks [requires manual intervention](https://www.mongodb.com/docs/manual/tutorial/clear-jumbo-flag/)

## Join the community

Charmed MongoDB is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongodb-operator/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongodb-operator/blob/main/CONTRIBUTING.md)
