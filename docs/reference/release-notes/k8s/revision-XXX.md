(revision-XXX)=

# Revision XXX

<sub>XX October 2026</sub>

Charmed MongoDB K8s Revision XXX has been release to the [`6/stable` channel](https://charmhub.io/mongodb-k8s?channel=6/stable) on Charmhub.

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

See the [Integrations page](https://charmhub.io/mongodb-k8s/integrations) for a list of all interfaces and compatible charms.

## Software contents

This charm is based on the Canonical [charmed mongodb rock](https://ghcr.io/canonical/charmed-mongodb@sha256:b6600ef095cb4aeb6f2f8340af0690ca7a436058c2f734413d5169475e5f6b6c). It packages:

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
