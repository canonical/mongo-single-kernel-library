(revision-90)=
# Revision 90

<sub>24 October 2025</sub>

Charmed MongoDB K8s Revision 90 has been deployed to the [`8/edge` channel](https://charmhub.io/mongodb-k8s?channel=8/edge) on Charmhub.

## Highlights

* MongoDB 8: This is the first stable release of Charmed MongoDB 8.
* 24.04 Base: This new charm features the Noble base (Ubuntu 24.04)
* New user management
* Migration to TLSv4 library
* Refreshes v3
* New storage volumes
* New [documentation](https://canonical-charmed-mongodb.readthedocs-hosted.com/8/#)

### Other features

* Manual upgrade path from MongoDB 6 to MongoDB 8.

### Bug Fixes

* Crash when removing partially integrated shards in some cases

For a detailed list of commits throughout all revisions, check our [GitHub Releases](https://github.com/canonical/mongo-single-kernel-library/releases).

## Requirements and compatibility

* Juju `3.6`

See {ref}`system-requirements` for more information about software and hardware prerequisites.

## Integrations

See the [Integrations page](https://charmhub.io/mongodb-k8s/integrations) for a list of all interfaces and compatible charms.

## Software contents

This charm is based on the Canonical [charmed-mongodb-rock](https://github.com/canonical/charmed-mongodb-rock). It packages:

* Percona Server for MongoDB `v8.0.10-4`
* MongoDB Exporter `v0.44.0`
* mongosh `v2.5.5`
* Percona Backup for MongoDB `v2.9.1`

## Known issues and limitations

The following issues are known.

* Restores on backups with old passwords will leave clients / operator user locked out of the DB.
* Sharding cluster cannot drain jumbo chunks - draining jumbo chunks [requires manual intervention](https://www.mongodb.com/docs/manual/tutorial/clear-jumbo-flag/)

## Join the community

Charmed MongoDB K8s is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongodb-k8s-operator/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongodb-k8s-operator/blob/main/CONTRIBUTING.md)


