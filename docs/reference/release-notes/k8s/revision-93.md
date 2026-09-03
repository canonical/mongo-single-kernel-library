(revision-93)=
# Revision 93

<sub>27 October 2025</sub>

This is the first release of Charmed MongoDB and Mongos 8 for Kubernetes, featuring a Ubuntu 24.04 base, security improvements, and other new features.

| Charm   | Revision | Charmhub track                                                 |
|---------|----------|----------------------------------------------------------------|
| MongoDB | 93       | [`8/stable`](https://charmhub.io/mongodb-k8s?channel=8/stable) |
| Mongos  | 54       | [`8/stable`](https://charmhub.io/mongos-k8s?channel=8/stable)  |

[Charmhub](https://charmhub.io/mongodb-k8s) | [Deployment guides](how-to-deploy) | [Upgrade guides](how-to-upgrade) | [System requirements](system-requirements)

## Features

* This is the first stable release of Charmed MongoDB 8
* This new charm features Noble Numbat (Ubuntu 24.04) as its base 
* Juju secrets-based management
* Migration to TLSv4 library
    * Client TLS is now mandatory if integrated
* In-place upgrades via refresh v3
* New storage volumes
* New [documentation site](https://canonical-charmed-mongodb.readthedocs-hosted.com/8/#)
* Manual upgrade path from MongoDB 6 to MongoDB 8.

### Bug fixes

* Crash when removing partially integrated shards in some cases

For a detailed list of commits throughout all revisions, check our [GitHub Releases](https://github.com/canonical/mongo-single-kernel-library/releases).

## Known issues and limitations

* Restores on backups with old passwords will leave clients / operator user locked out of the DB.
* Sharding cluster cannot drain jumbo chunks - draining jumbo chunks [requires manual intervention](https://www.mongodb.com/docs/manual/tutorial/clear-jumbo-flag/)

## Compatibility & software contents

**Minimum Juju version**: 3.6 LTS

See {ref}`system-requirements` for more information about software and hardware prerequisites.

This charm is based on the Canonical [charmed-mongodb-rock](https://github.com/canonical/charmed-mongodb-rock). It packages:

* Percona Server for MongoDB `v8.0.10-4`
* MongoDB Exporter `v0.44.0`
* mongosh `v2.5.5`
* Percona Backup for MongoDB `v2.9.1`

## Join the community

Charmed MongoDB K8s is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongo-single-kernel-library/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongo-single-kernel-library/blob/8/edge/CONTRIBUTING.md)


