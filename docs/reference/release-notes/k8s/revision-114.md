(revision-114)=

# Revision 114

<sub>16 January 2026</sub>

This is the second release of Charmed MongoDB and Mongos 8 for VM, featuring reporting improvements and a security fix for [CVE-2025-14847](https://ubuntu.com/security/CVE-2025-14847)

| Charm   | Revision | Charmhub track                                                 |
|---------|----------|----------------------------------------------------------------|
| MongoDB | 114       | [`8/stable`](https://charmhub.io/mongodb-k8s?channel=8/stable) |
| Mongos  | 69       | [`8/stable`](https://charmhub.io/mongos-k8s?channel=8/stable)  |

[Charmhub](https://charmhub.io/mongodb-k8s) | [Deployment guides](how-to-deploy) | [Upgrade guides](how-to-upgrade) | [System requirements](system-requirements)

## Features

* Patch for CVE-2025-14847 (MongoBleed)

## Bug fixes

* Correct URI for mongodb_exporter
* Small statuses improvements

### Other features

* Additional TLS Check: Ensures that Private Key and Certificate are matching.

## Known issues and limitations

* Restores on backups with old passwords will leave clients / operator user locked out of the DB.
* Sharding cluster cannot drain jumbo chunks - draining jumbo chunks [requires manual intervention](https://www.mongodb.com/docs/manual/tutorial/clear-jumbo-flag/)

## Compatibility & software contents

**Minimum Juju version**: 3.6 LTS

See {ref}`system-requirements` for more information about software and hardware prerequisites.

This charm is based on the Canonical [charmed-mongodb-rock](https://github.com/canonical/charmed-mongodb-rock). It packages:

* Percona Server for MongoDB `v8.0.10-4` (Patched for MongoBleed)
* MongoDB Exporter `v0.47.1`
* mongosh `v2.5.5`
* Percona Backup for MongoDB `v2.10.0`

## Join the community

Charmed MongoDB K8s is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongo-single-kernel-library/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongo-single-kernel-library/blob/8/edge/CONTRIBUTING.md)
