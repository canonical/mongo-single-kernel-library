(revision-YYY-ZZZ)=

# Revision YYY, ZZZ

<sub>16 October 2026</sub>

This release of Charmed MongoDB and Mongos 8 for VM brings support for ARM64, new versions of MongoDB, mongosh, PBM, mongodb_exporter. It features encryption at rest, GCS backup support, rolling operations, and many bug fixes. It also feature some new updated and refined Terraform modules

## Compatibility

| Charm   | Architecture | Charm revision | OCI Image revision* | MongoDB version | Min. recommended Juju version |
|-------- | ------------ | -------------- |-------------------- | --------------- | ----------------------------- |
| MongoDB |   `amd64`    | XXX            |  49                 |    8.0.28-12    |        3.6.29+                |
| MongoDB |   `arm64`    | YYY            |  49                 |    8.0.28-12    |        3.6.29+                |
| Mongos  |   `amd64`    | ...            |  49                 |    8.0.28-12    |        3.6.29+                |
| Mongos  |   `arm64`    | ...            |  49                 |    8.0.28-12    |        3.6.29+                |

\*OCI image resources:

* `mongodb-image=ghcr.io/canonical/charmed-mongodb@sha256:f9dff72533f5b2a8fa54784b94e06adbf1eec77dd0a37b97ad5250af46104e7f`

[Charmhub](https://charmhub.io/mongodb) | [Deployment guides](how-to-deploy) | [Upgrade guides](how-to-upgrade) | [System requirements](system-requirements)

## Features

* Build and test ARM64 architecture ([PR #203](https://github.com/canonical/mongo-single-kernel-library/pull/203))
* MongoDB 8.0.28 and PBM Agent log file ([PR #414](https://github.com/canonical/mongo-single-kernel-library/pull/414))
* MongoDB Encryption At Rest ([PR #258](https://github.com/canonical/mongo-single-kernel-library/pull/258))
* GCS Backup support ([PR #218](https://github.com/canonical/mongo-single-kernel-library/pull/218))
* Async restarts using `charmlibs-rollingops` ([PR #319](https://github.com/canonical/mongo-single-kernel-library/pull/319))
* New Terraform Modules:
  * You can find updated and better terraform modules for [Charmed MongoDB](https://github.com/canonical/mongodb-operator/tree/8/edge/terraform), [Charmed MongoDB K8s](https://github.com/canonical/mongodb-k8s-operator/tree/8/edge/terraform), [Charmed Mongos](https://github.com/canonical/mongos-operator/tree/8/edge/terraform) and [Charmed Mongos K8S](https://github.com/canonical/mongos-k8s-operator/tree/8/edge/terraform)
  * You can find some reference deployments terraform modules for AWS and Azure [here](https://github.com/canonical/charms-reference-architectures/tree/main/solutions/data/charmed-mongodb)
* A new [snap](https://snapcraft.io/mongodb-compass) for MongoDB Compass: MongoDB Compass is a GUI tool that lets builders explore their data, run queries and aggregations, and refine their data models through an easy-to-use visual interface.

## Bug fixes

Many bug fixes were brought to improve stability, handle connectivity issues, self healing and improve cross-model deployments support.

* allowConnectionsWithoutCertificates ([PR #287](https://github.com/canonical/mongo-single-kernel-library/pull/287))
* Self healing for LDAP ([PR #321](https://github.com/canonical/mongo-single-kernel-library/pull/321))
* Send CA certificate to clients ([PR #241](https://github.com/canonical/mongo-single-kernel-library/pull/241))
* Don't request certs for `unix` socket ([PR #351](https://github.com/canonical/mongo-single-kernel-library/pull/351))
* Report status upon missing workload ([PR #488](https://github.com/canonical/mongo-single-kernel-library/pull/488))
* Race condition handling + secret events ([PR #315](https://github.com/canonical/mongo-single-kernel-library/pull/315))
* Add tenacity when reaching the snapstore to get the `charmed-mongodb` snap ([PR #373](https://github.com/canonical/mongo-single-kernel-library/pull/373))
* Fix config-server start loop ([PR #424](https://github.com/canonical/mongo-single-kernel-library/pull/424))
* Raise on `mongos-k8s` missing trust ([PR #478](https://github.com/canonical/mongo-single-kernel-library/pull/478))
* Bug fixing and stabilization ([PR #353](https://github.com/canonical/mongo-single-kernel-library/pull/353))
* Catch `PrematureDataAccessError` exception when propagating CA secrets ([PR #434](https://github.com/canonical/mongo-single-kernel-library/pull/434))

## Other features

This release also includes CI, testing, and documentation improvements:

* Better backup configuration ([PR #406](https://github.com/canonical/mongo-single-kernel-library/pull/406))
* Use `json` output for backups ([PR #395](https://github.com/canonical/mongo-single-kernel-library/pull/395))
* Adjust FQDN usage + X-model fixes ([PR #436](https://github.com/canonical/mongo-single-kernel-library/pull/436))
* Set IPv4 TCP Keepalive time ([PR #207](https://github.com/canonical/mongo-single-kernel-library/pull/207))

## Known issues and limitations

* Restores on backups with old passwords will leave clients / operator user locked out of the DB.
* Sharding cluster cannot drain jumbo chunks - draining jumbo chunks [requires manual intervention](https://www.mongodb.com/docs/manual/tutorial/clear-jumbo-flag/)

## Compatibility & software contents

**Minimum Juju version**: 3.6 LTS

See {ref}`system-requirements` for more information about software and hardware prerequisites.

This charm is based on the Canonical [charmed-mongodb-snap](https://github.com/canonical/charmed-mongodb-snap). It packages:

* Percona Server for MongoDB `v8.0.28`
* MongoDB Exporter `v0.51.0`
* mongosh `v2.9.2`
* Percona Backup for MongoDB `v2.15.0`

## Join the community

Charmed MongoDB is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongo-single-kernel-library/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongo-single-kernel-library/blob/8/edge/CONTRIBUTING.md)
