(revision-61)=
# Revision 61

<sub>21 October 2024</sub>

Charmed MongoDB K8s Revision 61 has been deployed to the [`6/stable` channel](https://charmhub.io/mongodb-k8s?channel=6/stable) on Charmhub.

## Highlights

* User Management
* Sharding
* Backups
* Security with TLS
* Accessibility outside of K8s with the [mongos-k8s router](https://charmhub.io/mongos-k8s)
* Metrics with COS integration - with all sharding components visible in the same dashboard

### Other features

* Audit logging
* Log rotation
* Integration to mongos

For a detailed list of commits throughout all revisions, check our [GitHub Releases](https://github.com/canonical/mongodb-k8s-operator/releases).

## Requirements and compatibility

* Juju `v3.*`

See {ref}`system-requirements` for more information about software and hardware prerequisites.

## Integrations

See the [Integrations page](https://charmhub.io/mongodb-k8s/integrations) for a list of all interfaces and compatible charms.

## Software contents

This charm is based on the Canonical [charmed mongodb rock](https://ghcr.io/canonical/charmed-mongodb@sha256:b4b3edb805b20de471da57802643bfadbf979f112d738bc540ab148d145ddcfe). It packages:
* Percona Server for MongoDB `v6.0.6-5`
* MongoDB Exporter `v0.40.0`
* mongosh `2.3.1`
* Percona Backup for MongoDB `2.4.0`

## Known issues and limitations

The following issues are known.
* Restores on backups with old passwords will leave clients / operator user locked out of the DB
* Removing a shard before breaking its integration with the config-server results in data loss
* Sharding cluster cannot drain jumbo chunks - draining jumbo chunks [requires manual intervention](https://www.mongodb.com/docs/manual/tutorial/clear-jumbo-flag/)


## Join the community

Charmed MongoDB is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongodb-k8s-operator/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongodb-k8s-operator/blob/main/CONTRIBUTING.md)
