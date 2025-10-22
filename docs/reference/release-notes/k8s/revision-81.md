(revision-81)=
# Revision 81

<sub>06 August 2025</sub>

Charmed MongoDB K8s Revision 81 has been deployed to the [`6/stable` channel](https://charmhub.io/mongodb-k8s?channel=6/stable) on Charmhub.

## Highlights

* LDAP Integration: LDAP support with TLS encryption.
* Advanced Statuses: More complex statuses and multiple statuses reporting.
* Single Kernel Charms: Codebase unified with MongoDB K8s and Mongos charms.
* Terraform Modules for simple and sharded deployments.

### Other features

* Log Rotation improvements: Per file configuration and log rotation
* Support of HTTPS validation for backups
* Use config files instead of command line parameters for mongo services
* Optimisation of Kernel parameters: fine tuning of virtual memory maximum maps
* Unification of code base between VM and K8s 

### Bug Fixes

* Services are not enabled by default.
* TLS setup race condition between config-server and shard.
* Various bug fixes

For a detailed list of commits throughout all revisions, check our [GitHub Releases](https://github.com/canonical/mongo-single-kernel-library/releases).

## Requirements and compatibility

* Juju `3.6`

See {ref}`system-requirements` for more information about software and hardware prerequisites.

## Integrations

See the [Integrations page](https://charmhub.io/mongodb-k8s/integrations) for a list of all interfaces and compatible charms.

## Software contents

This charm is based on the Canonical [charmed-mongodb-rock](https://github.com/canonical/charmed-mongodb-rock). It packages:

* Percona Server for MongoDB `v6.0.24-19`
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

