(revision-199)=
# Revision 199

<sub>04 October 2024</sub>

Charmed MongoDB Revision 199 has been deployed to the [`6/stable` channel](https://charmhub.io/mongodb?channel=6/stable) on Charmhub.

## Highlights

* Upgrades 
* Rollbacks

### Other features

* Audit logging
* Log Rotation
* Can now view all sharding components in grafana dashboards

For a detailed list of commits throughout all revisions, check our [GitHub Releases](https://github.com/canonical/mongodb-operator/releases).

## Requirements and compatibility
* Juju `3.*`

See {ref}`system-requirements` for more information about software and hardware prerequisites.

## Integrations

See the [Integrations page](https://charmhub.io/mongodb/integrations) for a list of all interfaces and compatible charms.
 
## Software contents

This charm is based on the Canonical [charmed-mongodb-snap](https://github.com/canonical/charmed-mongodb-snap). It packages:
* Percona Server for MongoDB `v6.0.6-5`
* MongoDB Exporter `v0.40.0`
* mongosh `2.3.1`
* Percona Backup for MongoDB `2.4.0`

## Known issues and limitations

The following issues are known.
* Restores on backups with old passwords will leave clients / operator user locked out of the DB
* Sharding cluster cannot drain jumbo chunks - draining jumbo chunks [requires manual intervention](https://www.mongodb.com/docs/manual/tutorial/clear-jumbo-flag/)
* Shard goes into error state when integrated into the `s3` interface
* config-server can occasionally share key-file, password, and username to mongos as a non-secret 

## Join the community

Charmed MongoDB is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongodb-operator/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongodb-operator/blob/main/CONTRIBUTING.md)

