(revision-164)=
# Revision 164

<sub>March 26, 2024</sub>

Dear community,

We are excited to announce that Revision 164 of the [Charmed MongoDB operator](https://github.com/canonical/mongodb-operator) has been released in the `6/stable` track for IAAS/VM.

```{caution}
**Please note that track `5` is no longer supported by Canonical.** This means that it will not receive any bug fixes or new features. We are planning to close the track `5` in the coming months, and we will keep you updated on the timeline.

We strongly encourage users to **transition to the `6/stable` track to ensure that you continue to receive support and updates** from Canonical.
```

## Highlights

* Major snap upgrade to from charmed-mongodb/5 >charmed-mongodb/6:
  * MongoDB upgrade: `5.0 >` [`6.0.6-5`](https://www.mongodb.com/docs/v6.0/release-notes/6.0)
  * PBM upgrade: `2.0.5 > 2.4.0`
  * MongoDB exporter upgrade: `0.37.0 > 0.40.0`
* `juju 3` support
* Legacy relations deprecation
* Integration with the [`mongos` charm](https://charmhub.io/mongos) via the config-server interface

### Features

* Replication
* Sharding
* Encryption via TLS
* Backup and restore
* Client connections
* Password rotation
* Monitoring
* Audit logging

For a more detailed list of features and commits throughout all revisions, check our [GitHub Releases](https://github.com/canonical/mongodb-operator/releases).

## Known issues

* Charmed MongoDB does not support relations on the `mongodb_client` interface in `juju` versions `2.9 > 3.1`.
* Sometimes the cluster goes into maintenance mode with a message “Enabling TLS” when using self-signed-certificates charm. 
([#379](https://github.com/canonical/mongodb-operator/issues/379))
  * This might be an issue with the `self-signed-certificates` charm.

For known issues of official MongoDB, check [MongoDB | 6.0 Release Notes > Known Issues](https://www.mongodb.com/docs/v6.0/release-notes/6.0#known-issues) and [MongoDB | Open Issues](https://jira.mongodb.org/browse/SERVER-52164?filter=-5)

## Useful links

* [GitHub | **Release Notes**](https://github.com/canonical/mongodb-operator/releases)
* [Documentation | **Charmed MongoDB Tutorial**](../../../tutorial.md)
* [Youtube | **Charmed MongoDB Video Tutorial**](https://www.youtube.com/watch?v=dAGhfd6vwaE)
* [Ubuntu Webinar | **MongoDB Operations Simplified**](https://ubuntu.com/engage/simplifying-mongodb-operations)

## Project and community

Charmed MongoDB is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongodb-operator/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongodb-operator/blob/main/CONTRIBUTING.md) to the code

