(cryptography)=
# Cryptography

This document describes the cryptography used by Charmed MongoDB and [Charmed Mongos](https://charmhub.io/mongos). We discuss both charms since we acknowledge that Charmed Mongos is a required to access a sharded cluster. 

## Resource checksums

Charmed MongoDB and Charmed Mongos operators use pinned revisions of the [Charmed MongoDB snap](https://snapcraft.io/charmed-mongodb). This provides a reproducible and secure environments The snap packages the workloads associated with both charms (percona-server-mongodb, mongodb-exporter, pbm, etc), see [Charmed MongoDB snap contents](https://github.com/canonical/charmed-mongodb-snap/blob/8/edge/snap/snapcraft.yaml).

Every artifact bundled into the Charmed MongoDB snap is verified against their MD5, SHA256 or SHA512 checksum after download. The installation of certified snaps into the rock is ensured by snap primitives that verify their squashfs filesystems images GPG signature. For more information on the snap verification process, refer to the [snapcraft.io documentation](https://snapcraft.io/docs/assertions).

## Sources verification

Charmed MongoDB and Charmed Mongos sources are stored in:

* GitHub repositories for snaps, rocks and charms
* LaunchPad repositories for the percona-server-mongodb, mongodb-exporter, and pbm upstream forks used for building their respective distributions

### Launchpad

Distributions are built using private repositories only, hosted as part of the [SOSS namespace](https://launchpad.net/soss) to eventually
integrate with Canonical's standard process for fixing CVEs. 
Branches associated with releases are mirrored to a public repository, hosted in the [Data Platform namespace](https://launchpad.net/~data-platform) 
to also provide the community with the patched source code.

### GitHub

All MongoDB artifacts (including mongos) built by Canonical are published and released 
programmatically using release pipelines implemented via GitHub Actions. 
Distributions are published as both GitHub and LaunchPad releases via the [central-uploader repository](https://github.com/canonical/central-uploader), while 
charms, snaps and rocks are published using the workflows of their respective repositories. 

All repositories in GitHub are set up with branch protection rules, requiring:

* new commits to be merged to main branches via pull request with at least 2 approvals from repository maintainers

## Encryption

Charmed MongoDB can be used to deploy a secure database that provides encryption-in-transit capabilities out of the box 
for:

* mongod replica/shard communication
* mongos router communication
* External client connection 

To set up secure connections to Charmed MongoDB, the database must be integrated with TLS Certificate Provider charms, e.g. 
`self-signed-certificates` operator. Charmed MongoDB TLS management is done via the `tls_certificates_interface` 
library v4, which uses the `cryptography` Python library to create X.509 compatible certificates. 

The TLS Certificate Provider manages the lifetime of CSRs and private keys. Those are provided to the unit together
with a certificate to the units, and stored in a file with limited permissions and stored in Juju Secrets. 

When encryption is enabled, hostname verification is turned on for existing connections, including clients, shards, replicas, and routers.

Encryption at REST is currently not supported, although it can be provided by the substrate (cloud or on-premises).

## Authentication

In Charmed MongoDB and Charmed Mongos, authentication layers can be enabled for:
1. MongoDB replica/shard/router communication (i.e. Internal Membership) 
2. Client authentication to MongoDB

### MongoDB replica/shard/router communication (i.e. Internal Membership) 

Internal Members authenticate using:
1. KeyFiles using SCRAM-SHA-256 protocols 
2. x.509 certificates 

Both KeyFiles and certificates are stored as files with minimal permissions. Note MongoDB disables support for TLS 1.0 encryption on systems where TLS 1.1+ is available.

These files need to be readable and writable by root (as these files are created by the charm), and readable by the `snap_daemon` user running the Charmed MongoDB snap commands.

### Client and router authentication to MongoDB

Clients can authenticate to MongoDB using:

1. username and password exchanged using SCRAM-SHA-256 protocols 
2. client certificates or CAs (mTLS)

When using SCRAM, usernames and passwords are stored in Charmed MongoDB and Charmed Mongos to be used by the mongod and mongos processes, in peer-relation data and in external relation to be shared with client applications via Juju secrets. 

When using mTLS, client certificates are loaded into a `tls-certificates` operator and provided to the Charmed MongoDB via a plain-text unencrypted 
relation. Certificates are stored in a file with minimal permissions. Note MongoDB disables support for TLS 1.0 and TLS 1.1 encryption.