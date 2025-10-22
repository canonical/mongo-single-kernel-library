(sharding)=
# Sharding

This page goes over the logic and implementation behind sharding in Charmed MongoDB. For information about how sharding works in general, we recommend checking out this page from MongoDB's official documentation: [Sharding in MongoDB](https://www.mongodb.com/resources/products/capabilities/sharding).

In Charmed MongoDB, sharding is designed around the idea of multiple Juju applications making up the cluster, unlike replication, where multiple units make up the replica set. These different applications act as cluster components such as shards, config-servers, and mongos-routers. In this page, we will describe these components and the charms they are associated with.

## Sharded cluster components

### `config-server`
config-servers exist as a configuration of the already existing Charmed MongoDB charm. The config server manages the related sharding applications and is responsible for adding/removing shards, creating users, managing passwords, creating backups, and enabling TLS.

### `shard` 
Shards exist as a configuration of the already existing Charmed MongoDB charm. Once deployed as a shard, shards are unable to create users, manage passwords, and create backups.

### `mongos`
The mongos router is present in two forms in Charmed MongoDB:

1. **Cluster admin** - In this case, `mongos` runs as an administrative daemon within the config-server, managing shards, users, passwords, etc. It is not advisable to access this `mongos` daemon directly in a production environment.
2. **Router for client connections** -  In this case, `mongos` runs as a subordinate charm, [Charmed Mongos](https://charmhub.io/mongos), and acts as an independent router for client applications.

#### Designed for reduced latency

We designed our deployments around creating the most efficient sharded cluster possible. For this reason, the administrative `mongos` router runs within the same virtual machine as the config-server. This means that administrative cluster actions do not need to make additional network calls to configure the cluster. 

On the subordinate [Mongos charm](https://charmhub.io/mongos), a similar approach is taken for the non-administrative `mongos` router (i.e. the `mongos` client router). In this case, `mongos` is running using the Unix Domain Socket so that client requests to the sharded cluster do not have to make a network call when interfacing with their associated router.

## Replication-only vs. sharded cluster deployments

Some key differences between a bare replica set deployment and a sharded cluster deployment include:

| Replication-only                                | Sharded cluster                                |
|-------------------------------------------------|------------------------------------------------|
| Requires one MongoDB application                | Requires multiple MongoDB applications         |
| Can create users via `mongodb_client` interface | Can create users via `config-server` interface |

