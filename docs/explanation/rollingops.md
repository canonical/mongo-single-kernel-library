(rollingops)=
# Rolling operations

Disruptive operations such as restarting or scaling down MongoDB units are performed in a
rolling fashion to preserve service availability.

By default, Charmed MongoDB coordinates rolling operations within each application. For VM
deployments, stronger cluster-wide coordination is available by integrating all MongoDB
applications with [Charmed etcd](https://charmhub.io/charmed-etcd).

## Application-level guarantees

Application-level coordination is the default behavior.

In this mode, rolling operations are coordinated only within a single application, ensuring
that only one unit of that application performs the operation at a time.

This applies to:

- Standalone replica set deployments
- Cluster components that are not integrated with [Charmed etcd](https://charmhub.io/charmed-etcd)
- Shards and mongos applications that are not yet integrated with a config server
- Kubernetes deployments

Operations in different applications are not coordinated with each other.

## Cluster-level guarantees

For VM deployments, cluster-wide coordination can be enabled by integrating every MongoDB
application in the cluster with [Charmed etcd](https://charmhub.io/charmed-etcd).

In this mode:

- Only one unit across the entire cluster performs the operation at a time
- Operations are serialized across replica sets, config servers, shards, and mongos routers
- Concurrent rolling operations in different cluster components are prevented

### Sharded cluster behavior

In sharded deployments, coordination scope depends on cluster topology.

Before a shard or mongos router is integrated with the config server, rolling operations are
coordinated only within that application.

Once integrated into the sharded cluster, cluster-wide coordination applies, provided all
participating applications are integrated with etcd.

## Current limitations

Cluster-wide coordination is currently available only for Charmed MongoDB VM charms.

Charmed MongoDB Kubernetes charms currently support application-level coordination only.

