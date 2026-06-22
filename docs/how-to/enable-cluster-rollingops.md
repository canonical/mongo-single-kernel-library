(enable-cluster-rollingops)=
# Enable cluster-wide rolling operations

By default, Charmed MongoDB coordinates rolling operations only within each application.

To enable coordination across the entire MongoDB cluster, integrate each MongoDB application
with [Charmed etcd](https://charmhub.io/charmed-etcd).

## Pre-requisite

You'll need a Charmed MongoDB VM cluster deployment using at least the following revisions:
    - Charmed MongoDB - Revision 335 or higher
    - Charmed Mongos - Revision 144 or higher

Cluster-wide coordination is not currently supported for Kubernetes charms.

## Deploy etcd with a certificates provider

Charmed etcd requires TLS certificates before it can be used for cluster-wide rolling
coordination.

Any charm implementing the `tls-certificates` interface can be used, depending on your deployment
requirements. This guide uses
[Self-signed Certificates](https://charmhub.io/self-signed-certificates) as an example.

```bash
juju deploy charmed-etcd
juju deploy self-signed-certificates
juju integrate charmed-etcd:client-certificates self-signed-certificates
```

## Integrate MongoDB applications with etcd

Each MongoDB application that should participate in cluster-wide rolling coordination must be
integrated with etcd.

For sharded deployments, integrate every participating application:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju integrate config-server:etcd charmed-etcd:etcd-client
    juju integrate shard-one:etcd charmed-etcd:etcd-client
    juju integrate shard-two:etcd charmed-etcd:etcd-client
    juju integrate mongos:etcd charmed-etcd:etcd-client
```
````

Once the cluster is fully integrated, disruptive operations such as restarts or scale-downs
are coordinated across the cluster, ensuring that only one unit performs the operation at a
time.


```{note}
MongoDB applications can be integrated with etcd before the cluster topology is fully
established. However, cluster-wide rolling coordination is only enabled once the cluster
components are fully integrated with each other and all participating applications are
integrated with etcd.

Until then, rolling operations continue to be coordinated independently within each
application.
```
