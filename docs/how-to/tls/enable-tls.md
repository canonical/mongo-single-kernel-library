(enable-tls)=
# How to enable TLS

Charmed MongoDB 8 provides Transport Layer Security (TLS) for **peer-to-peer** and **client-server** communication. 

Peer-to-peer
: Communication between members in the cluster will be encrypted and authenticated using certificates.

Client-to-server
: The mongoDB client can verify the server identity and provide transport security.

## Deploy a TLS provider

Charmed MongoDB provides the option of using different CA certificates for client-server and peer-to-peer communication. This allows you to have different levels of trust for the two types of communication. You can also use the same CA certificate for both types of communication.

You can enable peer-to-peer encryption alone, client-to-server encryption alone, or both at the same time.

This guide will use the [Self-signed Certificates](https://charmhub.io/self-signed-certificates) charm as an example for all cases.

```{admonition} Caution
:class: warning

**[Self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate) are not recommended for a production environment.**

See [this guide](https://charmhub.io/topics/security-with-x-509-certificates) for an overview of the available TLS certificates charms and how to choose the right one for your use-case.
```

Deploy the `self-signed-certificates` charm.

```shell
juju deploy self-signed-certificates
```

## Enable TLS in a replica set
Integrate your replica set with the TLS provider according the required encryption.

### Peer-to-peer

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy self-signed-certificates
    juju integrate self-signed-certificates mongodb:peer-certificates
```

```{tab-item} K8s
:sync: k8s

    juju deploy self-signed-certificates
    juju integrate self-signed-certificates mongodb-k8s:peer-certificates
```
````

### Client-to-server

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy self-signed-certificates
    juju integrate self-signed-certificates mongodb:client-certificates
```

```{tab-item} K8s
:sync: k8s

    juju deploy self-signed-certificates
    juju integrate self-signed-certificates mongodb-k8s:client-certificates
```
````

## Enable TLS in a sharded cluster

Enabling encryption via TLS in a sharded cluster can be done before or after shards are added to the config-server.

However, it requires that:

1. All cluster components have encryption enabled
2. All cluster components are integrated to the **same** Certificate Authority (CA).

To enable TLS, integrate the TLS provider charm with all cluster components.

In a cluster with two shards (named `shard0` and `shard1`) and a config-server, it would look as follows:

### Peer-to-peer

```shell
juju integrate self-signed-certificates config-server:peer-certificates
juju integrate self-signed-certificates shard0:peer-certificates
juju integrate self-signed-certificates shard1:peer-certificates
```

Your sharded cluster now has peer-to-peer encryption enabled via TLS.

### Client-to-server

```shell
juju integrate self-signed-certificates config-server:client-certificates
juju integrate self-signed-certificates shard0:client-certificates
juju integrate self-signed-certificates shard1:client-certificates
```

Your sharded cluster now has client-to-server encryption enabled via TLS.