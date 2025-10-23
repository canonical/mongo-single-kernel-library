(disable-tls)=
# How to disable TLS

This guide assumes that you have a Charmed MongoDB deployment with TLS enabled. See [How to enable TLS](#enable-tls) for more information. 

To disable TLS encryption, remove the relation between your MongoDB applications and the TLS provider on the endpoint specific to the peer-to-peer or client-to-server communication.

You can disable **peer-to-peer** encryption alone, **client-to-server** encryption alone, or **both** at the same time.

## Disable TLS in a replica set

### Peer-to-peer

```shell
juju remove-relation self-signed-certificates mongodb:peer-certificates
```

You have successfully disabled peer-to-peer TLS encryption with for your replica set

### Client-to-server

```shell
juju remove-relation self-signed-certificates mongodb:client-certificates
```

You have successfully disabled client-to-server TLS encryption with for your replica set

## Disable TLS in a  sharded cluster

Remove the relations from all the cluster components.

### Peer-to-peer

```shell
juju remove-relation self-signed-certificates config-server:peer-certificates
juju remove-relation self-signed-certificates shard-one:peer-certificates
juju remove-relation self-signed-certificates shard-two:peer-certificates
```

You have successfully disabled peer-to-peer TLS encryption with for your sharded cluster.

### Client-to-server

```shell
juju remove-relation self-signed-certificates config-server:client-certificates
juju remove-relation self-signed-certificates shard-one:client-certificates
juju remove-relation self-signed-certificates shard-two:client-certificates
```

You have successfully disabled client-to-server TLS encryption with for your sharded cluster.