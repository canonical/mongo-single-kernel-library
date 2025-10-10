(enable-tls)=
# How to enable TLS

This guide shows how to enable TLS using the [`self-signed-certificates` operator](https://github.com/canonical/self-signed-certificates-operator) as an example, and how to rotate private keys.

```{admonition} Caution
:class: warning

**[Self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate) are not recommended for a production environment.**

See [this guide](https://charmhub.io/topics/security-with-x-509-certificates) for an overview of the available TLS certificates charms and how to choose the right one for your use-case.
```

## Enable TLS in a replica set

To enable TLS encryption, deploy the TLS charm and integrate it with the MongoDB application:

<!--TODO: Include --config ca-common-name?-->

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy self-signed-certificates
    juju integrate self-signed-certificates mongodb
```

```{tab-item} K8s
:sync: k8s

    juju deploy self-signed-certificates
    juju integrate self-signed-certificates mongodb-k8s
```
````

To disable TLS, simply remove the integration.
````{tab-set}
```{tab-item} VM
:sync: vm

    juju remove-relation mongodb self-signed-certificates
```

```{tab-item} K8s
:sync: k8s

    juju remove-relation mongodb-k8s self-signed-certificates
```
````

## Enable TLS in a sharded cluster

Enabling encryption via TLS in a sharded cluster can be done before or after shards are added to the config-server.

However, it requires that:

* All cluster components have encryption enabled
* All cluster components are integrated to the same Certificate Authority.

To enable TLS, deploy the TLS charm and integrate it with all cluster components.

In a cluster with two shards (named `shard0` and `shard1`) and a config-server, it would look as follows:

```shell
juju deploy self-signed-certificates

juju integrate config-server self-signed-certificates
juju integrate shard0 self-signed-certificates
juju integrate shard1 self-signed-certificates
```

To disable TLS, simply remove the integrations with the cluster components:

```shell
juju remove-relation config-server self-signed-certificates
juju remove-relation shard0 self-signed-certificates
juju remove-relation shard1 self-signed-certificates
```

## Rotate private keys

Updates to internal and external private keys for certificate signing requests (CSR) can be made via the `set-tls-private-key` action. To update all keys, you must run the`set-tls-private-key` action on all charmed MongoDB units in your replica set or sharded cluster. 

### Manually generated key
To rotate private keys, first generate the keys:

```shell
openssl genrsa -out internal-key.pem 3072
openssl genrsa -out external-key.pem 3072
```

Then, apply the new external key to the leader of your replica set or config-server. 

```{admonition} Caution
:class: warning

Passing keys to Juju should only be done with `base64 -w0`, not `cat`.
```
### Auto-generated key

To auto-generate and rotate keys, run:

```shell
juju run <application-name>/leader set-tls-private-key
```