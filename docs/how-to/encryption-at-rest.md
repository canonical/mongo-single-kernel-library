---
myst:
  html_meta:
    description: "Learn how to configure encryption at rest on Charmed MongoDB using Vault as a storage backend."
---

(encryption-at-rest)=
# How to configure encryption at rest

Data at rest encryption should be used when your data is highly valuable. It should be used with data in transit encryption (TLS), and adequate policies to protect accounts.
It helps organizations comply with security and privacy standards like HIPAA, PCI-DSS, GDPR and FIPS.

Charmed MongoDB provides encryption at rest using Vault as a key management backend for the encryption keys.

```{caution}
**This feature can only be enabled at deploy time.** 

It requires a MongoDB instance that has never been started. The charm will prevent you from enabling it after it has started.

If you remove the Vault integration and MongoDB restarts, the charm will be unable to decrypt the databases and start.
```

## Pre-requisite

````{tab-set}
```{tab-item} VM
:sync: vm

You'll need:
* Charmed MongoDB - Revision 305 or higher
* (Optional) Charmed Mongos - Revision 118 or higher
```

```{tab-item} K8s
:sync: k8s

You'll need:
* Charmed MongoDB K8s - Revision 162 or higher
* (Optional) Charmed Mongos K8s - Revision 115 or higher
```
````

## A few words of caution

Encryption at rest encrypts the data on disk. It relies on Vault to store the database encryption key. If Vault is unavailable for too long and MongoDB restarts, it will fail to start as it can't decrypt the database. It is recommended to have a scheduled backup policy working and regularly tested for both Charmed MongoDB and Vault.

This implementation provides some alerts if you are integrated with [COS Lite](https://charmhub.io/cos-lite). If Vault fails, the charm will raise critical statuses and start alerting. The tokens have a lifetime of one hour, so after one hour of downtime, a restart of MongoDB will fail.

It is highly recommended to make regular backups of the Vault to ensure the key is not lost. Without the credentials, you will be unable to decrypt the data.

## Deploy and configure Vault

Follow the [official Charmed Vault documentation](https://canonical-vault-charms.readthedocs-hosted.com/en/latest/tutorial/)
until the vault is unsealed, authorised and you have removed the `one-time-token` secret.
You don't need to create a key-value type secret, and you should not destroy your environment.

## Deploy MongoDB (replica set)

Deploy Charmed MongoDB replica set for your substrate, specifying the `enable-encryption-at-rest` config option

`````{tab-set}
````{tab-item} VM
:sync: vm
```shell
juju deploy mongodb --channel=8/edge --config enable-encryption-at-rest=True
```
````

````{tab-item} K8s
:sync: k8s
```shell
juju deploy mongodb-k8s --channel=8/edge --trust --config enable-encryption-at-rest=True
```
````
`````

After a few minutes it will stay in a `blocked/idle` status:

`````{tab-set}
````{tab-item} VM
:sync: vm
```text
Model       Controller  Cloud/Region         Version  SLA          Timestamp
integ-test  overlord    localhost/localhost  3.6.20   unsupported  14:38:07+02:00

App      Version  Status   Scale  Charm    Channel  Rev  Exposed  Message
mongodb  8.0.10   blocked      1  mongodb             0  no       Must be integrated with vault to enable encryption at rest.

Unit        Workload  Agent      Machine  Public address  Ports  Message
mongodb/0*  blocked   executing  0        10.137.178.131         Must be integrated with vault to enable encryption at rest.

Machine  State    Address         Inst id        Base          AZ    Message
0        started  10.137.178.131  juju-ceaebe-0  ubuntu@24.04  vali  Running
```
````

````{tab-item} K8s
:sync: k8s
```text
Model    Controller  Cloud/Region        Version  SLA          Timestamp
testing  36microk8s  microk8s/localhost  3.6.19   unsupported  14:44:24+02:00

App          Version  Status   Scale  Charm        Channel  Rev  Address         Exposed  Message
mongodb-k8s  8.0.10   blocked      1  mongodb-k8s             0  10.152.183.137  no       Must be integrated with vault to enable encryption at rest.

Unit            Workload  Agent      Address       Ports  Message
mongodb-k8s/0*  blocked   executing  10.1.238.194         Must be integrated with vault to enable encryption at rest.
````
`````

Integrate your charm with Vault

`````{tab-set}
````{tab-item} VM
:sync: vm
```shell
juju integrate mongodb:vault-kv vault:vault-kv
```
````

````{tab-item} K8s
:sync: k8s
```shell
juju integrate mongodb-k8s:vault-kv vault:vault-kv
```
````
`````

## Enable encryption at rest in a sharded cluster

In a sharded cluster, encryption at rest is configured per component. You don't need to encrypt every shard, and the components that are encrypted don't need to share the same Vault deployment, each can be integrated with its own Vault.

As with a replica set, encryption can only be enabled at deploy time for each component that needs it, so make sure the relevant Vault deployment(s) are ready and unsealed before deploying it.

In a cluster with two shards (named `shard0` and `shard1`) and a config-server, you could, for example, encrypt only `shard0` and the `config-server`, each with its own Vault deployment (`vault-a` and `vault-b`), and leave `shard1` unencrypted:

`````{tab-set}
````{tab-item} VM
:sync: vm
```shell
juju deploy mongodb --channel=8/edge --config enable-encryption-at-rest=True --config role="config-server" config-server
juju deploy mongodb --channel=8/edge --config enable-encryption-at-rest=True --config role="shard" shard0
juju deploy mongodb --channel=8/edge --config role="shard" shard1

juju integrate config-server:vault-kv vault-b:vault-kv
juju integrate shard0:vault-kv vault-a:vault-kv

juju integrate config-server:config-server shard0:sharding
juju integrate config-server:config-server shard1:sharding
```
````

````{tab-item} K8s
:sync: k8s
```shell
juju deploy mongodb-k8s --channel=8/edge --trust --config enable-encryption-at-rest=True --config role="config-server" config-server
juju deploy mongodb-k8s --channel=8/edge --trust --config enable-encryption-at-rest=True --config role="shard" shard0
juju deploy mongodb-k8s --channel=8/edge --trust --config role="shard" shard1

juju integrate config-server:vault-kv vault-b:vault-kv
juju integrate shard0:vault-kv vault-a:vault-kv

juju integrate config-server:config-server shard0:sharding
juju integrate config-server:config-server shard1:sharding
```
````
`````

Your sharded cluster now has encryption at rest enabled on `config-server` and `shard0`, each backed by its own Vault deployment, while `shard1` remains unencrypted.

## Rotate the encryption key

Key rotation can be used as part of compliance processes (e.g: once a year), or if you have a suspicion that it has leaked.

```{caution}
This operation is expensive. It requires to restart each MongoDB instance affected twice. One for rotating the encryption key,
and one to resume operation.
```

If for any reason, you need to rotate the encryption key, please apply the following instructions.
For each unit that could have leaked its key, run:

`````{tab-set}
````{tab-item} VM
:sync: vm
```shell
juju run mongodb/<unit-id> rotate-encryption-master-key
```
````

````{tab-item} K8s
:sync: k8s
```shell
juju run mongodb-k8s/<unit-id> rotate-encryption-master-key
```
````
`````

Your key has now been rotated.
