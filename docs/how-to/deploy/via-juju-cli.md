(via-juju-cli)=
# How to deploy via the Juju CLI

This guide goes over how to deploy Charmed MongoDB replica sets and sharded clusters with the Juju command-line interface.

## Prerequisites

The basic requirements for deploying any charm are the [**`juju` client**](https://documentation.ubuntu.com/juju/3.6/reference/juju-cli/) and a [**cloud**](https://juju.is/docs/juju/cloud). 

You must have a [bootstrapped](https://juju.is/docs/juju/juju-bootstrap) cloud controller and a [Juju model](https://documentation.ubuntu.com/juju/latest/reference/model/) on which MongoDB will be deployed.

```{note}
If you're new to these concepts and vocabulary, check out the Tutorial.
```
<!--TODO: Tutorial link -->

## Deploy a replica set

To deploy a MongoDB replica set via the command line, run

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy mongodb -n <number_of_replicas>
```

```{tab-item} K8s
:sync: k8s

    juju deploy mongodb-k8s -n <number_of_replicas> --trust
```
````

## Deploy a sharded cluster

To create a sharded cluster, deploy each cluster component separately with a manually defined role, then integrate them.

To deploy a component with a specific role, use the `--config` option:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy mongodb --config role="<role>" <name> -n <number_of_replicas>
```

```{tab-item} K8s
:sync: k8s

    juju deploy mongodb-k8s --config role="<role>" <name>  -n <number_of_replicas> --trust
```
````

The available roles are `config-server` and `shard`. 

For example, to deploy a shard and a config-server with 3 replicas each:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy mongodb --config role="shard" shard0 -n 3
    juju deploy mongodb --config role="config-server" config-server -n 3

    juju integrate config-server:config-server shard0:sharding
```

```{tab-item} K8s
:sync: k8s

    juju deploy mongodb-k8s --config role="shard" shard0 -n 3 --trust
    juju deploy mongodb-k8s --config role="config-server" config-server -n 3 --trust

    juju integrate config-server:config-server shard0:sharding

```
````

<!--TODO: link
```{seealso}
{ref}`sharding`
```
-->