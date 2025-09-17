(via-juju-cli)=
# How to deploy via the Juju CLI

The basic requirements for deploying any charm are the [**Juju client**](https://juju.is/docs/juju) and a machine [**cloud**](https://juju.is/docs/juju/cloud).

Make sure you've [bootstrapped](https://juju.is/docs/juju/juju-bootstrap) a cloud controller and have created a [Juju model](https://canonical-juju.readthedocs-hosted.com/en/latest/user/reference/model/).

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

## Sharded cluster

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

    juju deploy mongodb --config role="shard" shard_0 -n 3
    juju deploy mongodb --config role="config-server" config_server_0 -n 3

    juju integrate config-server:config-server shard_0:sharding
```

```{tab-item} K8s
:sync: k8s

    juju deploy mongodb-k8s --config role="shard" shard_0 -n 3 --trust
    juju deploy mongodb-k8s --config role="config-server" config_server_0 -n 3 --trust

    juju integrate config-server:config-server shard_0:sharding
```
````

