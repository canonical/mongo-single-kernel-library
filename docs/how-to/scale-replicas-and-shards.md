(scale-replicas-and-shards)=
# How to scale replicas and shards

MongoDB shards are a configuration of an existing MongoDB charm, but run as applications alongside the main MongoDB application.

This guide goes over how to scale replicas of any application by adding and removing [Juju units](https://documentation.ubuntu.com/juju/3.6/reference/unit/), and how to scale a sharded cluster.

## Scale a replica set

To scale a replica set, use `juju`'s  [`add-unit`](https://juju.is/docs/juju/juju-add-unit) and [`remove-unit`](https://juju.is/docs/juju/juju-remove-unit) commands. 

To add more replicas, run:

```shell
juju add-unit <application_name> -n <num_of_replicas_to_add>
```

where an `application` can be either a bare replica set, shard, or config-server.

To remove replicas, run:

```shell
juju remove-unit <application_name>/<unit_number> <application_name>/<unit_number>
```

where an `application` can be either a bare replica set, shard, or config-server.

```{note}
`juju remove-unit` allows removing more than one replica so long as they do not constitute the **majority** of the replicas. 
```

## Scale a sharded cluster

To add a shard to a cluster, deploy the new shard as an application and add it to your config-server.

For example, to deploy a new shard named `new-shard`, run:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy mongodb --config role="shard" new-shard -n <number_of_replicas>
```

```{tab-item} K8s
:sync: k8s

    juju deploy mongodb-k8s --config role="shard" new-shard -n <number_of_replicas>
```
````

Wait for the shard to show a `blocked` and `idle` status.

Next, add it to your config-server:

```shell
juju integrate <config-server-name>:config-server new-shard:sharding
```

To remove `new-shard`, remove the relation:

```shell
juju remove-relation <config-server-name>:config-server new-shard:sharding
```

Once the shard is drained, it can be fully removed with `remove-application`:

```shell
juju remove-application new-shard
```

```{admonition} Caution
:class: warning

As with upstream MongoDB, Charmed MongoDB does not support removing the last shard.
```

## Retrieve primary replica

To get the primary replica, use the Juju action `get-primary`:

```shell
juju run <application_name>/<unit_number> get-primary
```
Where an `application` can be either a bare replica set, shard, or config-server.