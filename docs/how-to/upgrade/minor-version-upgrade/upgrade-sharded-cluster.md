(upgrade-sharded-cluster)=
# How to upgrade (refresh) a sharded cluster

This guide goes over the steps to perform a minor in-place upgrade via `juju refresh` for a sharded cluster. Going forward, we will use the word "refresh" instead of "upgrade".

```{include} upgrade-replica-set.md
    :start-after: <!--start-include-->
    :end-before: <!--end-include-->
```

(refresh-the-config-server)=
## Refresh the config-server

Upgrade your config-server following the instructions in {ref}`upgrade-replica-set`.

```{warning}
Do not proceed if this step was not successful. If your refresh failed, {ref}`roll back <roll-back>` the cluster.
```

## Begin the refresh

After successfully refreshing your config-server, the next step is to upgrade your shards.

Refresh each shard **one at a time**. Start by refreshing the first shard, and follow the instructions in {ref}`upgrade-replica-set`.

Before upgrading the last shard, leave a burn-in period to ensure that everything is working correctly and that you do not have any kind of regression.

Only refresh the next shard when the current refresh succeeds - i.e. all units show `active` and `idle` statuses.

```{warning} 
Do not proceed if an upgrade of a shard fails. If an upgrade fails, {ref}`roll back <roll-back>` the entire cluster.
```

## Upgrade mongos application

Next, upgrade any integrated mongos application.

See:
* [Charmed Mongos VM > How to perform a minor upgrade](https://charmhub.io/mongos/docs/h-minor-upgrade)
* [Charmed Mongos K8s > How to perform a minor upgrade](https://charmhub.io/mongos-k8s/docs/h-minor-upgrade) 
