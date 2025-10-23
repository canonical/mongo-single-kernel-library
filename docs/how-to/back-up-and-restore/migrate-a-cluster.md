(migrate-a-cluster)=
# How to migrate a cluster

Cluster migration via restore is a method of restoring a backup from a different cluster.

The following terms will be used throughout this guide:

```{glossary}
new cluster
    the backed-up cluster that we will migrate data from

old cluster
    the currently active cluster that will be restored to the state of the new cluster
```

## Prerequisites

* Configured settings for S3 storage
* Backups from the new cluster in your S3 storage
* Password from your new cluster
* For **bare replica sets**: The {term}`new cluster` must have a number of replicas equal to or greater than the {term}`old cluster`.
  * E.g. Your old cluster had 2 replicas, so your new cluster must have 2 or more replicas
* For **sharded clusters**: The {term}`new cluster` has a number of shards and replicas equal to or greater than those in the {term}`old cluster`.
  * E.g. Your old cluster had 2 shards, so your new cluster must have 2 or more shards. 
  * E.g. Your old shard had 4 replicas, so your new shard must have 4 or more replicas.

```{seealso}
* {ref}`configure-s3-aws`
* {ref}`create-a-backup`
* {ref}`scale-replicas-and-shards`
```

## Change old cluster's password

The migration process will restore the password from the {term}`new cluster` to your {term}`old cluster`.

Create a juju secret with the internal user's passwords in the new cluster:

```shell
juju add-secret <secret-name> charmed-operator=<password-1> charmed-backup=<password-2> charmed-stats=<password-3> charmed-logrotate=<password-4>
```

Note the secret URI obtained in the previous command and set it in the `system-users` configuration
option of your replica set or config server:

```shell
juju grant-secret <secret-name> <application-name>
juju config <application-name> system-users=<secret_URI>
```

```{seealso}
[How to > Manage passwords](/how-to/manage-passwords)
```

## List all backups

To view all available backups, use the {command}`list-backups` action:

```shell
juju run <replica-set name | config-server name>/leader list-backups
```

This shows a list of the available backups similar to the output below. Identify which {guilabel}`backup-id` corresponds to the new cluster:

```shell
backup-id             | backup-type  | backup-status
----------------------------------------------------
YYYY-MM-DDTHH:MM:SSZ  | logical      | finished 
```

(define-remap-pattern-sharded-cluster)=
## Define remap pattern (sharded cluster)

**If you are running Charmed MongoDB as a sharded cluster and you wish to migrate to a cluster with new names, you must generate a remap pattern.** If you are running Charmed MongoDB as a replica set, you can skip this step.

A remap pattern is a pattern that specifies which old components should be migrated to which new components. They are used when we are migrating to a cluster with new names. 

The following example shows how to create a remap pattern for a sample cluster migration.

Example {term}`old cluster`:

```shell
Model    Controller  Cloud/Region         Version  SLA          Timestamp
old-mod  overlord    localhost/localhost  3.1.6    unsupported  17:27:22Z

App            Version  Status   Scale  Charm       Channel  Rev  Exposed  Message
application             active       1  application            0  no
config-server           active       1  mongodb                0  no
shard1               active       1  mongodb                1  no
shard2               active       1  mongodb                2  no

Unit                         Workload  Agent  Machine  Public address  Ports            Message
application/0*               active    idle   4        10.130.84.77
config-server/0*             active    idle   0        10.130.84.120   27017-27018/tcp
self-signed-certificates/0*  active    idle   3        10.130.84.32
shard1/0*                 active    idle   1        10.130.84.78    27017/tcp
shard2/0*                 active    idle   2        10.130.84.68    27017/tcp
```

Example {term}`new cluster`:

```shell
Model    Controller  Cloud/Region         Version  SLA          Timestamp
new-mod  overlord    localhost/localhost  3.1.6    unsupported  17:27:22Z

App               Version  Status   Scale  Charm        Channel  Rev  Exposed  Message
application                active       1  application             0  no
config-server-new          active       1  mongodb                 0  no
shard1-new              active       1  mongodb                 1  no
shard2-new              active       1  mongodb                 2  no

Unit                         Workload  Agent  Machine  Public address  Ports            Message
application/0*               active    idle   4        10.130.84.77
config-server-new/0*         active    idle   0        10.130.84.120   27017-27018/tcp
self-signed-certificates/0*  active    idle   3        10.130.84.32
shard1-new/0*             active    idle   1        10.130.84.78    27017/tcp
shard2-new/0*             active    idle   2        10.130.84.68    27017/tcp
```

The following would be a valid remap pattern: 

```shell
config-server-new=config-server,shard1-new=shard1,shard2-new=shard2
```

## Restore the backup

To restore your current cluster to the state of the previous cluster, run the restore command and pass the correct `backup-id` to the command:

```shell
juju run <replica-set-name | config-server-name>/leader restore backup-id=YYYY-MM-DDTHH:MM:SSZ [remap-pattern=<remap-pattern>]
```

Your restore will then be in progress. Once it is complete, your {term}`old cluster` will represent the state of the {term}`new cluster`.