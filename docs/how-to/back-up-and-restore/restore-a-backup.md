# How to restore a backup

This is a guide on how to perform a basic restore of a local backup of your Charmed MongoDB replica set or sharded cluster.

## Prerequisites

* Configured settings for S3 storage
  * See: {ref}`configure-s3-aws`
* A replica set with at least three nodes **or** a sharded cluster with at least one shard
  * See: {ref}`scale-replicas-and-shards`
* An existing backup in your S3 storage
  * See: {ref}`create-a-backup`

## List all backups

First, determine the name of the application to pass to Juju when running back up and restore actions:

* For a **replica-set deployment**, it is the name of your Charmed MongoDB application
* For a **sharded cluster deployment**, it is the name of the Charmed MongoDB config-server application. *Never the shard applications!*

---

To list all available backups, run

```shell
juju run <replica-set name | config-server name>/leader list-backups
```

The output will be similar to the format below:

```text
backup-id             | backup-type  | backup-status
----------------------------------------------------
YYYY-MM-DDTHH:MM:SSZ  | logical      | finished 
```

## Restore a backup

```{caution}
Before restoring a backup, make sure your Charmed MongoDB deployment is `active` and `idle`.
```

To restore a backup from the list, use the {command}`restore` command:

```shell
juju run <replica-set name | config-server name>/leader restore backup-id=YYYY-MM-DDTHH:MM:SSZ
```

The restore will now be in progress.
