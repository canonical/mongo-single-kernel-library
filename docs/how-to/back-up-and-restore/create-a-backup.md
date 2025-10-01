# How to create a backup

This is a guide on how to create and list backups of a Charmed MongoDB replica set or sharded cluster using Amazon S3 storage. 

## Prerequisites
* Configured settings for S3 storage
  * See: {ref}`configure-s3-aws`
* A replica set with at least three nodes **or** a sharded cluster with at least one shard
  * See: {ref}`scale-replicas-and-shards`

## Create a backup

First, determine the name of the application to pass to Juju when running back up and restore actions:

* For a **replica-set deployment**, it is the name of your Charmed MongoDB application
* For a **sharded cluster deployment**, it is the name of the Charmed MongoDB application with the `config-server` role. *Never the shard applications!*

---

Check that your MongoDB deployment is `active` and `idle` with {command}`juju status`.

To create a backup, use the {command}`create-backup` action on the leader unit:

```shell
juju run <replica-set name | config-server name>/leader create-backup
```

## List all backups

To list all available, failed, and in-progress backups, use the {command}`list-backup` action on the leader unit:

```shell
juju run <replica-set name | config-server name>/leader list-backups
```
