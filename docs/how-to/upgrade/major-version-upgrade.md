(major-version-upgrade)=
# How to perform a major version upgrade

This guide explains how to upgrade from MongoDB 6 to MongoDB 8. This major upgrade requires stepping through an intermediary MongoDB 7 charm, so there are two upgrades involved: from 6 to 7, and finally from 7 to 8.

To summarize:

* Deploy a MongoDB 7 cluster from a dedicated Charmhub channel, and integrate it with `s3-integrator`.
* Replicate all credentials to the new cluster (so that you do not lock yourself out after the backup restore!)
* Create a backup on your MongoDB 6 cluster
* Restore the backup on the MongoDB 7 cluster
* Repeat the same steps to go from MongoDB 7 to 8

```{note}
In this guide, we refer to your orchestrator application as `<app>`. This is equivalent to:

* `mongodb` if you have replica set on VM
* `mongodb-k8s` if you have replica set on K8s
* `config-server` if you have sharded deployment
```

## Prerequisites

This guide requires that your MongoDB deployment is integrated with [S3-integrator](https://charmhub.io/s3-integrator). See: {ref}`configure-s3-aws`.  

If you are not relying on Amazon S3, you can use microceph and rados-gateway (or any S3-compatible storage). The {ref}`last section of this guide <configure-microceph-and-radosgw-for-backups>` shows how to install and configure them for the purpose of major version upgrades through backups.

## Add the MongoDB-8 internal users to MongoDB 6

MongoDB 8 uses different internal usernames. You must create the new users in the MongoDB 6 deployment before performing the upgrade.

| MongoDB 6      | MongoDB 7      | MongoDB 8         |
|----------------|----------------|-------------------|
| operator       | operator       | charmed-operator  |
| backup         | backup         | charmed-backup    |
| logrotate      | logrotate      | charmed-logrotate |
| monitor        | monitor        | charmed-stats     |

Retrieve the passwords for all MongoDB 6 internal users:

```shell
operator_password=$(juju run <app>/leader get-password username=operator)
backup_password=$(juju run <app>/leader get-password username=backup)
logrotate_password=$(juju run <app>/leader get-password username=logrotate)
monitor_password=$(juju run <app>/leader get-password username=monitor)
```

SSH into your deployment:

`````{tab-set}
````{tab-item} VM
:sync: vm

```shell
juju ssh <app>/leader
```
````

````{tab-item} K8s
:sync: k8s

```shell
juju ssh --container=mongod <app>/leader
```
````
`````

Create the MongoDB-8 internal users (`charmed-operator`, `charmed-backup`, `charmed-logrotate`, `charmed-stats`). Replace the password placeholders with the passwords previously obtained, and the `<app>` placeholder with your ochestrator application:

```shell
mongosh "mongodb://operator:<operator-password>@<app>-0.<app>-endpoints:27017/admin?replicaSet=<app>" --quiet --eval "db.createUser({user: 'charmed-operator', pwd: '<operator-password>', roles: [{role: 'userAdminAnyDatabase', db: 'admin'},{role: 'readWriteAnyDatabase', db: 'admin'}, {role: 'clusterAdmin', db: 'admin'}], mechanisms: ['SCRAM-SHA-256'], passwordDigestor: 'server'})"

mongosh "mongodb://operator:<operator-password>@<app>-0.<app>-endpoints:27017/admin?replicaSet=<app>" --quiet --eval "db.createUser({user: 'charmed-backup', pwd: '<backup-password>', roles: [{role: 'backup', db: 'admin'}, {role: 'readWrite', db: 'admin'}, {role: 'clusterMonitor', db: 'admin'}, {role: 'restore', db: 'admin'}, {role:'pbmAnyAction', db:'admin'}], mechanisms: ['SCRAM-SHA-256'], passwordDigestor: 'server'})"

mongosh "mongodb://operator:<operator-password>@<app>-0.<app>-endpoints:27017/admin?replicaSet=<app>" --quiet --eval "db.createUser({user: 'charmed-logrotate', pwd: '<logrotate-password>', roles: [{role: 'logRotate', db: 'admin'}], mechanisms: ['SCRAM-SHA-256'], passwordDigestor: 'server'})"

mongosh "mongodb://operator:<operator-password>@<app>-0.<app>-endpoints:27017/admin?replicaSet=<app>" --quiet --eval "db.createUser({user: 'charmed-stats', pwd: '<monitor-password>', roles: [{role: 'explainRole', db: 'admin'}, {role: 'clusterMonitor', db: 'admin'}, {role: 'read', db: 'local'}], mechanisms: ['SCRAM-SHA-256'], passwordDigestor: 'server'})"
```

## Deploy MongoDB 7 cluster

This first step towards migrating to MongoDB 8 is to upgrade to a transition cluster on MongoDB 7.

```{admonition} Safety precaution
    :class: warning
Until you have fully deployed MongoDB 8, ensured it is stable and verified there are no regressions, **keep your MongoDB 6 cluster running** and do not switch the load to the new cluster!
```

{ref}`Deploy <how-to-deploy>` a MongoDB 7 cluster from the Charmhub channel `8-transition/edge` with the same topology as your initial cluster. For example, if your cluster has 1 config-server and three shards, your `8-transition` cluster should also have 1 config-server and three shards.

Then, integrate the new cluster with S3-integrator. If you're deploying your new cluster in the same model, it should be as easy as {command}`juju integrate mongodb-seven s3-integrator`. See {ref}`configure-s3-aws` for more information.

Replicate all the passwords from your initial application to the new one. Create a new Juju secret including `operator`, `backup`, `logrotate` and `monitor` usernames and theirs passwords and set it to the `system-user` configuration option of your orchestrator application as it is decribe in {ref}`manage-passwords`.


## Back up MongoDB 6 cluster

Now, create a backup of the initial cluster, and note the `<backup-id>`. Wait for it to finish.

```shell
juju run <app>/leader create-backup
```

Log into your MongoDB 7 cluster and set the feature compatibility version to `6.0`. This will allow a safe restore to the new cluster.

```javascript
db.adminCommand(
    {
        setFeatureCompatibilityVersion: "6.0",
        confirm: true,
    }
)
```

## Restore backup on MongoDB 7 cluster

Restore the MongoDB 6 backup on the MongoDB 7 cluster:

```shell
juju run <app>-seven/leader restore backup-id=<backup-id>
```

For sharded clusters, see {ref}`how to define a remap pattern <define-remap-pattern-sharded-cluster>`.

This is the time to ensure stability of your deployment. When you are sure you want to continue, run:

```javascript
db.adminCommand(
    {
        setFeatureCompatibilityVersion: "7.0",
        confirm: true,
    }
)
```

Your cluster is now running MongoDB 7, and you can proceed to the next part of this documentation for upgrading to MongoDB 8.

## Deploy a MongoDB 8 cluster

These steps are pretty similar to the previous ones, but we will go through it again.

{ref}`Deploy <how-to-deploy>` a MongoDB 8 cluster from the Charmhub channel `8/stable` with the same topology as your initial cluster. For example, if your cluster has 1 config-server and three shards, your `8` cluster should also have 1 config-server and three shards.

Then, integrate that cluster with S3-integrator. If you're deploying your new cluster in the same model, it should be as easy as {command}`juju integrate mongodb-eight s3-integrator`. See {ref}`configure-s3-aws` for more information.

Replicate all the passwords from your initial application to the new one. Create a new Juju secret including `charmed-operator`, `charmed-backup`, `charmed-logrotate` and `charmed-stats` usernames and theirs passwords and set it to the `system-user` configuration option of your orchestrator application as it is decribe in {ref}`manage-passwords`.

## Back up MongoDB 7 cluster

Now, create a backup of the MongoDB 7 cluster, and note the `<backup-id>`. Wait for it to finish.

```shell
juju run <app>-seven/leader create-backup
```

Log into your cluster and set the feature compatibility version to `7.0`. This will allow a safe restore to the new cluster.

```javascript
db.adminCommand(
    {
        setFeatureCompatibilityVersion: "7.0",
        confirm: true,
    }
)
```

## Restore backup on MongoDB 8 cluster

```shell
juju run <app>-eight/leader restore backup-id=<backup-id>
```

For sharded clusters, see {ref}`how to define a remap pattern <define-remap-pattern-sharded-cluster>`.

This is the time to ensure stability of your deployment. When you are sure you want to continue, run:

```javascript
db.adminCommand(
    {
        setFeatureCompatibilityVersion: "8.0",
        confirm: true,
    }
)
```

Congratulations! Your cluster is now running MongoDB 8. We highly recommend giving it some time to ensure stability, and performing extensive testing before switching the load onto this new cluster.

(configure-microceph-and-radosgw-for-backups)=
## Configure MicroCeph and RadosGW for backups

This appendix will teach you how to deploy microceph and rados-gateway to take backups.

Start by installing the microceph snap:

```shell
sudo snap install microceph
```

Bootstrap a cluster, and add a disk:

```shell
sudo microceph cluster bootstrap
sudo microceph disk add loop,4G,3 # Chose the correct size accordingly
```

Create a certificate:

```shell
HOSTIP=$(hostname -I | cut -d" " -f 1)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj /CN=$HOSTIP -addext subjectAltName=IP:${HOSTIP}
```

And then enable `https` on microceph:

```shell
sudo microceph enable rgw --ssl-port 445 --ssl-certificate "$(base64 -w0 cert.pem)" --ssl-private-key "$(base64 -w0 key.pem)"
```

Create a user on rados-gateway for your chosen `<username>`:

```shell
sudo microceph.radosgw-admin user create --uid <username> --display-name <username>
```

This will output an `access_key` and a `secret_key`. Those are the credentials that you will use to configure your s3-integrator.

## Remove MongoDB-6 internal users from MongoDB 8

`operator`, `backup`, `logrotate` and `monitor` users are no longer needed in MongoDB 8, so they can be removed.

Replace the `<charmed-operator-password>` placeholders with the password previously obtained, and the `<app>` placeholder with your ochestrator application:

```shell
mongosh "mongodb://charmed-operator:<charmed-operator-password>@<app>-0.<app>-endpoints:27017/admin?replicaSet=<app>" --quiet --eval "db.dropUser('operator')"
mongosh "mongodb://charmed-operator:<charmed-operator-password>@<app>-0.<app>-endpoints:27017/admin?replicaSet=<app>" --quiet --eval "db.dropUser('backup')"
mongosh "mongodb://charmed-operator:<charmed-operator-password>@<app>-0.<app>-endpoints:27017/admin?replicaSet=<app>" --quiet --eval "db.dropUser('monitor')"
mongosh "mongodb://charmed-operator:<charmed-operator-password>@<app>-0.<app>-endpoints:27017/admin?replicaSet=<app>" --quiet --eval "db.dropUser('logrotate')"
```