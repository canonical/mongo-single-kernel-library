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

## Deploy MongoDB 7 cluster

This first step towards migrating to MongoDB 8 is to upgrade to a transition cluster on MongoDB 7.

```{admonition} Safety precaution
    :class: warning
Until you have fully deployed MongoDB 8, ensured it is stable and verified there are no regressions, **keep your MongoDB 6 cluster running** and do not switch the load to the new cluster!
```

{ref}`Deploy <how-to-deploy>` a MongoDB 7 cluster from the Charmhub channel `8-transition/edge` with the same topology as your initial cluster. For example, if your cluster has 1 config-server and three shards, your `8-transition` cluster should also have 1 config-server and three shards.

Then, integrate the new cluster with S3-integrator. If you're deploying your new cluster in the same model, it should be as easy as {command}`juju integrate mongodb-seven s3-integrator`. See {ref}`configure-s3-aws` for more information.

Replicate all the passwords from your initial application to the new one:

```shell
for username in backup orchestrator monitor logrotate; do
    password=$(juju run <app>/leader get-password username=$username);
    juju run <app>-seven/leader set-password username=$username password=$password;
done
```

## Back up MongoDB 6 cluster

Now, create a backup of the initial cluster, and note the `<backup-id>`. Wait for it to finish.

```shell
juju run <app>/leader create-backup
```

{ref}`Log into your MongoDB 7 cluster <access-a-replica-set>` and set the feature compatibility version to `6.0`. This will allow a safe restore to the new cluster.

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

Replicate all the passwords from your initial application to the new one:

```shell
for username in backup orchestrator monitor logrotate; do
    password=$(juju run <app>/leader get-password username=$username);
    juju run <app>-eight/leader set-password username=$username password=$password;
done
```

## Back up MongoDB 7 cluster

Now, create a backup of the MongoDB 7 cluster, and note the `<backup-id>`. Wait for it to finish.

```shell
juju run <app>-seven/leader create-backup
```

{ref}`Log into your cluster <access-a-replica-set>` and set the feature compatibility version to `7.0`. This will allow a safe restore to the new cluster.

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
