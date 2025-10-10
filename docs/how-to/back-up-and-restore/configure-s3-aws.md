(configure-s3-aws)=
# How to configure S3 storage on AWS

[Amazon S3](https://aws.amazon.com/s3/) storage can be configured for Charmed MongoDB replica sets and sharded clusters with the [`s3-integrator` charm](https://charmhub.io/s3-integrator).

## Prerequisites
* An existing bucket in Amazon S3 
* A replica set with at least three nodes **or** a sharded cluster with at least one shard
  * See {ref}`scale-replicas-and-shards`

## Configure `s3-integrator`

Deploy `s3-integrator`:

```shell
juju deploy s3-integrator
```

Sync your `s3-integrator` credentials:

```shell
juju run s3-integrator/leader sync-s3-credentials access-key=<access-key> secret-key=<secret-key>
```

To configure `s3-integrator`, run `juju config` with the [relevant parameters](https://charmhub.io/s3-integrator/configure) to your S3 storage. 

For example:

```shell
juju config s3-integrator path="my/path" region="us-west-2" bucket="pbm-test-bucket-1" endpoint="https://s3.amazonaws.com"
```

## Pass S3 configuration to MongoDB

First, determine the name of the application to pass to Juju when running back up and restore actions:

* For a **replica-set deployment**, it is the name of your Charmed MongoDB application
* For a **sharded cluster deployment**, it is the name of the Charmed MongoDB application with the `config-server` role. *Never the shard applications!*

---

To integrate your deployment with `s3-integrator`, run:

```shell
juju integrate s3-integrator <replica-set-name | config-server-name>
```

```{note}
You can also update your configuration options after integrating:

    juju config s3-integrator endpoint=<endpoint-name>
```