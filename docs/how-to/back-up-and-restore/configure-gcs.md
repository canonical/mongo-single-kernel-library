(configure-gcs)=

# How to configure GCS storage

[Google Cloud Storage](https://cloud.google.com/storage) can be configured for Charmed MongoDB replica sets and sharded clusters with the [`gcs-integrator` charm](https://charmhub.io/gcs-integrator).

## Prerequisites

* A GCP Service account with the minimum roles needed:
  * Read/write/List/delete objects (recommended minimum): roles/storage.objectAdmin
  * Manage buckets (if the bucket does not already exists): roles/storage.admin
* A replica set with at least three nodes **or** a shared cluster with a least one shard.
  * See {ref}`scale-replicas-and-shards`

## Configure `gcs-integrator`

Deploy `gcs-integrator`

```shell
juju deploy gcs-integrator --channel 1/edge
```

[Create a JSON file](https://cloud.google.com/iam/docs/keys-create-delete#creating) for your service account and download it to you local file system.

Add a new [secret](https://documentation.ubuntu.com/juju/3.6/reference/secret/#secret) containing the GCP service account key you just obtained to Juju, and grant its permissions to `gcs-integrator`:

```shell
juju add-secret mysecret secret-key#file=service_account.json
juju grant-secret mysecret gcs-integrator
```

The first command will return an ID like `secret:d0erdgfmp25c762i8np0`.

Then, configure the `gcs-integrator` with the newly created secret:

```shell
juju config gcs-integrator credentials=secret:d0erdgfmp25c762i7np0
```

To configure `gcs-integrator`, run `juju config` with the [relevant parameters](https://charmhub.io/gcs-integrator/configure) to your GCS storage.

Example:

```shell
juju config gcs-integrator bucket=<your-bucket> path="my/path" 
```

## Pass GCS configuration to MongoDB

First, determine the name of the application to pass to Juju when running back up and restore actions:

* For a **replica-set deployment**, it is the name of your Charmed MongoDB application
* For a **sharded cluster deployment**, it is the name of the Charmed MongoDB config-server application. *Never the shard applications!*


To integrate your deployment with `gcs-integrator`, run:

```shell
juju integrate gcs-integrator <replica-set-name | config-server-name>
```

Your GCS storage is now set up!
