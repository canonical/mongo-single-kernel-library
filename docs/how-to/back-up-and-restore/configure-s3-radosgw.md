(configure-s3-radosgw)=

# How to configure S3 storage on Microceph with RadosGW

Microceph S3-compatible RadosGW storage can be configured for Charmed MongoDB replica sets and sharded clusters with the [`s3-integrator` charm](https://charmhub.io/s3-integrator).

## Prerequisites

* A replica set with at least three nodes **or** a sharded cluster with at least one shard
  * See {ref}`scale-replicas-and-shards`

## Configure RadosGW

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

You can now refer to {ref}`configure-s3-aws` to configure `s3-integrator`.
In the configuration parameters, take care to add `tls-ca-chain="$(base64 -w0 cert.pem)` to provide the certificate created above.
