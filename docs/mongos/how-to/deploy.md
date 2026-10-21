(deploy-mongos)=
# How to deploy Mongos

The following steps will guide you through briefly creating a client connection to a sharded MongoDB cluster via `mongos`, the router for queries and write operations in shared clusters.

You'll need a Juju environment and a {ref}`MongoDB application deployed as a sharded cluster <deploy-a-sharded-cluster>`.

## Deploy and integrate

To deploy `mongos` and `data-integrator`, run

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy mongos
    juju deploy data-integrator --config database-name=<name>
```

```{tab-item} K8s
:sync: k8s

    juju deploy mongos-k8s --trust
    juju deploy data-integrator --config database-name=<name>
```
````

Integrate `mongos` with `data-integrator` and with the `mongodb` application running as `config-server`:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju integrate mongos data-integrator
    juju integrate config-server mongos
```

```{tab-item} K8s
:sync: k8s

    juju integrate mongos-k8s data-integrator
    juju integrate config-server mongos-k8s
```
````

## Access the database via mongos

In order to access the integrated database, you will need the `mongos` URI. To retrieve this, run the following command:

```shell
juju run data-integrator/leader get-credentials
```

You will find the URI under the field `uris` in the output.

Then SSH into the unit and access the `mongo` shell:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju ssh mongos/0
    mongosh <URI>
```

```{tab-item} K8s
:sync: k8s

    juju ssh --container mongos mongos-k8s/0
    charmed-mongodb.mongosh <URI>
```
````
