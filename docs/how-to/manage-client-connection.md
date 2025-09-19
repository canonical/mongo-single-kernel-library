(manage-client-connections)=
# How to manage a client connection

[Integrations](https://documentation.ubuntu.com/juju/3.6/reference/relation/) (also called "relations") are connections between two applications with compatible endpoints. These connections simplify the creation and management of users, passwords, and other shared data.

## Connect to a bare replica set

To create a client connection to a replica set, simply integrate your client application with a Charmed MongoDB application running in replication mode.

<!-- TODO: clarify "replication mode" and interface/endpoint we're referring to below -->

```{note}
If you do not have a client application that implements this interface, you can use the [`data-integrator` charm](https://github.com/canonical/data-integrator).
```

To integrate MongoDB with a client application, run:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju integrate mongodb <application>
```

```{tab-item} K8s
:sync: k8s

    juju integrate mongodb-k8s <application>
```
````

To disable the client connection and the user associated with it, remove the integration:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju remove-relation mongodb <application>
```

```{tab-item} K8s
:sync: k8s

    juju remove-relation mongodb-k8s <application>
```
````

### Rotate the client password

To rotate the replica set client user credentials, remove and re-relate the applications. 

````{tab-set}
```{tab-item} VM
:sync: vm

    juju remove-relation <application> mongodb
    juju integrate <application> mongodb
```

```{tab-item} K8s
:sync: k8s

    juju remove-relation <application> mongodb-k8s
    juju integrate <application> mongodb-k8s
```
````

This process will generate a new user and password for the application.

## Connect to a sharded cluster

To create a client connection to a sharded cluster, you must use the `mongos` router.

<!-- TODO: clarify role of mongos in VM and K8s context, and clarify role of data-integrator -->

To deploy `mongos` and [`data-integrator`](https://charmhub.io/data-integrator), run:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy mongos
    juju deploy data-integrator <options>

Wait for `mongos`'s status to be `idle`, then integrate it with `data-integrator`.

    juju integrate mongos data-integrator

Integrate the `mongos` charm to a Charmed MongoDB application running as a config-server:

    juju integrate config-server mongos

To disable the client connection and the user associated with it, remove the integration:

    juju remove-relation config-server mongos
```

```{tab-item} K8s
:sync: k8s

    juju deploy mongos-k8s
    juju deploy data-integrator <options>

Wait for `mongos-k8s`'s status to be `idle`, then integrate it with `data-integrator`.

    juju integrate mongos-k8s data-integrator

Integrate the `mongos` charm to a Charmed MongoDB application running as a config-server:

    juju integrate config-server mongos-k8s

To disable the client connection and the user associated with it, remove the integration:

    juju remove-relation config-server mongos-k8s
```
````

```{seealso}
[`data-integrator` configuration options](https://charmhub.io/data-integrator/configurations)
```

### Rotate the `mongos` client password

<!--TODO: Need technical review of VM and K8s docs for this
https://charmhub.io/mongodb-k8s/docs/h-manage-client-connections#create-a-client-connection-to-a-sharded-cluster

https://charmhub.io/mongodb/docs/h-manage-client-connections#heading--sharded-cluster
 -->

To rotate user credentials, remove and re-relate the client application and `mongos`. 

````{tab-set}
```{tab-item} VM
:sync: vm

    juju remove-relation <application> mongos
    juju integrate <application> mongos
```

```{tab-item} K8s
:sync: k8s

    juju remove-relation <application> mongos-k8s
    juju integrate <application> mongos-k8s
```
````