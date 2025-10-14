(manage-client-connections)=
# How to manage a client connection

[Integrations](https://documentation.ubuntu.com/juju/3.6/reference/relation/) (relations) are connections between two applications with compatible endpoints. These connections simplify the creation and management of users, passwords, and other shared data.

## Connect to a bare replica set

To create a client connection to a replica set, integrate your client application with a Charmed MongoDB application running as a replica set.

```{note}
If you do not have a client application that implements the [`database` endpoint](https://charmhub.io/integrations/mongodb_client#developer-documentation), you can use the [`data-integrator` charm](https://github.com/canonical/data-integrator).
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

```{note}
If you do not have a client application that implements the [`database` endpoint](https://charmhub.io/integrations/mongodb_client#developer-documentation), you can use the [`data-integrator` charm](https://github.com/canonical/data-integrator).
```

````{tab-set}
```{tab-item} VM
:sync: vm

    juju deploy mongos
    juju deploy <application>

Wait for `mongos`'s status to be `idle`, then integrate it with `<application>`.

    juju integrate mongos <application>

Integrate the `mongos` charm to a Charmed MongoDB application running as a config-server:

    juju integrate config-server mongos

To disable the client connection and the user associated with it, remove the integration:

    juju remove-relation config-server mongos
```

```{tab-item} K8s
:sync: k8s

    juju deploy mongos-k8s
    juju deploy <application>

Wait for `mongos-k8s`'s status to be `idle`, then integrate it with `<application>`.

    juju integrate mongos-k8s <application>

Integrate the `mongos` charm to a Charmed MongoDB application running as a config-server:

    juju integrate config-server mongos-k8s

To disable the client connection and the user associated with it, remove the integration:

    juju remove-relation config-server mongos-k8s
```
````

### Rotate the `mongos` client password

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

### External connection (K8s only)

To connect to a sharded cluster outside of Juju, 

````{tab-set}
```{tab-item} VM
:sync: vm

This section does not apply to Charmed MongoDB VM.
```

```{tab-item} K8s
:sync: k8s

To connect to a sharded MongoDB K8s cluster from outside of Juju, set the `expose-external` configuration option on `mongos-k8s`:

    juju config mongos-k8s expose-external=nodeport

You can see that all of your client URIs have been updated by running

    juju run data-integrator get-credentials

To reconfigure the charm for internal access only, set `expose-external` to `none`.
```
````

## Internal operator user

The `operator` (admin) user is used internally by the MongoDB charm for database and cluster management tasks. <!--See {ref}`users` for more information.-->

To rotate its password, use the {command}`set-password` action:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju run mongodb/leader set-password password=<new password>
```

```{tab-item} K8s
:sync: k8s

    juju run mongodb-k8s/leader set-password password=<new password>
```
````