(enable-tls-mongos)=
# How to enable TLS

If the sharded MongoDB cluster has TLS enabled, `mongos` must also enable TLS. Enable it by integrating `mongos` with a TLS application:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju integrate mongos <tls-application>
```

```{tab-item} K8s
:sync: k8s

    juju integrate mongos-k8s <tls-application>
```
````

`<tls-application` must be the same TLS application that the sharded MongoDB cluster is integrated to. 

For more information about TLS in sharded clusters, see the Charmed MongoDB documentation for {ref}`enabling security in sharded clusters <enable-tls>`.

## Remove the connection

To remove a `mongos` connection to the sharded cluster, run:

````{tab-set}
```{tab-item} VM
:sync: vm

    juju remove-relation config-server mongos
```

```{tab-item} K8s
:sync: k8s

    juju remove-relation config-server mongos-k8s
```
````

When`mongos` is removed from the sharded cluster, the client is removed as well.

## External connections (Kubernetes-only)
<!--TODO: VM -->

If you would like to connect the sharded MongoDB K8s cluster outside of Juju, this is possible with the configuration expose-external in the mongos-k8s charm.

Simply configure the charm to use `nodeport`:

```
juju config mongos-k8s expose-external=nodeport
```

This will make the mongos router accessible outside of Juju and will provide you access to the cluster. You will now see that all of your client URIs have been updated.

For example, if you run

```
juju run data-integrator get-credentials
```

You will see that the URI has changed.

To reconfigure the charm to have internal access only, run:

```
juju config mongos-k8s expose-external=none
```
