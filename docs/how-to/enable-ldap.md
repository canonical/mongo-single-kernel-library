(enable-ldap)=
# How to enable LDAP authentication

LDAP (Lightweight Directory Access Protocol) enables centralized authentication for MongoDB Replica Sets and Sharded Clusters, reducing the overhead of managing local credentials and access policies.

This guide goes over the steps to integrate LDAP as an authentication method with the MongoDB charm within the Juju ecosystem.

```{caution}
In this guide, we use [self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate) provided by the [`self-signed-certificates` operator](https://github.com/canonical/self-signed-certificates-operator).

**This is not recommended for a production environment.**

Check the collection of [Charmhub operators](https://charmhub.io/?q=tls-certificates) that implement the `tls-certificate` interface.
```

## Prerequisites 

````{tab-set}
```{tab-item} VM
:sync: vm

You'll need:
* Charmed MongoDB - Revision 213 or higher
* (Optional) Charmed Mongos - Revision 42 or higher
* A Kubernetes Juju controller
```

```{tab-item} K8s
:sync: k8s

You'll need:
* Charmed MongoDB K8s - Revision 64 or higher
* (Optional) Charmed Mongos - Revision 31 or higher
```
````

## Deploy an LDAP server on Kubernetes

````{tab-set}
```{tab-item} VM
:sync: vm

With MongoDB for machines, you'll need a separate Juju controller with a K8s model in order to deploy the [`glauth-k8s` charm](https://charmhub.io/glauth-k8s). We'll then create a cross-controller relation to the MongoDB VM model.

    juju switch <k8s-controller-name>
    juju add-model <k8s-model-name>
```

```{tab-item} K8s
:sync: k8s

With MongoDB for Kubernetes, you can simply deploy GLAuth alongside MongoDB without a separate Juju model.
```
````

Deploy `glauth-k8s`, `self-signed-certificates`, and `postgresql-k8s`:

```shell
juju deploy glauth-k8s --channel edge --trust
juju deploy self-signed-certificates
juju deploy postgresql-k8s --channel 14/stable --trust
```

Integrate `glauth-k8s` with `self-signed-certificates` and `postgresql-k8s`:

```shell
juju integrate glauth-k8s self-signed-certificates
juju integrate glauth-k8s postgresql-k8s
```

Deploy the [`glauth-utils` charm](https://charmhub.io/glauth-utils) to manage LDAP users, and integrate it with the GLAuth application:

```shell
juju deploy glauth-utils --channel edge --trust
juju integrate glauth-k8s glauth-utils
```

Users and groups can now be created using `glauth-utils`.

## Create a cross-model relation (VM only)

`````{tab-set}
````{tab-item} VM
:sync: vm

## Expose cross-controller URLs

Enable the required MicroK8s plugin:

```shell
IPADDR=$(ip -4 -j route get 2.2.2.2 | jq -r '.[] | .prefsrc')
sudo microk8s enable metallb $IPADDR-$IPADDR
```

Deploy the [Traefik charm](https://charmhub.io/traefik-k8s) in order to expose endpoints from the K8s cluster:

```shell
juju deploy traefik-k8s --trust
```

Integrate the two applications:

```shell
juju integrate traefik-k8s glauth-k8s:ingress
```

## Expose cross-model relations

To offer the GLAuth interfaces, run:

```shell
juju offer glauth-k8s:ldap ldap
juju offer glauth-k8s:send-ca-cert send-ca-cert
```

## Consume offers

Switch to the VM controller:

```shell
juju switch <lxd_controller>:<my-model>
```

Consume the LDAP offers:

```shell
juju consume <k8s_controller>:admin/glauth.ldap
juju consume <k8s_controller>:admin/glauth.send-ca-cert
```
````

````{tab-item} K8s
:sync: k8s

This step is not needed with MongoDB K8s. Proceed to the next section: [](configure-roles).
````
`````

(configure-roles)=
## Configure roles

With the MongoDB LDAP integration, you must define roles whose names are the exact Distinguished Name (DN) of a group in the LDAP directory.

For example, if you have a group named `ou=superheroes,ou=users,dc=glauth,dc=com`, create a role such as:

```javascript
db.createRole({role: 'ou=superheroes,ou=users,dc=glauth,dc=com', 
               privileges: [], 
               roles: [{'db': 'superdb', 'role': 'readWrite'}]
               })
```

```{admonition} Disclaimer
:class: warning

The GLAuth service returns all groups as members of the Organizational Unit (OU) `users`, meaning you must add `ou=users` in the DN of your group when creating your role.
```

At this stage, you can fine tune some parameters used by MongoDB using two config options:

**For a MongoDB replica set**:

```shell
juju config mongodb ldap-query-template="" ldap-user-to-dn-mapping=""
```

**For a MongoDB sharded cluster**:

```shell
juju config <config-server-name> ldap-query-template="" ldap-user-to-dn-mapping=""
```

`ldap-query-template` 
: Query template used to get the group of a user

`ldap-user-to-dn-mapping`
: Maps usernames to LDAP Distinguished Names for the users

These two configuration parameters are explained in detail in [the Percona Server for MongoDB documentation](https://docs.percona.com/percona-server-for-mongodb/6.0/ldap-setup.html), and in their descriptions accessible [via the Juju CLI](https://documentation.ubuntu.com/juju/3.6/reference/juju-cli/list-of-juju-cli-commands/config/#command-juju-config).

``````{dropdown} Example

John Doe is a member of the group `ou=superheroes,ou=users,dc=glauth,dc=com`.

To allow the user `cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com` to authenticate using the username `johndoe@superheroes`, one could configure the following mapping:

`````{tab-set}
````{tab-item} VM
:sync: vm

**For a MongoDB replica set**:

```shell
juju config mongodb ldap-query-template="dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))" ldap-user-to-dn-mapping='[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]'
```
````

````{tab-item} K8s
:sync: k8s

**For a MongoDB replica set**:

```shell
juju config mongodb-k8s ldap-query-template="dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))" ldap-user-to-dn-mapping='[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]'
```
````
`````

**For a MongoDB sharded cluster**:
```shell
juju config <config-server-name> ldap-query-template="dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))" ldap-user-to-dn-mapping='[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]'
```
``````

## Enable LDAP

To enable LDAP authentication on MongoDB, integrate the MongoDB charm with the GLAuth charm. 

`````{tab-set}
````{tab-item} VM
:sync: vm

**For a MongoDB replica set**:

```shell
juju integrate mongodb:ldap ldap:ldap
juju integrate mongodb:ldap-certificate-transfer send-ca-cert:send-ca-cert
```

**For a MongoDB sharded cluster**:

```shell
juju integrate <config-server-name>:ldap ldap:ldap
juju integrate <config-server-name>:ldap-certificate-transfer send-ca-cert:send-ca-cert
```

If you are using the [`mongos` router](https://charmhub.io/mongos), integrate it with the GLAuth charm in the same way as the MongoDB application. The mongos charm supports LDAP starting from revision 42.
````

````{tab-item} K8s
:sync: k8s

**For a MongoDB replica set**:

```shell
juju integrate mongodb-k8s:ldap glauth-k8s:ldap
juju integrate mongodb-k8s:ldap-certificate-transfer glauth-k8s:send-ca-cert
```

**For a MongoDB sharded cluster**:

```shell
juju integrate <config-server-name>:ldap glauth-k8s:ldap
juju integrate <config-server-name>:ldap-certificate-transfer glauth-k8s:send-ca-cert
```

If you are using the [`mongos` router](https://charmhub.io/mongos-k8s), integrate it with the GLAuth charm in the same way as the MongoDB application. The mongos charm supports LDAP starting from revision 31.
````
`````

When everything has stabilised, you will be able to log in using your username `johndoe@superheroes` and your LDAP password. You will inherit from the permissions granted by the roles corresponding to your LDAP groups.

## Disable LDAP

You can disable LDAP by removing the relations with GLAuth.

`````{tab-set}
````{tab-item} VM
:sync: vm

If you are using the [`mongos` router](https://charmhub.io/mongos), remove the relations in the same way as the MongoDB application shown below.

**For a MongoDB replica set**:
```shell
juju remove-relation mongodb:ldap-certificate-transfer send-ca-cert:send-ca-cert
juju remove-relation mongodb:ldap ldap:ldap
```

**For a MongoDB sharded cluster**:
```shell
juju remove-relation <config-server-name>:ldap-certificate-transfer send-ca-cert:send-ca-cert
juju remove-relation <config-server-name>:ldap ldap:ldap
```

````

````{tab-item} K8s
:sync: k8s

If you are using the [`mongos` router](https://charmhub.io/mongos-k8s), remove the relations in the same way as the MongoDB application shown below.

**For a MongoDB replica set**:
```shell
juju remove-relation mongodb-k8s:ldap-certificate-transfer glauth-k8s:send-ca-cert
juju remove-relation mongodb-k8s:ldap glauth-k8s:ldap
```

**For a MongoDB sharded cluster**:
```shell
juju remove-relation <config-server-name>:ldap-certificate-transfer glauth-k8s:send-ca-cert
juju remove-relation <config-server-name>:ldap glauth-k8s:ldap
```
````
`````