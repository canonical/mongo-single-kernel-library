(upgrade-mongos)=
# How to upgrade

## Major version upgrade

This refers to an upgrade from MongoDB 6 to MongoDB 8.

After having upgraded your sharded cluster with (see {ref}`MongoDB - How to upgrade <how-to-upgrade>`), you can proceed to deploy a new Mongos VM application (see: {ref}`Mongos - How to deploy <deploy-mongos>`)) and relate it with the `config-server`.

Please note that **Mongos 6 and MongoDB 8 are not compatible, so you have to update them separately**.

Please also note that Mongos 8 is released on Ubuntu 24.04 base, which means the host application has to be deployed as well using an Ubuntu 24.04 base.

## Minor version  upgrade

This refers to an upgrade between different charm revisions of MongoDB 8.

(supported-revisions)=
### Supported revisions

Only upgrade from these supported revisions in a production environment.

VM:
* Revision 62
* Revision 78

K8s:
* Revision 54
* Revision 69

### Upgrade steps

Minor upgrades are performed using Juju's `refresh` command.

#### Step 1: Determine your current revision

Find your current revision with `juju status`:

```
juju status | grep <mongos-app-name> | head -1 | awk '{print $5}'
``` 

```{caution}
If your current revision is not in the list, then upgrade is not supported.
```

In the case that your upgrade is not successful, you will need this revision number to roll back your application.

(step-2-determine-new-revision)=
### Step 2: Determine new revision

Choose a revision to upgrade to from the {ref}`list of available revisions to upgrade to <supported-revisions>`

### Step 3: Upgrade the router

Using the revision from {ref}`Step 2 <step-2-determine-new-revision>`, upgrade your application

````{tab-set}
```{tab-item} VM
:sync: vm

    juju refresh mongos --revision=<revision number>
```
```{tab-item} K8s
:sync: k8s

    juju refresh mongos --revision=<revision number>
```
````

The upgrade should begin, and upgrade all deployed `mongos` routers. You can watch and wait for the upgrade to succeed with `juju status --watch 1s`.

If all units show `active` and `idle` statuses after upgrading, then your upgrade succeeded.

If your upgrade failed, then ` juju status` will show that the unit is blocked with the message `Unhealthy after refresh`. You can do the following:
1. Recommended: Wait for 5-10 minutes to see if the router can heal itself 
2. Recommended: Roll back. To roll back complete redo Step 3 using the revision from Step 2.
3. **Not Recommended**: Force an upgrade by running `juju run mongos/leader force-refresh-start`. Please **note this can break your database and is not recommended.**
