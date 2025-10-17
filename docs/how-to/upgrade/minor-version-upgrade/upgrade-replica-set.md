(upgrade-replica-set)=
# How to upgrade (refresh) a replica set

This guide goes over the steps to perform a minor in-place upgrade via `juju refresh` for a replica set. Going forward, we will use the word "refresh" instead of "upgrade".

<!--start-include-->
```{seealso}
To upgrade from MongoDB 6 to 8, see {ref}`major-version-upgrade`.
```

## Before refreshing

**Ensure your MongoDB deployment is healthy** (`active` and `idle`), and not performing any long-running operations such as creating a backup.

**Do not perform any extraordinary operations on your cluster while refreshing**, as it can lead the cluster into inconsistent states. Some dangerous operations could be:
* Adding or removing units
* Creating or destroying relations
* Upgrading other related applications simultaneously

**Make sure to have created and tested a backup of your data.** See: {ref}`create-a-backup`.

**Take note of your MongoDB application's current revision**:

```shell
juju status | grep <app-name> | head -1 | awk '{print $5}'
```

Save this number in case you need to roll back your application.
<!--end-include-->

(run-a-pre-refresh-check)=
## Run a pre-refresh check

Before refreshing, the charm needs to perform some preparatory tasks to define the refresh plan. 

Run the pre-refresh-check action against the leader unit of your MongoDB application:

```shell
juju <app-name>/leader pre-refresh-check 
```

```{warning} 
Do not proceed if this action is unsuccessful.
```

## Begin the refresh

To begin the refresh process, run

```shell
juju refresh <app-name> --revision=<new-revision>
```

It may take a minute before the charm receives the `refresh` command. When it does, the units will begin to execute the command. 

Wait until `juju status --watch 1s` shows that all units in your deployment are `idle`. 

The refresh process upgrades the charm and services inside the charm. There are three possible outcomes:
* {ref}`Case 1 <case-1>`: Successful upgrade - where the new charm uses the same underlying snap
* {ref}`Case 2 <case-2>`: Successful upgrade - where the new charm uses a new underlying snap
* {ref}`Case 3 <case-3>`: Failure to upgrade

(case-1)=
### Case 1: Success (same snap)

If the new charm revision uses the same underlying snap, all units will finish refresh automatically. If the refresh is successful, your {command}`juju status` will show something similar to:

```text
App      Version  Status  Scale  Charm    Channel  Rev  Exposed  Message
mongodb           active      3  mongodb             2  no

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        10.84.191.38    27017/tcp
mongodb/1   active    idle   1        10.84.191.252   27017/tcp
mongodb/2   active    idle   2        10.84.191.189   27017/tcp

Machine  State    Address        Inst id        Base          AZ  Message
0        started  10.84.191.38   juju-9ac398-0  ubuntu@22.04      Running
1        started  10.84.191.252  juju-9ac398-1  ubuntu@22.04      Running
2        started  10.84.191.189  juju-9ac398-2  ubuntu@22.04      Running
```

If this is the case, proceed directly to section {ref}`verify-the-success-of-the-refresh`.

(case-2)=
### Case 2: Success (new snap)

If the new revision has a new underlying snap, the charm only refreshes the first unit and waits for you to proceed with the refresh.

Your model will show that the first unit has successfully upgraded and you will see the following message in {command}`juju status`: 

```text
Refreshing. Verify highest unit is healthy & run `resume-refresh` action. To rollback, `juju refresh` to last revision
```

Running {command}`juju status | grep mongo | awk 'END{print $2 " " $3}'` outputs `active idle`.

If this is the case, proceed to section {ref}`continue-the-refresh`.

(case-3)=
### Case 3: Failure to refresh

If your upgrade failed, then ` juju status` will show that the unit is blocked with the message `Unhealthy after refresh`. 

If the upgrade of the first unit failed, you can:

* Wait for 5-10 minutes to see if the cluster can heal itself 
* Roll back. To roll back, repeat the refresh steps starting from {ref}`run-a-pre-refresh-check` using the original revision number.

```{warning}
In extreme cases, a refresh can be forced by running `juju run <app-name>/leader force-refresh-start`.

**This is NOT recommended - it can break your database**
```

(continue-the-refresh)=
## Continue the refresh

Before continuing the upgrade, verify that your deployment is healthy. The charm performs a simple health check after upgrading the unit, but it is suggested that the user verifies that the database is indeed healthy.

To proceed with the upgrade run the `resume-refresh` action on the leader of the deployment:

```shell
juju <app-name>/leader resume-refresh
```

(verify-the-success-of-the-refresh)=
## Verify the success of the refresh

Wait until `juju status --watch 1s` shows all units in the `active` status. If all nodes in your Charm MongoDB deployment are `active`, your upgrade was successful. 

If your upgrade failed, you should see the charm go into the `blocked` state with the message `Unhealthy after refresh`. 

* Wait for 5-10 minutes to see if the cluster can heal itself 
* Roll back. To roll back, repeat the refresh steps starting from {ref}`run-a-pre-refresh-check` using the original revision number.

```{warning}
In extreme cases, a refresh can be forced by running `juju run <app-name>/leader force-refresh-start`.

**This is NOT recommended - it can break your database**
```