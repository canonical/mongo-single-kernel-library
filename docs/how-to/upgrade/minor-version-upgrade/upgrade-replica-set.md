(upgrade-replica-set)=
# How to upgrade (refresh) a replica set

```{admonition} Emergency stop button
:class: attention
Use `juju config <app name> pause-after-unit-refresh=all` to halt an in-progress refresh.
Then, consider {ref}`rolling back <roll-back>`.
```

Charmed MongoDB supports minor version in-place refresh via the [`juju refresh`](https://documentation.ubuntu.com/juju/3.6/reference/juju-cli/list-of-juju-cli-commands/refresh/#details) command.


<!--start-include-->

```{seealso}
To upgrade from MongoDB 6 to 8, see {ref}`major-version-upgrade`.
```

<!--end-include-->

## Before refreshing

**Ensure your MongoDB deployment is healthy** (`active` and `idle`), and not performing any long-running operations such as creating a backup.

**Do not perform any extraordinary operations on your cluster while refreshing**, as it can lead the cluster into inconsistent states. They might work, but could put your cluster at risk. Some dangerous operations could be:
* Scaling up the application
* Scaling down the application—unless it is necessary for recovery
* Creating or removing relations
* Creating or restoring a backup (on the Juju application)
* Changes to config values (except `pause-after-unit-refresh`)
* Upgrading other related applications simultaneously

## Determine which version to refresh to

:**Take note of your MongoDB application's current revision**:
```shell
juju status | grep <app-name> | head -1 | awk '{print $7}'
```

(recommended-refreshes)=
### Recommended refreshes

These refreshes are well-tested and should be preferred.

```{eval-rst}
+--------------+------------+----------+--------------+------------+----------+-----------------------------------------------------------------------------------------------+
| .. centered:: From                   | .. centered:: To                     | Charm release notes to review                                                                 |
+--------------+------------+----------+--------------+------------+----------+                                                                                               |
| Charm        | MongoDB    | Snap     | Charm        | MongoDB    | Snap     |                                                                                               |
| revision     | Version    | revision | revision     | Version    | revision |                                                                                               |
+==============+============+==========+==============+============+==========+===============================================================================================+
|              |            |          |              |            |          |                                                                                               |
+--------------+------------+----------+--------------+------------+----------+-----------------------------------------------------------------------------------------------+
```


## Create a backup

See {ref}`create-a-backup`.

### Verify the backup

Verify the integrity of the backup by performing a test [restore on another application](/how-to/back-up-and-restore/migrate-a-cluster).
Check the restored data by ensuring that:
* recent data is present
* the data size is correct
* the data matches what you expected in the backup


## Read the rollback instructions

In the event that something goes wrong (e.g. the refresh fails, the new version of MongoDB is not performant enough, a database client is incompatible with the new version), you may want to quickly roll back.

Prepare for this possibility by reading through the entire refresh documentation—with special attention to the [](#halt-the-refresh) and [](#roll-back) sections—before starting the refresh.
Save this number in case you need to roll back your application.

## Review release notes

For every charm version between the version that you are refreshing from and to—and for the version you are refreshing to, review the release notes to understand what changed and if any action is required from you before, during, or after the refresh.

For [recommended refreshes](#recommended-refreshes), refer to the rightmost column of the table.

If the MongoDB versions that you are refreshing from and to are different, refer to the [upstream MongoDB release notes](https://docs.percona.com/percona-server-for-mongodb/8.0/release_notes/index.html) to understand what changed and if any action is required from you.

## Consider scaling up

During the refresh of the application, units will be restarted one by one.
While a unit is restarting, the performance of the cluster will be degraded.

To ensure that the cluster can handle all traffic during the refresh, consider scaling up the application by 1 unit.

(pre-refresh-check)=
## Run a pre-refresh check

Before refreshing, the charm needs to perform some preparatory tasks to define the refresh plan. 

Run the pre-refresh-check action against the leader unit of your MongoDB application:

```shell
juju <app-name>/leader pre-refresh-check 
```

```{warning} 
Do not proceed if this action is unsuccessful.
```

If the action succeeds, copy down the rollback command.
Keep the command available in case you need to [roll back](#roll-back).

(configure-pause-after-unit-refresh)=
## Configure `pause-after-unit-refresh`

After each unit is refreshed, the charm will perform automatic health checks.
We recommend supplementing the automatic checks with manual checks.

Examples of manual checks:
* Database clients are healthy and can connect to the refreshed units
* Transactions per second and resource consumption (CPU, memory, disk) are similar on refreshed and non-refreshed units
* Leaving the application in a partially-refreshed state (only some units refreshed) for several weeks and monitoring that the new version is stable in your environment

To facilitate your manual checks, the application can be configured to pause the refresh and wait for your confirmation.

Set the `pause-after-unit-refresh` config option to:
* `all` to wait for your confirmation after each unit refreshes
* `first` (default) to wait for your confirmation once, after the first unit refreshes
* `none` to never wait for your confirmation

For example:

```shell
juju config <app-name> pause-after-unit-refresh=all
```

```{note}
If the charm's automatic health checks fail, the refresh will be paused (until those health checks succeed) regardless of the value of the `pause-after-unit-refresh` config option.
```

## Begin the refresh

To begin the refresh process, run

```shell
juju refresh <app-name> --revision=<new-revision>
```

It may take a minute before the charm receives the `refresh` command. When it does, the units will begin to execute the command. 

(halt-the-refresh)=
## Halt the refresh

If something goes wrong, halt the refresh by running:

```shell
juju config <app-name> pause-after-unit-refresh=all
```

Next, assess the situation and plan the recovery.
Often, the safest recovery path is to [roll back](#roll-back).
Consider contacting us.


(roll-back)=
## Roll back

If something went wrong, the safest recovery path is often to roll back to the original version.

First, [halt the refresh](#halt-the-refresh).

Run the rollback command [you copied down earlier](#pre-refresh-check).
In most cases, the rollback command is also displayed in the application's status message in `juju status`.

### Resume the rollback

If more than one unit was refreshed before the rollback was started and `pause-after-unit-refresh` is set to `all` or `first`, your manual confirmation will be needed to complete the rollback.
The procedure for the rollback is the same as described in [](#monitor-the-refresh).

(reflect)=
### Reflect

After the application has been rolled back and you have confirmed that service has been fully restored, investigate what went wrong.

If applicable, please [file a bug report](https://github.com/canonical/mongo-single-kernel-library/issues).

Once you understand what went wrong and have tested that it has been fixed, the refresh can be attempted again.

(monitor-the-refresh)=
## Monitor the refresh

Use `juju status` to monitor the progress of the refresh.

In some cases, it may take a few minutes for the statuses to update after the refresh has started.

If the application status or any of the unit statuses are `blocked`, your action is required.
Follow the instructions in the status messages.

If the application status or any of the unit statuses are `error`, your action may be required.
Monitor `juju debug-log`.
The error may have been a temporary issue.
If the error persists, your action is required—consider [rolling back](#roll-back).

Monitor the refresh until it successfully finishes.
When the refresh completes, the application status will go from a message beginning with "Refreshing" to an `active` status with no message.

### Resume refresh

If `pause-after-unit-refresh` is set to `all` or `first` (default), your confirmation will be needed during the refresh.

The application status in `juju status` will instruct you when your confirmation is needed with the `resume-refresh` action.

Before running the `resume-refresh` action:
* Wait until all of the application's unit agent statuses are `idle`
* Wait until all of the refreshed units' workload statuses are `active`
* Perform [manual checks](#configure-pause-after-unit-refresh) to ensure that everything is healthy

Example of running the `resume-refresh` action on leader unit:

```shell
juju run <app-name>/leader resume-refresh
```

### Force refresh start

If anything wrong happens after the charm is refreshed, you might have to force the start of the refresh. Often, the safest way is to [roll back](#roll-back).
Consider contacting us.

This can happen in the following situations:
 * The charm you're refreshing to is incompatible: a status indicating the incompatibility will be displayed.
 * The health checks failed after the charm code was refreshed, which indicates that something is wrong. First, [reflect](#reflect) on the situation.


 If you really want to continue, this is at your own risk.
**This is NOT recommended - it can break your database**

 You can use the `force-refresh-start` command on the last upgraded unit (usually the unit with the highest unit id):

```shell
juju run <app-name>/leader force-refresh-start
```

This command has the following options:
 * check-compatibility: If `false`, force refresh if new version of MongoDB and/or charm is not compatible with previous version
 * run-pre-refresh-checks: If `false`, force refresh if app is unhealthy or not ready to refresh (and unit status shows "Pre-refresh check failed")
 * check-workload-container: MongoDB-k8s only, if `false`, allow refresh to MongoDB container version that has not been validated to work with the charm revision
