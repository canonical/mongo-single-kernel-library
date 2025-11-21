(advanced-statuses)=
# Advanced statuses

MongoDB charms leverages advanced statuses to provide and expose detailed, component-specific status information. This interface supports more complex and multiple statuses.

## Basics

Advanced statuses are implemented in the homebrewed [Data Platform Helpers](https://pypi.org/project/data-platform-helpers/) library.

Each component of the charm recomputes its statuses on every status-update event, and will sort the statuses by order of importance.

They are first order like `ops` does: `Error > Blocked > Maintenance > Waiting > Active  > Unknown` and then by component priority for an equal status level.

If multiple important (understand `Blocked`, `Maintenance` or `Waiting`) are reported, a special status is computed. This status has the priority of the most important status, and its message is the following:

```text
"<status message>. Run `status-detail`: X action required; Y additional statuses")
```

For example, the following `juju status` output shows an aggregated status for a charmed-mongodb sharded deployment.

```text
Model       Controller  Cloud/Region         Version  SLA          Timestamp
integ-test  overlord    localhost/localhost  3.6.8    unsupported  16:17:23+02:00

App                       Version  Status   Scale  Charm                     Channel        Rev  Exposed  Message
application                        active       1  application                                0  no
config-server             8.0.10   active       1  mongodb                                    0  no
config-server-two         8.0.10   active       1  mongodb                                    1  no
data-integrator                    blocked      1  data-integrator           latest/stable  180  no       Please specify either topic, index, database name, or prefix
mongos                             unknown      0  mongos                                     0  no
replication               8.0.10   active       1  mongodb                                    3  no
s3-integrator                      active       1  s3-integrator             latest/edge    192  no
self-signed-certificates           active       1  self-signed-certificates  1/stable       264  no
shard-one                 8.0.10   active       1  mongodb                                    2  no

Unit                         Workload  Agent  Machine  Public address  Ports            Message
application/0*               active    idle   7        10.137.178.161
config-server-two/0*         blocked   idle   1        10.137.178.124  27017-27018/tcp  Missing relation to shard(s).
config-server/0*             blocked   idle   0        10.137.178.103  27017-27018/tcp  Sharding roles do not support database i... Run `status-detail`: 1 action required; 2 additional statuses.
data-integrator/0*           blocked   idle   5        10.137.178.241                   Please specify either topic, index, database name, or prefix
replication/0*               active    idle   6        10.137.178.242  27017/tcp        Primary.
s3-integrator/0*             active    idle   4        10.137.178.92
self-signed-certificates/0*  active    idle   3        10.137.178.134
shard-one/0*                 blocked   idle   2        10.137.178.63   27017/tcp        Missing relation to config-server.

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.137.178.103  juju-86c745-0  ubuntu@24.04      Running
1        started  10.137.178.124  juju-86c745-1  ubuntu@24.04      Running
2        started  10.137.178.63   juju-86c745-2  ubuntu@24.04      Running
3        started  10.137.178.134  juju-86c745-3  ubuntu@22.04      Running
4        started  10.137.178.92   juju-86c745-4  ubuntu@22.04      Running
5        started  10.137.178.241  juju-86c745-5  ubuntu@24.04      Running
6        started  10.137.178.242  juju-86c745-6  ubuntu@24.04      Running
7        started  10.137.178.161  juju-86c745-7  ubuntu@24.04      Running
```

Due to their extended structure, advanced statuses contain more information than regular ones, providing developers with valuable hints for operators. They can specify an action to run to resolve a status and indicate which check led to the status being computed.

Statuses can be set as critical so that they override the regular flow and are displayed no matter what happens if they require immediate action.

## `status-detail` action

The `status-detail` action is a helper that provides extended access to the charm statuses.

Running this action will display all application and unit statuses. It includes an optional `recompute` argument that allows for status re-evaluation. When `recompute` is used, the system re-computes statuses for non-leader units and all statuses for leader units.

```{note}
Though the `recompute` flag will yield the most up-to-date status of the application, it can also come with a performance penalty depending on the list of deployed components. 
```
This action is particularly useful for debugging and understanding the charm's current state, as it provides a detailed view of all statuses, including those not visible in the standard status output.

Running the `status-detail` action produces output similar to the following:

```shell
juju run config-server/0 status-detail
```

```text
Running operation 9 with 1 task
  - task 10 on unit-config-server-0

Waiting for task 10...
16:16:55 Stored statuses:
16:16:55                      App Statuses

| Status | Component Name | Message | Action | Reason |
|--------|----------------|---------|--------|--------|
| Active | upgrade        |         | N/A    | N/A    |


16:16:55                      Unit Statuses
| Status   | Component Name | Message            | Action         | Reason |
|----------|----------------|--------------------|----------------|--------|
| Blocked  | mongod         | Sharding roles do  | N/A            | N/A    |
|          |                | not support        |                |        |
|          |                | database           |                |        |
|          |                | interface.         |                |        |
| Blocked  | backup         | s3 configurations  | N/A            | N/A    |
|          |                | missing.           |                |        |
| Blocked  | backup         | s3 credentials are | Check S3       | N/A    |
|          |                | incorrect.         | credentials on |        |
|          |                |                    | s3-integrator  |        |
| Active   | mongo          | Primary.           | N/A            | N/A    |
| Active   | upgrade        |                    | N/A            | N/A    |

json-output:
  app: '[{"Status": "Active", "Component Name": "upgrade", "Message": "", "Action":
    "N/A", "Reason": "N/A"}]'
  unit: '[{"Status": "Blocked", "Component Name": "mongod", "Message": "Sharding roles
    do not support database interface.", "Action": "N/A", "Reason": "N/A"}, {"Status":
    "Blocked", "Component Name": "backup", "Message": "s3 configurations missing.",
    "Action": "N/A", "Reason": "N/A"}, {"Status": "Blocked", "Component Name": "backup",
    "Message": "s3 credentials are incorrect.", "Action": "Check S3 credentials on
    s3-integrator", "Reason": "N/A"}, {"Status": "Active", "Component Name": "mongo",
    "Message": "Primary.", "Action": "N/A", "Reason": "N/A"}, {"Status": "Active",
    "Component Name": "upgrade", "Message": "", "Action": "N/A", "Reason": "N/A"}]'
```

This output provides a comprehensive view of statuses, detailing component names, messages, actions, and reasons for each status. The `json-output` section at the end offers a structured format, which is ideal for parsing by automation tools and scripts.

## Developing with advanced statuses

With advanced statuses, the charm never sets statuses directly but goes through the [Data Platform Helpers](https://pypi.org/project/data-platform-helpers/) advanced statuses module.

While documentation is available in the library, keep these key points in mind:

* Add new statuses to the status collection in `src/statuses.py`.
* Ensure your manager inherits from the `ManagerStatusProtocol`.
* Implement the `get_statuses(scope, recompute)` method within your manager.
* Add your manager to the list of those that report statuses in `src/charm.py`.

