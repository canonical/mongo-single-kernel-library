(users)=
# Users

Charmed MongoDB has the following internal users:

| user        | function                                              |
|-------------|-------------------------------------------------------|
| `operator`  | Admin user that manages database/cluster (i.e. admin) |
| `monitor`   | Manages COS integration                               |
| `backup`    | Manages all backup operations                         |
| `logrotate` | Manages log rotation                                  |

Sample full dump of internal users on a newly installed Charmed MongoDB replica set:

<!--TODO: updated example of db.system.users.find() -->

```{caution}
These users are dedicated to the operator's logic, and **using them incorrectly could damage your deployment.**

Use the [data-integrator](https://github.com/canonical/data-integrator) charm to manage external credentials. To learn more, see {ref}`manage-client-connections`.
```
