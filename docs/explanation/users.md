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

\`\`\`
[
  {
    _id: 'admin.operator',
    userId: UUID('d2d91b91-e8e2-462c-85a2-bf4683bb6a8d'),
    user: 'operator',
    db: 'admin',
    credentials: {
      'SCRAM-SHA-256': {
        iterationCount: 15000,
        salt: 's2k6kiohM0A67XqUb30RvkCrWYOM5J7VPXwnxQ==',
        storedKey: 'tz0RKnDBnZbPng0Rr+/AXXVstQ9SLMHCYXtd3R2MPF8=',
        serverKey: 'Vy9eP0MgJS5kXtLvw5TvFuK0lOmTNfaJupH1zBaH0Gs='
      }
    },
    roles: [
      { role: 'readWriteAnyDatabase', db: 'admin' },
      { role: 'clusterAdmin', db: 'admin' },
      { role: 'userAdminAnyDatabase', db: 'admin' }
    ]
  },
  {
    _id: 'admin.monitor',
    userId: UUID('68d02deb-bac1-4bbf-bfde-60d746fb1aa0'),
    user: 'monitor',
    db: 'admin',
    credentials: {
      'SCRAM-SHA-256': {
        iterationCount: 15000,
        salt: 'tamz+zpLH/3kR+DHyP4jws1eqDJ1kc8CimHcmA==',
        storedKey: 'gqsvj4/aaJPworoqDpGkbdWEXwovp3X1kBu5wkF8+nw=',
        serverKey: '42zLkiE7sq/xaBxX3QSjKdyqqluCogFnIzv2BAue4vY='
      }
    },
    roles: [
      { role: 'clusterMonitor', db: 'admin' },
      { role: 'read', db: 'local' },
      { role: 'explainRole', db: 'admin' }
    ]
  },
  {
    _id: 'admin.backup',
    userId: UUID('88e4b516-43a8-4679-a2f9-5bd4f79f6f57'),
    user: 'backup',
    db: 'admin',
    credentials: {
      'SCRAM-SHA-256': {
        iterationCount: 15000,
        salt: 'R6IZOgbk97I9ZYhMXCUpN35yliCrRr3WgCVK9Q==',
        storedKey: 'hOa6YE+CBq504oNn1W7Op+DtIyO1dPO6dm9sFE6qwUo=',
        serverKey: 'Q2kLTrf2oRpGJc0c9xQZtALZeLOlVYc7/sBhk5zwywY='
      }
    },
    roles: [
      { role: 'backup', db: 'admin' },
      { role: 'clusterMonitor', db: 'admin' },
      { role: 'readWrite', db: 'admin' },
      { role: 'restore', db: 'admin' },
      { role: 'pbmAnyAction', db: 'admin' }
    ]
  },
  {
    _id: 'admin.logrotate',
    userId: UUID('6771cf52-1afc-4ae3-9330-30f4fd576f55'),
    user: 'logrotate',
    db: 'admin',
    credentials: {
      'SCRAM-SHA-256': {
        iterationCount: 15000,
        salt: 'N1AEcSSOIsqVs3CukBtfzqYs16vvaKzcdUM7dQ==',
        storedKey: 'sqKYLqcbTR98lu8E6vtPoGPA+VXCYp6p1x0rj1j07Qw=',
        serverKey: '2fiPIOW+YJHgqSLqIcaDarKYF8ftqHLqxVf55L2o7tk='
      }
    },
    roles: [ { role: 'logRotate', db: 'admin' } ]
  }
]
\`\`\`

```{caution}
These users are dedicated to the operator's logic, and **using them incorrectly could damage your deployment.**

Use the [data-integrator](https://github.com/canonical/data-integrator) charm to manage external credentials. To learn more, see {ref}`manage-client-connections`.
```
