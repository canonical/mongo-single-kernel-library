(view-audit-logs)=
# How to view audit logs

You can view [audit logs](https://www.mongodb.com/docs/manual/core/auditing/) in two ways:
* [via `syslog`](view-logs-with-syslog) - built-in console logging
* [via Grafana](view-logs-with-grafana) - requires COS integration 

(view-logs-with-syslog)=
## View logs with `syslog`

`````{tab-set}
````{tab-item} VM
:sync: vm

First, `ssh` to the relevant unit. For example:

```shell
juju ssh mongodb/leader
``` 

In the unit's shell, run:

```shell
tail -f /var/log/syslog 
``` 

The console will now display audit log messages, for example:

```text
Jan 26 13:22:56 juju-f6ba89-2 mongod: { "atype" : "updateOperation", "ts" : { "$date" : "2024-01-26T13:22:56.300+00:00" }, "local" : { "ip" : "10.55.47.232", "port" : 27017 }, "remote" : {}, "users" : [], "roles" : [], "param" : { "ns" : "local.replset.oplogTruncateAfterPoint", "doc" : { "_id" : "oplogTruncateAfterPoint", "oplogTruncateAfterPoint" : { "$timestamp" : { "t" : 1706275376, "i" : 1 } } } }, "result" : 0 }
```
````

````{tab-item} K8s
:sync: k8s

First, `ssh` to the relevant unit. For example:

```shell
juju ssh --container=mongod mongodb-k8s/0
``` 
In the unit's shell, run:

```shell
tail -f /var/log/mongodb/audit.log
``` 
The console will now display audit log messages, for example:

```text
Jan 26 13:22:56 juju-f6ba89-2 mongod: { "atype" : "updateOperation", "ts" : { "$date" : "2024-01-26T13:22:56.300+00:00" }, "local" : { "ip" : "10.55.47.232", "port" : 27017 }, "remote" : {}, "users" : [], "roles" : [], "param" : { "ns" : "local.replset.oplogTruncateAfterPoint", "doc" : { "_id" : "oplogTruncateAfterPoint", "oplogTruncateAfterPoint" : { "$timestamp" : { "t" : 1706275376, "i" : 1 } } } }, "result" : 0 }
```
````
`````
(view-logs-with-grafana)=
## View logs with Grafana

Audit logs can be viewed with grafana using [COS (Canonical Observability Stack)](https://charmhub.io/topics/canonical-observability-stack).

To view logs, you must first integrate Charmed MongoDB with COS. See: {ref}`access-metrics-with-grafana`.

Once Grafana is active and you are able to access the GUI, navigate to the {guilabel}`Logging` section. There you will be able to see your audit log messages.
