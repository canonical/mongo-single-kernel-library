# How to view metrics

You can view Charmed MongoDB metrics in two ways:
* [via the metrics endpoint](query-the-metrics-endpoint) - built-in, quick to access
* [via Grafana](access-metrics-with-grafana) - requires COS integration

(query-the-metrics-endpoint)=
## Query the metrics endpoint

Charmed MongoDB comes with [MongoDB Exporter](https://github.com/percona/mongodb_exporter) and provides replication and cluster metrics. 

The metrics can be queried by accessing the following endpoint:

```shell
http://<unit-ip>:9216/metrics
```

For example:
```
curl http://10.56.148.138:9216/metrics
```

(access-metrics-with-grafana)=
## Access metrics with Grafana

Charmed MongoDB supports integration with the [Canonical Observability Stack (COS)](https://charmhub.io/topics/canonical-observability-stack), which enables the usage of observability tools like Grafana, Loki, and Prometheus. 


`````{tab-set}
````{tab-item} VM
:sync: vm

First, deploy the [`cos-lite` bundle](https://charmhub.io/cos-lite) in a Kubernetes environment. Follow the [COS deployment tutorial](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s).

Wait for the status of the `cos-lite` bundle to become `active` and `idle`.

Switch back to the VM model hosting Charmed MongoDB, deploy the [`grafana-agent`](https://charmhub.io/grafana-agent) sidecar charm, and integrate them.

```shell
juju switch <vm-controller-name>
juju deploy grafana-agent
juju integrate grafana-agent mongodb
```

Watch {command}`juju status` and wait for the model to become `idle`. The `grafana-agent` application will enter an error state, since it requires relations from the COS bundle.

Now, consume offers from the COS bundle and relate it to the `grafana-agent`:

```shell
juju consume <k8s-controller-name>:admin/cos.prometheus-scrape
juju consume <k8s-controller-name>:admin/cos.alertmanager-karma-dashboard
juju consume <k8s-controller-name>:admin/cos.grafana-dashboards
juju consume <k8s-controller-name>:admin/cos.loki-logging
juju consume <k8s-controller-name>:admin/cos.prometheus-receive-remote-write

juju integrate grafana-agent prometheus-receive-remote-write
juju integrate grafana-agent loki-logging
juju integrate grafana-agent grafana-dashboards
```

Wait for `grafana-agent` to be `active` and `idle`.

To view the dashboard, we need the Grafana URL and dashboard credentials. Switch to the K8s model hosting the `cos-lite` bundle and show all applications:

```shell
juju switch <k8s-controller-name>
juju status
```
````

````{tab-item} K8s
:sync: k8s

First, deploy the [`cos-lite` bundle](https://charmhub.io/cos-lite). Follow the [COS deployment tutorial](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s)

Wait for the status of the `cos-lite` bundle to become `active` and `idle`.

```{note}
Make sure to use the following offers:

    https://raw.githubusercontent.com/canonical/cos-lite-bundle/09715997467e1b568109064fa17ecefd4b574032/overlays/offers-overlay.yaml
    https://raw.githubusercontent.com/canonical/cos-lite-bundle/09715997467e1b568109064fa17ecefd4b574032/overlays/storage-small-overlay.yaml

They contain the `prometheus-scrape` endpoint, which is essential to our stack, but was removed from the example offer of the bundle.
```
<!--TODO: this note was only in the K8s doc - is it relevant to VM? -->

Switch to your MongoDB model, consume offers from the `cos-lite` bundle, and relate it to your application:

```shell
juju switch <mongodb-controller-name>

juju consume <cos-controller-name>:admin/cos.prometheus-scrape
juju consume <cos-controller-name>:admin/cos.alertmanager-karma-dashboard
juju consume <cos-controller-name>:admin/cos.grafana-dashboards
juju consume <cos-controller-name>:admin/cos.loki-logging
juju consume <cos-controller-name>:admin/cos.prometheus-receive-remote-write

juju integrate mongodb-k8s prometheus-scrape
juju integrate mongodb-k8s loki-logging
juju integrate mongodb-k8s grafana-dashboards
```

To view the dashboard, we need the Grafana URL and dashboard credentials. Switch to the K8s model hosting the `cos-lite` bundle and show all applications:

```shell
juju switch <cos-controller-name>
juju status
```
````
`````

Run the following action to obtain the admin password:

```shell
juju run grafana/0 get-admin-password
```

The IP address of the Grafana GUI is listed as the {guilabel}`Public Address` for the application `grafana`. Copy this address and navigate to it in your browser. 

In the login page, enter the username `admin` and the password you obtained with {command}`get-admin-password`.