(via-terraform)=
# How to deploy MongoDB via Terraform

Make sure you have a working Terraform 1.8+ installed in your machine. You can install [Terraform](https://snapcraft.io/terraform) or [OpenTofu](https://snapcraft.io/terraform) via a snap.

Terraform modules make use of the Terraform Juju provider. More information about the Juju provider can be found [here](https://registry.terraform.io/providers/juju/juju/latest/docs). For more information about Terraform, please refer to the [official docs](https://developer.hashicorp.com/terraform/docs).

Charmed MongoDB has a [base module](https://github.com/canonical/mongodb-operator/tree/6/edge/terraform) that bundles all the base resources of the Charmed MongoDB solution. But it also provides two product modules that bundle all the resources and integrations for [replica set deployments](#deploy-a-replica-set-with-terraform) and [sharded deployments](#deploy-a-sharded-cluster-with-terraform). These deployments also integrate with necessary applications for: backups ([s3-integrator](https://charmhub.io/s3-integrator)), client connections ([data-integrator](https://charmhub.io/data-integrator)), monitoring ([grafana-agent](https://charmhub.io/grafana-agent)), encryption ([self-signed-certificates](https://charmhub.io/self-signed-certificates)), and in the case of a sharded cluster a [mongos router](https://charmhub.io/mongos).

## Deploy a replica set

Get access to the replica set product terraform module code:

`````{tab-set}
````{tab-item} VM
:sync: vm

```shell
git clone https://github.com/canonical/mongodb-operator.git
cd terraform/modules/replica_set
```
````

````{tab-item} K8s
:sync: k8s

```shell
git clone https://github.com/canonical/mongodb-k8s-operator.git
cd terraform/modules/replica_set
```
````
`````

Then deploy Charmed MongoDB using the stand Terraform commands:

```shell
terraform init
terraform plan -out <filename>
terraform apply "<filename>"
```

## Deploy a sharded cluster

Get access to the sharded cluster product terraform module code:

`````{tab-set}
````{tab-item} VM
:sync: vm

```shell
git clone https://github.com/canonical/mongodb-operator.git
cd terraform/modules/sharded_cluster
```
````

````{tab-item} K8s
:sync: k8s

```shell
git clone https://github.com/canonical/mongodb-k8s-operator.git
cd terraform/modules/sharded_cluster
```
````
`````

Then deploy Charmed MongoDB using the standard Terraform commands:

```shell
terraform init
terraform plan -out <filename>
terraform apply "<filename>"
```
