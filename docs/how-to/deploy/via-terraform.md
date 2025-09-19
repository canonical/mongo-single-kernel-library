(via-terraform)=
# How to deploy via Terraform

These modules require the [Terraform Juju provider](https://registry.terraform.io/providers/juju/juju/latest/docs). For general Terraform usage, see the [official documentation](https://developer.hashicorp.com/terraform/docs).

Charmed MongoDB offers a base module with core resources: [VM](https://github.com/canonical/mongodb-operator/tree/6/edge/terraform) | [K8s](https://github.com/canonical/mongodb-k8s-operator/tree/6/edge/terraform)

This includes modules for both replica set and sharded cluster deployments. 

These modules support integrations for:
- Backups via [s3-integrator](https://charmhub.io/s3-integrator)
- Client connections via [data-integrator](https://charmhub.io/data-integrator)
- Monitoring via [grafana-agent](https://charmhub.io/grafana-agent)
- Encryptionvia [self-signed-certificates](https://charmhub.io/self-signed-certificates)
- Sharded clusters via the [`mongos` router](https://charmhub.io/mongos)

## Prerequisites

Ensure you have [Terraform 1.8+](https://snapcraft.io/terraform) or [OpenTofu](https://snapcraft.io/terraform) installed.

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
