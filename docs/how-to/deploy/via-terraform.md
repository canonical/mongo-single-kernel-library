(via-terraform)=
# How to deploy via Terraform

These modules require the [Terraform Juju provider](https://registry.terraform.io/providers/juju/juju/latest/docs). For general Terraform usage, see the [official documentation](https://developer.hashicorp.com/terraform/docs).

Charmed MongoDB offers a base module with core resources: [VM](https://github.com/canonical/mongodb-operator/tree/6/edge/terraform) | [K8s](https://github.com/canonical/mongodb-k8s-operator/tree/6/edge/terraform)

This includes modules for both replica set and sharded cluster deployments. 

These modules support integrations for:
- Backups via [s3-integrator](https://charmhub.io/s3-integrator)
- Client connections via [data-integrator](https://charmhub.io/data-integrator)
- Monitoring via [cos-lite](https://charmhub.io/cos-lite)
- Encryption via [self-signed-certificates](https://charmhub.io/self-signed-certificates)
- Sharded clusters via the [`mongos` router](https://charmhub.io/mongos)

## Prerequisites

Ensure you have [Terraform 1.8+](https://snapcraft.io/terraform) or [OpenTofu](https://snapcraft.io/terraform) installed.

## Deploy a replica set

Get access to the replica set product Terraform module code:

````{tab-set}
```{tab-item} VM
:sync: vm

    git clone https://github.com/canonical/mongodb-operator.git
```

```{tab-item} K8s
:sync: k8s

    git clone https://github.com/canonical/mongodb-k8s-operator.git
```
````

Then deploy Charmed MongoDB using Terraform:

```shell
cd ./terraform/charm/replica_set/
terraform init
terraform plan -out <filename> -var='model=<model-name>'
terraform apply "<filename>"
```

## Deploy a sharded cluster

Get access to the sharded cluster product Terraform module code:

````{tab-item} VM
:sync: vm

    git clone https://github.com/canonical/mongodb-operator.git
```

```{tab-item} K8s
:sync: k8s

    git clone https://github.com/canonical/mongodb-k8s-operator.git
```
````

Then deploy Charmed MongoDB using Terraform:

```shell
cd ./terraform/charm/sharded_cluster/
terraform init
terraform plan -out <filename> -var='config_server={"model": "<model-name>", "app_name":"<config-server-name>"' -var='shards=[{"app_name": "<first-shard-name>", "model": "<model-name>"},{"app_name": "<second-shard-name>", "model": "<model-name>"}]'
terraform apply "<filename>"
```
