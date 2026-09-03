(via-terraform)=
# How to deploy via Terraform

These modules require the [Terraform Juju provider](https://registry.terraform.io/providers/juju/juju/latest/docs). For general Terraform usage, see the [official documentation](https://developer.hashicorp.com/terraform/docs).

Charmed MongoDB offers a base module with core resources: [VM](https://github.com/canonical/mongodb-operator/tree/8/edge/terraform) | [K8s](https://github.com/canonical/mongodb-k8s-operator/tree/8/edge/terraform)

This includes modules for both replica set and sharded cluster deployments. 

These modules support integrations for:
- Backups via [s3-integrator](https://charmhub.io/s3-integrator)
- Client connections via [data-integrator](https://charmhub.io/data-integrator)
- Monitoring via [cos-lite](https://charmhub.io/cos-lite)
- TLS via [self-signed-certificates](https://charmhub.io/self-signed-certificates)
- Encryption at rest via [vault](https://charmhub.io/vault)
- LDAP via [glauth-k8s](https://charmhub.io/glauth-k8s)
- Sharded clusters via the [`mongos`](https://charmhub.io/mongos) and [`mongos-k8s`](https://charmhub.io/mongos-k8s) routers

## Prerequisites

Ensure you have [Terraform 1.6+](https://snapcraft.io/terraform) or [OpenTofu](https://snapcraft.io/opentofu) installed, along with the [`juju` Terraform provider `~> 2.0`](https://registry.terraform.io/providers/juju/juju/latest).

You must also have a [bootstrapped](https://juju.is/docs/juju/juju-bootstrap) cloud controller and an existing [Juju model](https://documentation.ubuntu.com/juju/latest/reference/model/) to deploy into, since these modules deploy into a model rather than creating one.

These modules identify models by UUID rather than by name. Retrieve a model's UUID with:

```shell
juju show-model <model-name> | grep model-uuid
```

```{note}
If you're new to these concepts and vocabulary, check out the {ref}`tutorial`.
```

## Deploy a replica set

Get access to the replica set product Terraform module code:

````{tab-set}
```{tab-item} VM
:sync: vm

    git clone https://github.com/canonical/mongodb-operator.git
    cd ./mongodb-operator
```

```{tab-item} K8s
:sync: k8s

    git clone https://github.com/canonical/mongodb-k8s-operator.git
    cd ./mongodb-k8s-operator
```
````

Then deploy Charmed MongoDB using Terraform:

```shell
cd ./terraform/product/replica_set/
terraform init
terraform plan -out <filename> -var='model_uuid=<model-uuid>'
terraform apply "<filename>"
```

## Deploy a sharded cluster

Get access to the sharded cluster product Terraform module code:

````{tab-set}
```{tab-item} VM
:sync: vm

    git clone https://github.com/canonical/mongodb-operator.git
    cd ./mongodb-operator
```

```{tab-item} K8s
:sync: k8s

    git clone https://github.com/canonical/mongodb-k8s-operator.git
    cd ./mongodb-k8s-operator
```
````

Then deploy Charmed MongoDB using Terraform:

```shell
cd ./terraform/product/sharded_cluster/
terraform init
terraform plan -out <filename> -var='config_server={"model_uuid": "<model-uuid>", "app_name":"<config-server-name>"' -var='shards=[{"app_name": "<first-shard-name>", "model_uuid": "<model-uuid>"},{"app_name": "<second-shard-name>", "model_uuid": "<model-uuid>"}]' -var='mongos={"model_uuid": "${config_model}","app_name":"<mongos-name>"}' \
terraform apply "<filename>"
```

See the [`charms-reference-architectures`](https://github.com/canonical/charms-reference-architectures/tree/main/solutions/data/charmed-mongodb) repository for full, cloud-specific examples of deploying Charmed MongoDB with Terraform, including more integration examples.
