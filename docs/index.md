---
relatedlinks: "[Charmhub&#32;|&#32;MongoDB&#32;VM](https://charmhub.io/mongodb?channel=6/edge), [Charmhub&#32;|&#32;MongoDB&#32;K8s](https://charmhub.io/mongodb-k8s?channel=6/edge)"
myst:
  html_meta:
    description: "Official documentation for Charmed MongoDB. Deploy and manage MongoDB on bare metal/virtual machines and Kubernetes using Juju."
---

# Charmed MongoDB documentation

Charmed MongoDB is an open-source software operator that deploys and operates [MongoDB](https://www.mongodb.com/) databases on IAAS/VM and Kubernetes. In addition to MongoDB's essential operations for managing production-grade deployments, Charmed MongoDB offers advanced features such as backup and restores, monitoring, easy application integrations, sharding, and encryption.

Charmed MongoDB was created to reduce the complexity of the deployment, scaling, and the operational challenges of MongoDB database operations. Built on top of Canonical’s Charm SDK and Juju 3, it wraps the expertise of a real-world operations team into a single charm that greatly simplifies the management of all kinds of data infrastructures.

This charm is for anyone looking for a complete database management interface. This could be a team of system administrators maintaining large data infrastructures, a software developer who wants to connect a database to their application, or even someone curious to learn more about database charms through our tutorials. 

## In this documentation

This documentation contains practical information about installing and operating Charmed MongoDB. It covers instructions for both VM and K8s substrates.  

### Get started

Learn about what's in the charm, how to try it out, and perform the most common operations.

* **Charm overview**: {ref}`system-requirements` • {ref}`release-notes` 
* **Deploy MongoDB**: {ref}`Quickstart <via-juju-cli>` • {ref}`Guided tutorial <tutorial>` • {ref}`Terraform <via-terraform>`
* **Key operations**: {ref}`Scale your cluster <scale-replicas-and-shards>` • {ref}`Connect to a client <manage-client-connections>` • {ref}`Create a backup <create-a-backup>`

### Production deployments

Advanced deployments and operations focused on production scenarios and high availability.

* **Advanced configuration**: {ref}`Enable LDAP <enable-ldap>`
* **Upgrades and data migration**: {ref}`Minor upgrades <minor-version-upgrade>` • {ref}`Upgrade from MongoDB 6 to 8 <major-version-upgrade>` • {ref}`Migrate a cluster <migrate-a-cluster>`
* **Security**: {ref}`TLS encryption <enable-tls>` • {ref}`Hardening guide <hardening-guide>`
* **Troubleshooting**: {ref}`Monitoring <monitoring>` • {ref}`Advanced statuses <advanced-statuses>` 

### Charm developers

Information for developers looking to make their application compatible with MongoDB.

* **Libraries and interfaces**: [`mongodb_client` interface](https://charmhub.io/integrations/mongodb_client)
* **Learn more about the charm**: {ref}`Internal users <users>` • {ref}`sharding`

## How this documentation is organised

This documentation uses the [Diátaxis documentation structure](https://diataxis.fr/):

* The {ref}`tutorial` provides step-by-step guidance for a beginner through the basics of a deployment in a local machine.
* {ref}`how-to` are more focused, and assume you already have basic familiarity with the product.
* {ref}`reference` contains structured information for quick lookup, such as system requirements and configuration parameters
* {ref}`explanation` gives more background and context about key topics

## Project and community

Charmed MongoDB is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

### Get involved

* [Report an issue](https://github.com/canonical/mongo-single-kernel-library/issues/new/choose)
* [Public Matrix channel](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Discourse forum](https://discourse.charmhub.io/tag/mongodb)
* [Contribute](https://github.com/canonical/mongo-single-kernel-library/blob/6/edge/CONTRIBUTING.md)

### Governance and policies

* [Code of Conduct](https://ubuntu.com/community/code-of-conduct)

```{toctree}
:titlesonly:
:hidden:

Tutorial <tutorial>
How-to guides <how-to/index>
Reference <reference/index>
Explanation <explanation/index>
```