(hardening-guide)=
# Security hardening guide

This document provides guidance and instructions to achieve a secure deployment of Charmed MongoDB and Charmed Mongos. We discuss both charms since we acknowledge that Charmed Mongos is required to access a sharded cluster. Additionally, we include guidance and instructions for setting up and managing a secure environment.

The document is divided into the following sections:

1. Environment, outlining the recommendation for deploying a secure environment
2. Applications, outlining the product features that enable a secure deployment of Charmed MongoDB
3. Additional resources, providing any further information about security and compliance

## Environment

The environment where applications operate can be divided in two components:

1. Cloud
2. Juju

###  Cloud
````{tab-set}
```{tab-item} VM
:sync: vm

Charmed MongoDB can be deployed on top of several clouds and virtualization layers: 

| Cloud     | Security guides                                                                       |
|-----------|---------------------------------------------------------------------------------------|
| OpenStack | [OpenStack Security Guide]                                                            |
| AWS       | [Best Practices for Security, Identity and Compliance], [AWS security credentials]    |
| Azure     | [Azure security best practices and patterns], [Managed identities for Azure resource] |

```
```{tab-item} K8s
:sync: k8s

Charmed MongoDB can be deployed on top of several Kubernetes distributions. 
The following table provides references for the security documentation for the 
main supported cloud platforms.

| Cloud              | Security guides                                                                                          |
|--------------------|----------------------------------------------------------------------------------------------------------|
| Charmed Kubernetes | [Security in Charmed Kubernetes]                                                                         |
| AWS EKS            | [Best Practices for Security, Identity and Compliance], [AWS security credentials], [Security in EKS]    |
| Azure              | [Azure security best practices and patterns], [Managed identities for Azure resource], [Security in AKS] |

```
````

### Juju 

Juju is the component responsible for orchestrating the entire lifecycle, from deployment to Day 2 operations, of 
all applications. Therefore, it is imperative that it is set up securely. Please refer to the Juju documentation for more information on:

* [Juju security](https://documentation.ubuntu.com/juju/latest/explanation/juju-security/index.html)
* [How to harden your deployment](https://documentation.ubuntu.com/juju/latest/howto/manage-your-juju-deployment/harden-your-juju-deployment/)

#### Cloud credentials

````{tab-set}
```{tab-item} VM
:sync: vm

When configuring cloud credentials to be used with Juju, ensure that users have correct permissions to operate at the required level. 
Juju superusers responsible for bootstrapping and managing controllers require elevated permissions to manage several kinds of resources, such as
virtual machines, networks, storages, etc. Please refer to the references below for more information on the policies required to be used depending on the cloud. 

| Cloud     | Cloud user policies                                             |
|-----------|-----------------------------------------------------------------|
| OpenStack | N/A                                                             |
| AWS       | [Juju AWS Permission], [AWS Instance Profiles], [Juju on AWS]   | 
| Azure     | [Juju Azure Permission], [How to use Juju with Microsoft Azure] |

```
```{tab-item} K8s
:sync: k8s

When configuring cloud credentials to be used with Juju, ensure that users have correct permissions to operate at the required level on the Kubernetes cluster. 
Juju superusers responsible for bootstrapping and managing controllers require elevated permissions to manage several kinds of resources. For this reason, the 
K8s user used for bootstrapping and managing the deployments should have full permissions, such as: 

* create, delete, patch, and list:
    * namespaces
    * services
    * deployments
    * stateful sets
    * pods
    * PVCs

In general, it is common practice to run Juju using the admin role of K8s, to have full permissions on the Kubernetes cluster. 
```
````

#### Juju users

It is very important that Juju users are set up with minimal permissions depending on the scope of their operations. 
Please refer to the [User access levels](https://juju.is/docs/juju/user-permissions) documentation for more information on the access levels and corresponding abilities.

Juju user credentials must be stored securely and rotated regularly to limit the chances of unauthorized access due to credentials leakage.

## Applications

In the following section , we provide guidance on how to harden your deployment using:

* Operating system (VM)
* Base images (K8s)
* Security upgrades
* Encryption 
* Authentication
* Monitoring and auditing

### Operating system (VM)

Charmed MongoDB VM and Charmed Mongos VM currently run on top of Ubuntu 22.04. Deploy a [Landscape Client Charm](https://charmhub.io/landscape-client?) to 
connect the underlying VM to a Landscape User Account to manage security upgrades and integrate Ubuntu Pro subscriptions. 

### Base images (K8s)

Charmed MongoDB K8s and Charmed Mongos K8s run on top of rockcraft-based image shipping the percona-server, mongodb-exporter, and pbm
distribution binaries built by Canonical with its images are based on Ubuntu 22.04. 
The images that can be found in the [Charmed MongoDB rock](https://github.com/canonical/charmed-mongodb-rock) Github repository are used as the base 
images for the different pods providing MongoDB services. 
The following table summarise the relation between the component and its underlying base image. 

A new version of the Charmed MongoDB image may be released to provide patching of vulnerabilities (CVEs). 

### Security upgrades

````{tab-set}
```{tab-item} VM
:sync: vm

Charmed MongoDB and Charmed Mongos install pinned revisions of the [Charmed MongoDB snap](https://snapcraft.io/charmed-mongodb), to provide reproducible and secure environments. 
New versions of Charmed MongoDB and Charmed Mongos may be released to provide patching of vulnerabilities (CVEs). 
It is important to refresh the charms regularly to make sure the workload is as secure as possible. 
For more information on how to refresh the MongoDB charm, see {ref}`how-to-upgrade`.
```
```{tab-item} K8s
:sync: k8s

Charmed MongoDB K8s and Charmed Mongos K8s install a pinned revisions of the [Charmed MongoDB snap](https://snapcraft.io/charmed-mongodb), to provide reproducible and secure environments. 
New versions of Charmed MongoDB K8s and Charmed Mongos K8s may be released to provide patching of vulnerabilities (CVEs). 
It is important to refresh charms regularly to make sure the workload is as secure as possible. 
For more information on how to refresh the MongoDB charm, see {ref}`how-to-upgrade`.
```
````

### Encryption

Both Charmed MongoDB and Charmed Mongos can be used without encryption. However, encryption is required for a hardened system. To enable encryption, you need to relate Charmed MongoDB and Charmed Mongos to one of the TLS certificate operator charms. 

Please refer to the [Charming Security page](https://charmhub.io/topics/security-with-x-509-certificates) for more information on how to select the right certificate
provider for your use case. 

For more information on encryption setup, see {ref}`enable-tls`.

### Authentication

Charmed MongoDB supports the following authentication layers:

* MongoDB replica/shard/router communication (i.e. Internal Membership) (See: {ref}`enable-tls`)
  * KeyFile or TLS
* SASL authentication to MongoDB (SCRAM-based) (See: {ref}`manage-client-connections`)

### Monitoring and auditing

Charmed MongoDB provides native integration with the [Canonical Observability Stack (COS)](https://charmhub.io/topics/canonical-observability-stack).
To reduce the blast radius of infrastructure disruptions, the general recommendation is to deploy COS and the observed application into 
separate environments, isolated from one another. Refer to the [COS production deployments best practices](https://charmhub.io/topics/canonical-observability-stack/reference/best-practices) for more information. 

See: {ref}`view-metrics`.

## Additional resources

For details on cryptography used by Charmed MongoDB, see {ref}`cryptography`.


<!-- Links -->

[OpenStack Security Guide]: https://docs.openstack.org/security-guide/
[Best Practices for Security, Identity and Compliance]: https://aws.amazon.com/architecture/security-identity-compliance
[AWS security credentials]: https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html
[Azure security best practices and patterns]: https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns
[Managed identities for Azure resource]: https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/
[Juju AWS Permission]: https://discourse.charmhub.io/t/juju-aws-permissions/5307
[AWS Instance Profiles]: https://discourse.charmhub.io/t/using-aws-instance-profiles-with-juju-2-9/5185
[Juju on AWS]: https://juju.is/docs/juju/amazon-ec2
[Juju Azure Permission]: https://juju.is/docs/juju/microsoft-azure
[How to use Juju with Microsoft Azure]: https://discourse.charmhub.io/t/how-to-use-juju-with-microsoft-azure/15219

[Security in Charmed Kubernetes]: https://ubuntu.com/kubernetes/docs/security
[Security in EKS]: https://docs.aws.amazon.com/eks/latest/userguide/security.html
[Security in AKS]: https://learn.microsoft.com/en-us/azure/aks/concepts-security