(system-requirements)=
# System requirements

Below are the minimum software and hardware requirements for running Charmed MongoDB 8.

## Software
* Juju `3.0` or higher
* Ubuntu 24.04 (Noble)

## Hardware

* At least **2GB of RAM** for replica sets
* At least **4GB of RAM** for sharded clusters
* At least **2CPU threads per host**
* At least **60GB of available storage per host** for production deployments

## Architecture
<!--TODO: verify if this section is applicable to both VM and K8s -->

This charm must run on architectures that support AVX.

To check your architecture, run:

```shell
grep avx /proc/cpuinfo
```

or

```shell
grep avx /proc/cpuinfo
```


## Kernel Parameters

Charmed MongoDB 8 works best with Transparent Hugepages enabled.

If you're running Charmed MongoDB on VM, this is handled by the charm

If you're running Charmed MongoDB on an LXD Container, please enable the Transparent Huge Tabes on the host:
* Follow the [official documentation](https://www.mongodb.com/docs/manual/administration/tcmalloc-performance/#std-label-enable-thp) to enable the Tranparent Hugepages on the host.
* Configure each host manually to set the max number of hugepages of each size allowed for that host: [see the official documentation](https://documentation.ubuntu.com/lxd/stable-5.21/reference/instance_options/#huge-page-limits):

```shell
lxc config set <instance_name> limits.hugepages.<hugepage-size>=<number of hugepages>
```

Charmed MongoDB on Kubernetes does not support yet setting the Transparent Hugepages.
