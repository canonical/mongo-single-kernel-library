(system-requirements)=
# System requirements

Below are the minimum software and hardware requirements for running Charmed MongoDB 6.

## Software
* Juju `3.0` or higher
* Ubuntu 22.04 (Jammy)

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