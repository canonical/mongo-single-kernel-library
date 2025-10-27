(manage-persistent-storage)=
# How to manage persistent storage (VM only)


MongoDB K8s atuomatically manages persistent storages using the Kubernetes persistent volumes. This guide explains how to manage persistent storage only for VM MongoDB.

Like many other databases, MongoDB stores its state on disk. In a default deployment the file system attached to 
charmed MongoDB will be removed when charmed MongoDB is removed. The content of the MongoDB database
would then be lost.

To decouple the life cycle of the MongoDB database from the life cycle of its deployment, charmed MongoDB provides a feature 
called persistent storage. It allows to keep storage volumes around, even after a deployed MongoDB application or unit 
has been removed.

Charmed MongoDB uses four storage volumes:
- `data` containing the raw data files (the actual database) written and managed by MongoDB
- `archive` for temporarily storing a backup file before uploading it to object storage or when downloading it from object storage
- `logs` for log files written by MongoDB
- `temp` for storing temporary tablespaces.

## Prerequisites

The storage volumes that can be attached to charmed MongoDB depend on the storage providers available in the cloud where
charmed MongoDB gets deployed. Please refer to the documentation about [Juju storage](https://canonical-juju.readthedocs-hosted.com/en/latest/user/reference/storage)
for more information on possible providers.

## Create a storage pool

In our case, as we deploy charmed MongoDB in a local LXD cloud, we use the `lxd` storage provider to create a storage pool
for MongoDB:

```shell
juju create-storage-pool mongodb-storage lxd volume-type=standard
```

Make sure the storage pool has been created:

```shell
juju storage-pools
```

Example output:

```shell
Name             Provider  Attributes
loop             loop      
lxd              lxd       
lxd-btrfs        lxd       driver=btrfs lxd-pool=juju-btrfs
lxd-zfs          lxd       driver=zfs lxd-pool=juju-zfs zfs.pool_name=juju-lxd
mongodb-storage  lxd       volume-type=standard
rootfs           rootfs    
tmpfs            tmpfs 
```     

Details about how to manage storage pools with Juju can be found [in this guide](https://canonical-juju.readthedocs-hosted.com/en/latest/user/howto/manage-storage-pools/#manage-storage-pools).

## Deploy with persistent storage
The decision about using the persistent storage feature of charmed MongoDB has to be made at deploy time. In order to create
persistent storage volumes, add the `--storage` option and define your storage parameters.

This command will deploy a charmed MongoDB application with three units, create two storage volumes of 8 GB each, and attach them as `data` and `archive` volume mounts:

```shell
juju deploy mongodb --channel=8/edge -n 3 --storage data=mongodb-storage,8G,1 --storage archive=mongodb-storage,8G,1
```

You can track the progress by executing:

```shell
juju status --storage --watch=1s
```

When the application is ready, `juju status --storage` will show something similar to the sample output below: 

```shell
Model             Controller    Cloud/Region         Version  SLA          Timestamp
pers-storage-lxd  overlord-lxd  localhost/localhost  3.6.11   unsupported  11:28:46Z

App      Version  Status  Scale  Charm    Channel  Rev  Exposed  Message
mongodb  8.0.10   active      3  mongodb  8/edge   239  no       

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        10.32.4.182     27017/tcp  Primary.
mongodb/1   active    idle   1        10.32.4.192     27017/tcp  
mongodb/2   active    idle   2        10.32.4.189     27017/tcp  

Machine  State    Address      Inst id        Base          AZ       Message
0        started  10.32.4.182  juju-6a883e-0  ubuntu@24.04  machine  Running
1        started  10.32.4.192  juju-6a883e-1  ubuntu@24.04  machine  Running
2        started  10.32.4.189  juju-6a883e-2  ubuntu@24.04  machine  Running

Storage Unit  Storage ID  Type        Pool             Mountpoint                                        Size     Status    Message
mongodb/0     archive/0   filesystem  mongodb-storage  /var/snap/charmed-mongodb/common/archive          8.0 GiB  attached  
mongodb/0     data/1      filesystem  mongodb-storage  /var/snap/charmed-mongodb/common/var/lib/mongodb  8.0 GiB  attached  
mongodb/0     logs/2      filesystem  rootfs           /var/snap/charmed-mongodb/common/var/log/mongodb  1.7 TiB  attached  
mongodb/0     temp/3      filesystem  rootfs           /tmp                                              1.7 TiB  attached  
mongodb/1     archive/4   filesystem  mongodb-storage  /var/snap/charmed-mongodb/common/archive          8.0 GiB  attached  
mongodb/1     data/5      filesystem  mongodb-storage  /var/snap/charmed-mongodb/common/var/lib/mongodb  8.0 GiB  attached  
mongodb/1     logs/6      filesystem  rootfs           /var/snap/charmed-mongodb/common/var/log/mongodb  1.7 TiB  attached  
mongodb/1     temp/7      filesystem  rootfs           /tmp                                              1.7 TiB  attached  
mongodb/2     archive/8   filesystem  mongodb-storage  /var/snap/charmed-mongodb/common/archive          8.0 GiB  attached  
mongodb/2     data/9      filesystem  mongodb-storage  /var/snap/charmed-mongodb/common/var/lib/mongodb  8.0 GiB  attached  
mongodb/2     logs/10     filesystem  rootfs           /var/snap/charmed-mongodb/common/var/log/mongodb  1.7 TiB  attached  
mongodb/2     temp/11     filesystem  rootfs           /tmp                                              1.7 TiB  attached  
```

As you can see, volumes from the `mongodb-storage` pool have been attached as the `data` and `archive` volume mounts, 
whereas for the `logs` and `temp` volume mounts, non-persistent storage from `rootfs` has been used. The `logs` and the `temp` storage will be removed when the respective unit gets removed, while the `data` storage will persist.
