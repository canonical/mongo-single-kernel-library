## Introduction to Charmed MongoDB rock  (OCI Image)
[![Publish rock](https://github.com/canonical/charmed-mongodb-rock/actions/workflows/publish.yaml/badge.svg)](https://github.com/canonical/charmed-mongodb-rock/actions/workflows/publish.yaml)
[![Operator Tests](https://github.com/canonical/charmed-mongodb-rock/actions/workflows/integration.yaml/badge.svg)](https://github.com/canonical/charmed-mongodb-rock/actions/workflows/integration.yaml)

[MongoDB](https://github.com/mongodb/mongo) is a source-available, cross-platform, document-oriented database application. Classified as a NoSQL database program, MongoDB uses JSON-like documents with optional schemas.

Charmed MongoDB rock is an Open Container Initiative (OCI) image derived from the [Charmed MongoDB Snap](https://snapcraft.io/charmed-mongodb). The tool used to create this rock is called [Rockcraft](https://canonical-rockcraft.readthedocs-hosted.com/en/latest/index.html).

The [Charmed MongoDB rock](https://github.com/canonical/charmed-mongodb-rock/pkgs/container/charmed-mongodb)  is an enhanced, source-available, fully-compatible, drop-in replacement of the OCI image of MongoDB 6.0.6 Community version. In addition, the Charmed MongoDB rock package offers more features than the MongoDB Community version, such as backup and restore, monitoring and security features.

One benefit of using the Charmed MongoDB rock is that it bundles MongoDB with other tools in its ecosystem to be used in the Charmed MongoDB Operator. One of the operators that uses this rock is the [Charmed MongoDB (Kubernetes Operator)](https://charmhub.io/mongodb-k8s).

The Charmed MongoDB (Kubernetes Operator) delivers automated operations management from day 0 to day 2 on the[  ](https://github.com/mongodb/mongo)MongoDB document database. Charmed MongoDB (K8s Operator) is an enhanced, open source and fully-compatible, drop-in replacement for the MongoDB Community Edition with advanced MongoDB enterprise features. You can use the operator to manage your MongoDB clusters with automation capabilities.  In addition, it provides automated database operations on a wide range of cloud and cloud-like environments, including AWS, Azure, OpenStack and VMWare. 

## Version

Rocks will be named as `<version>-<series>_<risk>`.

`<version>` is the software version; `<series>` is the Ubuntu LTS series that rocks supports; and the <risk> is the type of release, if it is edge, candidate or stable. Example versioning will be 5-22.04_stable which means Charmed MongoDB is a version 5 of the software, supporting the 22.04 Ubuntu release and currently a 'stable' version of the software. See  versioning details [here](https://snapcraft.io/docs/channels).

Channel can also be represented by combining `<version>_<risk>`

## Release
Charmed MongoDB rock  Release Notes
https://discourse.charmhub.io/t/release-notes-charmed-mongodb-5-rock/10038

## Rocks Usage
### Starting mongod and accessing the database
To get started with the charmed-mongodb rocks, first install docker:
```
sudo snap install docker
```
Then to use the Charmed MongoDB rock run the following command
```
sudo docker run --rm -it ghcr.io/canonical/charmed-mongodb:6.0.6-22.04_edge
```
By running this command you have already started the mongod service with Percona Server for MongoDB. Leave this command running and create another terminal.

*Note if you would like to start `mongod` with custom options you can append your desired options to the container run command i.e.*: `sudo docker run --rm -it ghcr.io/canonical/charmed-mongodb:6.0.6-22.04_edge --bind-ip-all --another-option` *you can read more about [mongod optons here](https://www.mongodb.com/docs/manual/reference/program/mongod/)*

To access your now running MongoDB instance enter the command: 
```
sudo docker container ls
```
This should output something like this:
```
CONTAINER ID   IMAGE                                COMMAND                  CREATED          STATUS          PORTS     NAMES
bf08481d18a3   ghcr.io/canonical/charmed-mongodb:6.0.6-22.04_edge   "/bin/pebble enter -…"   About a minute ago   Up About a minute             quizzical_sinoussi
```
The name of the container is listed under `NAME` - use this name to connect to your now running database
```
sudo docker exec --interactive <container-name> mongosh
```
Now enter `show dbs` this should show you all of your available databases and output something like: 
```
admin   0.000GB
config  0.000GB
local   0.000GB
```

While using `mongo` can run a variety of [database commands](https://www.mongodb.com/docs/manual/reference/command/) such as creating databases, users, adding config options, etc. When you are ready to return to the terminal enter `exit`.


### Backup and restore
Percona Backup for MongoDB (`pbm`) is packaged within the Charmed MongoDB rock. To use it you can follow these instructions.

Percona Backup for MongoDB has a set of pre-requisites, to function properly. These can be found here:[ https://docs.percona.com/percona-backup-mongodb/initial-setup.html](https://docs.percona.com/percona-backup-mongodb/initial-setup.html)

It is up to you to add the pbm user to your MongoDB database. But we will explain how to configure pbm and how to use the tool.

To configure the `pbm` tool, it is necessary to create a config file and set `pbm` to use it. Before setting the config file and options it is necessary to provide `pbm` with a suitable [Mongodb URI](https://www.mongodb.com/docs/manual/reference/connection-string/): 

*Note this URI may look different if you have auth, tls, or replication enabled*

```
sudo docker exec  <container-name> touch config.txt
sudo docker exec romantic_newton pbm config --file=config.txt --mongodb-uri=mongodb://127.0.0.1:27017
sudo docker exec  <container-name> pbm config --set storage.type=s3 --mongodb-uri=mongodb://127.0.0.1:27017
```

Starting pbm-agent: The pbm-agent is a daemon that performs the backup and restore operations. You can start the pbm-agent by starting the pbm-agent process and providing it with your MongoDB URI: 
```
sudo docker exec <container-name> pbm-agent --mongodb-uri=mongodb://127.0.0.1:27017
```
Leave the `pbm-agent` daemon running and create another terminal.

If you would like to see the pbm logs you can enter the following command with the correct URI:
```
sudo docker exec <container-name> pbm logs  --mongodb-uri=mongodb://127.0.0.1:27017
```

Backups and more: Once you've configured everything appropriately and started the agent you may now perform backups and restores. Performing a backup can be done with: 
```
sudo docker exec <container-name> pbm backup
```

Check out the rest of the supported operations with:
```
docker exec <container-name> pbm --help
``` 

### Others tools within the rock

The MongoDB rock also packages other useful tools like `mongodb-exporter`, `mongodump`, `mongorestore`, and many other tools. You can read more about the tools packaged in the snap by entering:
```
docker exec <container-name> <tool name> --help`
``` 


## Bugs and feature request

If you find a bug in this rock or want to request a specific feature, here are the useful links:

-   Raise the issue or feature request in the [Canonical Github](https://github.com/canonical/charmed-mongodb-rock/issues)

-   Meet the community and chat with us if there are issues and feature requests in our [Mattermost Channel](https://github.com/canonical/charmed-mongodb-rock/issues).

## Licence statement

The Charmed MongoDB Operator is free software, distributed under the [Apache Software License, version 2.0](https://github.com/canonical/mongodb-operator/blob/main/LICENSE). It instals and operates Percona Server for MongoDB, which is licensed under the Server Side Public License (SSPL) version 1.


## Project & Community

Charmed MongoDB is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/charmed-mongodb-rock/issues)
* Report security issues through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File). 
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/charmed-mongodb-rock/blob/main/CONTRIBUTING.md) to the code

## Trademark Notice

"MongoDB" is a trademark or registered trademark of MongoDB, Inc. Other trademarks are property of their respective owners. Charmed MongoDB is not sponsored, endorsed, or affiliated with MongoDB, Inc.
