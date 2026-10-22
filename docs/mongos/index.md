(mongos)=
# Charmed Mongos documentation

The Charmed Mongos operator deploys and operates [`mongos`](https://www.mongodb.com/docs/v8.0/reference/program/mongos/) instances on both physical and virtual machines, along with a wide range of cloud and cloud-like environments. 

`mongos` is a router for connecting client applications to a sharded MongoDB clusters. It is the only way to access a sharded MongoDB cluster from the client perspective.

Charmed Mongos acts as a subordinate charm, and is meant to act as a proxy to a sharded MongoDB cluster. **To deploy a sharded MongoDB cluster, see the {ref}`Charmed MongoDB documentation <mongodb>`**
