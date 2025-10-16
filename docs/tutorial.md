(tutorial)=
# Tutorial

This hands-on tutorial aims to help you become familiar with Charmed MongoDB by going through a real deployment of a MongoDB replica set on VM. You will learn the basics of deploying, scaling, managing credentials, accessing a database, and other essential operations that will prepare you for more advanced deployments.

This tutorial is meant as a very guided learning experience for someone new to charms, MongoDB, or both. All steps described in this tutorial are covered more succinctly in how-to guides both for replica sets and sharded clusters, as well as for MongoDB VM and K8s. 

## Prerequisites

While this tutorial intends to guide you as you deploy Charmed MongoDB for the first time, it will be most  beneficial if:
* You have some experience using a Linux-based CLI
* You are familiar with MongoDB concepts, such as replica sets
* Your computer fulfils the minimum system requirements <!--TODO: link to system requirements reference page -->

---

## Set up the environment

First, we will set up a cloud environment using the [LXD](https://documentation.ubuntu.com/lxd/latest/) virtual machine manager and [Juju](https://documentation.ubuntu.com/juju/3.6/). One of the simplest ways to get started using the MongoDB charm is to set up a local LXD cloud and running the charm in a LXD container.

```{seealso}
To learn about other types of deployment environments and methods, see {ref}`how-to-deploy`.
```

### Set up LXD

Verify if your Ubuntu system already has LXD installed by entering the command {command}`which lxd` into the command line. If there is no output, install LXD with

```shell
sudo snap install lxd
```

After installation, we need to run {command}`lxd init` to perform post-installation tasks. For this tutorial, the default parameters are preferred and the network bridge should be set to have no IPv6 addresses, since Juju does not support IPv6 addresses with LXD:

```shell
lxd init --auto
lxc network set lxdbr0 ipv6.address none
```

You can list all LXD containers by entering the command {command}`lxc list`. If you have not used any LXD containers before, the output will be blank at this stage in the tutorial:

```text
+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```

### Set up Juju

[Juju](https://documentation.ubuntu.com/juju/3.6/) is an operator lifecycle manager (OLM) for clouds, bare metal, LXD or Kubernetes. We will be using it to deploy and manage Charmed MongoDB.

As with LXD, Juju is installed from a snap package:

```shell
sudo snap install juju
```
<!--TODO: I removed `--channel 3.1/stable`. Need confirmation if this is ok or if we want to install a version other than the latest stable -->

Juju already has a built-in knowledge of LXD and how it works, so there is no additional setup or configuration needed. However, because Juju 3 is a a [strictly confined snap](https://snapcraft.io/docs/classic-confinement), and is not allowed to create a `~/.local/share` directory, we need to create it manually:

```shell
mkdir -p ~/.local/share
```

To deploy and operate Charmed MongoDB, we need to bootstrap a [Juju controller](https://documentation.ubuntu.com/juju/3.6/reference/controller/). We will call our new controller "overlord", but you can give it any name you'd like:

```shell
juju bootstrap localhost overlord
```

This bootstrapping processes can take several minutes depending on how provisioned (RAM, CPU, etc.) your machine is.

The Juju controller exists within an LXD container. You can verify this by entering the command {command}`lxc list`, which will output something like the following:

```text
+---------------+---------+-----------------------+------+-----------+-----------+
|     NAME      |  STATE  |         IPV4          | IPV6 |   TYPE    | SNAPSHOTS |
+---------------+---------+-----------------------+------+-----------+-----------+
| juju-<id>     | RUNNING | 10.105.164.235 (eth0) |      | CONTAINER | 0         |
+---------------+---------+-----------------------+------+-----------+-----------+
```

where `<id>` is a unique combination of numbers and letters such as `9d7e4e-0`

The controller can work with different [Juju models](https://documentation.ubuntu.com/juju/3.6/reference/model/), which is where charmed applications such as Charmed MongoDB are hosted. 

Set up a specific model for our MongoDB deployment named "tutorial":

```shell
juju add-model tutorial
```

You can now view the model you created above by entering the command {command}`juju status` into the command line. You should see the following:

```text
Model    Controller  Cloud/Region         Version  SLA          Timestamp
tutorial overlord    localhost/localhost  3.6.9    unsupported  23:20:53Z

Model "admin/tutorial" is empty.
```

## Deploy MongoDB

To deploy Charmed MongoDB in your Juju model, run

```shell
juju deploy mongodb
```

Juju  will fetch the charm from [Charmhub](https://charmhub.io/mongodb) and begin deploying it to the LXD cloud. This process can take several minutes depending on how provisioned (RAM, CPU, etc) your machine is.

You can check the status of your deployment by running:

```shell
juju status --watch 1s --relations
```

This will display a table with an overview of all the status info of the elements in your juju model, like IP addresses, ports, state, and other useful data. The `--watch 1s` flag means that it will update every second. To exit this screen, use {kbd}`Ctrl` + {kbd}`C`.

```{tip}
For this tutorial, it is recommended to have a dedicated terminal running {command}`juju status --watch 1s --relations`. This way you can see what is happening every time you make changes to your juju model.

The `--relations` flag will display additional information about relations/integrations that will be useful later on.
```

When your MongoDB application is ready, {command}`juju status` will show something similar to output below:

```text
Model     Controller  Cloud/Region         Version  SLA          Timestamp
tutorial  overlord    localhost/localhost  3.6.9    unsupported  11:24:30Z

App      Version  Status  Scale  Charm    Channel   Rev  Exposed  Message
mongodb           active      1  mongodb  6/stable  229  no

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        10.23.62.156    27017/tcp

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  jammy       Running
```

## Access a replica set

MongoDB databases can be accessed via the `mongosh`, the [MongoDB shell](https://www.mongodb.com/docs/mongodb-shell/). This shell comes pre-installed in the units hosting the Charmed MongoDB application as `charmed-mongodb.mongosh`.

Connecting to the database requires a Uniform Resource Identifier (URI). MongoDB expects a [MongoDB-specific URI](https://www.mongodb.com/docs/manual/reference/connection-string/) that contains information used to authenticate us to the database. 

In this part of the tutorial, we will fetch all the information needed to generate a URI that will grant us access to MongoDB, connect to the `mongo` shell, and create a test database.

```{admonition} Production disclaimer
:class: warning
This part of the tutorial accesses the sharded MongoDB cluster via the `operator` user. This is the admin user in Charmed MongoDB. 

**Do not directly interface with the `operator` user in a production environment.** 

Always connect to MongoDB via a separate user via integrations, which will be covered later in {ref}`integrate-with-another-application`.
```

### Retrieve URI data

To access MongoDB via `mongos`, we need to build a URI of the format

```text
mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP/$DB_NAME?replicaSet=$REPL_SET_NAME
```

Connecting via URI requires that you know the values for username, password, hosts, database name, and the replica set name. 

**Username | `$DB_USERNAME`**

In this case, we are using the `operator` user to connect to MongoDB directly. This is the admin user in Charmed MongoDB. 

Use `operator` as the username:

```shell
export DB_USERNAME="operator"
```

**Password | `$DB_PASSWORD`**

Run the `get-password` action on the Charmed MongoDB application:

```shell
juju run mongodb/leader get-password
```

The command will output something similar to:

```yaml
Running operation 5 with 1 task
  - task 6 on unit-mongodb-0

Waiting for task 6...
password: 9JLjd0tuGngW5xFKWWbo0Blxyef0oGec
```

The command below sets the environment variable automatically by running `get-password` and filtering the `password` field:

```shell
export DB_PASSWORD=$(juju run mongodb/leader get-password  | grep password|  awk '{print $2}')
```

**Hosts | `$HOST_IP`**

The hosts are the units hosting the MongoDB application. The host’s IP address can be found with `juju status`:

```text
Model     Controller  Cloud/Region         Version  SLA          Timestamp
tutorial  overlord    localhost/localhost  3.6.9   unsupported  11:31:16Z

App      Version  Status  Scale  Charm    Channel   Rev  Exposed  Message
mongodb           active      1  mongodb  6/stable  229  no       Replica set primary

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        <host IP>    27017/tcp     Replica set primary

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  jammy       Running

```

Set the variable `HOST_IP` to the IP address for `mongodb/0`:

```shell
export HOST_IP=$(juju exec --unit mongodb/0 -- hostname -I | awk '{print $1}')
```

**Database name | `$DB_NAME`**

In this case, we are connecting to the `admin` database. Use `admin` as the database name. 

Once we access the database via the MongoDB URI, we will create a `test-db` database to store data.

```shell
export DB_NAME="admin"
```

**Replica set name | `$REPL_SET_NAME`**

The replica set name is the name of the application on Juju hosting MongoDB. The application name in this tutorial is `mongodb`. Use `mongodb` as the replica set name.

```shell
export REPL_SET_NAME="mongodb"
```

(generate-the-full-uri)=
#### Generate the full URI

To summarize:

```shell
export DB_USERNAME="operator"
export DB_PASSWORD=$(juju run mongodb/leader get-password  | grep password|  awk '{print $2}')
export HOST_IP=$(juju exec --unit mongodb/0 -- hostname -I | awk '{print $1}')
export DB_NAME="admin"
export REPL_SET_NAME="mongodb"
```

We can create the URI with:

```shell
export URI=mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP/$DB_NAME?replicaSet=$REPL_SET_NAME
```

Now echo the URI and save it, as you won't be able to rely on this environment variable when you `ssh` into a unit in the next step.

```shell
echo $URI
```

### Connect via URI

To access the unit hosting MongoDB, `ssh` into it:

```shell
juju ssh mongodb/0
```

While `ssh`'d into `mongodb/0`, we can access `mongo` using the URI that we saved in the previous step.

```shell
charmed-mongodb.mongosh <uri>
```

You should now see something similar to:

```text
Current Mongosh Log ID: 6389e2adec352d5447551ae0
Connecting to:    mongodb://<credentials>@10.23.62.156/admin?replicaSet=mongodb&appName=mongosh+1.6.1
Using MongoDB:    5.0.14
Using Mongosh:    1.6.1

For mongosh info see: https://docs.mongodb.com/mongodb-shell/

To help improve our products, anonymous usage data is collected and sent to MongoDB periodically (https://www.mongodb.com/legal/privacy-policy).
You can opt-out by running the disableTelemetry() command.

------
   The server generated these startup warnings when booting
   2022-12-02T11:24:05.416+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
------

------
   Enable MongoDB's free cloud-based monitoring service, which will then receive and display
   metrics about your deployment (disk utilization, CPU, operation statistics, etc).

   The monitoring data will be available on a MongoDB website with a unique URL accessible to you
   and anyone you share the URL with. MongoDB may use this information to make product
   improvements and to suggest MongoDB products and deployment options to you.

   To enable free monitoring, run the following command: db.enableFreeMonitoring()
   To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
------

mongodb [primary] admin>
```

You can now interact with MongoDB directly using any [MongoDB commands](https://www.mongodb.com/docs/manual/reference/command/). For example, entering 

```shell
show dbs
``` 

should output something like:

```text
admin   172.00 KiB
config  120.00 KiB
local   404.00 KiB
```

### Create a database

Now that we have access to MongoDB, we can create a database named `test-db`.

In the MongoDB shell, run:

```shell
use test-db
```

Now create a user called `testUser` with read/write access to `test-db`:

```bash
db.createUser({
  user: "testUser",
  pwd: "password",
  roles: [
    { role: "readWrite", db: "test-db" }
  ]
})
```

You can verify that you added the user correctly by entering the command {command}`show users` into the `mongo` shell. This will output:

```yaml
[
  {
    _id: 'test-db.testUser',
    userId: new UUID("6e841e28-b1bc-4719-bf42-ba4b164fc546"),
    user: 'testUser',
    db: 'test-db',
    roles: [ { role: 'readWrite', db: 'test-db' } ],
    mechanisms: [ 'SCRAM-SHA-1', 'SCRAM-SHA-256' ]
  }
]
```

Feel free to test out any other MongoDB commands. When you’re ready to leave the MongoDB shell, just type {command}`exit`. You will be back in the host of Charmed MongoDB (`mongodb/0`). 

Exit this host by once again typing {command}`exit`. Now you will be in your original shell where you can interact with Juju and LXD. 

```{note}
If you accidentally exit one more time or close your terminal session at some point, note that all the environment variables used in the URI will be removed. 

If this happens, simply re-export these variables as described in {ref}`generate-the-full-uri`
```

## Scale your replicas

A replica set in MongoDB is a group of processes that copy stored data in order to make a database highly available. Replication provides redundancy, which means the application can provide self-healing capabilities in case one replica fails. 

```{admonition} Production disclaimer
:class: warning
This tutorial hosts all replicas on the same machine. 

**This should never be done in a production environment**. 

To enable high availability in a production environment, replicas should be hosted on different servers to [maintain isolation.](https://canonical.com/blog/database-high-availability)
```

### Add replicas

You can add two replicas to your deployed MongoDB application with:

```shell
juju add-unit mongodb -n 2
```

It usually takes several minutes for the replicas to be added to the replica set. You’ll know that all three replicas are ready when {command}`juju status --watch 1s` reports:

```text
Model     Controller  Cloud/Region         Version  SLA          Timestamp
tutorial  overlord    localhost/localhost  3.6.9   unsupported   14:42:04Z

App      Version  Status  Scale  Charm    Channel   Rev  Exposed  Message
mongodb           active      3  mongodb  6/stable  229  no       Replica set primary

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        10.23.62.156    27017/tcp  Replica set primary
mongodb/1   active    idle   1        10.23.62.55     27017/tcp  Replica set secondary
mongodb/2   active    idle   2        10.23.62.243    27017/tcp  Replica set secondary

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  jammy       Running
1        started  10.23.62.55   juju-d35d30-1  jammy       Running
2        started  10.23.62.243  juju-d35d30-2  jammy       Running
```

#### Verify replica set
If you want to verify the replica set configuration, you could connect to MongoDB via `charmed-mongodb.mongo`. Since your replica set has 2 additional hosts, you will need to update the hosts in your URI. You can retrieve these host IPs with:

```shell
export HOST_IP_1=$(juju show-unit mongodb/1 | awk '/public-address:/{print $NF;exit}')
export HOST_IP_2=$(juju show-unit mongodb/2 | awk '/public-address:/{print $NF;exit}')
```

Then recreate the URI using your new hosts and reuse the `username`, `password`, `database name`, and `replica set name` that you previously used when you *first* connected to MongoDB:

```shell
export URI=mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP,$HOST_IP_1,$HOST_IP_2/$DB_NAME?replicaSet=$REPL_SET_NAME
```

Now view and save the output of the URI:

```shell
echo $URI
```

Like earlier, we access `mongo` by `ssh`ing into one of the Charmed MongoDB hosts:

```shell
juju ssh mongodb/0
```

While `ssh`d into `mongodb/0`, we can access `mongo` with `charmed-mongodb.mongo`, using our new URI that we saved above:

```shell
charmed-mongodb.mongosh <saved URI>
```

Now, run {command}`rs.status()` and you should see your replica set configuration. The first few lines should look something like this:

```yaml
{
  set: 'mongodb',
  date: ISODate("2022-12-02T14:39:52.732Z"),
  myState: 1,
  term: Long("1"),
  syncSourceHost: '',
  syncSourceId: -1,
  heartbeatIntervalMillis: Long("2000"),
  majorityVoteCount: 2,
  writeMajorityCount: 2,
  votingMembersCount: 3,
  writableVotingMembersCount: 3,
  optimes: {
    lastCommittedOpTime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
    lastCommittedWallTime: ISODate("2022-12-02T14:39:50.020Z"),
    readConcernMajorityOpTime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
    appliedOpTime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
    durableOpTime: { ts: Timestamp({ t: 1669991990, i: 1 }), t: Long("1") },
    lastAppliedWallTime: ISODate("2022-12-02T14:39:50.020Z"),
    lastDurableWallTime: ISODate("2022-12-02T14:39:50.020Z")
},
  ...
```

Leave the MongoDB shell by typing {command}`exit`. 

You will be back in the host of Charmed MongoDB (`mongodb/0`). Exit this host by typing {command}`exit` again. 

You should now be at the original shell where you can interact with Juju and LXD.

### Remove replicas

Removing a unit from the application scales the replicas down. Before we scale down the replicas, list all the units with {command}`juju status`, here you will see three units `mongodb/0`, `mongodb/1`, and `mongodb/2`. Each of these units hosts a MongoDB replica. 

To remove the replica hosted on the unit `mongodb/2` enter:

```shell
juju remove-unit mongodb/2
```

You’ll know that the replica was successfully removed when {command}`juju status --watch 1s` reports:

```text
Model     Controller  Cloud/Region         Version  SLA          Timestamp
tutorial  overlord    localhost/localhost  3.6.9   unsupported  14:44:25Z

App      Version  Status  Scale  Charm    Channel   Rev  Exposed  Message
mongodb           active      2  mongodb  6/stable  229  no       Replica set primary

Unit        Workload  Agent  Machine  Public address  Ports      Message
mongodb/0*  active    idle   0        10.23.62.156    27017/tcp  Replica set primary
mongodb/1   active    idle   1        10.23.62.55     27017/tcp  Replica set secondary

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  jammy       Running
1        started  10.23.62.55   juju-d35d30-1  jammy       Running

```

You can also see that the replica was successfully removed by using the new URI (where the removed host has been excluded).

(integrate-with-another-application)=
## Integrate with another application

Juju [integrations](https://documentation.ubuntu.com/juju/3.6/reference/relation/), also called "relations", are the easiest way to create a user for MongoDB in Charmed MongoDB. Relations automatically create a username, password, and database for the desired user/application. The best practice is to connect to MongoDB via a specific user rather than the admin user, like we did earlier in this tutorial.

In this part of the tutorial, you will learn how to integrate MongoDB with another charm, access an integrated database, and manage users via integrations.

### Deploy `data-integrator`

Before relating to a charmed application, we must first deploy our charmed application. In this tutorial, we will relate to the [data-integrator charm](https://charmhub.io/data-integrator). This is a bare-bones charm that allows for central management of database users. 

When deploying the Data Integrator charm, we will set a name for a database called `test-database` using Juju's config flag:

```shell
juju deploy data-integrator --config database-name=test-database
```

Example output:

```text
Located charm "data-integrator" in charm-hub...
Deploying "data-integrator" from charm-hub charm "data-integrator"...
```
### Integrate with MongoDB

Now that the Database Integrator charm has been set up, we can relate it to MongoDB. This will automatically create a username, password, and database for the Database Integrator Charm. 

Integrate the two applications with:

```shell
juju integrate data-integrator mongodb
```

Wait for `juju status --watch 1s` to show:

```text
Model     Controller  Cloud/Region         Version  SLA          Timestamp
tutorial  overlord    localhost/localhost  3.6.9    unsupported  10:32:09Z

App                  Version  Status  Scale  Charm                Channel   Rev  Exposed  Message
data-integrator               active      1  data-integrator      stable    181  no
mongodb                       active      2  mongodb              6/stable  229  no

Unit                    Workload  Agent  Machine  Public address  Ports      Message
data-integrator/0*      active    idle   5        10.23.62.216               received mongodb credentials
mongodb/0*              active    idle   0        10.23.62.156    27017/tcp
mongodb/1               active    idle   1        10.23.62.55     27017/tcp  Replica set primary

Machine  State    Address       Inst id        Series  AZ  Message
0        started  10.23.62.156  juju-d35d30-0  jammy       Running
1        started  10.23.62.55   juju-d35d30-1  jammy       Running
5        started  10.23.62.216  juju-d35d30-5  jammy       Running
```

To retrieve credentials, run:

```shell
juju run data-integrator/leader get-credentials
```

This should output something like:

```text
​​Running operation 21 with 1 task
  - task 22 on unit-data-integrator-0

Waiting for task 22...
mongodb:
  database: test-database
  endpoints: 10.63.102.106,10.63.102.223
  password: kXOOyTbccn2cXs3kokOqPJz3Mu9g3a5g
  replset: mongodb
  uris: mongodb://relation-2:kXOOyTbccn2cXs3kokOqPJz3Mu9g3a5g@10.63.102.106,10.63.102.223/test-database?replicaSet=mongodb&authSource=admin
  username: relation-2
ok: "True"
```
Save the value listed under `uris:` Note that your hostnames, usernames, and passwords will likely be different.

### Access the related database

Notice that in the previous step when you typed `juju run data-integrator/leader get-credentials` the output also included the full URI. This means you do not have to generate the URI yourself.

To connect to this URI, first ssh into `mongodb/0`:

```shell
juju ssh mongodb/0
```

Then access `mongo` with the URI that you copied above:

```shell
charmed-mongodb.mongosh "<uri copied from get-credentials>"
```
Make sure you wrap the URI in quotation marks ( `""` ) with no trailing whitespace.

You will now be in the mongo shell as the user created for this relation. When you relate two applications, Charmed MongoDB automatically sets up a user and database for you. 

Enter `db.getName()` into the MongoDB shell. This will output the name of the database we specified when we first deployed the `data-integrator` charm:

```shell
test-database
```

To create a collection in `test-database` and then show the collection, enter:

```shell
db.createCollection("test-collection")
show collections
```

Now insert a document into this database:

```shell
db.test_collection.insertOne(
  {
    First_Name: "Jammy",
    Last_Name: "Jellyfish",
  })
```

You can verify this document was inserted by running:

```shell
db.test_collection.find()
```

Return to the original shell where you can interact with Juju and LXD by typing {command}`exit` twice.

### Remove the integration

Removing the integration automatically removes the user that was created with it.

To remove the integration (and therefore the user), run the following command:

```shell
juju remove-relation mongodb data-integrator
```

Now try again to connect to the same URI you just used to access the related database:

```shell
juju ssh mongodb/0
charmed-mongodb.mongosh "<uri copied from juju run-action data-integrator/leader get-credentials --wait>"
```

Make sure you wrap the URI in quotation marks ( `""` ) with no trailing whitespace.

This will output an error message:
```text
Current Mongosh Log ID: 638f5ffbdbd9ec94c2e58456
Connecting to:    mongodb://<credentials>@10.23.62.38,10.23.62.219/mongodb?replicaSet=mongodb&authSource=admin&appName=mongosh+1.6.1
MongoServerError: Authentication failed.
```

This is expected, since the user no longer exists. However, the database data still exists.

Return to the original shell where you can interact with Juju and LXD by typing {command}`exit` twice.

### Re-create the integration

If you wanted to recreate the user we just removed, all you would need to do is integrate the two applications again. This will generate new credentials, and therefore a new URI.

If you then connect to the database with the new URI and enter {command}`db.test_collection.find()`, you will see all your original documents are still present in the database.

Before proceeding, make sure you are in the original shell where you can interact with Juju and LXD.

## Enable encryption with TLS

[Transport Layer Security (TLS)](https://en.wikipedia.org/wiki/Transport_Layer_Security) is a protocol used to encrypt data exchanged between two applications. Essentially, it secures data transmitted over a network.

Typically, enabling TLS internally within a highly available database or between a highly available database and client/server applications requires a high level of expertise. This has all been encoded into Charmed MongoDB so that configuring TLS requires minimal effort on your end.

TLS is enabled by integrating Charmed MongoDB with the [Self Signed Certificates Charm](https://charmhub.io/self-signed-certificates). This charm centralises TLS certificate management consistently and handles operations like providing, requesting, and renewing TLS certificates.

In this section, you will learn how to enable security in your MongoDB deployment using TLS encryption.

```{admonition} Production disclaimer
:class: warning
**[Self-signed certificates](https://en.wikipedia.org/wiki/Self-signed_certificate) are not recommended for a production environment.**

For production environments, check the collection of [Charmhub operators](https://charmhub.io/?q=tls-certificates) that implement the `tls-certificate` interface, and choose the most suitable for your use-case.
```

### Deploy and configure the TLS operator

First, deploy the `self-signed-certificates` charm:

```shell
juju deploy self-signed-certificates
```

Wait until the `self-signed-certificates` app is `active`.

Once it has finished deploying, add a CA name to its configuration:

```shell
juju config self-signed-certificates ca-common-name="Tutorial CA" 
```

Now, to enable TLS on Charmed MongoDB, integrate the two applications:

```shell
juju integrate self-signed-certificates mongodb
```

### Access MongoDB via TLS

Like before, generate and save the URI that is used to connect to MongoDB:

```shell
export URI=mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP/$DB_NAME?replicaSet=$REPL_SET_NAME
echo $URI
```

Now ssh into `mongodb/0`:

```shell
juju ssh mongodb/0
```

We are now in the unit that is hosting Charmed MongoDB. 

Once TLS has been enabled, we will need to change how we connect to MongoDB. We will need to specify the TLS CA file along with the TLS Certificate file that were automatically created when we integrated the two charms.

You will find these files on the units hosting the Charmed MongoDB application in the folder `/var/snap/charmed-mongodb/common/etc/mongod`. 

If you enter: 

```shell
ls /var/snap/charmed-mongodb/current/etc/mongod/external*
``` 

you should see the following external certificate file and external CA files:

```shell
/var/snap/charmed-mongodb/current/etc/mongod/external-ca.crt  
/var/snap/charmed-mongodb/current/etc/mongod/external-cert.pem
```

As before, we will connect to MongoDB via the saved MongoDB URI. Connect using the saved URI and the following TLS options:

```shell
sudo charmed-mongodb.mongosh mongodb://$DB_USERNAME:$DB_PASSWORD@$HOST_IP/$DB_NAME?replicaSet=$REPL_SET_NAME --tls --tlsCAFile /var/snap/charmed-mongodb/current/etc/mongod/external-ca.crt  --tlsCertificateKeyFile /var/snap/charmed-mongodb/current/etc/mongod/external-cert.pem
```

You have successfully connected to MongoDB with TLS! 

When you are ready, leave the MongoDB shell by typing {command}`exit`. You will be back in the host of Charmed MongoDB (`mongodb/0`). Exit this host by typing {command}`exit` again.

You should now be at the original shell where you can interact with Juju and LXD.

### Disable TLS

To disable TLS, remove the integration between the two applications:

```shell
juju remove-relation mongodb self-signed-certificates
```

## Clean up your environment

In this tutorial, we’ve successfully:
* Deployed MongoDB on LXD
* Accessed a database and added data 
* Scaled our deployment 
* Added and removed database users
* Enabled and disabled TLS

You may now keep your MongoDB deployment running to continue experimenting, or remove it entirely to free up resources on your machine.

### Remove MongoDB

```{caution}
If you remove Charmed MongoDB as shown below, you will lose all data stored in MongoDB.    
```

**To remove Charmed MongoDB**, delete the model it is hosted on:

```shell
juju destroy-model tutorial --destroy-storage --force
```

Then, remove the `overlord` Juju controller:

```shell
juju destroy-controller overlord
```

### Remove Juju

```{caution}
If you remove Juju as shown below, you will lose access to any other applications you have hosted on Juju.
```

To remove Juju altogether, enter:
```shell
sudo snap remove juju --purge
```

You've successfully completed our Charmed MongoDB tutorial!

<!-- ## Next steps

Explain documentation structure - all instructions are for K8s and VM and for replica sets and sharded cluster. 
Mention we are working on a more advanced tutorial for a production deployment of a sharded cluster?
-->