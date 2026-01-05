(decommissioning)=
# How to decommission your deployment

When Charmed MongoDB is no longer required, it is important to decommission it securely to avoid accidental retention or exposure of sensitive data such as credentials, user data, or operational metadata.

## Recommended Decommissioning Steps

### 1. Stop Client Access

Ensure all applications and clients are disconnected from MongoDB. Revoke any application credentials or database users that will no longer be used.

If you used the Database Integrator charm to integrate your application with Charmed MongoDB, remove all the integrations as
specified [here](https://canonical-charmed-mongodb.readthedocs-hosted.com/6/tutorial/#remove-the-integration).

### 2. Backup (Optional)

If required, take a final backup of the database before removal. See: {ref}`how-to-backup-index`.

### 3. Remove Charmed MongoDB applications

```{caution}
If you remove Charmed MongoDB as shown below, you will lose all data stored in MongoDB.
```

Remove all the applications related to your deployment, including:
- Shards
- Config servers
- Replica sets
- Mongos
- Database integrator charms

To ensure data is securely removed, destroy all associated storage:

```shell
juju remove-application <application-name> --destroy-storage
```

See: [How to remove an application](https://documentation.ubuntu.com/juju/3.6/howto/manage-applications/#remove-an-application)

### 4. Remove the environment

If the entire environment is no longer needed, destroy the Juju model to ensure no residual resources remain.

```shell
juju destroy-model <model-name> --destroy-storage
```

See: [How to remove a model](https://documentation.ubuntu.com/juju/3.6/howto/manage-models/#destroy-a-model)

Then, remove the Juju controller:

```shell
juju destroy-controller <controller-name>
```

See:[How to remove a controller](https://documentation.ubuntu.com/juju/3.6/howto/manage-controllers/#remove-a-controller)

### 5. Remove Juju

```{caution}
If you remove Juju as shown below, you will lose access to any other applications you have hosted on Juju.
```

To remove Juju altogether, enter:
```shell
sudo snap remove juju --purge
```

See: [How to remove Juju](https://documentation.ubuntu.com/juju/3.6/howto/manage-juju/#uninstall-juju)
