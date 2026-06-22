(how-to)=

# How-to guides

Key processes and common tasks for deploying, configuring, and operating Charmed MongoDB.

## Deployment and setup

Available deployment methods and operations to consider at deploy-time:

```{toctree}
:titlesonly:
:maxdepth: 2

Deploy <deploy/index>
Manage persistent storage <manage-persistent-storage>
```

## Operations and maintenance

Essential operations to configure and manage a MongoDB cluster:

```{toctree}
:titlesonly:

Scale replicas and shards <scale-replicas-and-shards>
Enable cluster-wide rolling ops <rolling-ops>
Manage TLS encryption <tls/index>
````

Connect to an application and manage user credentials and authentication:

```{toctree}
:titlesonly:

Manage client connections <manage-client-connections>
Manage passwords <manage-passwords>
Enable LDAP <enable-ldap>
````

### Back up and restore

Configure storage providers and manage backups for safety and data migration:

```{toctree}
:titlesonly:
:maxdepth: 2

Back up and restore <back-up-and-restore/index>
```

### Monitoring

Integrate with observability services like Grafana through the Canonical Observability Stack (COS):

```{toctree}
:titlesonly:
:maxdepth: 2

Monitoring <monitoring/index>
```

### Upgrade

Upgrade your MongoDB applications to a new minor revision in-place, or across major versions:

```{toctree}
:titlesonly:
:maxdepth: 3

Upgrade <upgrade/index>
Encryption at rest <encryption-at-rest>
```
## Delete your deployment

Securely decomission your deployment to avoid exposing sensitive data:

```{toctree}
:titlesonly:

Decommission your deployment <decommission>
```

For more information about security hardening, see {ref}`security`.