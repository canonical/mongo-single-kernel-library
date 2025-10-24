(manage-private-keys)=
# How to manage private keys

By default, Charmed MongoDB 8 automatically manages private keys when TLS is enabled.

If preferred, you can use [Juju secrets](https://documentation.ubuntu.com/juju/latest/reference/secret/#secret) to manage the private keys used by the charm to generate the certificate signing requests (CSR).

You can manage the private keys used by the charm to generate the certificate signing requests (CSR), by storing the private key in a [juju secret](https://canonical-juju.readthedocs-hosted.com/en/latest/user/reference/secret/) and then referencing the secret in the [charm configuration](https://documentation.ubuntu.com/juju/latest/howto/manage-applications/index.html#configure-an-application).

```{seealso}
[Juju | How to manage secrets](https://documentation.ubuntu.com/juju/latest/howto/manage-secrets/#manage-secrets)
```

## Generate private keys

The recommendation is to use a private key per MongoDB application and per encryption (peer-to-peer or client-to-server).

Generate as many private keys as needed, using the following command:

```shell
openssl genrsa -out <private-key-name>.pem 3072
```

## Create secrets

Create a juju secret for each private key generated:

```{admonition} Caution
:class: warning

Passing keys to Juju should only be done with `base64 -w0`, not `cat`.
```

```shell
juju add-secret <secret-name> private-key=$(base64 -w0 <private-key-name>.pem)
```

The command will output a secret URI similar to the example below, which you will need shortly:

```text
secret:ctbirhuutr9sr8mgrmpg
```

Grant the secret to your MongoDB application:

```shell
juju grant-secret <secret-name> <application-name>
```

## Reference the secret in the charm configuration

According to the required TLS encryption, set the configuration option in your MongoDB application to the secret’s URI obtained in the previous step:

```{tip}
Make sure to include the `secret:` prefix.
```

### Peer-to-peer TLS

```shell
juju config <application-name> tls-peer-private-key=<secret-uri>`
```

### Client-to-server TLS

```shell
juju config <application-name> tls-client-private-key=<secret-uri>`
```