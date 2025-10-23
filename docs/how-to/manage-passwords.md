(manage-passwords)=
# How to manage passwords

By default, Charmed MongoDB 8 automatically generates passwords for the following internal users: `charmed-operator`, `charmed-stats`, `charmed-backup`, `charmed-logrotate`.

You can use [Juju secrets](https://documentation.ubuntu.com/juju/latest/reference/secret/#secret) to manage passwords for these users.

```{seealso}
[Juju | How to manage secrets](https://documentation.ubuntu.com/juju/latest/howto/manage-secrets/#manage-secrets)
```

## Set passwords

Create a Juju secret containing one or more user passwords:

```shell
juju add-secret <secret-name> <username-1>=<password-1> <username-2>=<password-2>
```

```{note}
Valid usernames: `charmed-operator`, `charmed-stats`, `charmed-backup`, `charmed-logrotate`.
```

Internal users that are not included in the secret will keep the automatically-generated password.

The command above will output a secret URI similar to the example below, which you will need shortly:

```text
secret:ctbirhuutr9sr8mgrmpg
```

Grant the secret to your replica set, or to your config server if you are using a sharded deployment:

```shell
juju grant-secret <secret-name> <application-name>

```

## Configure `system-users`

Set the `system-users` configuration option in your replica set or config-server, to the secret’s URI obtained in the previous step:

```{tip}
Make sure to include the `secret:` prefix.
```

```{caution}
Do not set this configuration option for applications using the `shard` role.
```

```shell
juju config <application-name> system-users=<secret_URI>
```

When the `system-users` configuration option is set, the charm will:
* Use the content of the secret specified by the `system-users` config option instead of the one automatically generated.
* Update the passwords of the internal `system-users` in the database.

## Update passwords

To update passwords, update the value of the existing secret:

```shell
juju update-secret <secret-name> <username-1>=<new-password-1> <username-3>=<password-3>
```

In this example,
* `username-1`’s password was updated from `password-1` to `new-password-1`
* `username-3`’s password was updated from an auto-generated password to `password-3`
* `username-2`’s password remains as it was when the secret was added, but **`username-2` is no longer part of the secret**.

See also: [Explanation > Users](/explanation/users)

See also: [How to > Manage client connections](/how-to/manage-client-connections) to manage client passwords