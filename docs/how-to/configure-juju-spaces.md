(configure-juju-spaces)=
# How to configure Juju spaces

```{admonition} Caution
:class: warning

Juju spaces are only available on VM charms.
```

Use [Juju spaces](https://documentation.ubuntu.com/juju/3.6/reference/space/) to select separate networks for MongoDB traffic and client connections. This guide configures spaces at deployment time for Charmed MongoDB on machines (VM), using a local LXD deployment.

The example uses these endpoint bindings:

| Endpoint         | Space     | Subnet            | Traffic                                   |
| ---------------- | --------- | ----------------- | ----------------------------------------- |
| `database-peers` | `peers`   | `10.137.180.0/24` | Communication between replica-set members |
| `database`       | `clients` | `10.137.181.0/24` | Client connections to MongoDB             |

## Prerequisites

- An initialized LXD installation and permission to manage its networks with `sudo lxc`.
- A bootstrapped Juju controller on LXD and a model selected for this deployment. See {ref}`via-juju-cli`.
- The two example subnets must not overlap with existing networks on your host.

## Create the LXD networks

Create one bridge for replica-set members and another for clients:

```bash
sudo lxc network create peers --type=bridge \
  ipv4.address="10.137.180.1/24" ipv4.nat=True \
  ipv6.address=none dns.mode=none
sudo lxc network create clients --type=bridge \
  ipv4.address="10.137.181.1/24" ipv4.nat=True \
  ipv6.address=none dns.mode=none
```

Prevent these additional networks from advertising a default gateway or DNS server over DHCP, so machines continue to use their existing network for those services:

```bash
sudo lxc network set clients raw.dnsmasq "dhcp-option=3
dhcp-option=6"
sudo lxc network set peers raw.dnsmasq "dhcp-option=3
dhcp-option=6"
```

## Register the spaces in Juju

Refresh Juju's network information, then associate each subnet with a space:

```bash
juju reload-spaces
juju add-space clients 10.137.181.0/24
juju add-space peers 10.137.180.0/24
juju spaces
```

Check that `clients` contains `10.137.181.0/24` and `peers` contains `10.137.180.0/24`.

## Deploy MongoDB and the client

Deploy three MongoDB units with access to both spaces and bind the endpoints to their respective networks:

```bash
juju deploy mongodb --channel 8/stable \
  --constraints spaces=peers,clients \
  --bind "alpha database-peers=peers database=clients" \
  -n 3
```

The `spaces` constraint requests access to the named networks. The endpoint bindings select the space for each relation endpoint. The standalone `alpha` sets the default binding for endpoints not explicitly listed.

Deploy the `data-integrator` charm with its `mongodb` endpoint bound to the `clients` space:

```bash
juju deploy data-integrator --config database-name=example \
  --constraints spaces=clients \
  --bind "alpha mongodb=clients"
juju integrate mongodb:database data-integrator:mongodb
```

## Verify the client addresses

Wait for the applications to become active and idle:

```bash
juju status --watch 1s
```

Retrieve the client credentials:

```bash
juju run data-integrator/0 get-credentials
```

Inspect the connection URI in the action output (the `uris` field). Every MongoDB host address in that URI should belong to `10.137.181.0/24`, the `clients` subnet, rather than the `peers` subnet.

## Deploy on public clouds

For a public-cloud deployment, use the cloud's networking configuration to provision the subnets and connectivity, then map those subnets to Juju spaces and bind the application endpoints. The LXD bridge commands above apply only to the local example.

See the [Charmed MongoDB reference architectures](https://github.com/canonical/charms-reference-architectures/tree/main/solutions/data/charmed-mongodb) for public-cloud deployment references, and [Juju's guide to managing spaces](https://documentation.ubuntu.com/juju/3.6/howto/manage-spaces/) for space configuration.
