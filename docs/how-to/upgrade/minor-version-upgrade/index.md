(minor-version-upgrade)=
# How to perform a minor version upgrade

Charmed MongoDB supports in-place upgrades via [`juju refresh`](https://documentation.ubuntu.com/juju/3.6/reference/juju-cli/list-of-juju-cli-commands/refresh/#details) for replica sets and sharded clusters.

This type of upgrade can only be done between revisions of the same major version.

*e.g.* revision 199 in `6/stable` --> revision 229 in `6/stable`.   

## Guides
```{toctree}
:titlesonly:

Upgrade a replica set <upgrade-replica-set>
Upgrade a sharded cluster <upgrade-sharded-cluster>
```