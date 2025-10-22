(how-to-upgrade)=
# How to upgrade

The MongoDB charm supports two kinds of upgrades:
* Minor in-place upgrades of MongoDB 6 revisions via [`juju refresh`](https://documentation.ubuntu.com/juju/3.6/reference/juju-cli/list-of-juju-cli-commands/refresh/#details)
  * See: {ref}`minor-version-upgrade`
* Major upgrade from MongoDB 6 to MongoDB 8 via cluster migration
  * See: {ref}`major-version-upgrade`


```{toctree}
:titlesonly:
:hidden:

Minor version upgrade <minor-version-upgrade/index>
Major version upgrade <major-version-upgrade>
```
