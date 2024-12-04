# Mongo Charms Single Kernel library

Library containing shared code for MongoDB operators (mongodb, mongos, VM and k8s).

The goal of this library is to provide reusable and shared code for the four
mongo charms:

* [MongoDB VM](https://github.com/canonical/mongodb-operator/)
* [MongoDB Kubernetes](https://github.com/canonical/mongodb-k8s-operator/)
* [Mongos VM](https://github.com/canonical/mongos-operator/)
* [Mongos Kubernetes](https://github.com/canonical/mongos-k8s-operator/)

## Code layout

The source code can be found in [./single_kernel_mongo/](./single_kernel_mongo/)
The layout is organised as so:

* [configurations](./single_kernel_mongo/config)
* [core services](./single_kernel_mongo/core/)
* [events handlers](./single_kernel_mongo/events/)
* [event managers](./single_kernel_mongo/managers/)
* [charm state](./single_kernel_mongo/state/)
* [charm workloads](./single_kernel_mongo/workload/)
* [utils and helpers](./single_kernel_mongo/utils/)
* [abstract charm skeleton](./single_kernel_mongo/abstract_charm.py)
* [exceptions](./single_kernel_mongo/exceptions.py)

## Contributing

You can have longer explanations in [./CONTRIBUTING.md](./CONTRIBUTING.md) but for a quick start:

```shell
# Install poetry and tox
pipx install tox
pipx install poetry

poetry install
```

Code quality is enforced using [pre-commit](https://github.com/pre-commit/pre-commit) hooks. They will run before each commit and also at other stages.

```shell
# Install the first time
pre-commit install

# Run it manually with
pre-commit run --all-files
```

## Project and community

Charmed Mongos K8s is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests on [GitHub](https://github.com/canonical/mongo-single-kernel-library/issues)
* Report security issues through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File).
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongo-single-kernel-library/blob/main/CONTRIBUTING.md) to the code

## License

The Mongo Single Library is free software, distributed under the Apache Software License, version 2.0. See [LICENSE](https://github.com/canonical/mongo-single-kernel-library/blob/main/LICENSE) for more information.
