# Contributing

## Overview

This documents explains the processes and practices recommended for contributing enhancements to
this operator.

- Generally, before developing enhancements to this charm, you should consider
  [opening an issue](https://github.com/canonical/mongo-single-kernel-library/issues) explaining
  your use case.
- If you would like to chat with us about your use-cases or proposed
  implementation, you can reach us at [Data Platform Matrix public channel](https://matrix.to/#/#charmhub-data-platform:ubuntu.com) or [Discourse](https://discourse.charmhub.io/).
- Familiarising yourself with the [Charmed Operator Framework](https://juju.is/docs/sdk) library will help you a lot when working
  on new features or bug fixes.
- All enhancements require review before being merged. Code review typically
  examines
  - code quality
  - test coverage
  - user experience for Juju administrators this charm.
- Please help us out in ensuring easy to review branches by rebasing your pull
  request branch onto the `6/edge` branch. This also avoids merge commits and
  creates a linear Git commit history.

## Developing

Install `tox` and `poetry`

Install pipx: [https://pipx.pypa.io/stable/installation/](https://pipx.pypa.io/stable/installation/)

```shell
pipx install tox
pipx install poetry
```

You can create an environment for development:

```shell
poetry install
```

### Testing

```shell
tox run -e format        # update your code according to linting rules
tox run -e lint          # code style
tox run -e unit          # unit tests
tox run -e integration   # integration tests
tox                      # runs 'lint' and 'unit' environments
```

### `pre-commit` hooks

This repository comes with a sensible [pre-commit](https://github.com/pre-commit/pre-commit) hook configuration.
Please install it with `pre-commit install` as this will be checked in the CI anyway.

### Development guidelines

We try to create each object at most once, at the highest level it's used:
We reduce the cost of object creation, and we also ensure that any variable
modification is kept and accessible from everywhere: For example the
Container object is created in the operator and then passed down to all
workload objects.

## Canonical Contributor Agreement

Canonical welcomes contributions to the Mongo Charms Single Kernel Library.
check out our [contributor agreement](https://ubuntu.com/legal/contributors) if you're interested in contributing to the solution.
