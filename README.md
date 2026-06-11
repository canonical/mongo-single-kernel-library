# mongodb-artifacts

This repository contains MongoDB packaging artifacts used by Canonical, including snaps and rocks for MongoDB server deployments.


## Repository structure

The main directory structure is:

```text
mongodb-artifacts/
├── LICENSE
├── README.md
└── mongodb/
    ├── snaps/
    │   └── slim/
    │       ├── mongodb-server-replicaset/ # Snap for a MongoDB replica set deployment.
    │       └── mongodb-server-sharded/ # Snap for a full MongoDB sharded deployment that includes both `mongod` and `mongos`.
    └── rocks/  # future MongoDB rocks
└── mongos/
    ├── snaps/
    │   └── slim/
    │       └── mongos/ # Snap for the MongoDB sharded cluster query router only (`mongos`).
    └── rocks/  # future mongos rocks
```

## Getting started

To work on a specific snap, change into the appropriate subdirectory and use `snapcraft` to build it:

```bash
git clone https://github.com/canonical/mongodb-artifacts.git
cd mongodb-artifacts/mongodb/snaps/slim/<snap-name>
snapcraft pack
```

For development builds, install the generated snap with `--devmode`:

```bash
sudo snap install ./<snap-name>*.snap --devmode
```

Each snap also includes its own `README.md` and `CONTRIBUTING.md` with installation, usage, and build instructions.

## Project & Community

MongoDB artifacts is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongodb-artifacts/issues)
* Report security issues through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)


## Contributing

If you want to contribute, see the `CONTRIBUTING.md` file in the relevant snap subdirectory for clone, build, lint, and test instructions.

## License

This repository is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
