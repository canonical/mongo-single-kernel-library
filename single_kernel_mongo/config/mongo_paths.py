#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Paths for Mongo charms."""

SNAP_NAME = "charmed-mongodb"

VM_PATH = {
    "mongod": {
        "ENVIRONMENT": "/etc/environment",
        "CONF": f"/var/snap/{SNAP_NAME}/current/etc/mongod",
        "DATA": f"/var/snap/{SNAP_NAME}/common/var/lib/mongodb",
        "LOGS": f"/var/snap/{SNAP_NAME}/common/var/log/mongodb",
        "ETC": f"/var/snap/{SNAP_NAME}/common/etc",
        "VAR": f"/var/snap/{SNAP_NAME}/common/var",
        "BIN": "/snap/bin",
        "SHELL": "/snap/bin/charmed-mongodb.mongosh",
        "LICENSES": f"/snap/{SNAP_NAME}/current/licenses",
    }
}
K8S_PATH = {
    "mongod": {
        "ENVIRONMENT": "/etc/environment",
        "CONF": "/etc/mongod",
        "DATA": "/var/lib/mongodb",
        "LOGS": "var/log/mongodb",
        "ETC": "/etc",
        "VAR": "/var/",
        "BIN": "/usr/bin/",
        "SHELL": "/usr/bin/mongosh",
        "LICENSES": "/licenses",
    }
}
