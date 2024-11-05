#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The different roles."""
from dataclasses import dataclass

from single_kernel_mongo.config.mongo_paths import VM_PATH


@dataclass
class Role:
    """Defines a role for the charm."""

    substrate: str
    service: str
    paths: dict[str, str]


VM_MONGOD = Role(substrate="vm", service="mongod", paths=VM_PATH["mongod"])
K8S_MONGOD = Role(substrate="k8s", service="mongod", paths=VM_PATH["mongod"])
VM_MONGOS = Role(substrate="vm", service="mongos", paths=VM_PATH["mongod"])
K8S_MONGOS = Role(substrate="k8s", service="mongos", paths=VM_PATH["mongod"])
