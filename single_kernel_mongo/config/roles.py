#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The different roles."""

from dataclasses import dataclass

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.mongo_paths import K8S_PATH, VM_PATH


@dataclass
class Role:
    """Defines a role for the charm."""

    substrate: Substrates
    paths: dict[str, str]


@dataclass
class MongoDBRole(Role):
    """Role for MongoDB charms."""

    ...


@dataclass
class MongosRole(Role):
    """Role for Mongos charms."""

    ...


VM_MONGO = MongoDBRole(substrate="vm", paths=VM_PATH["mongod"])
K8S_MONGO = MongoDBRole(substrate="k8s", paths=K8S_PATH["mongod"])

ROLES = {"vm": VM_MONGO, "k8s": K8S_MONGO}
