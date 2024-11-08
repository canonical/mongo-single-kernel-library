#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The different roles."""

from dataclasses import dataclass

from single_kernel_mongo.config.mongo_paths import K8S_PATH, VM_PATH


@dataclass
class Role:
    """Defines a role for the charm."""

    substrate: str
    paths: dict[str, str]


VM_MONGO = Role(substrate="vm", paths=VM_PATH["mongod"])
K8S_MONGO = Role(substrate="k8s", paths=K8S_PATH["mongod"])

ROLES = {"vm": VM_MONGO, "k8s": K8S_MONGO}
