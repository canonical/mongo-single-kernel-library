#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Some useful relational models."""

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
    DatabaseRequirerData,
    ProviderData,
    RequirerData,
)


class ClusterData(DatabaseProviderData, DatabaseRequirerData):  # type: ignore[misc]
    """Broker provider data model."""

    SECRET_FIELDS = [
        "username",
        "password",
        "tls",
        "tls-ca",
        "uris",
        "key-file",
        "int-ca-secret",
    ]


class ConfigServerData(ProviderData, RequirerData):  # type: ignore[misc]
    """Config Server data interface."""

    SECRET_FIELDS = [
        "username",
        "password",
        "tls",
        "tls-ca",
        "uris",
        "key-file",
        "operator-password",
        "backup-password",
        "int-ca-secret",
    ]
