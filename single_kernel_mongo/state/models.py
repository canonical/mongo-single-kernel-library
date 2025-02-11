#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Some useful relational models."""

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    ProviderData,
    RequirerData,
)


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
