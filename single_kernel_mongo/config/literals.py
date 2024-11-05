# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Literal string for the different charms."""

from typing import Literal

Substrates = Literal["vm", "k8s"]
INTERNAL_USERS = ["operator", "backup", "monitor"]
SECRETS_APP = [f"{user}-password" for user in INTERNAL_USERS] + ["keyfile"]
