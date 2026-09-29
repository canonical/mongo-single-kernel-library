# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from enum import StrEnum


class Substrate(StrEnum):
    """The substrate a charm/test is running against."""

    lxd = "lxd"
    k8s = "k8s"
