# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Skeleton for the abstract charm."""

from typing import Generic, TypeVar

from single_kernel_mongo.core.structured_config import MongoConfigModel
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_models import (
    TypedCharmBase,
)
from single_kernel_mongo.status import StatusManager

T = TypeVar("T", bound=MongoConfigModel)


class AbstractMongoCharm(Generic[T], TypedCharmBase[T]):
    """An abstract mongo charm."""

    status_manager: StatusManager
    config: T

    pass
