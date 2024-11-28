#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Test MongoDB charm."""

from ops.main import main

from single_kernel_mongo.abstract_charm import AbstractMongoCharm
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.core.structured_config import MongoDBCharmConfig


class MongoTestCharm(AbstractMongoCharm[MongoDBCharmConfig]):
    config_type = MongoDBCharmConfig
    substrate = "vm"
    peer_rel_name = RelationNames.PEERS.value
    name = "mongodb-test"


if __name__ == "__main__":
    main(MongoTestCharm)
