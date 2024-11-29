#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Test MongoDB charm."""

from ops.main import main

from single_kernel_mongo.abstract_charm import AbstractMongoCharm
from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.core.structured_config import MongoDBCharmConfig
from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


class MongoTestCharm(AbstractMongoCharm[MongoDBCharmConfig, MongoDBOperator]):
    config_type = MongoDBCharmConfig
    operator_type = MongoDBOperator
    substrate = Substrates.VM
    peer_rel_name = RelationNames.PEERS.value
    name = "mongodb-test"


if __name__ == "__main__":
    main(MongoTestCharm)
