#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

UNIT_IDS = [0, 1, 2]
MONGODB_SNAP_CONF_DIR = "/var/snap/charmed-mongodb/current/etc/mongod"
MONGODB_ROCK_CONF_DIR = "/etc/mongod"

MONGO_SHELL = "charmed-mongodb.mongosh"
MONGOD_PORT = 27017
MONGOS_PORT = 27018
BASE = "ubuntu@24.04"
TIMEOUT = 15 * 60
DEPLOYMENT_TIMEOUT = 2000
CHARMED_BACKUP_USERNAME = "charmed-backup"
CHARMED_OPERATOR_USERNAME = "charmed-operator"
CHARMED_OPERATOR_PASSWORD = "operator-password"
CHARMED_STATS_USERNAME = "charmed-stats"
INTERNAL_USER_PASSWORD_CONFIG = "system-users"


CONTINUOUS_WRITE_APPLICATION = "continuous-write"
CONTINUOUS_WRITE_APPLICATION_BIS = "continuous-write-bis"
READER_APPLICATION = "reader-application"
DATA_INTEGRATOR_APP_NAME = "data-integrator"

# Keep in sync with tests/integration/applications/continuous_write_charm/src/charm.py
DEFAULT_DATABASE_NAME = "continuous_writes_database"
DEFAULT_COLLECTION_NAME = "continuous_writes_collection"
DEFAULT_REPLICATION_COLL_NAME = "test_ubuntu_collection"

MEDIAN_REELECTION_TIME = 12

TEST_DOCUMENTS = """[
    {
        \"uid\": 123,
        \"label\": \"Lorem\",
        \"price\": 2.3,
        \"currency\": \"eur\",
        \"exp_date\": \"2022-12-12\"
    },
    {
        \"uid\": 3456,
        \"label\": \"Ipsum\",
        \"price\": 18,
        \"currency\": \"usd\",
        \"exp_date\": \"2023-01-13\"
    }
]"""


MONGOS_APP_NAME = "mongos"
