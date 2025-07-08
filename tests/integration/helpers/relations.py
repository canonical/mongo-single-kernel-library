# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    stop_after_delay,
    wait_fixed,
)

from ..helpers.common import (
    execute_on_mongod,
    generate_mongodb_client,
    get_application_relation_data,
)
from ..helpers.types import Substrate

REPLICATION_APP_NAME = "replication"
APPLICATION_APP_NAME = "application"
FIRST_DATABASE_RELATION_NAME = "first-database"
SECOND_DATABASE_RELATION_NAME = "second-database"


async def verify_application_data(
    ops_test: OpsTest,
    application_name: str,
    database_app: str,
    relation_name: str,
) -> bool:
    """Verifies the application relation metadata matches with the MongoDB deployment.

    Specifically, it verifies that all units are present in the URI and that there are no
    additional units
    """
    try:
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3)):
            with attempt:
                endpoints_str = await get_application_relation_data(
                    ops_test, application_name, relation_name, "endpoints"
                )
                for unit in ops_test.model.applications[database_app].units:
                    if unit.public_address not in endpoints_str:
                        raise Exception(f"unit {unit.name} not present in connection URI")

                if len(endpoints_str.split(",")) != len(
                    ops_test.model.applications[database_app].units
                ):
                    raise Exception(
                        "number of endpoints in replicaset URI do not match number of units"
                    )

    except RetryError:
        return False

    return True


async def assert_created_user_can_connect(
    ops_test: OpsTest, substrate: Substrate, database_name: str, username: str, password: str
):
    """Verifies that the provided username can connect to the DB with the given password."""
    uri = await generate_mongodb_client(
        ops_test, substrate, database_name, mongos=False, username=username, password=password
    )

    result = await execute_on_mongod(
        ops_test, database_name, substrate, uri, "db.runCommand({ping: 1})", expecting_output=False
    )

    assert result.succeeded, f"User {username} failed to connect with password {password}"
