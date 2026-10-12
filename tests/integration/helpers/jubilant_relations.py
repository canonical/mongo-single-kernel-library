# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
from tenacity import (
    RetryError,
    Retrying,
    stop_after_delay,
    wait_fixed,
)

from tests.integration.helpers.jubilant_common import (
    execute_on_mongod,
    get_application_relation_data,
    get_mongodb_hostname_for_unit,
    get_mongodb_hostnames_for_app,
    replica_set_uri,
)
from tests.integration.helpers.types import Substrate


def verify_application_data(
    juju: jubilant.Juju, substrate: Substrate, app_name: str, database_app: str, relation_name: str
) -> bool:
    """Verifies the application relation metadata matches with the MongoDB deployment.

    Specifically, it verifies that all units are present in the URI and that there are no
    additional units
    """
    try:
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3)):
            with attempt:
                endpoints_str = get_application_relation_data(
                    juju, app_name, relation_name, "endpoints"
                )
                if not endpoints_str:
                    raise Exception("Missing endpoints URI")
                for unit, unit_status in juju.status().get_units(database_app).items():
                    public_address = get_mongodb_hostname_for_unit(
                        juju, substrate, unit, unit_status
                    )
                    if public_address not in endpoints_str:
                        raise Exception(f"unit {unit} not present in connection URI")

                if len(endpoints_str.split(",")) != len(juju.status().get_units(database_app)):
                    raise Exception(
                        "number of endpoints in replicaset URI do not match number of units"
                    )

    except RetryError:
        return False

    return True


def assert_created_user_can_connect(
    juju: jubilant.Juju, substrate: Substrate, database_name: str, username: str, password: str
):
    """Verifies that the provided username can connect to the DB with the given password."""
    hosts = get_mongodb_hostnames_for_app(juju, substrate, database_name)
    uri = replica_set_uri(
        username=username, password=password, ip_addresses=list(hosts), replica_set=database_name
    )

    result = execute_on_mongod(
        juju,
        substrate,
        database_name,
        uri=uri,
        command="db.runCommand({ping: 1})",
        expecting_output=False,
    )

    assert result.succeeded, f"User {username} failed to connect with password {password}"
