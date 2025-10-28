# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


from logging import getLogger

from juju.unit import Unit as JujuUnit
from pymongo import MongoClient
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from tests.integration.helpers.backups import insert_unwanted_data
from tests.integration.helpers.common import (
    DEPLOYMENT_TIMEOUT,
    MONGOS_PORT,
    deploy_charm,
    get_direct_mongo_client,
    get_leader_id,
    mongodb_uri,
)
from tests.integration.helpers.tls import (
    SNAP_MONGOD_SERVICE,
    SNAP_MONGOS_SERVICE,
    TLS_CERTIFICATES_APP_NAME,
    TLS_RELATION_NAME,
    check_certs_correctly_distributed,
    check_tls,
    external_cert_path,
    get_file_content,
    internal_cert_path,
    set_private_keys,
    time_file_created,
    time_process_started,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)

MONGODB_CHARM_NAME = "mongodb"
SHARD_ONE_APP_NAME = "shard-one"
SHARD_TWO_APP_NAME = "shard-two"
SHARD_THREE_APP_NAME = "shard-tree"
CONFIG_SERVER_APP_NAME = "config-server"
CONFIG_SERVER_TWO_APP_NAME = "config-server-two"
CLUSTER_COMPONENTS = [CONFIG_SERVER_APP_NAME, SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME]
CONFIG_SERVER_REL_NAME = "config-server"
SHARD_REL_NAME = "sharding"
CLUSTER_REL_NAME = "cluster"
SHARD_APPS = [SHARD_ONE_APP_NAME, SHARD_TWO_APP_NAME]

SHARD_ONE_APP_NAME_NEW = "shard-one-new"
SHARD_TWO_APP_NAME_NEW = "shard-two-new"
CONFIG_SERVER_APP_NAME_NEW = "config-server-new"
CLUSTER_APPS_NEW = [
    SHARD_ONE_APP_NAME_NEW,
    SHARD_TWO_APP_NAME_NEW,
    CONFIG_SERVER_APP_NAME_NEW,
]

SHARD_DEFAULT_COLL_NAME = "test_collection"
SHARD_ONE_DB_NAME = "continuous_writes_database"
SHARD_ONE_COLL_NAME = "test_collection"
SHARD_TWO_DB_NAME = "new-db-2"
SHARD_TWO_COLL_NAME = "test_collection"

CLUSTER_APPS = [
    CONFIG_SERVER_APP_NAME,
    SHARD_ONE_APP_NAME,
    SHARD_TWO_APP_NAME,
    SHARD_THREE_APP_NAME,
]


async def deploy_cluster_components(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict,
    num_units_cluster_config: dict | None = None,
    config_server_name: str = CONFIG_SERVER_APP_NAME,
    shard_one_name: str = SHARD_ONE_APP_NAME,
    shard_two_name: str = SHARD_TWO_APP_NAME,
    channel: str | None = None,
    extra_config_config_server: dict[str, str] = {},
) -> None:
    if not num_units_cluster_config:
        num_units_cluster_config = {
            config_server_name: 2,
            shard_one_name: 3,
            shard_two_name: 1,
        }

    if channel is None:
        my_charm = mongodb_charm
    else:
        my_charm = "mongodb" if substrate == "lxd" else "mongodb-k8s"

    await deploy_charm(
        ops_test,
        my_charm,
        substrate,
        app_name=config_server_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[config_server_name],
        channel=channel,
        config={"role": "config-server"} | extra_config_config_server,
    )
    await deploy_charm(
        ops_test,
        my_charm,
        substrate,
        app_name=shard_one_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[shard_one_name],
        channel=channel,
        config={"role": "shard"},
    )
    await deploy_charm(
        ops_test,
        my_charm,
        substrate,
        app_name=shard_two_name,
        mongod_resource=mongod_resource,
        num_units=num_units_cluster_config[shard_two_name],
        channel=channel,
        config={"role": "shard"},
    )

    await ops_test.model.wait_for_idle(
        apps=[config_server_name, shard_one_name, shard_two_name],
        idle_period=20,
        timeout=DEPLOYMENT_TIMEOUT,
    )


async def integrate_sharding_components(
    ops_test: OpsTest,
    config_server_name: str = CONFIG_SERVER_APP_NAME,
    shard_one_name: str = SHARD_ONE_APP_NAME,
    shard_two_name: str = SHARD_TWO_APP_NAME,
) -> None:
    """Integrates the cluster components with each other."""
    await ops_test.model.integrate(
        f"{shard_one_name}:{SHARD_REL_NAME}",
        f"{config_server_name}:{CONFIG_SERVER_REL_NAME}",
    )
    await ops_test.model.integrate(
        f"{shard_two_name}:{SHARD_REL_NAME}",
        f"{config_server_name}:{CONFIG_SERVER_REL_NAME}",
    )


def get_cluster_shards(mongos_client: MongoClient) -> set:
    """Returns a set of the shard members."""
    shard_list = mongos_client.admin.command("listShards")
    curr_members = [member["host"].split("/")[0] for member in shard_list["shards"]]
    return set(curr_members)


def has_correct_shards(mongos_client: MongoClient, expected_shards: list[str]) -> bool:
    """Returns true if the cluster config has the expected shards."""
    shard_names = get_cluster_shards(mongos_client)
    logger.info(f"Expecting {expected_shards}, got {shard_names}")
    return shard_names == set(expected_shards)


def write_data_to_mongodb(client: MongoClient, db_name: str, coll_name: str, content: dict) -> None:
    """Writes data to the provided collection and database."""
    db = client[db_name]
    horses_collection = db[coll_name]
    horses_collection.insert_one(content)


def remove_db_writes(client: MongoClient, db_name: str, coll_name: str):
    """Remove any writes to the test collection."""
    db = client[db_name]

    # collection for continuous writes
    test_collection = db[coll_name]
    test_collection.drop()


def verify_data_mongodb(
    client: MongoClient, db_name: str, coll_name: str, key: str, value: str
) -> bool:
    """Checks a key/value pair for a provided collection and database."""
    db = client[db_name]
    test_collection = db[coll_name]
    query = test_collection.find({}, {key: 1})
    return query[0][key] == value


def get_databases_for_shard(mongos_client: MongoClient, shard_name: str) -> list[str] | None:
    """Returns the databases hosted on the given shard."""
    config_db = mongos_client["config"]
    if "databases" not in config_db.list_collection_names():
        return None

    databases_collection = config_db["databases"]

    if databases_collection is None:
        return None

    return databases_collection.distinct("_id", {"primary": shard_name})


def shard_has_databases(
    mongos_client: MongoClient, shard_name: str, expected_databases_on_shard: list[str]
) -> bool:
    """Returns true if the provided shard is a primary for the provided databases."""
    databases_on_shard = get_databases_for_shard(mongos_client, shard_name=shard_name)
    if not databases_on_shard:
        return False
    return set(databases_on_shard) == set(expected_databases_on_shard)


def count_users(mongos_client: MongoClient) -> int:
    """Returns the number of users using the cluster."""
    admin_db = mongos_client["admin"]
    users_collection = admin_db.system.users
    return users_collection.count_documents({})


async def integrate_with_tls(ops_test: OpsTest, applications: list[str] | None = None) -> None:
    """Integrates cluster components with self-signed certs operator."""
    if not applications:
        applications = CLUSTER_COMPONENTS
    for app in applications:
        await ops_test.model.integrate(
            f"{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
            f"{app}:{TLS_RELATION_NAME}",
        )


async def remove_tls_integrations(ops_test: OpsTest, applications: list[str] | None = None) -> None:
    """Removes the TLS integration from all cluster components."""
    if not applications:
        applications = CLUSTER_COMPONENTS
    for app in applications:
        await ops_test.model.applications[app].remove_relation(
            f"{app}:{TLS_RELATION_NAME}",
            f"{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION_NAME}",
        )


async def check_cluster_tls_enabled(
    ops_test: OpsTest,
    substrate: Substrate,
    components: list[str] = CLUSTER_COMPONENTS,
    config_server: str = CONFIG_SERVER_APP_NAME,
) -> None:
    # check each replica set is running with TLS enabled
    for cluster_component in components:
        for unit in ops_test.model.applications[cluster_component].units:
            assert await check_tls(
                ops_test, substrate, unit, enabled=True, app_name=cluster_component, mongos=False
            ), f"MongoDB TLS not enabled in unit {unit.name}"

    # check mongos is running with TLS enabled
    for unit in ops_test.model.applications[config_server].units:
        assert await check_tls(
            ops_test, substrate, unit, enabled=True, app_name=config_server, mongos=True
        ), f"Mongos TLS not enabled in unit {unit.name}"


async def check_cluster_tls_disabled(ops_test: OpsTest, substrate: Substrate) -> None:
    # check each replica set is running with TLS enabled
    for cluster_component in CLUSTER_COMPONENTS:
        for unit in ops_test.model.applications[cluster_component].units:
            assert await check_tls(
                ops_test, substrate, unit, enabled=False, app_name=cluster_component, mongos=False
            ), f"MongoDB TLS not disabled in unit {unit.name}"

    # check mongos is running with TLS enabled
    for unit in ops_test.model.applications[CONFIG_SERVER_APP_NAME].units:
        assert await check_tls(
            ops_test, substrate, unit, enabled=False, app_name=CONFIG_SERVER_APP_NAME, mongos=True
        ), f"Mongos TLS not disabled in unit {unit.name}"


async def rotate_and_verify_certs(ops_test: OpsTest, substrate: Substrate, app_name: str) -> None:
    """Verify provided app can rotate its TLS certs."""
    original_tls_info = {}

    ext_cert_path = external_cert_path(substrate)
    int_cert_path = internal_cert_path(substrate)

    for unit in ops_test.model.applications[app_name].units:
        original_tls_info[unit.name] = {}
        original_tls_info[unit.name]["external_cert_contents"] = await get_file_content(
            ops_test, substrate, unit.name, ext_cert_path
        )
        original_tls_info[unit.name]["internal_cert_contents"] = await get_file_content(
            ops_test, substrate, unit.name, int_cert_path
        )
        original_tls_info[unit.name]["external_cert"] = await time_file_created(
            ops_test, substrate, unit.name, ext_cert_path
        )
        original_tls_info[unit.name]["internal_cert"] = await time_file_created(
            ops_test, substrate, unit.name, int_cert_path
        )
        original_tls_info[unit.name]["mongod_service"] = await time_process_started(
            ops_test, substrate, unit.name, SNAP_MONGOD_SERVICE
        )
        if app_name == CONFIG_SERVER_APP_NAME:
            original_tls_info[unit.name]["mongos_service"] = await time_process_started(
                ops_test, substrate, unit.name, SNAP_MONGOS_SERVICE
            )
        await check_certs_correctly_distributed(ops_test, substrate, app_name=app_name, unit=unit)

    # set external and internal key using auto-generated key for each unit
    await set_private_keys(ops_test, app_name)

    # wait for certificate to be available and processed. Can get receive two certificate
    # available events and restart twice so we want to ensure we are idle for at least 1 minute
    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, idle_period=60
    )

    # After updating both the external key and the internal key a new certificate request will be
    # made; then the certificates should be available and updated.
    for unit in ops_test.model.applications[app_name].units:
        new_external_cert = await get_file_content(ops_test, substrate, unit.name, ext_cert_path)
        new_internal_cert = await get_file_content(ops_test, substrate, unit.name, int_cert_path)
        new_external_cert_time = await time_file_created(
            ops_test, substrate, unit.name, ext_cert_path
        )
        new_internal_cert_time = await time_file_created(
            ops_test, substrate, unit.name, int_cert_path
        )
        new_mongod_service_time = await time_process_started(
            ops_test, substrate, unit.name, SNAP_MONGOD_SERVICE
        )
        if app_name == CONFIG_SERVER_APP_NAME:
            new_mongos_service_time = await time_process_started(
                ops_test, substrate, unit.name, SNAP_MONGOS_SERVICE
            )

        await check_certs_correctly_distributed(ops_test, substrate, app_name=app_name, unit=unit)
        assert (
            new_external_cert != original_tls_info[unit.name]["external_cert_contents"]
        ), "external cert not rotated"

        assert (
            new_internal_cert != original_tls_info[unit.name]["external_cert_contents"]
        ), "external cert not rotated"
        assert (
            new_external_cert_time > original_tls_info[unit.name]["external_cert"]
        ), f"external cert for {unit.name} was not updated."
        assert (
            new_internal_cert_time > original_tls_info[unit.name]["internal_cert"]
        ), f"internal cert for {unit.name} was not updated."

        # Once the certificate requests are processed and updated the .service file should be
        # restarted
        assert (
            new_mongod_service_time > original_tls_info[unit.name]["mongod_service"]
        ), f"mongod service for {unit.name} was not restarted."

        if app_name == CONFIG_SERVER_APP_NAME:
            assert (
                new_mongos_service_time > original_tls_info[unit.name]["mongos_service"]
            ), f"mongos service for {unit.name} was not restarted."

    # Verify that TLS is functioning on all units.
    await check_cluster_tls_enabled(ops_test, substrate)


async def count_shard_writes(
    ops_test: OpsTest,
    substrate: Substrate,
    config_server_name: str,
    db_name: str,
    collection_name: str,
) -> int:
    """New versions of pymongo no longer support the count operation, instead find is used."""
    leader_id = await get_leader_id(ops_test, config_server_name)
    connection_string = await mongodb_uri(
        ops_test, substrate, unit_ids=[leader_id], app_name=config_server_name, port=MONGOS_PORT
    )

    client = MongoClient(connection_string, directConnection=True)
    db = client[db_name]
    test_collection = db[collection_name]
    count = test_collection.count_documents({})
    client.close()
    return count


async def get_cluster_writes_count(
    ops_test: OpsTest,
    substrate: Substrate,
    shard_app_names: list[str],
    db_names: list[str],
    config_server_name: str = CONFIG_SERVER_APP_NAME,
) -> dict:
    """Returns a dictionary of the writes for each cluster_component and the total writes."""
    cluster_write_count = {}
    total_writes = 0
    for app_name in shard_app_names:
        cluster_write_count[app_name] = 0
        for db in db_names:
            component_writes = await count_shard_writes(
                ops_test,
                substrate,
                config_server_name=config_server_name,
                db_name=db,
                collection_name=SHARD_DEFAULT_COLL_NAME,
            )
            cluster_write_count[app_name] += component_writes
            total_writes += component_writes

    cluster_write_count["total_writes"] = total_writes
    return cluster_write_count


async def add_and_verify_unwanted_writes(
    ops_test: OpsTest, substrate: Substrate, unit: JujuUnit, old_cluster_writes: dict
) -> None:
    """Add writes to all shards that will be cleared after restoring backup.

    Note: this test also verifies every shard has unwanted writes.
    """
    await insert_unwanted_data(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, unit=unit, mongos=True
    )

    # new writes added to cluster in `insert_unwanted_data` get sent to shard-one - add more
    # writes to shard-two
    mongos_client = await get_direct_mongo_client(
        ops_test, substrate, app_name=CONFIG_SERVER_APP_NAME, mongos=True
    )
    write_data_to_mongodb(
        mongos_client,
        db_name=SHARD_TWO_DB_NAME,
        coll_name=SHARD_TWO_COLL_NAME,
        content={"horse-breed": "pegasus", "real": True},
    )
    new_total_writes = await get_cluster_writes_count(
        ops_test,
        substrate,
        shard_app_names=SHARD_APPS,
        db_names=[SHARD_ONE_DB_NAME, SHARD_TWO_DB_NAME],
        config_server_name=CONFIG_SERVER_APP_NAME,
    )

    assert (
        new_total_writes["total_writes"] > old_cluster_writes["total_writes"]
    ), "No writes to be cleared after restoring."
    assert (
        new_total_writes[SHARD_ONE_APP_NAME] > old_cluster_writes[SHARD_ONE_APP_NAME]
    ), "No writes to be cleared on shard-one after restoring."
    assert (
        new_total_writes[SHARD_TWO_APP_NAME] > old_cluster_writes[SHARD_TWO_APP_NAME]
    ), "No writes to be cleared on shard-two after restoring."


async def verify_writes_restored(
    ops_test: OpsTest, substrate: Substrate, expected_cluster_writes: dict
) -> None:
    """Verify that writes were correctly restored."""
    config_server_name = CONFIG_SERVER_APP_NAME
    shard_one_name = SHARD_ONE_APP_NAME
    shard_two_name = SHARD_TWO_APP_NAME
    shard_apps = [shard_one_name, shard_two_name]

    # verify all writes are present
    for attempt in Retrying(stop=stop_after_delay(4), wait=wait_fixed(20), reraise=True):
        with attempt:
            restored_total_writes = await get_cluster_writes_count(
                ops_test,
                substrate,
                shard_app_names=shard_apps,
                db_names=[SHARD_ONE_DB_NAME, SHARD_TWO_DB_NAME],
                config_server_name=config_server_name,
            )
            assert (
                restored_total_writes["total_writes"] == expected_cluster_writes["total_writes"]
            ), "writes not correctly restored to whole cluster"
            assert (
                restored_total_writes[shard_one_name] == expected_cluster_writes[shard_one_name]
            ), f"writes not correctly restored to {shard_one_name}"
            assert (
                restored_total_writes[shard_two_name] == expected_cluster_writes[shard_two_name]
            ), f"writes not correctly restored to {shard_two_name}"
