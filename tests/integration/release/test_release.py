#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from logging import getLogger

import pytest
from juju.model import Model
from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying
from tenacity.stop import stop_after_delay
from tenacity.wait import wait_fixed

from tests.integration.helpers.backups import S3_APP_NAME, count_logical_backups
from tests.integration.helpers.common import (
    CONTINUOUS_WRITE_APPLICATION,
    CONTINUOUS_WRITE_APPLICATION_BIS,
    DATA_INTEGRATOR_APP_NAME,
    DEFAULT_COLLECTION_NAME,
    DEFAULT_DATABASE_NAME,
    DEPLOYMENT_TIMEOUT,
    READER_APPLICATION,
    TIMEOUT,
    UNIT_IDS,
    count_writes,
    deploy_application,
    deploy_charm,
    execute_on_mongod,
    find_unit,
    get_app_name,
    relate_mongodb_and_application,
    start_continous_writes,
    start_continuous_reads,
    stop_continous_writes,
    stop_continuous_reads,
)
from tests.integration.helpers.ldap import (
    LDAP_CERT_OFFER,
    LDAP_OFFER,
    apply_ldif,
    consume_glauth_offers,
    create_mongodb_user_roles,
    deploy_glauth,
    generate_mongodb_ldap_client,
)
from tests.integration.helpers.tls import (
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
    integrate_apps_with_tls,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)

SECOND_DB_NAME = f"{DEFAULT_DATABASE_NAME}_bis"
SECOND_COLL_NAME = f"{DEFAULT_COLLECTION_NAME}_bis"


@pytest.mark.abort_on_fail
async def test_deploy_apps(
    ops_test: OpsTest,
    mongodb_charm_name: str,
    application_path: str,
    substrate: Substrate,
    mongodb_revision: int,
    mongodb_base_app_name: str,
    kubernetes_model: Model,
):
    """Deploy MongoDB with the right revision.

    This also deploys a data integrator, alongside a continuous write application,
    a self-signed-certificates application, and LDAP with all it needs.
    """
    tls_config = {"ca-common-name": "MongoDB release CA"}

    assert ops_test.model
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    await asyncio.gather(
        deploy_charm(
            ops_test=ops_test,
            revision=mongodb_revision,
            charm=mongodb_charm_name,
            substrate=substrate,
            app_name=mongodb_base_app_name,
            num_units=len(UNIT_IDS),
        ),
        deploy_application(
            ops_test, application_path=application_path, app_name=CONTINUOUS_WRITE_APPLICATION
        ),
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME,
            channel=TLS_CERTIFICATES_CHANNEL,
            config=tls_config,
            base=TLS_CERTIFICATES_BASE,
        ),
        ops_test.model.deploy(
            DATA_INTEGRATOR_APP_NAME,
            channel="latest/stable",
            series="noble",
            config={"database-name": "test-database"},
        ),
    )

    await deploy_glauth(ops_test, kubernetes_model)

    # Consume the offers exposed by glauth
    await consume_glauth_offers(ops_test, kubernetes_model)

    # Apply the LDIF file on glauth-utils to create users and groups
    await apply_ldif(ops_test, kubernetes_model, "ldap_entries.ldif")

    await ops_test.model.wait_for_idle(
        apps=[mongodb_base_app_name, TLS_CERTIFICATES_APP_NAME],
        timeout=DEPLOYMENT_TIMEOUT,
        status="active",
    )


@pytest.mark.abort_on_fail
async def test_integrate_with_tls(
    ops_test: OpsTest,
):
    """Tests that we can integrate with TLS, and then add a writer and start writing."""
    assert ops_test.model
    app_name = await get_app_name(ops_test)
    assert app_name
    await integrate_apps_with_tls(ops_test, applications=[app_name])

    await ops_test.model.wait_for_idle(
        apps=[app_name, TLS_CERTIFICATES_APP_NAME], status="active", timeout=1000, idle_period=60
    )

    await relate_mongodb_and_application(ops_test, app_name, CONTINUOUS_WRITE_APPLICATION)
    await start_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)


@pytest.mark.abort_on_fail
async def test_integrate_with_ldap(ops_test: OpsTest, substrate: Substrate):
    """Tests that we can integrate with LDAP without losing data."""
    assert ops_test.model
    app_name = await get_app_name(ops_test)
    assert app_name

    await ops_test.model.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")
    await ops_test.model.integrate(
        f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer"
    )
    # Create the roles on MongoDB
    await create_mongodb_user_roles(
        ops_test,
        substrate,
        app_name=app_name,
        role_name="ou=superheroes,ou=users,dc=glauth,dc=com",
        db=DEFAULT_DATABASE_NAME,
        tls=True,
    )

    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_integrate_second_client(ops_test: OpsTest, application_path: str):
    """Tests that we can integrate with a second client, and we also start writing on that client.

    The client is a continuous write application.
    """
    app_name = await get_app_name(ops_test)

    await deploy_application(
        ops_test,
        application_path=application_path,
        app_name=CONTINUOUS_WRITE_APPLICATION_BIS,
        database_name=SECOND_DB_NAME,
    )
    await relate_mongodb_and_application(ops_test, app_name, CONTINUOUS_WRITE_APPLICATION_BIS)
    await start_continous_writes(
        ops_test,
        CONTINUOUS_WRITE_APPLICATION_BIS,
        db_name=SECOND_DB_NAME,
        coll_name=SECOND_COLL_NAME,
    )


@pytest.mark.abort_on_fail
async def test_integrate_third_client(ops_test: OpsTest, application_path: str):
    """Tests that we can integrate with a third client, which will only read data.

    The client is a continuous write application.
    """
    app_name = await get_app_name(ops_test)

    await deploy_application(
        ops_test,
        application_path=application_path,
        app_name=READER_APPLICATION,
        database_name=DEFAULT_DATABASE_NAME,
    )
    await relate_mongodb_and_application(ops_test, app_name, READER_APPLICATION)

    await start_continuous_reads(
        ops_test,
        READER_APPLICATION,
        db_name=DEFAULT_DATABASE_NAME,
        coll_name=DEFAULT_COLLECTION_NAME,
    )


@pytest.mark.abort_on_fail
async def test_integrate_with_s3(
    ops_test: OpsTest,
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
):
    """Tests that we can integrate with S3 and create a backup.

    This test ensures that the backup is created and finished.
    """
    assert ops_test.model
    app_name = await get_app_name(ops_test)
    assert app_name

    # deploy the s3 integrator charm
    await ops_test.model.deploy(S3_APP_NAME, channel="1/edge")
    await ops_test.model.wait_for_idle(apps=[S3_APP_NAME], timeout=DEPLOYMENT_TIMEOUT)

    s3_integrator_unit = ops_test.model.applications[S3_APP_NAME].units[0]

    # apply new configuration options
    await ops_test.model.applications[S3_APP_NAME].set_config(storage_config)
    action = await s3_integrator_unit.run_action(
        action_name="sync-s3-credentials", **storage_credentials
    )
    await action.wait()

    await ops_test.model.integrate(S3_APP_NAME, app_name)

    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, app_name], status="active", timeout=TIMEOUT
    )

    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    action = await leader_unit.run_action(action_name="create-backup")
    backup_result = await action.wait()

    logger.info(f"Create backup result {backup_result.results=}")
    assert "backup started" in backup_result.results["backup-status"], "backup didn't start"
    try:
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
            with attempt:
                backups = await count_logical_backups(leader_unit)
                assert backups == 1
    except RetryError:
        assert backups == 1, "Backup not created."

    # Wait for status to go back to idle.
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def tests_restore_backup(ops_test: OpsTest, substrate: Substrate):
    """Tests that we can restore a backup.

    This test starts by stopping the writes applications, and counting the number of writes
    ensuring that we have never lost any write until now.
    Then it restores the backup, counts the number of writes,
    and checks that it is lower than what we had, proving that the backup was restored successfully.
    """
    assert ops_test.model
    app_name = await get_app_name(ops_test)
    assert app_name

    first_reported_writes = await stop_continous_writes(ops_test, CONTINUOUS_WRITE_APPLICATION)
    second_reported_writes = await stop_continous_writes(
        ops_test,
        CONTINUOUS_WRITE_APPLICATION_BIS,
        db_name=SECOND_DB_NAME,
        coll_name=SECOND_COLL_NAME,
    )
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    # count total writes
    first_number_writes = await count_writes(ops_test, substrate, app_name, leader_unit, tls=True)
    second_number_writes = await count_writes(
        ops_test,
        substrate,
        app_name,
        leader_unit,
        db_name=SECOND_DB_NAME,
        coll_name=SECOND_COLL_NAME,
        tls=True,
    )
    assert first_number_writes == first_reported_writes
    assert second_number_writes == second_reported_writes

    # find most recent backup id and restore
    action = await leader_unit.run_action(action_name="list-backups")
    list_result = await action.wait()
    list_result = list_result.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]

    backup_id = most_recent_backup.split()[0]

    action = await leader_unit.run_action(action_name="restore", **{"backup-id": backup_id})
    restore = await action.wait()
    logger.info(f"Restore backup result {restore.results=}")
    assert restore.results["restore-status"] == "restore started", "restore not successful"

    async with ops_test.fast_forward("60s"):
        await ops_test.model.wait_for_idle(apps=[app_name], status="active", idle_period=15)

    first_number_writes_after_restore = await count_writes(
        ops_test, substrate, app_name, leader_unit, tls=True
    )
    second_number_writes_after_restore = await count_writes(
        ops_test,
        substrate,
        app_name,
        leader_unit,
        db_name=SECOND_DB_NAME,
        coll_name=SECOND_COLL_NAME,
        tls=True,
    )

    assert first_number_writes_after_restore < first_number_writes
    assert second_number_writes_after_restore < second_number_writes


@pytest.mark.abort_on_fail
async def test_ldap_user_can_write(ops_test: OpsTest, substrate: Substrate):
    """Checks that the LDAP user can write to the DB.

    This checks both authentication and authorisation.
    """
    app_name = await get_app_name(ops_test)
    assert app_name

    # We create a client which should be able to write
    uri = await generate_mongodb_ldap_client(
        ops_test,
        substrate,
        app_name,
        database=DEFAULT_DATABASE_NAME,
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
    )

    result = await execute_on_mongod(
        ops_test, app_name, substrate, uri, "db.test.insertOne({number: 1})", tls=True
    )
    assert result.succeeded, "Failed to insert value with LDAP client"

    result = await execute_on_mongod(
        ops_test, app_name, substrate, uri, "db.test.findOne({number: 1})", tls=True
    )
    assert result.succeeded, "Failed to read value with LDAP client"


@pytest.mark.abort_on_fail
async def test_valid_reads(ops_test: OpsTest):
    """Checks the reads at the end of the tests."""
    reads, failed_reads = await stop_continuous_reads(
        ops_test,
        READER_APPLICATION,
        db_name=DEFAULT_DATABASE_NAME,
        coll_name=DEFAULT_COLLECTION_NAME,
    )
    assert reads > 1000
    # We can allow for a few errors during restore for example
    assert len(failed_reads) < 50
