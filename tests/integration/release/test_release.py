#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger

import jubilant

from tests.integration.helpers.constants import (
    BASE,
    CONTINUOUS_WRITE_APPLICATION,
    CONTINUOUS_WRITE_APPLICATION_BIS,
    DATA_INTEGRATOR_APP_NAME,
    DEFAULT_COLLECTION_NAME,
    DEFAULT_DATABASE_NAME,
    DEPLOYMENT_TIMEOUT,
    READER_APPLICATION,
    S3_APP_NAME,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
    UNIT_IDS,
)
from tests.integration.helpers.continuous_writes_helpers import (
    count_writes,
    start_continuous_reads,
    start_continuous_writes,
    stop_continuous_reads,
    stop_continuous_writes,
)
from tests.integration.helpers.jubilant_backups import (
    configure_s3,
    create_and_verify_backup,
)
from tests.integration.helpers.jubilant_common import (
    deploy_application,
    deploy_charm,
    execute_on_mongod,
    existing_app,
    find_leader,
    relate_application,
)
from tests.integration.helpers.jubilant_ldap import (
    LDAP_CERT_OFFER,
    LDAP_OFFER,
    apply_ldif,
    consume_glauth_offers,
    create_mongodb_user_roles,
    deploy_glauth,
    generate_mongodb_ldap_client,
    teardown_offers,
)
from tests.integration.helpers.jubilant_tls import (
    integrate_apps_with_tls,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
)
from tests.integration.helpers.types import Substrate

logger = getLogger(__name__)

SECOND_DB_NAME = f"{DEFAULT_DATABASE_NAME}_bis"
SECOND_COLL_NAME = f"{DEFAULT_COLLECTION_NAME}_bis"


def test_deploy_apps(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm_name: str,
    application_path: str,
    mongodb_revision: int,
    mongodb_base_app_name: str,
    mongodb_charm_channel: str | None,
    juju_k8s_model: jubilant.Juju,
):
    """Deploy MongoDB with the right revision.

    This also deploys a data integrator, alongside a continuous write application,
    a self-signed-certificates application, and LDAP with all it needs.
    """
    tls_config = {"ca-common-name": "MongoDB release CA"}

    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    deploy_charm(
        juju=juju,
        revision=mongodb_revision,
        charm=mongodb_charm_name,
        substrate=substrate,
        app_name=mongodb_base_app_name,
        channel=mongodb_charm_channel,
        num_units=len(UNIT_IDS),
    )
    deploy_application(
        juju, application_path=application_path, app_name=CONTINUOUS_WRITE_APPLICATION
    )
    juju.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
        config=tls_config,
    )
    juju.deploy(
        DATA_INTEGRATOR_APP_NAME,
        channel="latest/stable",
        base=BASE,
        config={"database-name": "test-database"},
    )

    deploy_glauth(juju_k8s_model)

    # Consume the offers exposed by glauth
    consume_glauth_offers(juju, juju_k8s_model)

    # Apply the LDIF file on glauth-utils to create users and groups
    apply_ldif(juju_k8s_model, "ldap_entries.ldif")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, mongodb_base_app_name, TLS_CERTIFICATES_APP_NAME, idle_period=20
        ),
        timeout=DEPLOYMENT_TIMEOUT,
    )


def test_integrate_with_tls(
    juju: jubilant.Juju,
):
    """Tests that we can integrate with TLS, and then add a writer and start writing."""
    app_name = existing_app(juju)
    assert app_name
    integrate_apps_with_tls(juju, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, app_name, TLS_CERTIFICATES_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    relate_application(juju, app_name, CONTINUOUS_WRITE_APPLICATION)
    start_continuous_writes(
        juju,
        CONTINUOUS_WRITE_APPLICATION,
        db_name=DEFAULT_DATABASE_NAME,
        coll_name=DEFAULT_COLLECTION_NAME,
    )


def test_integrate_with_ldap(juju: jubilant.Juju, substrate: Substrate):
    """Tests that we can integrate with LDAP without losing data."""
    app_name = existing_app(juju)
    assert app_name

    juju.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")
    juju.integrate(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, app_name, idle_period=20),
        timeout=TIMEOUT,
    )
    # Create the roles on MongoDB
    create_mongodb_user_roles(
        juju,
        substrate,
        app_name=app_name,
        role_name="ou=superheroes,ou=users,dc=glauth,dc=com",
        db=DEFAULT_DATABASE_NAME,
        tls=True,
    )


def test_integrate_second_client(juju: jubilant.Juju, application_path: str):
    """Tests that we can integrate with a second client, and we also start writing on that client.

    The client is a continuous write application.
    """
    app_name = existing_app(juju)
    assert app_name

    deploy_application(
        juju,
        application_path=application_path,
        app_name=CONTINUOUS_WRITE_APPLICATION_BIS,
        database_name=SECOND_DB_NAME,
    )
    relate_application(juju, app_name, CONTINUOUS_WRITE_APPLICATION_BIS)
    start_continuous_writes(
        juju,
        CONTINUOUS_WRITE_APPLICATION_BIS,
        db_name=SECOND_DB_NAME,
        coll_name=SECOND_COLL_NAME,
    )


def test_integrate_third_client(juju: jubilant.Juju, application_path: str):
    """Tests that we can integrate with a third client, which will only read data.

    The client is a continuous write application.
    """
    app_name = existing_app(juju)
    assert app_name

    deploy_application(
        juju,
        application_path=application_path,
        app_name=READER_APPLICATION,
        database_name=DEFAULT_DATABASE_NAME,
    )
    relate_application(juju, app_name, READER_APPLICATION)

    start_continuous_reads(
        juju,
        READER_APPLICATION,
        db_name=DEFAULT_DATABASE_NAME,
        coll_name=DEFAULT_COLLECTION_NAME,
    )


def test_integrate_with_s3(
    juju: jubilant.Juju,
    storage_credentials: dict[str, str],
    storage_config: dict[str, str],
):
    """Tests that we can integrate with S3 and create a backup.

    This test ensures that the backup is created and finished.
    """
    app_name = existing_app(juju)
    assert app_name

    # deploy the s3 integrator charm
    juju.deploy(S3_APP_NAME, channel="2/stable")
    juju.wait(
        lambda status: are_agents_idle(status, S3_APP_NAME, idle_period=20),
        timeout=DEPLOYMENT_TIMEOUT,
    )

    configure_s3(juju, S3_APP_NAME, storage_config, storage_credentials)
    juju.integrate(S3_APP_NAME, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, app_name, idle_period=20),
        timeout=TIMEOUT,
    )

    create_and_verify_backup(juju, app_name)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(status, app_name, idle_period=20),
        timeout=TIMEOUT,
    )


def tests_restore_backup(juju: jubilant.Juju, substrate: Substrate):
    """Tests that we can restore a backup.

    This test starts by stopping the writes applications, and counting the number of writes
    ensuring that we have never lost any write until now.
    Then it restores the backup, counts the number of writes,
    and checks that it is lower than what we had, proving that the backup was restored successfully.
    """
    app_name = existing_app(juju)
    assert app_name

    first_reported_writes = stop_continuous_writes(
        juju,
        CONTINUOUS_WRITE_APPLICATION,
        db_name=DEFAULT_DATABASE_NAME,
        coll_name=DEFAULT_COLLECTION_NAME,
    )
    second_reported_writes = stop_continuous_writes(
        juju,
        CONTINUOUS_WRITE_APPLICATION_BIS,
        db_name=SECOND_DB_NAME,
        coll_name=SECOND_COLL_NAME,
    )
    leader_unit, leader_status = find_leader(juju, app_name=app_name)
    # count total writes
    first_number_writes = count_writes(
        juju,
        substrate,
        app_name,
        leader_unit,
        leader_status,
        db_name=DEFAULT_DATABASE_NAME,
        coll_name=DEFAULT_COLLECTION_NAME,
        tls=True,
    )
    second_number_writes = count_writes(
        juju,
        substrate,
        app_name,
        leader_unit,
        leader_status,
        db_name=SECOND_DB_NAME,
        coll_name=SECOND_COLL_NAME,
        tls=True,
    )
    assert first_number_writes == first_reported_writes
    assert second_number_writes == second_reported_writes

    # find most recent backup id and restore
    task = juju.run(leader_unit, action="list-backups")
    list_result = task.results["backups"]
    most_recent_backup = list_result.split("\n")[-1]
    backup_id = most_recent_backup.split()[0]
    restore_task = juju.run(leader_unit, action="restore", params={"backup-id": backup_id})
    logger.info(f"Restore backup result {restore_task.results=}")
    assert restore_task.results["restore-status"] == "restore started", "restore not successful"

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=15,
        ),
        timeout=TIMEOUT,
    )

    first_number_writes_after_restore = count_writes(
        juju,
        substrate,
        app_name,
        leader_unit,
        leader_status,
        db_name=DEFAULT_DATABASE_NAME,
        coll_name=DEFAULT_COLLECTION_NAME,
        tls=True,
    )
    second_number_writes_after_restore = count_writes(
        juju,
        substrate,
        app_name,
        leader_unit,
        leader_status,
        db_name=SECOND_DB_NAME,
        coll_name=SECOND_COLL_NAME,
        tls=True,
    )

    assert first_number_writes_after_restore < first_number_writes
    assert second_number_writes_after_restore < second_number_writes


def test_ldap_user_can_write(juju: jubilant.Juju, substrate: Substrate):
    """Checks that the LDAP user can write to the DB.

    This checks both authentication and authorisation.
    """
    app_name = existing_app(juju)
    assert app_name

    # We create a client which should be able to write
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database=DEFAULT_DATABASE_NAME,
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
    )

    result = execute_on_mongod(
        juju, substrate, app_name, uri, "db.test.insertOne({number: 1})", tls=True
    )
    assert result.succeeded, "Failed to insert value with LDAP client"

    result = execute_on_mongod(
        juju, substrate, app_name, uri, "db.test.findOne({number: 1})", tls=True
    )
    assert result.succeeded, "Failed to read value with LDAP client"


def test_valid_reads(juju: jubilant.Juju):
    """Checks the reads at the end of the tests."""
    reads, failed_reads = stop_continuous_reads(
        juju,
        READER_APPLICATION,
        db_name=DEFAULT_DATABASE_NAME,
        coll_name=DEFAULT_COLLECTION_NAME,
    )
    assert reads > 1000
    # We can allow for a few errors during restore for example
    assert len(failed_reads) < 50


def test_teardown(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju):
    """Teardown of the whole offers and relations."""
    app_name = existing_app(juju)
    assert app_name

    # Removing the second relation should go into active
    juju.remove_relation(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")
    # We remove the cert relation, it should go into blocked state
    juju.remove_relation(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            app_name,
            idle_period=30,
            unit_count=3,
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Remove the offers and tear down deployment
    teardown_offers(juju, juju_k8s_model)
