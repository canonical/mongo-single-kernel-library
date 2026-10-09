#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant
import pytest
from yaml import safe_load

from single_kernel_mongo.config.statuses import LdapStatuses
from tests.integration.helpers.constants import UNIT_IDS
from tests.integration.helpers.jubilant_common import (
    deploy_charm,
    ensure_app_number_units,
    execute_on_mongod,
    existing_app,
    find_leader,
    is_relation_joined,
    mongodb_config_path,
    read_remote_file,
)
from tests.integration.helpers.jubilant_ldap import (
    LDAP_CERT_OFFER,
    LDAP_GROUP_ENDPOINT,
    LDAP_GROUP_REQUESTER,
    LDAP_OFFER,
    apply_ldif,
    consume_glauth_offers,
    create_mongodb_user_roles,
    deploy_glauth,
    drop_mongodb_role,
    generate_mongodb_ldap_client,
    request_ldap_group_role,
    teardown_offers,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
    none_is_restarting,
)
from tests.integration.helpers.types import Substrate

TIMEOUT = 15 * 60
ENDPOINT_LDAP = "ldap"
ENDPOINT_LDAP_CERT = "send-ca-cert"
# entity-permissions granting `find` on a single collection.
OTHERDB_POSTS_FIND = (
    '[{"resource_name": "otherdb.posts", "resource_type": "collection", "privileges": ["find"]}]'
)
CLASH_GROUP_DN = "cn=clash,ou=users,dc=glauth,dc=com"

logger = logging.getLogger(__name__)


def remove_ldap_group_relation(juju: jubilant.Juju, app_name: str) -> None:
    """Removes the requester relation and waits until both applications settled."""
    juju.remove_relation(f"{LDAP_GROUP_REQUESTER}:{LDAP_GROUP_ENDPOINT}", f"{app_name}:database")
    juju.wait(
        lambda status: (
            not is_relation_joined(
                status,
                app_one=app_name,
                app_two=LDAP_GROUP_REQUESTER,
                endpoint_one="database",
                endpoint_two=LDAP_GROUP_ENDPOINT,
            )
            and are_apps_active_and_agents_idle(
                status,
                app_name,
                LDAP_GROUP_REQUESTER,
                idle_period=30,
                unit_count={app_name: 3, LDAP_GROUP_REQUESTER: 1},
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    juju_k8s_model: jubilant.Juju,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    base_app_name: str,
    client_relation_charm_path: str,
) -> None:
    """Build and deploy three unit of MongoDB.

    Deploy GLAUTH components and expose offers, consumes them and create groups on MongoDB.
    The group role is requested by the test requester charm as a GROUP entity.
    """
    # it is possible for users to provide their own cluster for testing. Hence check if there
    # is a pre-existing cluster.
    app_name = existing_app(juju)
    if app_name:
        ensure_app_number_units(juju, substrate, app_name, required_units=len(UNIT_IDS))
        juju.config(
            app_name,
            {
                "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))",
                "ldap-user-to-dn-mapping": "",
            },
        )
    else:
        app_name = base_app_name
        deploy_charm(
            juju=juju,
            charm=mongodb_charm,
            substrate=substrate,
            mongod_resource=mongod_resource,
            app_name=base_app_name,
            num_units=3,
            config={
                "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={PROVIDED_USER}))"
            },
        )

    # deploy the glauth-k8s charm
    deploy_glauth(juju_k8s_model)

    # Consume the offers exposed by glauth
    consume_glauth_offers(juju, juju_k8s_model)

    # Apply the LDIF file on glauth-utils to create users and groups
    apply_ldif(juju_k8s_model, "ldap_entries.ldif")

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
    # Request the group role over a relation, as a GROUP entity.
    request_ldap_group_role(juju, substrate, client_relation_charm_path, app_name)


@pytest.mark.abort_on_fail
def test_integrate_ldap_only(juju: jubilant.Juju):
    """Only integrate ldap endpoint, should go into blocked state."""
    app_name = existing_app(juju)
    assert app_name

    # Integrate LDAP only so it goes into blocked state
    juju.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [LdapStatuses.TLS_REQUIRED.value],
                },
                expected_app_statuses={},
            )
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )


@pytest.mark.abort_on_fail
def test_integrate_ldap_cert(juju: jubilant.Juju):
    """Integrate the second relation, we should end up with everything active."""
    app_name = existing_app(juju)
    assert app_name

    # Integrate also certificate relation, it should go into active state
    juju.integrate(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")

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


@pytest.mark.abort_on_fail
def test_user_can_write(juju: jubilant.Juju, substrate: Substrate):
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
        database="superdb",
        username="cn=johndoe,ou=superheroes,ou=users,dc=glauth,dc=com",
        password="dogood",
    )

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.insertOne({number: 1})")
    assert result.succeeded, "Failed to insert value with LDAP client"

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.findOne({number: 1})")
    assert result.succeeded, "Failed to read value with LDAP client"


@pytest.mark.abort_on_fail
def test_ldap_user_to_dn_mapping(juju: jubilant.Juju, substrate: Substrate):
    """We want to ensure that we can log in using the ldap userToDNMapping.

    So we update the config for both and we log in with the user and check that we can
    still write in the DB.
    """
    app_name = existing_app(juju)
    assert app_name

    # We update the config to be able to login as johndoe@superheroes
    juju.config(
        app_name,
        {
            "ldap-user-to-dn-mapping": '[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]',
            "ldap-query-template": "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))",
        },
    )

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

    path = mongodb_config_path(substrate)

    # Check that all units have restarted and updated their configuration.
    for unit in juju.status().get_units(app_name):
        output = read_remote_file(
            juju,
            substrate,
            unit,
            path,
        )
        configuration = safe_load(output)
        assert (
            configuration["security"]["ldap"].get("userToDNMapping", "")
            == '[{"match": "([^@]+)@([^@]+)", "substitution": "cn={0},ou={1},ou=users,dc=glauth,dc=com"}]'
        ), "Invalid userToDNMapping."
        assert (
            configuration["security"]["ldap"]["authz"].get("queryTemplate", "")
            == "dc=glauth,dc=com??sub?(&(objectClass=posixGroup)(uniqueMember={USER}))"
        ), "Invalid ldap Query Template."

    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )
    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.insertOne({number: 2})")
    assert result.succeeded, "Failed to write value with LDAP client"

    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.findOne({number: 2})")
    assert result.succeeded, "Failed to read value with LDAP client"


@pytest.mark.abort_on_fail
def test_group_role_removed_with_relation(
    juju: jubilant.Juju, substrate: Substrate, client_relation_charm_path: str
):
    """Removing the requester relation drops the role: the LDAP user loses its privileges.

    Re-adding it with collection-level entity-permissions grants exactly those.
    """
    app_name = existing_app(juju)
    assert app_name
    remove_ldap_group_relation(juju, app_name)

    # The user-to-DN mapping of test_ldap_user_to_dn_mapping is still configured.
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )
    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri,
        "db.test.insertOne({number: 2})",
        expecting_output=False,
    )
    assert result.failed, "LDAP user still writes after the group role was dropped"

    # Re-add with collection-level permissions only and check they are enforced.
    request_ldap_group_role(
        juju, substrate, client_relation_charm_path, app_name, permissions=OTHERDB_POSTS_FIND
    )

    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="otherdb",
        username="johndoe@superheroes",
        password="dogood",
    )
    result = execute_on_mongod(juju, substrate, app_name, uri, "db.posts.find().toArray()")
    assert result.succeeded, "LDAP user cannot read the collection granted by entity-permissions"

    result = execute_on_mongod(
        juju, substrate, app_name, uri, "db.posts.insertOne({a: 1})", expecting_output=False
    )
    assert result.failed, "LDAP user writes to a collection granted find only"

    result = execute_on_mongod(
        juju, substrate, app_name, uri, "db.comments.find().toArray()", expecting_output=False
    )
    assert result.failed, "LDAP user reads a collection outside entity-permissions"


@pytest.mark.abort_on_fail
def test_group_role_name_collision_is_rejected(
    juju: jubilant.Juju, substrate: Substrate, client_relation_charm_path: str
):
    """A hand-made role with the requested name blocks the request until removed.

    Once the conflicting role is dropped, re-adding the relation creates the role. The test
    ends with the default group role restored, so that the LDAP removal tests below still
    prove LDAP is disabled by a write that failed.
    """
    app_name = existing_app(juju)
    assert app_name
    remove_ldap_group_relation(juju, app_name)
    create_mongodb_user_roles(juju, substrate, app_name, CLASH_GROUP_DN)
    juju.config(
        LDAP_GROUP_REQUESTER, {"ldap-group-dn": CLASH_GROUP_DN, "ldap-group-permissions": ""}
    )

    juju.integrate(f"{LDAP_GROUP_REQUESTER}:{LDAP_GROUP_ENDPOINT}", f"{app_name}:database")
    juju.wait(
        lambda status: (
            status.apps[app_name].app_status.current == "blocked"
            and jubilant.all_blocked(status, LDAP_GROUP_REQUESTER)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # `MongoDB refused createRole: <errmsg> (relation <id>)` on the provider and the relation
    # status message on the requester. The errmsg wording varies between MongoDB versions
    # (`Role "<name>@admin" already exists`), so only its stable parts are matched.
    requester_leader, _ = find_leader(juju, LDAP_GROUP_REQUESTER)
    rel_id = next(
        info.relation_id
        for info in juju.show_unit(requester_leader).relation_info
        if info.endpoint == LDAP_GROUP_ENDPOINT
    )
    status = juju.status()
    app_message = status.apps[app_name].app_status.message
    assert "MongoDB refused createRole:" in app_message, app_message
    assert "already exists" in app_message, app_message
    assert f"(relation {rel_id})" in app_message, app_message
    for unit in status.get_units(LDAP_GROUP_REQUESTER).values():
        message = unit.workload_status.message
        assert "MongoDB refused createRole:" in message, message
        assert "already exists" in message, message

    remove_ldap_group_relation(juju, app_name)

    # The conflict gone, re-adding the relation creates the role.
    drop_mongodb_role(juju, substrate, app_name, CLASH_GROUP_DN)
    request_ldap_group_role(
        juju, substrate, client_relation_charm_path, app_name, group_dn=CLASH_GROUP_DN
    )
    remove_ldap_group_relation(juju, app_name)

    # Restore the default group role (superheroes DN, no entity-permissions).
    request_ldap_group_role(juju, substrate, client_relation_charm_path, app_name)
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )
    result = execute_on_mongod(juju, substrate, app_name, uri, "db.test.insertOne({number: 3})")
    assert result.succeeded, "LDAP user cannot write once the group role is restored"


@pytest.mark.abort_on_fail
def test_remove_ldap_goes_to_blocked(juju: jubilant.Juju, substrate: Substrate):
    """Only integrate ldap-certificate-transfer endpoint, should go into blocked state."""
    app_name = existing_app(juju)
    assert app_name

    # We remove the first relation integrated, it should go into blocked state
    juju.remove_relation(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [LdapStatuses.LDAP_REQUIRED.value],
                },
                expected_app_statuses={},
            )
            and none_is_restarting(status, juju, app_name)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # John should not be able to log in now.
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )

    # We expect this write to fail when the ldap relation is missing.
    # As soon as one relation is removed, a restart is triggered and it
    # should have disabled LDAP.
    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri,
        "db.test.insertOne({number: 2})",
        expecting_output=False,
    )
    assert result.failed


@pytest.mark.abort_on_fail
def test_remove_ldap_certs_goes_to_blocked(juju: jubilant.Juju, substrate: Substrate):
    """With only ldap relation it should also go to blocked."""
    app_name = existing_app(juju)
    assert app_name

    # Add back the ldap relation.
    juju.integrate(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")
    # Everything should go back to normal.
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

    # We remove the cert relation, it should go into blocked state
    juju.remove_relation(f"{LDAP_CERT_OFFER}:send-ca-cert", f"{app_name}:ldap-certificate-transfer")

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and does_status_match(
                model_status=status,
                expected_unit_statuses={
                    app_name: [LdapStatuses.TLS_REQUIRED.value],
                },
                expected_app_statuses={},
            )
            and none_is_restarting(status, juju, app_name)
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # John should not be able to log in now.
    uri = generate_mongodb_ldap_client(
        juju,
        substrate,
        app_name,
        database="superdb",
        username="johndoe@superheroes",
        password="dogood",
    )

    # We expect this write to fail when the ldap relation is missing.
    # As soon as one relation is removed, a restart is triggered and it
    # should have disabled LDAP.
    result = execute_on_mongod(
        juju,
        substrate,
        app_name,
        uri,
        "db.test.insertOne({number: 2})",
        expecting_output=False,
    )
    assert result.failed


@pytest.mark.abort_on_fail
def test_teardown(juju: jubilant.Juju, juju_k8s_model: jubilant.Juju):
    """Teardown of the whole offers and relations."""
    app_name = existing_app(juju)
    assert app_name

    # Remove the requester (its relation drops the group role) before the LDAP offers.
    juju.remove_application(LDAP_GROUP_REQUESTER)

    # Removing the second relation should go into active
    juju.remove_relation(f"{LDAP_OFFER}:ldap", f"{app_name}:ldap")

    juju.wait(
        lambda status: (
            are_apps_active_and_agents_idle(
                status,
                app_name,
                idle_period=30,
                unit_count=3,
            )
            and LDAP_GROUP_REQUESTER not in status.apps
        ),
        timeout=TIMEOUT,
        delay=5,
        successes=3,
    )

    # Remove the offers and tear down deployment
    teardown_offers(juju, juju_k8s_model)
