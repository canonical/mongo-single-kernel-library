#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import jubilant
import pytest

from single_kernel_mongo.config.statuses import MongosStatuses
from tests.integration.helpers.constants import (
    DIFFERENT_CERTIFICATES_APP_NAME,
    MONGOS_APP_NAME,
    MONGOS_CLUSTER_COMPONENTS,
    TIMEOUT,
    TLS_CERTIFICATES_APP_NAME,
    TLS_CERTIFICATES_BASE,
    TLS_CERTIFICATES_CHANNEL,
)
from tests.integration.helpers.jubilant_mongos import (
    assert_mongos_tls_disabled,
    assert_mongos_tls_enabled,
    build_cluster,
    deploy_cluster_components,
    get_k8s_public_ip,
    get_sans_ips,
    rotate_and_verify_certs,
    toggle_tls_mongos,
)
from tests.integration.helpers.jubilant_tls import (
    integrate_apps_with_tls,
)
from tests.integration.helpers.status_helpers import (
    are_agents_idle,
    are_apps_active_and_agents_idle,
    does_status_match,
)
from tests.integration.helpers.types import Substrate


def test_build_and_deploy(
    juju: jubilant.Juju,
    substrate: Substrate,
    mongodb_charm: str,
    mongos_charm: str,
    mongod_resource: dict[str, str],
    mongos_resource: dict[str, str],
    application_path: str,
) -> None:
    """Build and deploy a sharded cluster."""
    deploy_cluster_components(
        juju,
        substrate,
        mongodb_charm,
        mongos_charm,
        mongod_resource,
        mongos_resource,
        application_path,
    )
    build_cluster(juju, substrate, integrate_with_mongos=True, integrate_with_client=True)

    config = {"ca-common-name": "Test CA"}
    juju.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
        config=config,
    )

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, TLS_CERTIFICATES_APP_NAME, idle_period=20
        ),
        timeout=TIMEOUT,
    )


def test_mongos_tls_enabled(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that mongos charm can enable TLS."""
    integrate_apps_with_tls(juju, MONGOS_APP_NAME)

    juju.wait(
        lambda status: (
            are_agents_idle(status, MONGOS_APP_NAME, idle_period=20)
            and does_status_match(
                status,
                expected_unit_statuses={
                    MONGOS_APP_NAME: [MongosStatuses.INVALID_PEER_TLS_REL.value]
                },
                expected_app_statuses={
                    MONGOS_APP_NAME: [MongosStatuses.INVALID_PEER_TLS_REL.value]
                },
            )
        ),
        timeout=TIMEOUT,
    )

    integrate_apps_with_tls(juju, *MONGOS_CLUSTER_COMPONENTS)

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status, MONGOS_APP_NAME, *MONGOS_CLUSTER_COMPONENTS, idle_period=20
        ),
        timeout=TIMEOUT,
    )

    assert_mongos_tls_enabled(juju, substrate)


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_mongos_tls_nodeport(juju: jubilant.Juju, substrate: Substrate):
    """Tests that TLS is stable on nodeport enablement/removal."""
    # test that charm can enable nodeport without breaking mongos or accidentally disabling TLS
    juju.config(MONGOS_APP_NAME, {"expose-external": "nodeport"})

    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            MONGOS_APP_NAME,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )
    for internal in [True, False]:
        assert_mongos_tls_enabled(juju, substrate, internal=internal)

    # check for expected IP addresses in the pem file
    for unit in juju.status().get_units(MONGOS_APP_NAME):
        assert get_k8s_public_ip() in get_sans_ips(juju, unit, internal=True)
        assert get_k8s_public_ip() in get_sans_ips(juju, unit, internal=False)

    # test that charm can disable nodeport without breaking mongos or accidentally disabling TLS
    juju.config(MONGOS_APP_NAME, {"expose-external": "none"})
    juju.wait(
        lambda status: are_apps_active_and_agents_idle(
            status,
            MONGOS_APP_NAME,
            idle_period=60,
        ),
        timeout=TIMEOUT,
    )

    assert_mongos_tls_enabled(juju, substrate, internal=True)

    # check for no public k8s IP address in the pem file
    for unit in juju.status().get_units(MONGOS_APP_NAME):
        assert get_k8s_public_ip() not in get_sans_ips(juju, unit, internal=True)
        assert get_k8s_public_ip() not in get_sans_ips(juju, unit, internal=False)


def test_mongos_rotate_certs(juju: jubilant.Juju, substrate: Substrate) -> None:
    rotate_and_verify_certs(juju, substrate, MONGOS_APP_NAME)


def test_mongos_tls_disabled(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Tests that mongos charm can disable TLS."""
    toggle_tls_mongos(juju, enable=False)
    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                MONGOS_APP_NAME,
                TLS_CERTIFICATES_APP_NAME,
                *MONGOS_CLUSTER_COMPONENTS,
                idle_period=60,
            )
            and does_status_match(
                status,
                expected_unit_statuses={
                    MONGOS_APP_NAME: [MongosStatuses.MISSING_PEER_TLS_REL.value]
                },
                expected_app_statuses={
                    MONGOS_APP_NAME: [MongosStatuses.MISSING_PEER_TLS_REL.value]
                },
            )
        ),
        timeout=TIMEOUT,
    )

    assert_mongos_tls_disabled(juju, substrate)


def test_tls_reenabled(juju: jubilant.Juju, substrate: Substrate) -> None:
    """Test that mongos can enable TLS after being integrated to cluster ."""
    toggle_tls_mongos(juju, enable=True)
    assert_mongos_tls_enabled(juju, substrate)


def test_mongos_tls_ca_mismatch(juju: jubilant.Juju) -> None:
    """Tests that mongos charm can disable TLS."""
    toggle_tls_mongos(juju, enable=False)

    juju.deploy(
        TLS_CERTIFICATES_APP_NAME,
        app=DIFFERENT_CERTIFICATES_APP_NAME,
        channel=TLS_CERTIFICATES_CHANNEL,
        base=TLS_CERTIFICATES_BASE,
    )

    juju.wait(
        lambda status: (
            are_agents_idle(status, MONGOS_APP_NAME, idle_period=20)
            and are_apps_active_and_agents_idle(
                status, DIFFERENT_CERTIFICATES_APP_NAME, idle_period=20
            )
        ),
        timeout=TIMEOUT,
    )

    toggle_tls_mongos(juju, enable=True, certs_app_name=DIFFERENT_CERTIFICATES_APP_NAME)

    juju.wait(
        lambda status: (
            are_agents_idle(
                status,
                MONGOS_APP_NAME,
                idle_period=20,
            )
            and does_status_match(
                status,
                expected_unit_statuses={MONGOS_APP_NAME: [MongosStatuses.PEER_CA_MISMATCH.value]},
                expected_app_statuses={MONGOS_APP_NAME: [MongosStatuses.PEER_CA_MISMATCH.value]},
            )
        ),
        timeout=TIMEOUT,
    )
