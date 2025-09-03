# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import httpx
import pytest
from lightkube.core.exceptions import ApiError
from ops.testing import Harness

from single_kernel_mongo.exceptions import DeployedWithoutTrustError
from tests.charms.mongos_k8s_test_charm.src.charm import MongosKubernetesTestCharm

STATUS_JUJU_TRUST = "Insufficient permissions, try: `juju trust mongos-k8s --scope=cluster`"
CLUSTER_ALIAS = "cluster"


@pytest.mark.skip_if_substrate("lxd")
def test_delete_unit_service_has_no_metadata(
    mongos_harness: Harness[MongosKubernetesTestCharm], mocker
):
    """Verify that when no metadata is present, the charm raises an error."""
    service = mocker.Mock()
    service.metadata = None
    get_service = mocker.patch("single_kernel_mongo.managers.k8s.K8sManager.get_service")
    get_service.return_value = service

    with pytest.raises(Exception):
        mongos_harness.charm.operator.k8s.delete_service()


@pytest.mark.skip_if_substrate("lxd")
def test_delete_unit_service_raises_apierror(
    mongos_harness: Harness[MongosKubernetesTestCharm], mocker
):
    """Verify that when no metadata is present, the charm raises an error."""
    mock_client = mocker.patch(
        "single_kernel_mongo.managers.k8s.K8sManager.client",
        new_callable=mocker.PropertyMock(),
    )
    get_service = mocker.patch("single_kernel_mongo.managers.k8s.K8sManager.get_service")

    metadata_mock = mocker.Mock()
    metadata_mock.name = "service-name"
    service = mocker.Mock()
    service.metadata = metadata_mock

    get_service.return_value = service

    # We need a valid API error due to error handling in lightkube
    api_error = ApiError(
        request=httpx.Request(url="http://controller/call", method="DELETE"),
        response=httpx.Response(409, json={"message": "bad call"}),
    )

    delete_mock = mocker.Mock()
    delete_mock.side_effect = api_error
    mock_client.delete = delete_mock

    with pytest.raises(ApiError):
        mongos_harness.charm.operator.k8s.delete_service()


@pytest.mark.skip_if_substrate("lxd")
def test_delete_unit_service_needs_juju_trust(
    mongos_harness: Harness[MongosKubernetesTestCharm], mocker
):
    """Verify that when charm needs juju trust a status is logged."""
    mock_client = mocker.patch(
        "single_kernel_mongo.managers.k8s.K8sManager.client",
        new_callable=mocker.PropertyMock(),
    )
    get_service = mocker.patch("single_kernel_mongo.managers.k8s.K8sManager.get_service")
    metadata_mock = mocker.Mock()
    metadata_mock.name = "service-name"
    service = mocker.Mock()
    service.metadata = metadata_mock
    get_service.return_value = service

    # We need a valid API error due to error handling in lightkube
    api_error = ApiError(
        request=httpx.Request(url="http://controller/call", method="DELETE"),
        response=httpx.Response(409, json={"message": "bad call", "code": 403}),
    )

    delete_mock = mocker.Mock()
    delete_mock.side_effect = api_error
    mock_client.delete = delete_mock

    with pytest.raises(DeployedWithoutTrustError):
        mongos_harness.charm.operator.k8s.delete_service()
