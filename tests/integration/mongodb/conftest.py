# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import os
import uuid
from collections.abc import Generator
from typing import Any

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers.ha import deploy_chaos_mesh, destroy_chaos_mesh
from ..helpers.types import Substrate


@pytest.fixture
def base_app_name(mongod_metadata) -> str:
    """Default application name for testing."""
    return mongod_metadata["name"]


@pytest.fixture(scope="module")
def chaos_mesh(ops_test: OpsTest, substrate: Substrate) -> Generator[None, Any, Any]:
    if substrate == "microk8s":
        deploy_chaos_mesh(ops_test.model.info.name)
        yield
        destroy_chaos_mesh(ops_test.model.info.name)


@pytest.fixture(scope="session")
def cloud_configs_aws(substrate: Substrate) -> tuple[dict[str, str], dict[str, str]]:
    path = "mongodb-vm" if substrate == "lxd" else "mongodb-k8s"
    configs: dict[str, str] = {
        "endpoint": "https://s3.amazonaws.com",
        "bucket": "data-charms-testing",
        "path": f"{path}/{uuid.uuid4()}",
        "region": "us-east-1",
    }
    credentials: dict[str, str] = {
        "access-key": os.environ["AWS_ACCESS_KEY"],
        "secret-key": os.environ["AWS_SECRET_KEY"],
    }
    return configs, credentials


@pytest.fixture(scope="session")
def cloud_configs_gcp(substrate: Substrate) -> tuple[dict[str, str], dict[str, str]]:
    path = "mongodb-vm" if substrate == "lxd" else "mongodb-k8s"
    configs: dict[str, str] = {
        "bucket": "data-charms-testing",
        "endpoint": "https://storage.googleapis.com",
        "region": "",
        "path": f"{path}/{uuid.uuid4()}",
    }
    credentials: dict[str, str] = {
        "access-key": os.environ["GCP_ACCESS_KEY"],
        "secret-key": os.environ["GCP_SECRET_KEY"],
    }
    return configs, credentials


@pytest.fixture(scope="session")
def cloud_configs(cloud_configs_gcp, cloud_configs_aws):
    yield {"AWS": cloud_configs_aws, "GCP": cloud_configs_gcp}
