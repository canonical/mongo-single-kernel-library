import pytest

from tests.integration.helpers.jubilant_vault import VAULT, VAULT_K8S
from tests.integration.helpers.types import Substrate


@pytest.fixture
def vault_charm_name(substrate: Substrate) -> str:
    return VAULT if substrate == Substrate.lxd else VAULT_K8S
