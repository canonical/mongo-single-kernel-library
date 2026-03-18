import pytest

from tests.integration.helpers.types import Substrate
from tests.integration.helpers.vault import VAULT, VAULT_K8S


@pytest.fixture
def vault_charm_name(substrate: Substrate) -> str:
    return VAULT if substrate == "lxd" else VAULT_K8S
