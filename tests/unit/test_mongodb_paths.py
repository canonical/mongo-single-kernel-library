from pathlib import Path

from parameterized import parameterized

from single_kernel_mongo.config.roles import (
    K8S_MONGO,
    VM_MONGO,
    Role,
)
from single_kernel_mongo.core.workload import MongoPaths


@parameterized.expand([[K8S_MONGO], [VM_MONGO]])
def test_mongo_paths(role: Role):
    paths = MongoPaths(role)

    assert paths.config_file.parent == Path(role.paths["CONF"])
    assert paths.keyfile.parent == Path(role.paths["CONF"])
    assert paths.log_file.parent == Path(role.paths["LOGS"])
    assert paths.audit_file.parent == Path(role.paths["LOGS"])
    assert paths.ext_pem_file.parent == Path(role.paths["CONF"])
    assert paths.ext_ca_file.parent == Path(role.paths["CONF"])
    assert paths.int_pem_file.parent == Path(role.paths["CONF"])
    assert paths.int_ca_file.parent == Path(role.paths["CONF"])
    assert paths.socket_path.parent == Path(role.paths["VAR"])
    assert paths.common_path == Path(role.paths["VAR"]).parent

    assert all(path.parent == Path(role.paths["CONF"]) for path in paths.tls_files)
