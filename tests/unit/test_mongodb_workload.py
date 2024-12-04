import getpass
from pathlib import Path

import pytest
from ops.pebble import Layer

from single_kernel_mongo.config.literals import VmUser
from single_kernel_mongo.config.models import ROLES, VM_MONGOD, VM_MONGOS
from single_kernel_mongo.core.workload import MongoPaths
from single_kernel_mongo.exceptions import WorkloadExecError, WorkloadServiceError
from single_kernel_mongo.lib.charms.operator_libs_linux.v2.snap import SnapError
from single_kernel_mongo.workload import (
    VMLogRotateDBWorkload,
    VMMongoDBExporterWorkload,
    VMMongoDBWorkload,
    VMMongosWorkload,
    VMPBMWorkload,
)


def test_mongodb_workload_init(monkeypatch):
    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)

    def mock_snap(*arg, **kwargs):
        return ""

    monkeypatch.setattr(workload.mongod, "get", mock_snap)
    assert workload.paths == MongoPaths(ROLES["vm"]["mongod"])
    assert workload.env_var == "MONGOD_ARGS"
    assert workload.role == ROLES["vm"]["mongod"]
    assert not workload.workload_present

    assert workload.layer == Layer(
        {
            "summary": "mongod layer",
            "description": "Pebble config layer for replicated mongod",
            "services": {
                "mongod": {
                    "override": "replace",
                    "summary": "mongod",
                    "command": "/usr/bin/mongod ${MONGOD_ARGS}",
                    "startup": "enabled",
                    "user": VmUser.user,  # type: ignore
                    "group": VmUser.group,  # type: ignore
                    "environment": {"MONGOD_ARGS": ""},
                }
            },
        }
    )


def test_mongos_workload_init(monkeypatch):
    workload = VMMongosWorkload(role=VM_MONGOS, container=None)

    assert workload.paths == MongoPaths(ROLES["vm"]["mongos"])
    assert workload.env_var == "MONGOS_ARGS"
    assert workload.role == ROLES["vm"]["mongos"]

    def mock_snap(*arg, **kwargs):
        return ""

    monkeypatch.setattr(workload.mongod, "get", mock_snap)

    assert workload.layer == Layer(
        {
            "summary": "mongos layer",
            "description": "Pebble config layer for mongos router",
            "services": {
                "mongos": {
                    "override": "replace",
                    "summary": "mongos",
                    "command": "/usr/bin/mongos ${MONGOS_ARGS}",
                    "startup": "enabled",
                    "user": VmUser.user,  # type: ignore
                    "group": VmUser.group,  # type: ignore
                    "environment": {"MONGOS_ARGS": ""},
                }
            },
        }
    )


def test_mongodb_exporter_workload_init(monkeypatch):
    workload = VMMongoDBExporterWorkload(role=VM_MONGOD, container=None)

    def mock_snap(*arg, **kwargs):
        return ""

    monkeypatch.setattr(workload.mongod, "get", mock_snap)

    assert workload.paths == MongoPaths(ROLES["vm"]["mongod"])
    assert workload.env_var == "MONGODB_URI"
    assert workload.role == ROLES["vm"]["mongod"]

    assert workload.layer == Layer(
        {
            "summary": "mongodb_exporter layer",
            "description": "Pebble config layer for mongodb_exporter",
            "services": {
                "mongodb_exporter": {
                    "override": "replace",
                    "summary": "mongodb_exporter",
                    "command": "mongodb_exporter --collector.diagnosticdata --compatible-mode",
                    "startup": "enabled",
                    "user": VmUser.user,  # type: ignore
                    "group": VmUser.group,  # type: ignore
                    "environment": {"MONGODB_URI": ""},
                }
            },
        }
    )


def test_pbm_workload_init(monkeypatch):
    workload = VMPBMWorkload(role=ROLES["vm"]["mongod"], container=None)

    def mock_snap(*arg, **kwargs):
        return ""

    monkeypatch.setattr(workload.mongod, "get", mock_snap)

    assert workload.paths == MongoPaths(ROLES["vm"]["mongod"])
    assert workload.paths.pbm_config == Path(
        "/var/snap/charmed-mongodb/current/etc/pbm/pbm_config.yaml"
    )
    assert workload.env_var == "PBM_MONGODB_URI"
    assert workload.role == ROLES["vm"]["mongod"]

    assert workload.layer == Layer(
        {
            "summary": "pbm layer",
            "description": "Pebble config layer for pbm",
            "services": {
                "pbm-agent": {
                    "override": "replace",
                    "summary": "pbm",
                    "command": "/usr/bin/pbm-agent",
                    "startup": "enabled",
                    "user": VmUser.user,  # type: ignore
                    "group": VmUser.group,  # type: ignore
                    "environment": {"PBM_MONGODB_URI": ""},
                }
            },
        }
    )


def test_logrotate_workload_init():
    workload = VMLogRotateDBWorkload(ROLES["vm"]["mongod"], container=None)

    assert workload.paths == MongoPaths(ROLES["vm"]["mongod"])
    assert workload.env_var == ""
    assert workload.role == ROLES["vm"]["mongod"]

    assert workload.layer == Layer(
        {
            "summary": "Log rotate layer",
            "description": "Pebble config layer for rotating mongodb logs",
            "services": {
                "logrotate": {
                    "summary": "log rotate",
                    "command": "sh -c 'logrotate /etc/logrotate.d/mongodb; sleep 1'",
                    "startup": "enabled",
                    "override": "replace",
                    "backoff-delay": "1m0s",
                    "backoff-factor": 1,
                    "user": VmUser.user,  # type: ignore
                    "group": VmUser.group,  # type: ignore
                }
            },
        }
    )


def test_snap_install_failure(monkeypatch):
    def mock_snap_ensure(*args, **kwargs):
        raise SnapError

    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)

    monkeypatch.setattr(workload.mongod, "ensure", mock_snap_ensure)

    assert not workload.install()


def test_install_success(monkeypatch):
    def mock_snap(*args, **kwargs):
        return

    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)

    monkeypatch.setattr(workload.mongod, "ensure", mock_snap)
    monkeypatch.setattr(workload.mongod, "hold", mock_snap)

    assert workload.install()


def test_read_file_fail():
    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    assert workload.read(Path("/nonexistent")) == []


def test_read_file_succeed(tmp_path):
    tmp_file = tmp_path / "test_file.txt"
    tmp_file.write_text("need\ndead\ncafe\n")

    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    assert workload.read(tmp_file) == ["need", "dead", "cafe"]


def test_delete_fail():
    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    assert workload.delete(Path("/nonexistent")) is None


def test_delete_success(tmp_path):
    tmp_file = tmp_path / "test_file.txt"
    tmp_file.write_text("need\ndead\ncafe\n")

    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    workload.delete(tmp_file)

    assert not tmp_file.is_file()


@pytest.mark.parametrize("command", [("start"), ("stop"), ("restart")])
def test_command_success(monkeypatch, command):
    def mock_snap(*args, **kwargs):
        return

    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    monkeypatch.setattr(workload.mongod, command, mock_snap)

    assert getattr(workload, command)() is None


@pytest.mark.parametrize("command", [("start"), ("stop"), ("restart")])
def test_command_success_failure(monkeypatch, caplog, command):
    def mock_snap(*args, **kwargs):
        raise SnapError

    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    monkeypatch.setattr(workload.mongod, command, mock_snap)

    caplog.clear()
    with pytest.raises(WorkloadServiceError):
        getattr(workload, command)()
    # Check that we logged the SnapError
    assert any(
        record.levelname == "ERROR" and record.exc_info[0] == SnapError for record in caplog.records
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"mongod": {"active": True}}, True),
        ({"mongod": {"active": False}}, False),
        ({"mongod": {}}, False),
        ({}, False),
    ],
)
def test_active(mocker, value: dict, expected: bool):
    mocker.patch(
        "single_kernel_mongo.lib.charms.operator_libs_linux.v2.snap.Snap.services",
        return_value=value,
        new_callable=mocker.PropertyMock,
    )
    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    assert workload.active() == expected


def test_exec():
    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    user = getpass.getuser()
    user_exec = workload.exec(["whoami"]).strip()
    assert user == user_exec


def test_exec_fail(mocker, caplog):
    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    caplog.clear()
    with pytest.raises(WorkloadExecError) as err:
        workload.exec("false")

    assert err.value.return_code == 1
    assert err.value.cmd == "false"
    assert any(
        record.levelname == "ERROR" and record.msg == "cmd failed - cmd=false, stdout=, stderr="
        for record in caplog.records
    )


def test_run_bin_command(mocker):
    mock = mocker.patch("single_kernel_mongo.workload.VMMongoDBWorkload.exec")
    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)
    workload.run_bin_command("fail", [])

    mock.assert_called_once_with(command=["/snap/bin/charmed-mongodb.mongosh", "fail"], env={})


def test_logrotate_build_template(monkeypatch, tmp_path):
    tmp_file = tmp_path / "template.txt"

    def mock_write(path, content):
        tmp_file.write_text(content)

    def mock_exec(*args):
        return

    workload = VMLogRotateDBWorkload(role=VM_MONGOD, container=None)
    monkeypatch.setattr(workload, "write", mock_write)
    monkeypatch.setattr(workload, "exec", mock_exec)
    workload.build_template()
    assert "mongodb/*.log" in tmp_file.read_text()


def test_exists(tmp_path):
    tmp_file = tmp_path / "check_file"
    workload = VMMongoDBWorkload(role=VM_MONGOD, container=None)

    tmp_file.write_text("0xdeadbeef")
    assert workload.exists(tmp_file)
