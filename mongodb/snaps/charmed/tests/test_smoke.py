import yaml
import subprocess
import time
import pytest

SERVICES_TO_TEST = (
    "mongod",
    "mongos",
    "mongodb-exporter",
    "pbm-agent",
    "vault-agent",
)


def test_install():
    with open("snap/snapcraft.yaml") as file:
        snapcraft = yaml.safe_load(file)

        subprocess.run(
            f"sudo snap install ./{snapcraft['name']}_{snapcraft['version']}_amd64.snap --dangerous".split(),
            check=True,
        )


@pytest.mark.run(after="test_keyfile_actions")
def test_all_apps():
    with open("snap/snapcraft.yaml") as file:
        snapcraft = yaml.safe_load(file)

        for app, data in snapcraft["apps"].items():
            if not data.get("daemon"):
                print(f"Testing {snapcraft['name']}.{app}....")
                subprocess.run(
                    f"{snapcraft['name']}.{app} --help".split(),
                    check=True,
                )


def _current_status(name, app):
    """Return the 'Current' column from `snap services <name>.<app>`.

    The output looks like:

        Service                        Startup   Current   Notes
        mongodb-server-sharded.mongod  disabled  active    -

    so the status is the third whitespace-separated field of the data row.
    """
    result = subprocess.run(
        f"snap services {name}.{app}".split(),
        check=True,
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    for line in result.stdout.strip().splitlines()[1:]:
        fields = line.split()
        if fields and fields[0] == f"{name}.{app}":
            return fields[2]
    raise AssertionError(f"{name}.{app} not found in:\n{result.stdout}")


def _daemon_apps(snapcraft):
    return {app for app, data in snapcraft["apps"].items() if data.get("daemon")}


def _set_snap_config(name, config):
    subprocess.run(
        [
            "sudo",
            "snap",
            "set",
            name,
            *[f"{key}={value}" for key, value in config.items()],
        ],
        check=True,
    )


@pytest.mark.run(after="test_all_apps")
def test_all_services():
    with open("snap/snapcraft.yaml") as file:
        snapcraft = yaml.safe_load(file)
    name = snapcraft["name"]

    daemon_apps = _daemon_apps(snapcraft)
    services_to_test = set(SERVICES_TO_TEST)

    assert services_to_test == daemon_apps, (
        "SERVICES_TO_TEST must match daemon apps in snapcraft.yaml. "
        f"Missing from test list: {sorted(daemon_apps - services_to_test)}. "
        f"Not daemon apps: {sorted(services_to_test - daemon_apps)}."
    )

    _set_snap_config(
        name,
        {
            "mongod-args": "--configsvr --replSet configrs --port 27019 --bind_ip 127.0.0.1",
            "mongos-args": "--configdb configrs/127.0.0.1:27019 --bind_ip 127.0.0.1 --port 27018",
            "monitor-uri": "mongodb://127.0.0.1:27019",
            "pbm-uri": "mongodb://127.0.0.1:27019",
        },
    )

    try:
        for app in SERVICES_TO_TEST:
            print(f"\nTesting {name}.{app} service....")
            subprocess.run(f"sudo snap start {name}.{app}".split(), check=True)
            time.sleep(5)
            status = _current_status(name, app)
            assert status == "active", f"{name}.{app} is {status!r}, expected 'active'"
    finally:
        for app in SERVICES_TO_TEST:
            subprocess.run(f"sudo snap stop {name}.{app}".split())


@pytest.mark.run(after="test_all_services")
def test_remove():
    with open("snap/snapcraft.yaml") as file:
        snapcraft = yaml.safe_load(file)
    subprocess.run(f"sudo snap remove --purge {snapcraft['name']}".split())
