#!/bin/bash

## This builds the whl and then copies it to all 4 test charms and updates the requirements file.

DIST="dist"

if [ -d "${DIST}" ]; then
    rm -rf dist
fi

git_hash=$(git describe --always --dirty)

poetry build --format=wheel --output=$DIST

WHL_PATH=$(find dist -name "*.whl")

CHARMS_PATH="./tests/charms"

if [ $# -ge 1 ]; then
    declare -a TEST_CHARMS=("$1")
else
    declare -a TEST_CHARMS=("${CHARMS_PATH}/mongodb_test_charm" "${CHARMS_PATH}/mongodb_k8s_test_charm" "${CHARMS_PATH}/mongos_test_charm" "${CHARMS_PATH}/mongos_k8s_test_charm")
fi

for directory in "${TEST_CHARMS[@]}"; do
    cp -r "$DIST" "$directory"
    cp "${directory}/requirements.txt" "${directory}/requirements.txt.backup"
    echo "mongo-charms-single-kernel @ file:/root/project/${WHL_PATH}" > "${directory}/requirements.txt"
    poetry export --without-hashes >> "${directory}/requirements.txt"

    echo "Building charm ${directory}\n"


    pushd $directory
    python3 -c 'import pathlib; import shutil; import subprocess; git_hash=subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, check=True, encoding="utf-8").stdout; file = pathlib.Path("charm_version"); shutil.copy(file, pathlib.Path("charm_version.backup")); version = file.read_text().strip(); file.write_text(f"{version}+{git_hash}")'
    charmcraft -v pack
    mv charm_version.backup charm_version
    popd
    mv "${directory}/requirements.txt.backup" "${directory}/requirements.txt"
done
