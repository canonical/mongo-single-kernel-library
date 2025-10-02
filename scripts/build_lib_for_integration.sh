#!/bin/bash

## This builds the whl and then copies it to all 4 test charms and updates the requirements file.

set -e

LIB_PATH="./single_kernel_mongo"

CHARMS_PATH="./tests/charms"

VERSION=$(poetry version --short)

if [ $# -ge 1 ]; then
    declare -a TEST_CHARMS=("$1")
else
    declare -a TEST_CHARMS=("${CHARMS_PATH}/mongodb_test_charm" "${CHARMS_PATH}/mongodb_k8s_test_charm" "${CHARMS_PATH}/mongos_test_charm" "${CHARMS_PATH}/mongos_k8s_test_charm")
fi

for directory in "${TEST_CHARMS[@]}"; do
    echo "clearing out libs for charm"
    directory_lib_path="${directory}/${LIB_PATH}"
    rm -rf "$directory_lib_path"
    mkdir "$directory_lib_path"
    echo "copying over libs from single kernel charm"
    cp -r "${LIB_PATH}" "$directory_lib_path"
    cp "pyproject.toml" "$directory_lib_path"
    cp "README.md" "$directory_lib_path"

    echo "Building charm ${directory}\n"


    pushd $directory

    # Backup files
    cp refresh_versions.toml refresh_versions.toml.backup

    python3 -m venv /tmp/refresh-version-venv
    source /tmp/refresh-version-venv/bin/activate
    poetry install --only build-refresh-version
    /tmp/refresh-version-venv/bin/write-charm-version
    deactivate
    rm /tmp/refresh-version-venv/ -rf

    cp pyproject.toml pyproject.toml.backup
    cp poetry.lock poetry.lock.backup

    # Disable strict mode for build test lib.
    pushd "${LIB_PATH}"
    git init
    sed 's/strict = true/strict = false/' -i "pyproject.toml"
    popd

    poetry add "${LIB_PATH}/"
    poetry lock



    # Pack the charm
    if $CI_CACHE; then
        ccc pack -v
    else
        charmcraft pack -v --debug
    fi

    # Cleanup
    echo "removing copied files from single kernel charm."
    rm ${LIB_PATH} -rf
    mv pyproject.toml.backup pyproject.toml
    mv poetry.lock.backup poetry.lock
    mv refresh_versions.toml.backup refresh_versions.toml

    # Go back to root directory
    popd
done
