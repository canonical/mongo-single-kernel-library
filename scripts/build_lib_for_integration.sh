#!/bin/bash

## This builds the whl and then copies it to all 4 test charms and updates the requirements file.

git_hash=$(git describe --always --dirty)

LIB_PATH="./single_kernel_mongo"

CHARMS_PATH="./tests/charms"

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

    poetry add "${LIB_PATH}/"
    poetry lock

    python3 -c 'import pathlib; import shutil; import subprocess; git_hash=subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, check=True, encoding="utf-8").stdout; file = pathlib.Path("charm_version"); shutil.copy(file, pathlib.Path("charm_version.backup")); version = file.read_text().strip(); file.write_text(f"{version}+{git_hash}")'

    # Pack the charm
    charmcraft -v pack

    # Cleanup
    echo "removing copied files from single kernel charm."
    rm ${LIB_PATH} -rf
    mv charm_version.backup charm_version

    # Go back to root directory
    popd
done
