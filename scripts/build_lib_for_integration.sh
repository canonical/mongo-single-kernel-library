#!/bin/bash

## This builds the whl and then copies it to all 4 test charms and updates the requirements file.

set -e

git_hash=$(git describe --always --dirty)

LIB_PATH="./single_kernel_mongo"

CHARMS_PATH="./tests/charms"

# Default values
declare -a TEST_CHARMS=("${CHARMS_PATH}/mongodb_test_charm" "${CHARMS_PATH}/mongodb_k8s_test_charm" "${CHARMS_PATH}/mongos_test_charm" "${CHARMS_PATH}/mongos_k8s_test_charm")
PLATFORM="ubuntu@24.04:$(dpkg --print-architecture)"

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--charm)
        TEST_CHARMS=("$2")
      shift # past argument
      shift # past value
      ;;
    -p|--platform)
      PLATFORM="$2"
      shift # past argument
      shift # past value
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

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
    cp pyproject.toml pyproject.toml.backup
    cp poetry.lock poetry.lock.backup

    # Disable strict mode for build test lib.
    pushd "${LIB_PATH}"
    git init
    sed 's/strict = true/strict = false/' -i "pyproject.toml"
    popd

    poetry add "${LIB_PATH}/"
    poetry lock

    python3 -c 'import pathlib; import shutil; import subprocess; git_hash=subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, check=True, encoding="utf-8").stdout; file = pathlib.Path("charm_version"); shutil.copy(file, pathlib.Path("charm_version.backup")); version = file.read_text().strip(); file.write_text(f"{version}+{git_hash}")'

    # Pack the charm
    if $CI_CACHE; then
        ccc pack -v --platform="${PLATFORM}"
    else
        charmcraft pack -v --platform="${PLATFORM}"
    fi

    # Cleanup
    echo "removing copied files from single kernel charm."
    rm ${LIB_PATH} -rf
    mv charm_version.backup charm_version
    mv pyproject.toml.backup pyproject.toml
    mv poetry.lock.backup poetry.lock

    # Go back to root directory
    popd
done
