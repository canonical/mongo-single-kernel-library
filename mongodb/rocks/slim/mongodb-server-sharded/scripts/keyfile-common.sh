#!/bin/bash
# Shared helpers for managing the MongoDB internal-authentication keyfile.
#
# This file is sourced by the startup scripts and by the get-keyfile /
# set-keyfile commands. The keyfile lives next to the MongoDB config files at
# /etc/mongod/mongodb-keyfile and must be readable only by the _daemon_ UID/GID
# (584792:584792).

KEYFILE="${KEYFILE:-/etc/mongod/mongodb-keyfile}"
KEYFILE_UID=584792
KEYFILE_GID=584792

# Write stdin to the keyfile with permissions (400). When running as root, also
# set the ownership to the _daemon_ UID/GID (584792:584792). The write is atomic:
# a temporary file in the same directory is populated, locked down, then renamed
# over the keyfile so that readers never observe a partial key.
write_keyfile() {
  local keyfile_dir keyfile_name tmp
  keyfile_dir="$(dirname "${KEYFILE}")"
  keyfile_name="$(basename "${KEYFILE}")"
  if ! tmp="$(mktemp -p "${keyfile_dir}" "${keyfile_name}.XXXXXX")"; then
    echo "Unable to create temporary keyfile next to ${KEYFILE}." >&2
    echo "Run this command as ${KEYFILE_UID}:${KEYFILE_GID} or make ${keyfile_dir} writable by that user." >&2
    return 1
  fi
  trap 'rm -f "${tmp}"' EXIT
  cat > "${tmp}"
  if [ ! -s "${tmp}" ]; then
    echo "keyfile: KEY must not be empty" >&2
    exit 1
  fi
  chmod 400 "${tmp}"
  if [ "$(id -u)" -eq 0 ]; then
    chown "${KEYFILE_UID}:${KEYFILE_GID}" "${tmp}"
  fi
  mv -f "${tmp}" "${KEYFILE}"
  trap - EXIT
}

# Generate a fresh random key and store it in the keyfile.
generate_keyfile() {
  openssl rand -base64 756 | write_keyfile
}
