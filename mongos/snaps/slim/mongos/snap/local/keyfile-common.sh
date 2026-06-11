#!/bin/bash
# Shared helpers for managing the MongoDB internal-authentication keyfile.

KEYFILE="${KEYFILE:-${SNAP_DATA}/etc/mongodb-keyfile}"
KEYFILE_UID=584788
KEYFILE_GID=584788
OPENSSL="${OPENSSL:-${SNAP}/usr/bin/openssl}"

# Write stdin to the keyfile with the correct ownership (584788:584788) and
# permissions (400). The write is atomic: a temporary file in the same
# directory is populated, locked down, then renamed over the keyfile so that
# readers never observe a partial key.
write_keyfile() {
  local tmp
  mkdir -p "$(dirname "${KEYFILE}")"
  tmp="$(mktemp "${KEYFILE}.XXXXXX")"
  trap 'rm -f "${tmp}"' EXIT
  cat > "${tmp}"
  if [ ! -s "${tmp}" ]; then
    echo "keyfile: KEY must not be empty" >&2
    exit 1
  fi
  chmod 400 "${tmp}"
  if [ "$(id -u)" = "0" ]; then
    chown "${KEYFILE_UID}:${KEYFILE_GID}" "${tmp}"
  fi
  mv -f "${tmp}" "${KEYFILE}"
  trap - EXIT
}

# Generate a fresh random key and store it in the keyfile.
generate_keyfile() {
  "${OPENSSL}" rand -base64 756 | write_keyfile
}
