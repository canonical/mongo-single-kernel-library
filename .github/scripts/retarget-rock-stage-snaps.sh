#!/usr/bin/env bash
set -euo pipefail

: "${ROCK_NAME:?ROCK_NAME must be set}"
: "${SNAP_CHANNEL:?SNAP_CHANNEL must be set}"

# Check that rockcraft.yaml has stage snaps for this rock pointing at the
# expected channel, e.g. "mongodb-server-sharded/8/edge".
if ! yq \
    '.parts[] | select(has("stage-snaps")) | .["stage-snaps"][] | select(test("^" + env.ROCK_NAME + "/8/edge$"))' \
    "${ROCKCRAFT_FILE}" | grep -q .; then
  echo "No ${ROCK_NAME}/8/edge stage snap channel found in ${ROCKCRAFT_FILE}"
  exit 1
fi

# Rewrite rockcraft.yaml to point stage snaps at the PR snap channel. For
# example, "mongodb-server-sharded/8/edge" becomes
# "mongodb-server-sharded/8/edge/pr-123".
yq -Yi \
  '(.parts[] | select(has("stage-snaps")) | .["stage-snaps"][]) |= sub("/8/edge$"; "/" + env.SNAP_CHANNEL)' \
  "${ROCKCRAFT_FILE}"

git diff -- "${ROCKCRAFT_FILE}"
