#!/usr/bin/env bash
set -euo pipefail

# This script waits until the snap revisions for each architecture have advanced
# on the target channel, compared with the revisions previously recorded in
# CURRENT_REVISIONS.

source .github/scripts/snapcraft-revisions-lib.sh

snaps=$(jq -r 'keys[]' <<<"$CURRENT_REVISIONS")
if [ -z "$snaps" ]; then
  echo "No snap-backed rocks to wait for; nothing to do."
  exit 0
fi

# We track both amd64 and arm64 revisions.
archs="amd64 arm64"
pending=$(
  for snap in $snaps; do
    for arch in $archs; do
      echo "${snap} ${arch}"
    done
  done
)

# Poll up to 60 times with a 30-second delay between attempts.
for i in $(seq 1 60); do
  next_pending=""
  status=""
  pending_snaps=$(awk '{print $1}' <<<"$pending" | sort -u)
  for snap in $pending_snaps; do
    # Fetch the current live revision state for this snap/channel.
    current=$(get_live_snap_revisions_by_arch "$snap")

    snap_status=""
    pending_archs=$(awk -v snap="$snap" '$1 == snap {print $2}' <<<"$pending")
    for arch in $pending_archs; do
      previous=$(jq -r --arg s "$snap" --arg arch "$arch" '.[$s][$arch] // 0' <<<"$CURRENT_REVISIONS")
      now=$(jq -r --arg arch "$arch" '.[$arch] // 0' <<<"$current")
      if [ "$now" -le "$previous" ]; then
        # Still waiting for a new revision on this architecture.
        next_pending="${next_pending}${snap} ${arch}"$'\n'
        snap_status="${snap_status} ${arch}:${now}<=${previous}"
      else
        # Revision has advanced beyond the previously recorded value.
        snap_status="${snap_status} ${arch}:${now}>${previous}"
      fi
    done
    status="${status} ${snap}={${snap_status# }}"
  done
  if [ -z "$next_pending" ]; then
    echo "All new revisions live on ${CHANNEL}:${status}"
    exit 0
  fi

  pending="$next_pending"
  echo "Attempt ${i}: still waiting on ${CHANNEL}:${status}; retrying in 30s"
  sleep 30
done

# Timeout expired before all snaps updated.
echo "Timed out waiting for new snap revisions on ${CHANNEL}"
exit 1
