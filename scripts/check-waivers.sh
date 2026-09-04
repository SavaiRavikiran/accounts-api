#!/usr/bin/env bash
# Fails (exit 1) if any waiver YAML in the target directory has expired.
# Usage: scripts/check-waivers.sh [waivers-dir]   (default: waivers/)
set -euo pipefail

DIR="${1:-waivers}"
TODAY=$(date -u +%Y-%m-%d)
FAILED=0

if [ ! -d "$DIR" ]; then
  echo "no waivers directory at $DIR — nothing to check"
  exit 0
fi

shopt -s nullglob
for f in "$DIR"/*.yaml "$DIR"/*.yml; do
  [ -e "$f" ] || continue
  case "$(basename "$f")" in
    README.md) continue ;;
  esac

  expires=$(grep -E '^expires:' "$f" | head -1 | sed -E 's/^expires:[[:space:]]*//')
  id=$(grep -E '^id:' "$f" | head -1 | sed -E 's/^id:[[:space:]]*//')
  approved_by=$(grep -E '^approved_by:' "$f" | head -1 | sed -E 's/^approved_by:[[:space:]]*//')

  if [ -z "$expires" ]; then
    echo "FAIL: $f has no 'expires' field — every waiver must carry a hard expiry"
    FAILED=1
    continue
  fi
  if [ -z "$approved_by" ]; then
    echo "FAIL: $f has no 'approved_by' field — every waiver must be approved"
    FAILED=1
    continue
  fi

  if [[ "$expires" < "$TODAY" ]]; then
    echo "FAIL: waiver $id in $f expired on $expires (today: $TODAY) — renew with a new approval or fix the underlying finding"
    FAILED=1
  else
    echo "OK: waiver $id in $f valid until $expires"
  fi
done

exit $FAILED
