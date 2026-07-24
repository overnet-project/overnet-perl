#!/usr/bin/env bash
#
# Validate that the Quadlet units in this directory convert to systemd services,
# using podman's Quadlet generator in dry-run mode (no running systemd session
# required). This catches structural mistakes in the units -- a misspelled key,
# an unresolved .volume reference, a malformed Exec= -- that the behavioural
# smoke test does not exercise.
#
# It asserts that the units convert and that the generator reports no error, not
# what the units contain, so it survives edits to the units without changes here.
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

quadlet=""
for cand in \
  /usr/libexec/podman/quadlet \
  /usr/lib/systemd/system-generators/podman-system-generator \
  /usr/lib/systemd/user-generators/podman-user-generator; do
  if [[ -x "$cand" ]]; then quadlet="$cand"; break; fi
done
[[ -n "$quadlet" ]] || { echo "quadlet-check: no Quadlet generator found" >&2; exit 1; }
echo "quadlet-check: using $quadlet"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
mkdir -p "$workdir/containers/systemd"
cp "$HERE"/*.container "$HERE"/*.volume "$workdir/containers/systemd/"

# The generator reads units from the user config search path (XDG_CONFIG_HOME).
output="$(XDG_CONFIG_HOME="$workdir" "$quadlet" -dryrun -user 2>&1 || true)"
printf '%s\n' "$output"

status=0
if ! grep -q 'overnet-relay' <<<"$output"; then
  echo "quadlet-check: units did not convert to any service" >&2
  status=1
fi
# Quadlet prints conversion failures as `converting "X": ...` and warnings that
# name the offending key; treat any of those as a hard failure.
if grep -qiE 'converting "|error|invalid|unsupported|failed to' <<<"$output"; then
  echo "quadlet-check: the generator reported a problem with a unit" >&2
  status=1
fi

if [[ $status -eq 0 ]]; then
  echo "quadlet-check: PASS"
fi
exit $status
