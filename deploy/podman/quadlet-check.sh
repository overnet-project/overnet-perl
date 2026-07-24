#!/usr/bin/env bash
#
# Validate that every Quadlet unit in this directory converts to a systemd
# service, using podman's Quadlet generator in dry-run mode (no running systemd
# session required). This catches structural mistakes in the units -- a
# misspelled key, an unresolved .volume reference, a malformed Exec= -- that the
# behavioural smoke test does not exercise.
#
# It asserts that each .container converts and that each .volume-backed mount
# resolves to the declared VolumeName, not what the units otherwise contain, so
# it survives edits to the units without changes here and covers new units
# automatically.
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

# Each .container unit must convert to a runnable podman service naming that
# container. Asserting the generated ExecStart exists is a positive success
# signal: a unit that failed to convert produces no ExecStart at all.
for unit in "$HERE"/*.container; do
  cname="$(sed -n 's/^ContainerName=//p' "$unit" | head -n1)"
  [[ -n "$cname" ]] || { echo "quadlet-check: $unit has no ContainerName=" >&2; status=1; continue; }
  if ! grep -qE "ExecStart=.*podman run .*--name[ =]${cname}\b" <<<"$output"; then
    echo "quadlet-check: $(basename "$unit") did not convert to a podman service" >&2
    status=1
  fi
done

# Each .volume unit's mount must resolve to its declared VolumeName. If a
# .container's Volume= reference does not match the .volume unit's file name,
# Quadlet silently falls back to a `systemd-<name>` volume instead of linking
# the unit -- guard against that regression by reading the name from the unit.
for vunit in "$HERE"/*.volume; do
  volname="$(sed -n 's/^VolumeName=//p' "$vunit" | head -n1)"
  [[ -n "$volname" ]] || continue
  if ! grep -q "${volname}:/var/lib/overnet/" <<<"$output"; then
    echo "quadlet-check: no mount uses the declared volume name ($volname)" >&2
    status=1
  fi
  if grep -q "systemd-${volname}:" <<<"$output"; then
    echo "quadlet-check: a Volume= reference did not resolve to $(basename "$vunit") (fell back to systemd-$volname)" >&2
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "quadlet-check: PASS"
fi
exit $status
