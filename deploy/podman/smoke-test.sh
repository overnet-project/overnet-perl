#!/usr/bin/env bash
#
# Smoke-test a relay image built from this directory's Containerfile.
#
# The test drives the container with the SAME run arguments and health command
# declared in overnet-relay.container -- read out of that unit at run time
# rather than duplicated here -- so editing the unit automatically changes what
# this test exercises. It asserts only observable outcomes: the relay starts,
# listens, reports ready, and its health command passes. Retuning the image or
# the unit therefore does not require editing this script.
#
# Usage: smoke-test.sh IMAGE
#
set -euo pipefail

IMAGE="${1:?usage: smoke-test.sh IMAGE}"
HERE="$(cd "$(dirname "$0")" && pwd)"
UNIT="$HERE/overnet-relay.container"

[[ -f "$UNIT" ]] || { echo "smoke-test: missing $UNIT" >&2; exit 1; }

# --- read the deployment's own configuration out of the Quadlet unit ---------

# Join systemd backslash line-continuations so multi-line keys read as one line.
joined_unit() { perl -0777 -pe 's/\\\n\s*/ /g' "$UNIT"; }

exec_line="$(joined_unit | sed -n 's/^Exec=//p')"
health_cmd="$(joined_unit | sed -n 's/^HealthCmd=//p')"
publish="$(grep -m1 '^PublishPort=' "$UNIT" | cut -d= -f2-)"

[[ -n "$exec_line" ]]  || { echo "smoke-test: no Exec= in unit"        >&2; exit 1; }
[[ -n "$health_cmd" ]] || { echo "smoke-test: no HealthCmd= in unit"   >&2; exit 1; }
[[ -n "$publish" ]]    || { echo "smoke-test: no PublishPort= in unit" >&2; exit 1; }

# Word-split the Exec value while honouring quoted arguments (e.g. --name "a b").
mapfile -t run_args < <(printf '%s' "$exec_line" | xargs printf '%s\n')

port="${publish##*:}"                       # container port = last field
name="overnet-relay-smoke-$$"
volume="overnet-relay-smoke-vol-$$"

cleanup() {
  echo "----- container logs -----"
  podman logs "$name" 2>&1 | sed 's/^/[relay] /' || true
  podman rm -f "$name"     >/dev/null 2>&1 || true
  podman volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "smoke-test: starting $IMAGE with the unit's own arguments"
# Mount a fresh named volume where the unit points its store, exercising the
# first-mount ownership (copy-up) path the real deployment relies on.
podman run --detach \
  --name "$name" \
  --publish "$publish" \
  --volume "$volume:/var/lib/overnet/relay" \
  --health-cmd="$health_cmd" \
  "$IMAGE" "${run_args[@]}" >/dev/null

# --- wait for the listener, failing fast if the container dies ---------------

deadline=$(( SECONDS + 90 ))
until timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; do
  if [[ "$(podman inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo false)" != true ]]; then
    echo "smoke-test: container exited before it listened on $port" >&2
    exit 1
  fi
  if (( SECONDS > deadline )); then
    echo "smoke-test: timed out waiting for the relay to listen on $port" >&2
    exit 1
  fi
  sleep 2
done
echo "smoke-test: relay is listening on 127.0.0.1:$port"

# --- confirm the entrypoint's documented ready state and the health command --

# The listener can accept connections a moment before the entrypoint's ready
# timer prints its marker, so poll for it rather than checking once.
ready_deadline=$(( SECONDS + 30 ))
until podman logs "$name" 2>&1 | grep -q 'relay.health.*ready'; do
  if [[ "$(podman inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo false)" != true ]]; then
    echo "smoke-test: container exited before reporting readiness" >&2
    exit 1
  fi
  if (( SECONDS > ready_deadline )); then
    echo "smoke-test: relay never reported readiness" >&2
    exit 1
  fi
  sleep 1
done
echo "smoke-test: relay reported ready"

if ! podman healthcheck run "$name"; then
  echo "smoke-test: the unit's health command failed against the running relay" >&2
  exit 1
fi
echo "smoke-test: health command passed"

echo "smoke-test: PASS"
