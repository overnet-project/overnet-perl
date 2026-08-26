#!/usr/bin/env bash
# Print an OCI registry tag's digest, or print nothing when the tag is absent.
set -euo pipefail

image_repository="${1:?usage: registry-tag-digest.sh REGISTRY/REPOSITORY TAG}"
tag="${2:?usage: registry-tag-digest.sh REGISTRY/REPOSITORY TAG}"

registry="${image_repository%%/*}"
repository="${image_repository#*/}"
registry_pattern='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]+)?$'
repository_pattern='^[a-z0-9]+([._-]+[a-z0-9]+)*(/[a-z0-9]+([._-]+[a-z0-9]+)*)*$'

if [[ "$repository" == "$image_repository" \
  || ! "$registry" =~ $registry_pattern \
  || ! "$repository" =~ $repository_pattern ]]; then
  printf 'invalid image repository: %s\n' "$image_repository" >&2
  exit 64
fi
if [[ ! "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  printf 'invalid image tag: %s\n' "$tag" >&2
  exit 64
fi

headers="$(mktemp "${TMPDIR:-/tmp}/registry-tag-headers.XXXXXX")"
trap 'rm -f "$headers"' EXIT

status="$(
  curl --silent --show-error \
    --head \
    --output /dev/null \
    --dump-header "$headers" \
    --write-out '%{http_code}' \
    --header 'Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "https://${registry}/v2/${repository}/manifests/${tag}"
)"

case "$status" in
  200)
    digest="$(
      awk '
        tolower($0) ~ /^docker-content-digest:/ {
          sub(/\r$/, "")
          sub(/^[^:]+:[[:space:]]*/, "")
          print
          exit
        }
      ' "$headers"
    )"
    if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      printf 'registry returned an invalid manifest digest for %s:%s\n' \
        "$image_repository" "$tag" >&2
      exit 1
    fi
    printf '%s\n' "$digest"
    ;;
  404)
    ;;
  *)
    printf 'registry lookup for %s:%s returned HTTP %s\n' \
      "$image_repository" "$tag" "$status" >&2
    exit 1
    ;;
esac
