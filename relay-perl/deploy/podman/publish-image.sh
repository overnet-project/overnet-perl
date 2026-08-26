#!/usr/bin/env bash
# Publish a tested image without ever deliberately replacing its commit tag.
set -euo pipefail

image="${1:?usage: publish-image.sh IMAGE REGISTRY/REPOSITORY COMMIT EXISTING_DIGEST SUMMARY_FILE}"
repository="${2:?usage: publish-image.sh IMAGE REGISTRY/REPOSITORY COMMIT EXISTING_DIGEST SUMMARY_FILE}"
commit="${3:?usage: publish-image.sh IMAGE REGISTRY/REPOSITORY COMMIT EXISTING_DIGEST SUMMARY_FILE}"
existing_digest="${4-}"
summary_file="${5:?usage: publish-image.sh IMAGE REGISTRY/REPOSITORY COMMIT EXISTING_DIGEST SUMMARY_FILE}"
here="$(cd "$(dirname "$0")" && pwd)"
lookup="$here/registry-tag-digest.sh"

registry_host="${repository%%/*}"
repository_path="${repository#*/}"
registry_pattern='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]+)?$'
repository_pattern='^[a-z0-9]+([._-]+[a-z0-9]+)*(/[a-z0-9]+([._-]+[a-z0-9]+)*)*$'

if [[ "$repository_path" == "$repository" \
  || ! "$registry_host" =~ $registry_pattern \
  || ! "$repository_path" =~ $repository_pattern ]]; then
  printf 'invalid image repository: %s\n' "$repository" >&2
  exit 64
fi
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'invalid full Git commit: %s\n' "$commit" >&2
  exit 64
fi
if [[ -n "$existing_digest" && ! "$existing_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  printf 'invalid existing manifest digest: %s\n' "$existing_digest" >&2
  exit 64
fi

tag="sha-${commit}"
sha_ref="${repository}:${tag}"
main_ref="${repository}:main"
sha_digest_file="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/relay-sha-digest.XXXXXX")"
main_digest_file="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/relay-main-digest.XXXXXX")"
trap 'rm -f "$sha_digest_file" "$main_digest_file"' EXIT

current_digest="$($lookup "$repository" "$tag")"
if [[ -n "$existing_digest" ]]; then
  if [[ "$current_digest" != "$existing_digest" ]]; then
    printf 'commit tag changed during verification: expected %s@%s, found %s\n' \
      "$sha_ref" "$existing_digest" "${current_digest:-missing}" >&2
    exit 1
  fi
  sha_digest="$existing_digest"
  action=Reused
else
  if [[ -n "$current_digest" ]]; then
    printf 'commit tag appeared during the build; refusing to overwrite %s@%s\n' \
      "$sha_ref" "$current_digest" >&2
    exit 1
  fi

  podman tag "$image" "$sha_ref"
  podman push --digestfile "$sha_digest_file" "$sha_ref"
  sha_digest="$(<"$sha_digest_file")"
  action=Published
fi

if [[ ! "$sha_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  printf 'push returned an invalid commit manifest digest: %s\n' "$sha_digest" >&2
  exit 1
fi

podman tag "$image" "$main_ref"
podman push --digestfile "$main_digest_file" "$main_ref"
main_digest="$(<"$main_digest_file")"

if [[ "$main_digest" != "$sha_digest" ]]; then
  printf 'published digest mismatch: %s is %s but %s is %s\n' \
    "$sha_ref" "$sha_digest" "$main_ref" "$main_digest" >&2
  exit 1
fi

printf '%s `%s@%s` and verified `%s@%s`\n' \
  "$action" "$sha_ref" "$sha_digest" "$main_ref" "$main_digest" \
  >> "$summary_file"
