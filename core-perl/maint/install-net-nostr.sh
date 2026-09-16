#!/bin/sh
set -eu

# Temporary source pin until Net::Nostr::Core 1.002002 is available on CPAN.
# That release preserves numeric event and filter fields with JSON::XS (NIP-01).
# Arguments are forwarded to cpanm, e.g. --notest --local-lib ~/perl5.
revision=25d8b9b5ea12bbf3ed084c2bd6eef94b3e6b6a85
source_dir=$(mktemp -d)
trap 'rm -rf "$source_dir"' EXIT
trap 'exit 1' HUP INT TERM

curl --fail --location --retry 3 \
  "https://codeload.github.com/NicholasBHubbard/Net-Nostr/tar.gz/$revision" \
  --output "$source_dir/source.tar.gz"
tar -xzf "$source_dir/source.tar.gz" -C "$source_dir"

# Schnorr is distributed on CPAN but not indexed under its module name.
cpanm "$@" GUL/Crypt-PK-ECC-Schnorr-0.01.tar.gz
cpanm "$@" --reinstall "$source_dir/Net-Nostr-$revision/dist/Net-Nostr-Core" \
  Net::Nostr::Client Net::Nostr::Relay

# Source installs have no CPAN install record; retain metadata for image SBOMs.
if [ -n "${OVERNET_NOSTR_METADATA_FILE:-}" ]; then
  cp "$source_dir/Net-Nostr-$revision/dist/Net-Nostr-Core/MYMETA.json" \
    "$OVERNET_NOSTR_METADATA_FILE"
fi
