#!/bin/sh
# Stage the self-contained installer bundle into the Ansible role files directory.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
cd "$REPO_ROOT"
sh build-firstrun.sh
cp -f install-firstrun-el68.sh "$HERE/roles/networktracing_legacy/files/install-firstrun-el68.sh"
chmod 750 "$HERE/roles/networktracing_legacy/files/install-firstrun-el68.sh"
echo "Staged bundle: $HERE/roles/networktracing_legacy/files/install-firstrun-el68.sh ($(wc -c < "$HERE/roles/networktracing_legacy/files/install-firstrun-el68.sh") bytes)"
sha256sum "$HERE/roles/networktracing_legacy/files/install-firstrun-el68.sh"
