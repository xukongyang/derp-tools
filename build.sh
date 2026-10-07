#!/bin/sh
# Builds a patched derper for private-DERP admission control from the
# tailscale checkout beside this script.
#
# patches/*.patch is the single source of truth: the tailscale working
# tree is hard-reset to TAILSCALE_COMMIT and the patches replayed on
# top on every run, so the flow is idempotent.
#
# TAILSCALE_COMMIT is pinned to the commit that tailcat's go.mod
# requires, so tailcat's `replace` directive and the derper built
# here always share the same patched sources.
#
# Usage:
#
#	./build.sh                 # build ./derper for this platform
#	GOOS=windows ./build.sh    # cross-compile (GOARCH etc. pass through)
set -e
cd "$(dirname "$0")"

TAILSCALE_COMMIT=${TAILSCALE_COMMIT:-4862f5f46}  # keep in sync with tailcat/go.mod

if [ ! -d tailscale/.git ]; then
	git clone --filter=blob:none https://github.com/tailscale/tailscale.git tailscale
else
	# Fetching a bare commit SHA isn't supported by every remote; if
	# it fails, the objects may already be local from a prior fetch.
	git -C tailscale fetch --filter=blob:none origin "$TAILSCALE_COMMIT" 2>/dev/null || \
		echo "note: could not fetch $TAILSCALE_COMMIT; assuming it is already local"
fi
# Detach to the clean baseline so the auth-patch branch pointer is
# never moved by builds; the patches replay on top as working-tree
# changes. patches/*.patch is the single source of truth.
git -C tailscale checkout --detach -q "$TAILSCALE_COMMIT"
git -C tailscale apply "$(pwd)"/patches/*.patch

cd tailscale
go build -o ../derper ./cmd/derper
echo "built $(pwd)/../derper from tailscale@$(git describe --always)"
