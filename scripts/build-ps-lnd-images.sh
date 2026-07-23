#!/usr/bin/env bash
#
# Build multi-arch (amd64 + arm64) PS lnd dev images from the current checkout,
# with and without the `switchrpc` build tag, and push them.
#
# The two variants let a testing agent compare transitions between a
# switchrpc-enabled image and the same fork code with switchrpc compiled out.
#
# Reusable across base versions: when v0.21.2-beta drops and you rebase the fork,
# just run with BASE_VERSION=v0.21.2-beta.
#
# Prereqs:
#   - A docker-container buildx builder is active (multi-arch manifests require
#     it; the `docker` driver cannot build them). Check: `docker buildx ls`.
#   - Logged in to the target registry (default Docker Hub `czachman/lnd`).
#   - dev.Dockerfile parameterizes tags via `ARG BUILD_TAGS` (already done).
#
# Usage (run from anywhere; it cd's to the repo root):
#   ./scripts/build-ps-lnd-images.sh                 # build both variants, push
#   VARIANTS=off ./scripts/build-ps-lnd-images.sh    # only the tag-off variant
#   BASE_VERSION=v0.21.2-beta ./scripts/build-ps-lnd-images.sh
#   REGISTRY=myrepo/lnd PLATFORMS=linux/amd64 ./scripts/build-ps-lnd-images.sh
#
set -euo pipefail

REGISTRY="${REGISTRY:-czachman/lnd}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
# Upstream base tag this fork sits on; used in the image tag for clarity.
BASE_VERSION="${BASE_VERSION:-v0.21.1-beta}"
# Which variants to build: on | off | both.
VARIANTS="${VARIANTS:-both}"

# Full tag list WITH switchrpc (must match dev.Dockerfile's BUILD_TAGS default).
TAGS_ON="autopilotrpc signrpc switchrpc walletrpc chainrpc invoicesrpc watchtowerrpc neutrinorpc monitoring peersrpc kvdb_postgres kvdb_etcd kvdb_sqlite"
# Same list WITHOUT switchrpc (the tag-off / baseline build).
TAGS_OFF="autopilotrpc signrpc walletrpc chainrpc invoicesrpc watchtowerrpc neutrinorpc monitoring peersrpc kvdb_postgres kvdb_etcd kvdb_sqlite"

# Run from the repo root so the build context is the whole tree.
cd "$(git rev-parse --show-toplevel)"

COMMIT="$(git rev-parse --short HEAD)"
DIRTY=""
if ! git diff --quiet HEAD --; then
	DIRTY="-dirty"
	echo "WARNING: working tree has uncommitted tracked changes; tagging with -dirty." >&2
fi

echo "Active buildx builder:"
docker buildx ls | grep '\*' || true
echo

build_variant() {
	local label="$1" tags="$2"
	local image="${REGISTRY}:${BASE_VERSION}-${label}-${COMMIT}${DIRTY}"

	echo "=============================================================="
	echo ">>> building ${image}"
	echo ">>> platforms: ${PLATFORMS}"
	echo ">>> build tags: ${tags}"
	echo "=============================================================="

	docker buildx build \
		--platform "${PLATFORMS}" \
		--build-arg "BUILD_TAGS=${tags}" \
		-t "${image}" \
		--push \
		-f dev.Dockerfile .

	echo ">>> pushed ${image}; manifest platforms:"
	docker buildx imagetools inspect "${image}" | grep -E 'Platform:' || true
	echo
	echo "${image}" >>"${_BUILT_LIST}"
}

_BUILT_LIST="$(mktemp)"
trap 'rm -f "${_BUILT_LIST}"' EXIT

case "${VARIANTS}" in
	on)   build_variant "switchrpc"   "${TAGS_ON}" ;;
	off)  build_variant "noswitchrpc" "${TAGS_OFF}" ;;
	both)
		build_variant "switchrpc"   "${TAGS_ON}"
		build_variant "noswitchrpc" "${TAGS_OFF}"
		;;
	*) echo "VARIANTS must be on|off|both, got: ${VARIANTS}" >&2; exit 2 ;;
esac

echo "Done. Built and pushed:"
cat "${_BUILT_LIST}"
