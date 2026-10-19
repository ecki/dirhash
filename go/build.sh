#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
docker buildx build --target artifacts --file "$root/Dockerfile" \
    --build-context "test-vectors=$root/../tests/vectors" \
    --build-context "project-license=$root/.." \
    --output "type=local,dest=$root/../dist/go" "$root"
