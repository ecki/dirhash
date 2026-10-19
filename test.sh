#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
sh "$root/build.sh"
docker build --file "$root/tests/Dockerfile" --tag dirhash-conformance "$root"
docker run --rm dirhash-conformance
