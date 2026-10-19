#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -gt 1 ]; then
    printf '%s\n' 'Usage: sh build.sh [all|java|go]' >&2
    exit 2
fi
case "${1:-all}" in
    all)
        sh "$root/java/build.sh"
        sh "$root/go/build.sh"
        ;;
    java|go)
        sh "$root/$1/build.sh"
        ;;
    *)
        printf '%s\n' 'Usage: sh build.sh [all|java|go]' >&2
        exit 2
        ;;
esac
