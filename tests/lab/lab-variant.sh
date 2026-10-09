#!/bin/sh
# Lab target only. Selects which response headers the static lab site sends,
# so a retest has something to compare (see tests/lab/README.md).
#
#   lab-variant.sh start      container entrypoint: variant A, then run nginx
#   lab-variant.sh a|b|c      switch the running lab to that variant
#   lab-variant.sh            print the active variant
#
# The variants are read-only files from the repository; the active copy is in
# a tmpfs inside the container, so nothing on the host changes and recreating
# the container always starts again from variant A.
set -eu

VARIANTS=/etc/nginx/lab-variants
ACTIVE=/etc/nginx/lab-active

use() {
    cp "$VARIANTS/$1.inc" "$ACTIVE/headers.inc"
    echo "$1" > "$ACTIVE/variant"
}

case "${1:-}" in
    start)
        use a
        exec nginx -g "daemon off;"
        ;;
    a | b | c)
        use "$1"
        nginx -t -q
        nginx -s reload
        # A reload finishes asynchronously: wait until nginx really serves the
        # new variant, so a scan started right after sees its headers.
        tries=0
        until wget -q -S -O /dev/null http://127.0.0.1/ 2>&1 | grep -qi "X-Lab-Variant: $1"; do
            tries=$((tries + 1))
            if [ "$tries" -ge 50 ]; then
                echo "lab-target did not switch to variant $1" >&2
                exit 1
            fi
            sleep 0.2
        done
        echo "lab-target now serves variant $1"
        ;;
    "")
        cat "$ACTIVE/variant"
        ;;
    *)
        echo "usage: lab-variant.sh [a|b|c]" >&2
        exit 2
        ;;
esac
