#!/bin/sh
# Build the PS4 13.52 SELF decrypter payload.
#
# Requires the ps4-payload-sdk docker image, which already ships libPS4.a:
#   docker images | grep ps4-payload-sdk
# If it is missing, build it once with:
#   docker build -t ps4-payload-sdk ../build/ps4-payload-sdk   # from the repo root
#
# Usage:  ./build.sh          (from this directory)
set -e

HERE=$(cd "$(dirname "$0")" && pwd)

docker run --rm --entrypoint sh \
  -v "$HERE:/selfdec" \
  -e PS4SDK=/lib/ps4-payload-sdk \
  -w /selfdec \
  ps4-payload-sdk:latest \
  -c "make clean >/dev/null 2>&1; make"

echo
echo "built: $HERE/selfdec.bin"
ls -l "$HERE/selfdec.bin"
