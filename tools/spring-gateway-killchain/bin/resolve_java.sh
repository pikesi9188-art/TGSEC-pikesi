#!/usr/bin/env bash
# Resolve vendor java (mac Contents/Home or flat layout)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for c in \
  "$ROOT/vendor/jdk-17/bin/java" \
  "$ROOT/vendor/jdk-17/Contents/Home/bin/java"
do
  if [[ -x "$c" ]]; then
    echo "$c"
    exit 0
  fi
done
exit 1
