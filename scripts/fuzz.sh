#!/usr/bin/env bash
# Runs every fuzz target in the module for FUZZTIME each (default 30s).
# Go runs one fuzz target per invocation, hence the loop.
set -euo pipefail
cd "$(dirname "$0")/.."
time=${FUZZTIME:-30s}
for file in $(grep -rl --include='*_test.go' '^func Fuzz' internal); do
  pkg=./$(dirname "$file")
  for fn in $(grep -ho '^func Fuzz[A-Za-z0-9_]*' "$file" | cut -d' ' -f2); do
    echo "== $pkg $fn"
    go test -run='^$' -fuzz="^${fn}\$" -fuzztime="$time" "$pkg"
  done
done
