#!/usr/bin/env bash
# Runs every fuzz target in the module for FUZZTIME each (default 30s).
# Go runs one fuzz target per invocation, hence the loop.
set -euo pipefail
cd "$(dirname "$0")/.."
time=${FUZZTIME:-30s}
out=$(mktemp)
trap 'rm -f "$out"' EXIT
for file in $(grep -rl --include='*_test.go' '^func Fuzz' internal); do
  pkg=./$(dirname "$file")
  for fn in $(grep -ho '^func Fuzz[A-Za-z0-9_]*' "$file" | cut -d' ' -f2); do
    echo "== $pkg $fn"
    if go test -run='^$' -fuzz="^${fn}\$" -fuzztime="$time" "$pkg" 2>&1 | tee "$out"; then
      continue
    fi
    # The fuzzing engine sometimes reports "context deadline exceeded" when
    # -fuzztime ends while a worker is busy (golang/go#56238), without a
    # failing input. A real failure always names the input it saved.
    if grep -q 'context deadline exceeded' "$out" && ! grep -q 'Failing input written to' "$out"; then
      echo "(fuzz engine timed out at the deadline without a failing input; not a test failure)"
      continue
    fi
    exit 1
  done
done
