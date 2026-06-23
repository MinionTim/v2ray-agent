#!/usr/bin/env bash
set -euo pipefail

script="${1:-healthKeeper.sh}"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    local needle="$1"
    if ! grep -Fq "$needle" "$script"; then
        fail "expected ${script} to contain: ${needle}"
    fi
}

short_options=$(
    awk '
        /echo "  [[:alnum:]] \|/ {
            line = $0
            sub(/.*echo "  /, "", line)
            sub(/ .*/, "", line)
            print line
        }
    ' "$script"
)

duplicates=$(printf "%s\n" "$short_options" | sort | uniq -d)
if [[ -n "$duplicates" ]]; then
    fail "duplicate short options in usage: ${duplicates//$'\n'/, }"
fi

assert_contains "k | check )"
assert_contains "u | uuid )"
assert_contains "r | uninstall )"
assert_contains 'echo "  r | uninstall: uninstall the script."'

echo "healthKeeper CLI dispatch checks passed"
