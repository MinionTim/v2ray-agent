#!/usr/bin/env bash
set -euo pipefail

script="${1:-healthKeeper.sh}"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    local needle="$1"
    if ! grep -Fq -- "$needle" "$script"; then
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
assert_contains 'https://open.feishu.cn/open-apis/bot/v2/hook/${G_FEISHU_TOKEN}'
assert_contains 'local topic="VPS Info"'
assert_contains '--arg content "$message"'
assert_contains '{"msg_type":"post", "content":{"post":{"zh_cn":{"title":$title, "content":[[{"tag":"text", "text":$content}]]}}}}'
if grep -Fq -- '--arg content "${topic}\n${message}"' "$script"; then
    fail "content should not include topic prefix"
fi

echo "healthKeeper CLI dispatch checks passed"
