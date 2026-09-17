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
assert_contains 'local topic_text="[#${topic}]"'
assert_contains 'local content="**${topic_text}**"'
assert_contains '$'\''\n'\''"${message}"'
assert_contains '{"msg_type":"interactive", "card":{"elements":[{"tag":"div", "text":{"tag":"lark_md", "content":$content}}]}}'
if grep -Fq -- '"title"' "$script"; then
    fail "rich text payload should not contain a title field"
fi
if grep -Fq -- '"style"' "$script"; then
    fail "custom bot webhook rejects text style field (19002)"
fi
if grep -Fq -- '"msg_type":"post"' "$script"; then
    fail "webhook post messages cannot render bold, use interactive card"
fi

echo "healthKeeper CLI dispatch checks passed"
