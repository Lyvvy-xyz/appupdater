#!/usr/bin/env bash
# Static self-check for host.ps1's embedded UI <-> PowerShell bridge.
# Can't run the WebView2 GUI on Linux, but this catches the exact bug class
# that has broken the app before: a JS syntax error silently killing the
# whole script, or a JS action / PS Send-ToPage event with no matching
# handler on the other side (see SESSION_STATUS.txt Phase 1 and Phase 7).
set -euo pipefail
cd "$(dirname "$0")"

fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

ui_start=$(grep -n '^\$__UiHtml = @' host.ps1 | head -1 | cut -d: -f1)
ui_end=$(grep -n "^'@" host.ps1 | head -1 | cut -d: -f1)
sed -n "$((ui_start+1)),$((ui_end-1))p" host.ps1 > "$tmp/ui.html"

echo "== JS syntax check =="
awk '/<script>/{f=1;next}/<\/script>/{f=0}f' "$tmp/ui.html" > "$tmp/ui.js"
if node --check "$tmp/ui.js"; then
  echo "OK"
else
  echo "FAIL: JS syntax error would silently break the whole bridge (see Phase 1 in SESSION_STATUS.txt)"
  fail=1
fi

echo
echo "== JS send() actions vs PS switch (\$msg.action) cases =="
grep -oP "send\('[a-z0-9-]+'" "$tmp/ui.js" | sed -E "s/send\('//;s/'$//" | sort -u > "$tmp/js_sends.txt" || true
awk '/switch \(\$msg\.action\)/,/^  \}\)$/' host.ps1 | grep -oP "^\s*'[a-z0-9-]+'\s*\{" | sed "s/[' {]//g" | sort > "$tmp/ps_cases.txt" || true
dead_sends=$(comm -23 "$tmp/js_sends.txt" "$tmp/ps_cases.txt")
if [ -n "$dead_sends" ]; then
  echo "FAIL: JS sends these actions but PS has no matching case (button/action does nothing):"
  echo "$dead_sends" | sed 's/^/  - /'
  fail=1
else
  echo "OK (every JS send() has a PS case)"
fi
unused_cases=$(comm -13 "$tmp/js_sends.txt" "$tmp/ps_cases.txt")
if [ -n "$unused_cases" ]; then
  echo "INFO: PS cases never sent by JS (dead code, or a feature not wired up yet):"
  echo "$unused_cases" | sed 's/^/  - /'
fi

echo
echo "== PS Send-ToPage events vs JS 'case' handlers =="
grep -oP "Send-ToPage\s+\\\$\w+\s+'[a-z0-9-]+'" host.ps1 | grep -oP "'[a-z0-9-]+'" | tr -d "'" | sort -u > "$tmp/ps_sends.txt" || true
grep -oP "case '[a-z0-9-]+':" "$tmp/ui.js" | sed -E "s/case '//;s/'://" | sort -u > "$tmp/js_handles.txt" || true
dead_events=$(comm -23 "$tmp/ps_sends.txt" "$tmp/js_handles.txt")
if [ -n "$dead_events" ]; then
  echo "INFO: PS sends these events but JS has no handler (UI never updates for them):"
  echo "$dead_events" | sed 's/^/  - /'
fi

echo
echo "== \$('#id') / getElementById() references vs actual element ids =="
grep -oP "getElementById\('[\w-]+'\)|\\\$\('#[\w-]+'\)" "$tmp/ui.js" | grep -oP "[\w-]+(?='\))" | sort -u > "$tmp/js_ids.txt" || true
grep -oP 'id="[\w-]+"' "$tmp/ui.html" | sed -E 's/id="//;s/"//' | sort -u > "$tmp/html_ids.txt" || true
missing_ids=$(comm -23 "$tmp/js_ids.txt" "$tmp/html_ids.txt")
if [ -n "$missing_ids" ]; then
  echo "FAIL: JS references an element id that doesn't exist in the HTML:"
  echo "$missing_ids" | sed 's/^/  - /'
  fail=1
else
  echo "OK (every referenced id exists)"
fi

echo
echo "== host.ps1 brace/paren balance (crude corruption check) =="
if ! python3 - "host.ps1" <<'EOF'
import sys
s = open(sys.argv[1], encoding='utf-8', errors='replace').read()
pairs = {'{': '}', '(': ')', '[': ']'}
ok = True
for o, c in pairs.items():
    diff = s.count(o) - s.count(c)
    print(f"  {o}{c}: {'OK' if diff == 0 else 'MISMATCH diff=' + str(diff)}")
    if diff != 0:
        ok = False
sys.exit(0 if ok else 1)
EOF
then fail=1; fi

echo
if [ $fail -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "CHECKS FAILED - see FAIL lines above"
fi
exit $fail
