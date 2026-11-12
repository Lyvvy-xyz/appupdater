# Prints the embedded engine's $global:Version; release tags must match it.
import base64, re

src = open('host.ps1', encoding='utf-8-sig').read()
block = src.split('$__CoreB64Chunks = @(', 1)[1].split(')', 1)[0]
core = base64.b64decode(''.join(re.findall(r"'([A-Za-z0-9+/=]+)'", block))).decode('utf-8')
print(re.search(r"\$global:Version\s*=\s*'([^']+)'", core).group(1))
