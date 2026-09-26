# Prints $global:Version from inside host.ps1's base64 engine - the app compares
# that value against the latest release tag to decide whether an update exists,
# so releases are tagged with exactly this.
import base64, re

src = open('host.ps1', encoding='utf-8-sig').read()
block = src.split('$__CoreB64Chunks = @(', 1)[1].split(')', 1)[0]
core = base64.b64decode(''.join(re.findall(r"'([A-Za-z0-9+/=]+)'", block))).decode('utf-8')
print(re.search(r"\$global:Version\s*=\s*'([^']+)'", core).group(1))
