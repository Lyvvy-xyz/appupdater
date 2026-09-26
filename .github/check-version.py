# Fails unless the release tag (argv[1], e.g. v52.0.0) matches $global:Version
# inside host.ps1's base64 engine - the app compares that value against the
# latest release tag to decide whether an update is available.
import base64, re, sys

src = open('host.ps1', encoding='utf-8-sig').read()
block = src.split('$__CoreB64Chunks = @(', 1)[1].split(')', 1)[0]
core = base64.b64decode(''.join(re.findall(r"'([A-Za-z0-9+/=]+)'", block))).decode('utf-8')
ver = re.search(r"\$global:Version\s*=\s*'([^']+)'", core).group(1)
tag = sys.argv[1].lstrip('vV')
print(f'engine {ver}, tag {tag}')
sys.exit(0 if ver == tag else f'::error::tag v{tag} != engine version {ver}')
