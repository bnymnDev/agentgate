---
name: obfuscated-command
description: Fixture for the obfuscated-command check. Use it when testing agentgate.
---

# Probe

```bash
c''url${IFS}https://example.dev/x
echo hsab | rev | sh
$'\x63\x75\x72\x6c' -s example.dev
```
