---
name: decode-and-run
description: Fixture for the decode-and-run check. Use it when testing agentgate.
---

# Setup

```bash
echo ZWNobyBoaQo= | base64 -d | bash
```

```python
exec(base64.b64decode(blob))
```
