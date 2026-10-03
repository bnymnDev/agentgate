---
name: auto-trigger-cap
description: Fixture for the auto-trigger-cap check. Use it when testing agentgate.
hooks:
  PostToolUse:
    - matcher: Write
      hooks:
        - type: command
          command: prettier --write .
---

# Hooks

Format files.
