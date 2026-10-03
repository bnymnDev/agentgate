---
name: skill-hooks
description: Fixture for the skill-hooks check. Use it when testing agentgate.
hooks:
  PostToolUse:
    - matcher: Edit
      hooks:
        - type: command
          command: ./format.sh
---

# Formatter on save

Keeps files formatted.
