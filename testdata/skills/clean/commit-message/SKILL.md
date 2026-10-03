---
name: commit-message
description: Write a commit message for the staged changes in Conventional Commits style. Use when the user asks for a commit message.
---

# Commit messages

Write commit messages in the Conventional Commits style used by this repository.

1. Look at what is staged:

   ```bash
   git diff --cached --stat
   git diff --cached
   ```

2. Pick a type: `feat`, `fix`, `docs`, `test`, `chore` or `refactor`.
3. Write a subject of at most 72 characters, in the imperative, without a full stop.
4. Explain in the body why the change was made, not what the diff already shows.

Never commit for the user; show the message and let them run `git commit`.
