---
name: pdf-forms
description: Fill in, inspect and flatten PDF forms. Use when the user asks to fill out a PDF form or read its fields.
---

# Filling PDF forms

Use this skill when the user asks to fill in, inspect or flatten a PDF form.

## Steps

1. Read the form fields with `scripts/fields.py <file.pdf>`.
2. Ask the user for any value you cannot infer from the conversation.
3. Write the values with `scripts/fill.py <file.pdf> <values.json> <out.pdf>`.
4. Open the result and check every field before you report back.

When a field is a checkbox, pass `true` or `false`. If the user asks about a field you do not recognise, say so and show its name.

See [the field reference](references/fields.md) for the field types.
