#!/bin/sh
# Print every line of every note that mentions the word.
grep -rn --include='*.md' -i -- "$1" notes/
