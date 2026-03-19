---
name: human-commits
description: Commit code changes incrementally during development, the way a human developer would. TRIGGER whenever you are making code changes — do not wait until the end to commit everything at once.
---

# Human-Like Commit Workflow

When making code changes, commit incrementally as you go — like a real developer working through a problem. Do NOT batch all changes into one giant commit at the end.

## When to Commit

Commit after each logical unit of work:
- After implementing a single function or feature
- After fixing a bug (the fix itself, not the debugging)
- After refactoring a specific piece of code
- After adding tests for something
- After cleaning up or removing dead code
- Before switching to a different concern (e.g., done with the parser, moving to the serializer)

A good rule: if you could describe the change in one short sentence, it's a commit.

## Commit Message Style

Match the existing project style:
- Lowercase, no period at the end
- Short (under 72 chars), imperative mood
- Focus on what changed, not why (save that for PR descriptions)
- No prefixes like `feat:`, `fix:`, `chore:` — just describe the change
- No attribution lines, no `Co-Authored-By`, no AI references

Good examples (from this project's history):
- `add signature verification cache`
- `fix format string escape in cli help text`
- `parallel script verification during block validation`
- `expand validation tests with subsidy halvings and genesis hashes`
- `wire rpc into supervisor and app config`

Bad examples:
- `Update multiple files with various improvements` (too vague)
- `fix: resolve issue with block validation` (wrong style, has prefix)
- `Implement FindAndDelete and fix CHECKMULTISIG and update flags and clean up logging` (too many things — split into separate commits)

## How to Split Work

If a task involves multiple logical changes, commit them separately:

Example task: "fix the script interpreter crash and add tests"
1. Commit: `fix checkmultisig return type mismatch`
2. Commit: `add multisig script verification tests`

Example task: "add wallet support"
1. Commit: `add hd key derivation`
2. Commit: `wallet gen_server with address generation`
3. Commit: `transaction signing for p2wpkh and p2pkh`
4. Commit: `wire wallet into supervisor`

## Staging

- Stage specific files, not `git add -A`
- Don't commit unrelated changes together
- Don't commit debug logging, temporary files, or `.env` files
