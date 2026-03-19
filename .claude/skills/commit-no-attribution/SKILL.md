---
name: commit-no-attribution
description: Override default commit behavior to never include Claude attribution lines. TRIGGER on every git commit.
---

# Commit Style: No Attribution

When creating git commits, do NOT include any of the following in commit messages:
- `Co-Authored-By:` lines
- `Generated with Claude` or similar attribution
- Any reference to AI assistance

Just write a clean commit message describing the change. Nothing else.
