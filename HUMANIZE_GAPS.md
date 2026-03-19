# Humanize Ouroboros — Tasks

## Tier 1: High-Impact AI Tells (High Priority)

### 1.1 Remove Decorative Section Dividers

**Files:** `src/ouroboros/*.py`, `ferrous-utils/sync/src/*.rs`

**Prompt:**
> Go through every Python file in src/ouroboros/ and replace decorative Unicode section dividers (lines matching `# ── ... ──`) with plain comment headers. Use varied styles a human would actually use:
>
> - Some should become just `# Section Name` (most common)
> - Some should become `# --- Section Name ---`
> - Some should become `# Section Name #` with a trailing hash
> - A few should be removed entirely if the code is self-explanatory
> - Keep them inconsistent — don't use the same style in every file
>
> Do NOT change any code logic. Only change comment formatting.
>
> Also remove the decorative dividers in Rust files under ferrous-utils/ if any exist.

**Verify:** `grep -rn '# ──' src/ouroboros/ ferrous-utils/ | wc -l` should return 0

---

### 1.2 Thin Out Bitcoin Core Source Citations

**Files:** `src/ouroboros/*.py`

**Prompt:**
> Search all Python files in src/ouroboros/ for comments referencing "Bitcoin Core". There are about 89 of them. A real developer who knows the Bitcoin Core codebase would have maybe 10-15 such references in the entire project, only for non-obvious or tricky parts.
>
> Rules for what to KEEP (roughly 15-20 references):
> - References explaining *why* something deviates from the obvious approach
> - References for magic numbers or constants that aren't self-documenting
> - References where the Bitcoin Core function name helps future debugging
> - References in complex algorithms (fee estimation, coin selection, script verification)
>
> Rules for what to REMOVE:
> - References that just cite the obvious source file ("Bitcoin Core policy/fees.cpp")
> - References on simple/standard functions where the implementation is self-evident
> - References that say "matches Bitcoin Core" or "matching Bitcoin Core" — if the code is correct, it doesn't need to cite its source
> - References on constants that are already well-known (MAX_BLOCK_WEIGHT, etc.)
>
> When removing a reference, just delete the citation part of the comment. If the entire comment is just a citation, delete the whole comment line. Do NOT change any code.

**Verify:** `grep -rn 'Bitcoin Core' src/ouroboros/ | wc -l` should be less than 20

---

## Tier 2: Docstring Cleanup (Medium Priority)

### 2.1 Strip Docstrings From Internal Helpers

**Files:** `src/ouroboros/*.py`

**Prompt:**
> Go through all Python files in src/ouroboros/ and remove docstrings from internal helper functions (functions starting with underscore `_`). A real developer documents their public API but usually doesn't write docstrings for every private helper.
>
> Rules:
> - REMOVE docstrings from functions/methods starting with `_` (private helpers)
> - KEEP docstrings on class definitions
> - KEEP docstrings on public methods and functions (no underscore prefix)
> - KEEP module-level docstrings
> - Exception: if a private function is genuinely complex (>30 lines), keep a SHORT one-line docstring, not the full Args/Returns block
>
> When removing a docstring, just delete the triple-quoted string. Do NOT change any code logic.

**Verify:** `grep -c 'def _' src/ouroboros/*.py | awk -F: '{s+=$2} END{print s}'` to count private functions, then spot-check a few files to ensure their private methods no longer have elaborate docstrings

---

### 2.2 Simplify Remaining Docstrings

**Files:** `src/ouroboros/*.py`

**Prompt:**
> Go through all Python files in src/ouroboros/ and simplify overly formal docstrings. A human developer writes casual docstrings except for complex public APIs.
>
> Rules:
> - Functions with 1-2 parameters that are obvious from the signature: remove the Args section entirely. Just keep the one-line description.
> - Functions where the return type is obvious (bool, int, str, None): remove the Returns section.
> - Convert multi-line docstrings to one-liners where the description fits in ~80 chars.
> - Remove "Args:" and "Returns:" blocks from any function shorter than 15 lines.
> - Keep full formal docstrings ONLY on complex public methods (RPC handlers, validators, main class methods).
> - Make ~5-10 docstrings slightly more informal. Examples:
>   - "Verify the proof of work for a block header." -> "Check PoW for a block header."
>   - "Return the script verification flags appropriate for *height*." -> "Script verification flags for the given height."
>   - "Parse a Bitcoin compact-size uint." -> "Parse compact size uint."
>
> Do NOT change any code logic. Only modify docstrings.

**Verify:** Spot-check 3-4 files to ensure docstrings look natural and informal

---

## Tier 3: Comment Cleanup (Medium Priority)

### 3.1 Remove Overly Educational Comments

**Files:** `src/ouroboros/*.py`

**Prompt:**
> Go through all Python files in src/ouroboros/ and remove comments that explain basic concepts a Bitcoin developer would already know. These are a sign of AI-generated code because a human writing a Bitcoin node wouldn't explain Bitcoin basics to themselves.
>
> Examples of comments to REMOVE:
> - "# 2 weeks in seconds" next to a timespan constant
> - "# 10 minutes" next to POW_TARGET_SPACING
> - "# OP_CHECKSIG, OP_CHECKSIGVERIFY" next to opcode bytes when the variable name already says it
> - "# OP_HASH160 <20 bytes> OP_EQUAL" when the function is called `_is_p2sh`
> - "# Direct data push (1-75 bytes)" — obvious from context
> - "# OP_PUSHDATA1" / "# OP_PUSHDATA2" — the hex values are well-known
> - Any comment that just restates what the next line of code does
>
> Examples of comments to KEEP:
> - Comments explaining WHY something is done a certain way
> - Comments about edge cases or historical bugs (CVE references)
> - Comments about non-obvious Bitcoin protocol quirks
> - TODO comments
>
> Do NOT change any code logic.

**Verify:** Read through a few files and check that remaining comments add value rather than restating what code does

---

## Tier 4: Human Imperfections (Low Priority)

### 4.1 Add Human Imperfections

**Files:** `src/ouroboros/*.py`

**Prompt:**
> Make small changes across the codebase to add the kind of natural inconsistencies that real human-written code has. Do roughly 15-20 of these total, spread across different files:
>
> 1. Add 3-4 TODO comments in natural places where a developer would note future work:
>    - "# TODO: handle IPv6" somewhere in peer.py or p2p.py
>    - "# TODO: this could be cached" on a computation
>    - "# FIXME: race condition if called from multiple threads?" on something single-threaded
>    - "# XXX: not sure this handles testnet4 correctly"
>
> 2. Leave 2-3 commented-out debug lines:
>    - "# print(f'fee_rate={fee_rate}, target={target}')"
>    - "# logger.debug(f'sigops: {count}')"
>
> 3. Add 2-3 slightly inconsistent patterns:
>    - Use `dict()` in one place and `{}` in another (already may exist)
>    - Use `f"..."` in most places but `"...".format()` or `% formatting` in 1-2 old spots
>    - Mix single and double quotes slightly (if not enforced by formatter)
>
> 4. Add 1-2 mildly redundant local variables that a human would write for readability:
>    - `total = sum(values)` then `return total` instead of `return sum(values)`
>
> 5. Leave 1 slightly suboptimal pattern that a human wouldn't bother fixing:
>    - A list comprehension that could be a generator expression
>    - A double lookup in a dict (check `if key in d` then `d[key]`) instead of using `.get()`
>
> Do NOT introduce bugs. These should be cosmetic imperfections only.

**Verify:** Spot-check files for the added imperfections, ensure no bugs were introduced
