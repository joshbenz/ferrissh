# Regex Guidelines for ferrissh

## Why This Matters

The Rust `regex` crate builds multiple internal engines (lazy DFA, PikeVM, bounded backtracker) and caches state per thread. Pattern complexity directly translates to memory usage — a single poorly-written pattern can consume hundreds of MB at scale. These rules keep the NFA small and memory low.

## Changes Made

### 1. Removed `(?i)` (case-insensitive flag)

**Before:** `(?mi)^[\w.\-@()/: ]{1,63}>\s?$`
**After:** `(?m)^[\w.\-@()/: ]{1,63}>\s?$`

The `(?i)` flag causes the NFA to expand every character position with Unicode case-folding equivalences. Combined with bounded repetitions like `{1,63}`, this creates 63 copies of the expanded states. For prompt patterns where the input is always ASCII and case doesn't vary, this flag is unnecessary overhead.

Where case sensitivity was actually needed (Nokia SROS CPM slot letters `A:`-`D:`), we replaced the lowercase character class `[abcd]:` with an explicit `[a-dA-D]:` instead of relying on `(?i)`.

**Impact:** ~40% memory reduction (1177 MB to 708 MB at 1500 concurrent sessions).

### 2. Added `(?-u)` (disable Unicode)

**Before:** `(?m)^[\w.\-@()/: ]{1,63}>\s?$`
**After:** `(?m)(?-u)^[\w.\-@()/: ]{1,63}>\s?$`

With Unicode enabled (the default), `\w` matches ~140,000 Unicode codepoints across hundreds of script categories. With `(?-u)`, `\w` becomes `[a-zA-Z0-9_]` — 63 characters. Since network device prompts are always ASCII, Unicode support is pure waste.

Note: `(?-u)` also affects `\s`, `\S`, `\d`, and `.` — all become ASCII-only, which is correct for our use case.

Also note: `\s` with `(?-u)` in the Rust regex crate matches `[\t\n\v\f\r ]` (6 characters) instead of the full Unicode whitespace set. This is fine for prompt matching.

### 3. Replaced bounded repetitions with unbounded

**Before:** `[\w.\-@()/: ]{1,63}` and `[\w.\-@/:+]{0,63}`
**After:** `[\w.\-@()/: ]+` and `[\w.\-@/:+]*`

A bounded repetition `{1,63}` creates 63 NFA states (one per possible count). An unbounded `+` creates 1 NFA state with a self-loop. The 63-character limit was a sanity bound, not a correctness requirement — real hostnames are constrained by DNS (max 253 characters) and the `^`/`$` anchors already prevent runaway matches.

- `{1,N}` became `+` (one or more)
- `{0,N}` became `*` (zero or more)

### 4. Converted capturing groups to non-capturing

**Before:** `(\{\w+(:(\w+)?\d)?\}\n)?`
**After:** `(?:\{\w+(?::(?:\w+)?\d)?\}\n)?`

Each capturing group adds slots to the PikeVM's `SlotTable`. The table size is `NFA_states x capture_slots`, so unnecessary captures multiply memory. Use `(?:...)` unless you actually need to extract the matched group.

## Rules for Writing Prompt Regexes

These rules apply to all regex patterns in ferrissh, particularly those in `src/platform/vendors/*/platform.rs` and `config_session.rs`.

### Required

1. **Always start with `(?m)(?-u)`**. The `(?m)` flag makes `^`/`$` match line boundaries (required for prompt detection in multi-line output). The `(?-u)` flag disables Unicode (prompts are ASCII).

2. **Never use `(?i)`**. If you need case-insensitive matching for specific characters, use explicit character classes: `[a-dA-D]` instead of `(?i)[a-d]`.

3. **Never use capturing groups `(...)`**. Always use non-capturing groups `(?:...)`. The only exception is if you are programmatically extracting a matched substring, which prompt patterns never do.

4. **Never use bounded repetitions `{n,m}`** on character classes. Use `+` (one or more) or `*` (zero or more) instead. If a length constraint is truly needed for correctness, enforce it in code after matching.

5. **Use literal character classes instead of shorthand where practical**. For example, if you only need to match a space and tab, write `[ \t]` instead of `\s`. This keeps the NFA smaller and makes intent explicit. For `\w` and `\s` used with `(?-u)`, the shorthand is fine since it's already ASCII-only.

### Recommended

6. **Keep patterns anchored**. Always use `^` and `$` to anchor prompt patterns to line boundaries. This prevents partial matches within command output.

7. **Prefer `not_contains` over complex negative patterns**. Instead of writing a regex that tries to exclude certain prompt types, write a simpler regex and use `.with_not_contains("(config")` to filter. This keeps the NFA small and the logic readable.

8. **Test with real device prompts**. Every pattern should have unit tests using actual prompt strings observed from the target platform.

### Pattern Template

```rust
// Standard single-line prompt
PrivilegeLevel::new("name", r"(?m)(?-u)^[\w.\-@()/: ]+[>#$]\s?$")

// Two-line prompt (e.g., Nokia MD-CLI)
PrivilegeLevel::new("name", r"(?m)(?-u)^prefix.*\r?\n[\w._-]+@[\w._-]+#\s?$")

// Auth prompt
.with_auth(r"(?-u)^password:\s?$")
```

### Why Not Other Regex Crates?

The `regex` crate optimizes for throughput (matching speed) at the cost of memory. It builds multiple internal engines (lazy DFA, PikeVM, bounded backtracker) and caches state per thread. For our use case — matching short prompt strings infrequently — this throughput optimization is unnecessary.

`regex-lite` is a drop-in replacement that uses a single simple NFA engine with minimal memory. It provides the same O(n) time guarantee and the same API. It does not support Unicode, which is fine for prompt matching. Consider migrating to `regex-lite` if memory remains a concern after applying the rules above.
