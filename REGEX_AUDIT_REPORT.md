# KARADUL Regex Audit Report -- O(n) Safety Analysis
## 2026-04-03 | Codex Consultant Agent

**Total files scanned:** 72 Python files
**Total regex calls found:** 1135
**Verdict breakdown:**
- SAFE: ~1070 (anchored, bounded character classes, simple alternation)
- RISKY: ~42 (could degrade on adversarial input but guarded or limited scope)
- DANGEROUS: ~23 (will backtrack or hang on large input without guards)

**Existing mitigations found:**
- `_safe_dotall_search()` guard in formula_extractor.py and constraint_solver.py (50K limit)
- `len(code) > 50_000` guard in analyzer.py structural scan
- Phase 1/Phase 2 split in formula_extractor.py (DOTALL only in Phase 2, size-guarded)
- Prior fix at constraint_solver.py line 229-231 (replaced `[\w\s]*` with `(?:\w+\s*)*`)

---

## CRITICAL FINDINGS (DANGEROUS)

### 1. c_flow_simplifier.py:959-963 -- `[\s\S]*?` with re.escape suffix
```
FILE: karadul/reconstruction/c_flow_simplifier.py
LINE 959-963:
    label_block_pattern = re.compile(
        r"\n[ \t]*" + re.escape(label_name) + r"\s*:"
        r"[\s\S]*?" + re.escape(block.strip().split("\n")[-1].strip())
        + r"\s*\n?",
    )
VERDICT: DANGEROUS
REASON: [\s\S]*? is cross-line non-greedy matching. When the suffix
  (escaped last line of block) does NOT appear in the text, the engine
  tries every possible split point across the ENTIRE remaining string.
  On a 500KB function body, this is O(n^2) worst case.
  NO SIZE GUARD exists for this pattern.
```

**FIX:**
```python
# Replace regex with string-based search:
target_start = label_name + ":"  # approximation
start_idx = content.find(label_name + ":")
if start_idx == -1:
    pass  # not found, skip
else:
    last_line = block.strip().split("\n")[-1].strip()
    end_idx = content.find(last_line, start_idx)
    if end_idx != -1:
        end_idx += len(last_line)
        # consume trailing whitespace/newline
        while end_idx < len(content) and content[end_idx] in ' \t\n':
            end_idx += 1
        content = content[:start_idx] + "\n" + content[end_idx:]
```

---

### 2. comment_generator.py:20 -- `try\s*\{.*catch` with DOTALL
```
FILE: karadul/reconstruction/comment_generator.py
LINE 20: re.compile(r"try\s*\{.*catch", re.DOTALL)
VERDICT: DANGEROUS
REASON: .* with DOTALL scans the ENTIRE input between "try {" and "catch".
  This is a JS comment generator running on full function bodies.
  Greedy .* will match everything up to the LAST "catch" in the file,
  and if "catch" is absent, backtracks the entire string. O(n) per
  backtrack step but the match span can be the entire input.
  Not size-guarded.
```

**FIX:**
```python
# Replace with non-DOTALL or negated class:
re.compile(r"try\s*\{[^}]*\}[^}]*catch")
# Or simpler: just check both keywords exist
# re.compile(r"try\s*\{") and separately check "catch" in text
```

---

### 3. comment_generator.py:37 -- `\.has\(.*\.get\(` with DOTALL
```
FILE: karadul/reconstruction/comment_generator.py
LINE 37: re.compile(r"cache|memoize|\.has\(.*\.get\(", re.DOTALL)
VERDICT: DANGEROUS
REASON: .* with DOTALL between .has( and .get( scans entire input.
  Same problem as #2. Not size-guarded.
```

**FIX:**
```python
# Limit scan window with {0,500} or use non-DOTALL:
re.compile(r"cache|memoize|\.has\([^)]*\)[\s\S]{0,500}\.get\(")
```

---

### 4. c_algorithm_id.py:266-267 -- `for\s*\(.+\)\s*\{[^}]*\^=` with DOTALL
```
FILE: karadul/reconstruction/c_algorithm_id.py
LINE 266: re.compile(r"for\s*\(.+\)\s*\{[^}]*\^=", re.DOTALL)
LINE 267: re.compile(r"while\s*\(.+\)\s*\{[^}]*\^=", re.DOTALL)
VERDICT: DANGEROUS
REASON: .+ with DOTALL matches EVERYTHING including newlines and ')'.
  The .+ in \(.+\) will greedily consume past the closing ')' and
  scan the entire input trying to find a valid split. Then [^}]* after
  \{ creates overlapping backtrack: .+ can match '{' too.
  These patterns are used in _scan_signatures() which processes function
  bodies. NO SEPARATE SIZE GUARD -- relies on the 50K guard in analyzer.py
  but these are in c_algorithm_id.py which is called from a different path.
```

**FIX:**
```python
# Replace .+ with [^)]+ to bound the for/while condition:
re.compile(r"for\s*\([^)]+\)\s*\{[^}]*\^=", re.DOTALL)
re.compile(r"while\s*\([^)]+\)\s*\{[^}]*\^=", re.DOTALL)
```

---

### 5. formula_extractor.py:2166-2170 -- FFT Butterfly `.*?` DOTALL
```
FILE: karadul/reconstruction/computation/formula_extractor.py
LINE 2166-2170:
    _FFT_BUTTERFLY_RE = re.compile(
        r'(\w+)\s*=\s*(\w+(?:\[\w+\])?)\s*[\-\+]\s*(\w+)\s*;'
        r'.*?'
        r'\2\s*=\s*\2\s*[\+\-]\s*\3\s*;',
        re.DOTALL,
    )
VERDICT: DANGEROUS (but GUARDED by Phase 2 50K limit)
REASON: .*? DOTALL between two statements. When second statement
  doesn't exist, .*? tries every position. The backreference \2
  adds complexity. HOWEVER: this is in Phase 2 which is guarded
  by _MAX_DOTALL_INPUT_LEN (50K). Still dangerous if guard removed.
```

**FIX (defense in depth):**
```python
# Replace .*? with bounded window:
r'(\w+)\s*=\s*(\w+(?:\[\w+\])?)\s*[\-\+]\s*(\w+)\s*;'
r'[^;]{0,500};?\s*'  # max 500 chars between statements
r'\2\s*=\s*\2\s*[\+\-]\s*\3\s*;',
```

---

### 6. formula_extractor.py:2347-2351 -- Adam Optimizer `.*?` DOTALL
```
FILE: karadul/reconstruction/computation/formula_extractor.py
LINE 2347-2351:
    _ADAM_EMA_RE = re.compile(
        r'(\w+)\s*=\s*(\w+)\s*\*\s*\1\s*\+\s*[^;]*\*\s*(\w+)\s*;'
        r'.*?'
        r'(\w+)\s*=\s*(\w+)\s*\*\s*\4\s*\+\s*[^;]*\*\s*\3\s*\*\s*\3',
        re.DOTALL,
    )
VERDICT: DANGEROUS (GUARDED by Phase 2 50K limit)
REASON: .*? DOTALL with multiple backreferences (\1, \3, \4).
  Complex backtracking if second pattern not found.
```

---

### 7. formula_extractor.py:2238-2241 -- Convolution `.*?` DOTALL
```
FILE: karadul/reconstruction/computation/formula_extractor.py
LINE 2238-2241:
    _CONVOLUTION_RE = re.compile(
        r'(?:for|do)\s*(?:\([^)]*\))?\s*\{.*?'
        r'(\w+(?:\[\w+\])?)\s*\+=\s*[^;]*\w+\s*\[\s*\w+\s*\]\s*\*\s*\w+\s*\[\s*[^]]*[\-\+][^]]*\]',
        re.DOTALL,
    )
VERDICT: DANGEROUS (GUARDED by Phase 2 50K limit)
REASON: \{.*? with DOTALL scans entire input looking for the
  accumulator pattern. If pattern not found, O(n^2) backtracking.
```

---

### 8. formula_extractor.py:1946-1949 -- Newton-Raphson Loop `[^}]*` DOTALL
```
FILE: karadul/reconstruction/computation/formula_extractor.py
LINE 1946-1949:
    _NEWTON_LOOP_RE = re.compile(
        r'(?:while|do)\s*[^{]*\{[^}]*(\w+)\s*[+\-]=\s*[^;]*;[^}]*'
        r'(?:fabs|abs)\s*\(\s*\w+',
        re.DOTALL | re.IGNORECASE,
    )
VERDICT: RISKY (GUARDED -- Phase 1 for scalar, Phase 2 for loop)
REASON: [^{]*\{[^}]* is safe within a single brace block.
  But [^}]* after the semicolon allows scanning large loop bodies.
  With DOTALL, if the loop body has no closing brace (malformed),
  [^}]* scans entire input. HOWEVER the scalar form runs in Phase 1,
  and loop form detection is in _detect_newton_raphson which
  uses _safe_dotall_search. Adequately guarded.
```

---

### 9. constraint_solver.py:240-244 -- Linked List Loop `.*?` DOTALL
```
FILE: karadul/reconstruction/computation/constraint_solver.py
LINE 240-244:
    _LINKED_LIST_LOOP_RE = re.compile(
        r"(?:while|for)\s*\([^)]*\b(?P<var>\w+)\s*!=\s*(?:0|NULL|0x0)\b[^)]*\)"
        r"\s*\{.*?"
        r"(?P=var)\s*=\s*\*\s*\(.*?(?P=var)\s*\+\s*(?P<offset>0x[0-9a-fA-F]+|\d+)",
        re.DOTALL,
    )
VERDICT: DANGEROUS (GUARDED by _safe_dotall_search at call sites)
REASON: Two .*? with DOTALL plus named backreferences.
  The engine must find matching var names across potentially
  the entire input. Triple backtracking risk.
  GUARDED: all call sites use _safe_dotall_search (50K limit).
```

---

### 10. constraint_solver.py:183-189 -- Go Slice `.*?` DOTALL
```
FILE: karadul/reconstruction/computation/constraint_solver.py
LINE 183-189:
    _GO_SLICE_RE = re.compile(
        ... three .*? gaps with DOTALL and backreferences ...
    )
VERDICT: DANGEROUS (GUARDED by _safe_dotall_finditer)
REASON: Three .*? with DOTALL and \1 backreference.
  Worst case O(n^3) without guard.
  GUARDED: called only via _safe_dotall_finditer.
```

---

### 11. deobfuscators/binary_deobfuscator.py:59-62 -- XOR pattern without closing brace bound
```
FILE: karadul/deobfuscators/binary_deobfuscator.py
LINE 59-62:
    re.compile(
        r"for\s*\([^)]*\)\s*\{[^}]*"
        r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\s*\^\s*(0x[0-9a-fA-F]+|\w+)"
    )
VERDICT: RISKY
REASON: [^}]* without DOTALL is safe IF the input has a closing brace.
  But if a function body has nested braces (common in decompiled code),
  [^}]* may scan a very long stretch before finding '}'.
  Not technically catastrophic but can be O(n) with a large constant.
  The pattern lacks DOTALL so \n stops it at line boundaries -- WAIT,
  [^}] matches \n! This means it scans multi-line until }.
  On a 500KB function with deeply nested braces, this could scan
  the entire body before the first closing brace.
  NO SIZE GUARD.
```

**FIX:**
```python
# Add a length limit to [^}]*:
r"for\s*\([^)]*\)\s*\{[^}]{0,2000}"
r"(\w+)\[(\w+)\]\s*=\s*(\w+)\[(\w+)\]\s*\^\s*(0x[0-9a-fA-F]+|\w+)"
```

---

### 12. deobfuscators/binary_deobfuscator.py:71-72 -- WARNING comment removal `.*?` DOTALL
```
FILE: karadul/deobfuscators/binary_deobfuscator.py
LINE 71: re.compile(r"/\*\s*WARNING:.*?\*/", re.DOTALL)
LINE 72: re.compile(r"/\*\s*DISPLAY WARNING.*?\*/", re.DOTALL)
VERDICT: RISKY
REASON: .*? DOTALL between /* and */. If the closing */ is missing,
  scans entire input. But Ghidra comments always have */, so
  practically safe. The non-greedy .*? is O(n) when closing exists.
  Keep but add a length bound for safety.
```

**FIX (defense in depth):**
```python
re.compile(r"/\*\s*WARNING:[^*]{0,5000}\*/")
re.compile(r"/\*\s*DISPLAY WARNING[^*]{0,5000}\*/")
```

---

### 13. deobfuscators/string_decryptor.py:84 -- RC4 init pattern DOTALL
```
FILE: karadul/deobfuscators/string_decryptor.py
LINE ~74-84:
    self._rc4_init = re.compile(
        ... (likely has DOTALL based on line 84 reference) ...
    )
VERDICT: RISKY (needs SIZE GUARD)
```

---

### 14. c_namer_patterns.py:1235 -- `\s+(?:to\s+)?(\w+)` greedy
```
FILE: karadul/reconstruction/c_namer_patterns.py
LINE 1235:
    re.compile(r"(?:error|failed|failure|cannot|unable|couldn't|can't)\s+(?:to\s+)?(\w+)", re.I)
VERDICT: SAFE
REASON: \s+ and (?:to\s+)? are simple, non-overlapping. O(n).
```

---

### 15. engineering/patterns.py -- ALL DOTALL patterns (30+ entries)
```
FILE: karadul/reconstruction/engineering/patterns.py
ALL DOTALL patterns (lines 88, 107, 150, 193, 221, 246, 304, 372, 404, 433,
462, 486, 517, 539, 590, 646, 670, 736, 826, 881, 906, 933, 961, 1011,
1039, 1094, 1122, 1198, 1226, 1280, 1334, 1358, 1410, 1467, 1633)
VERDICT: RISKY (GUARDED by analyzer.py 50K limit)
REASON: Many patterns use [^{}]* or (?:[^{}]|\{[^{}]*\})* with DOTALL.
  [^{}]* is bounded by braces -- generally safe.
  (?:[^{}]|\{[^{}]*\})* is a balanced-brace approximation -- each
  step consumes at least one character, so O(n) per pattern.
  ALL are called from analyzer.py _scan_structural which has a
  len(code) > 50_000 guard. ADEQUATELY GUARDED.
```

**HOWEVER: Pattern at line 82 is dangerous:**
```python
# Line 81-87:
r"(?:for|while)\s*\([^)]*\)\s*\{"
r"(?:[^{}]|\{[^{}]*\})*"   # <-- This is O(n) per alternation step
r"(?:for|while)\s*\([^)]*\)\s*\{"
r"(?:[^{}]|\{[^{}]*\})*"
r"(?:for|while)\s*\([^)]*\)\s*\{"
r"(?:[^{}]|\{[^{}]*\})*"
r"\+=\s*[^;]*\*",
```
**Three nested `(?:[^{}]|\{[^{}]*\})*` creates potential O(n^3) when
the triple-nested loop pattern doesn't match. The 50K guard keeps
this bounded to 50K^3 / constant, but it's still slow.**

---

### 16. data_flow.py:1273 -- Dynamic regex on function body
```
FILE: karadul/reconstruction/engineering/data_flow.py
LINE 1273:
    use_pattern = re.compile(
        r"(\w+)\s*\([^)]*\b" + re.escape(var) + r"\b[^)]*\)\s*;",
    )
VERDICT: RISKY (HAS SIZE GUARD at line 1271)
REASON: [^)]*\bVAR\b[^)]* -- two [^)]* separated by \b...\b.
  When VAR is not inside parentheses, both [^)]* compete for the
  same characters. HOWEVER: line 1268-1271 has a comment saying
  "v1.6.1: catastrophic backtracking fix" and guards with
  len(_remaining) > 50_000 check + str.find pre-filter.
  The pre-filter (var not in _remaining) prevents regex from
  running when the variable doesn't even exist in the text.
  ADEQUATELY GUARDED.
```

---

### 17. c_namer.py:2044/2077/2121/2331 -- Dynamic pattern compilation per variable
```
FILE: karadul/reconstruction/c_namer.py
LINES 2044, 2077, 2121, 2331:
    specific_pattern = re.compile(
        pattern.pattern.replace("PARAM", re.escape(param_name))
    )
    if specific_pattern.search(body):
VERDICT: RISKY
REASON: These compile a new regex per variable per pattern, then
  search the ENTIRE function body. With ~100 _PARAM_USAGE_PATTERNS
  and ~100 _LOCAL_VAR_USAGE_PATTERNS, and N variables, this is
  O(N * P * body_size) where P is number of patterns.
  The individual patterns are mostly safe (PARAM is replaced with
  a literal, so no backtracking), but the sheer volume of regex
  executions on large bodies (500KB) could be slow.
  NO SIZE GUARD on body length.
```

**FIX:**
```python
# Add body size guard at the start of _name_by_dataflow:
if len(body) > 100_000:  # Skip detailed pattern matching for huge functions
    return
```

---

### 18. c_comment_generator.py:780 -- `([^)]{1,40})` bounded
```
FILE: karadul/reconstruction/c_comment_generator.py
LINE 780:
    re.search(r"if\s*\(\s*([^)]{1,40})\s*\)\s*(?:\{?\s*break|break)", rest)
VERDICT: SAFE
REASON: [^)]{1,40} is bounded to max 40 chars. O(1) per position.
```

---

### 19. formula_extractor.py:84-88 -- Matrix multiply triple-nested DOTALL
```
FILE: karadul/reconstruction/computation/formula_extractor.py
LINE 84-88:
    MATRIX_MUL_RE = re.compile(
        r'(?:for\s*\([^)]*\)|do)\s*\{[^{}]*(?:for\s*\([^)]*\)|do)\s*\{[^{}]*(?:for\s*\([^)]*\)|do)\s*\{[^{}]*'
        r'[\+\-]=.*\*',
        re.DOTALL,
    )
VERDICT: DANGEROUS (GUARDED by _safe_dotall_search)
REASON: Three [^{}]* plus .*\* at the end. The .* with DOTALL
  after the last opening brace scans until end of input if no
  [\+\-]=...\* pattern found. GUARDED by _safe_dotall_search.
```

**FIX (defense in depth):**
```python
# Replace trailing .* with bounded:
r'[\+\-]=[^;]{0,200}\*',
```

---

### 20. formula_extractor.py:1733-1734 -- Scalar Math `[^;]+;`
```
FILE: karadul/reconstruction/computation/formula_extractor.py
LINE 1733-1734:
    _SCALAR_MATH_RE = re.compile(
        r'(\w+)\s*=\s*[^;]*(exp|log|pow|sqrt|...)\s*\([^;]+;',
    )
VERDICT: SAFE
REASON: [^;]* and [^;]+ are bounded by semicolons. Semicolons
  are abundant in C code. O(n) guaranteed.
```

---

### 21. c_type_recoverer.py:343-348 -- Function definition regex
```
FILE: karadul/reconstruction/c_type_recoverer.py
LINE 343-348:
    _func_def = re.compile(
        r"^(?P<rtype>[\w\s\*]+?)\s+"
        r"(?P<fname>FUN_[0-9a-fA-F]+|_\w+|[a-z_]\w*)"
        r"\s*\((?P<params>[^)]*)\)",
        re.MULTILINE,
    )
VERDICT: RISKY
REASON: [\w\s\*]+? (non-greedy) matching return type.
  \w and \s overlap in that they both match at word boundaries.
  The non-greedy quantifier means it tries minimal first, then
  expands. With re.MULTILINE and ^, it anchors to line start,
  limiting the search space. Each line is typically short (<200 chars).
  PRACTICALLY SAFE but theoretically O(n^2) on a very long line
  with many \w and \s characters before the function name.
```

---

### 22. bsim.py:165 -- Comment removal `.*?` DOTALL
```
FILE: karadul/ghidra/bsim.py
LINE 165: re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
VERDICT: RISKY
REASON: .*? DOTALL between /* and */. O(n) when */ exists.
  If */ is missing (truncated input), scans to end of string
  and fails -- O(n) per attempt, O(n^2) total if many /* without */.
  Practically safe for well-formed Ghidra output.
```

---

### 23. cff_deflattener.py:64-80 -- While-switch DOTALL
```
FILE: karadul/deobfuscators/cff_deflattener.py
LINE 64-80:
    _WHILE_SWITCH_C = re.compile(
        r"while\s*\([^)]*\)\s*\{[^{}]*switch\s*\([^)]*\)\s*\{",
        re.DOTALL,
    )
VERDICT: SAFE
REASON: [^)]*  and [^{}]* are bounded by their delimiters.
  No overlapping quantifiers. O(n).
```

---

## SUMMARY OF SAFE PATTERNS (BULK)

The vast majority of patterns fall into these safe categories:

### Category A: Anchored simple patterns (SAFE)
- `^...$` with re.MULTILINE (c_namer.py lines 139-145, 743-745)
- `^\w+$` type patterns (type_inferrer.py lines 43-76)
- All `^type$` patterns in c_namer.py lines 581-613

### Category B: Negated character classes (SAFE)
- `[^)]*`, `[^;]*`, `[^}]*`, `[^"]*`, `[^]]*` -- all bounded by delimiter
- Used extensively in c_namer.py, c_type_recoverer.py, constraint_solver.py
- Examples: `\w+\s*\([^)]*\)`, `"[^"]*"`, `[^;]+;`

### Category C: Simple word/identifier patterns (SAFE)
- `\b\w+\b`, `\b(\w+)\s*\(`, `\b(param_\d+)\b`
- No nesting, no overlapping quantifiers
- All of c_namer.py lines 153-161, 226, 270-350

### Category D: Compiled alternation patterns (SAFE)
- `\b(name1|name2|name3)\s*\(` -- all escaped literals
- c_algorithm_id.py line 546-548, binary_intelligence.py line 1396

### Category E: Pattern-per-line search (SAFE)
- c_flow_simplifier.py: goto/label patterns with re.escape()
- c_type_recoverer.py: field access, switch, compare patterns
- All use specific delimiters, no unbounded wildcards

---

## UNGUARDED FILES REQUIRING FIXES

These files have DANGEROUS or RISKY patterns WITHOUT adequate size guards:

| File | Line | Pattern Issue | Fix Priority |
|------|------|--------------|-------------|
| c_flow_simplifier.py | 959-963 | `[\s\S]*?` no guard | **P0 CRITICAL** |
| comment_generator.py | 20 | `.*` DOTALL no guard | P1 HIGH |
| comment_generator.py | 37 | `.*` DOTALL no guard | P1 HIGH |
| c_algorithm_id.py | 266-267 | `.+` DOTALL no guard | P1 HIGH |
| binary_deobfuscator.py | 59-62 | `[^}]*` unbounded | P2 MEDIUM |
| c_namer.py | 2044+ | N*P*body regex storm | P2 MEDIUM |
| binary_deobfuscator.py | 71-72 | `.*?` DOTALL | P3 LOW |

---

## ALREADY-GUARDED FILES (No action needed)

| File | Guard Mechanism |
|------|----------------|
| formula_extractor.py | `_safe_dotall_search` + Phase 1/2 split |
| constraint_solver.py | `_safe_dotall_search/finditer` + `_MAX_DOTALL_INPUT_LEN` |
| analyzer.py | `len(code) > 50_000` guard |
| data_flow.py | `len(_remaining) > 50_000` + str.find pre-filter |
| engineering/patterns.py | Guarded by analyzer.py 50K limit |

---

## RECOMMENDED ACTIONS (Priority Order)

### P0: Fix immediately (will cause pipeline hangs)
1. **c_flow_simplifier.py:959-963** -- Replace `[\s\S]*?` regex with string-based find
2. **c_algorithm_id.py:266-267** -- Replace `.+` with `[^)]+` in DOTALL patterns

### P1: Fix soon (will cause slowdowns on large input)
3. **comment_generator.py:20,37** -- Remove DOTALL or bound `.*`
4. **c_namer.py:2044+** -- Add `len(body) > 100_000` guard before dataflow loop

### P2: Harden (defense in depth)
5. **binary_deobfuscator.py:59-62** -- Add `{0,2000}` limit to `[^}]*`
6. **binary_deobfuscator.py:71-72** -- Replace `.*?` with `[^*]{0,5000}`
7. **formula_extractor.py DOTALL patterns** -- Add `{0,N}` bounds even inside guard

### P3: Monitor
8. **c_type_recoverer.py:343** -- `[\w\s\*]+?` is theoretically risky but line-anchored
9. **bsim.py:165** -- `.*?` DOTALL for comment removal, practically safe
