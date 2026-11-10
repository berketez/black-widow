<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Ghidra-12.1.2-red?style=for-the-badge" alt="Ghidra 12.1.2">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

<h1 align="center">Black Widow</h1>
<h3 align="center">Karadul</h3>

<p align="center">
  <strong>A research pipeline on top of Ghidra that post-processes decompiled code from stripped binaries: proposed names, some recovered types, comments and reports.</strong>
</p>

---

## What it is

- **Ghidra does the heavy work.** Loading, disassembly and decompilation come from Ghidra 12.1.2, run headless (through PyGhidra when the `pyghidra` package is installed, otherwise through `analyzeHeadless`).
- **Karadul adds a layer on top.** It proposes function and variable names, tries to recover some types and structs, adds comments and writes reports. This naming layer is a research project; it is not finished and it is often wrong (see [Status](#status)).
- **No LLM, no ML model.** The engine is rule- and computation-based and is meant to be deterministic. In a committed check, two runs of the same code on htop and tmux produced byte-identical `naming_map.json` files ([`docs/arge/2026-10-21_g9_n0/ol7_yeniden_sonuc.md`](docs/arge/2026-10-21_g9_n0/ol7_yeniden_sonuc.md)); other output files were not compared there.
- **Offline by default.** Network access is off unless you pass `--enable-network`.
- **The target is not executed by default.** Dynamic analysis runs the target under Frida only when you pass `--dynamic` (`security.allow_target_execution`, default `false`, in `karadul/config.py`).

## Status

Read this section before relying on any output.

- **Name quality.** The most recent committed evaluation (2026-10-19, run `taban-v2-62ad154`, Ghidra 12.1.2) labelled function names Karadul assigned in two stripped macOS arm64 Mach-O programs (`scripts/measurement/macho_measure.py`):

  | Program | Names judged | Wrong | Exact or close |
  |---|---|---|---|
  | tmux | 385 | 45.5% | 19.7% |
  | htop | 97 | 81.4% | 4.1% |

  The labels come from Claude agents acting as blind proxy raters; no human rater has been used yet. Source and method: [`docs/arge/2026-10-19_g4_etiketleme/sonuc.md`](docs/arge/2026-10-19_g4_etiketleme/sonuc.md) and `onkayit.md` next to it (in Turkish).
- **Exact-match check of the 1.20 output (2026-11-10).** Function names written by the pipeline as it was before 1.21.1 (anchors, silencing and threshold off) were compared with symbol ground truth by exact equality on 118 arm64 binaries from 8 open-source programs (`scripts/measurement/urun_olc.py`): of 6,394 names, 1,184 are equal to the real name (18.5%); 5,210 are not. This test is stricter than the rater study above: a name a rater would call "close" counts as wrong here. The nine string sub-channels that 1.21.1 silences by default account for 4,321 of these names, 14 of them correct. The same measurement on the 1.21.1 default output has not been run yet. Source: [`docs/arge/2026-11-10_n1_adim3/urun_olcumu_taban.md`](docs/arge/2026-11-10_n1_adim3/urun_olcumu_taban.md) (in Turkish).
- **Exact-name anchors (KS-1).** A pre-registered measurement (2026-11-10; 119 arm64 binaries from 8 open-source programs) checked names read from the binary's own name slots against symbol ground truth, by exact equality. Names taken from `"%s: ..."` log calls that pass `__func__` were right for 249 of 262 distinct names (decision: precise, ≥ 95%). Names taken from assert calls were right for 188 of 228 (decision: not precise): 40 of the 42 wrong assert anchors name a function that was inlined into the measured one. These anchors cover only a small share of the functions that need a name (about 6% in tmux, none in htop, sqlite3 or tree). Since 1.21.1 three flags under `binary_reconstruction` are **on by default**: `enable_ks1_anchors` (names from `__func__` log calls are written and labelled `kesin`; names that rest only on an assert are not written), `enable_subchannel_silencing` (nine string sub-channels that a blind-label study found weak give no name) and `apply_global_naming_threshold` (`min_naming_confidence`, 0.7, is applied to function and data names). The result is fewer names: on a small program the output can contain no proposed function name at all. Set the three flags to `false` in `karadul.yaml` to get the 1.20 behaviour. Source: [`docs/arge/2026-10-21_g11_n1/ks1_olcum.md`](docs/arge/2026-10-21_g11_n1/ks1_olcum.md), pre-registration `ks1_onkayit.md` and deviation record `ks1_sapma_1.md` next to it (in Turkish).
- **Confidence values are not calibrated.** The clean output carries the confidence recorded by the naming step and a label (`kesin` / `doğrulanmadı`) for each function and data name (`karadul/core/output_formatter.py`, `karadul/core/naming_labels.py`). Only names that come from the `__func__` anchors are labelled `kesin`; every other name is labelled `doğrulanmadı` (not verified).
- **Algorithm and crypto tags** (`ALGORITHM:` comments) are pattern heuristics. Their precision has not been measured. Constant-based tags now require whole-token matches and at least two algorithm-specific constants in the same function; before that fix, programs without any cryptography received hundreds of such tags.
- **Measured formats.** Name and type measurements have been run only on arm64 Mach-O and arm64 ELF. The code also recognises PE, .NET, JVM/APK, Go, Swift, Rust, Delphi, Python bytecode, JavaScript bundles and Electron apps; none of these has an accuracy measurement.
- **No release yet.** No GitHub release or prebuilt DMG has been published.
- **CLI messages are mostly in Turkish.**

## Requirements

- Python 3.11 or newer (`requires-python` in `pyproject.toml`).
- Ghidra **12.1.2** for native binaries. This is the pinned version (`GHIDRA_PINNED_VERSION` in `karadul/config.py`). Other versions are used with a warning, because decompiler output can differ between Ghidra versions.
- A JDK that your Ghidra release supports (the macOS app build bundles JDK 21: `packaging/macos/build_mac_app.sh`).
- Optional: Node.js for JavaScript targets (helper scripts in `scripts/package.json`; run `npm install --prefix scripts`), Frida for `--dynamic`.

Point Karadul at Ghidra with `GHIDRA_INSTALL_DIR` (or `GHIDRA_HOME`). Without it, a few common install locations and `PATH` are searched (`_find_ghidra_tool` in `karadul/config.py`). The Ghidra path is not read from `karadul.yaml`.

The large signature and name databases used during development (`sigs/`, `~/.karadul/signatures.lmdb`) are **not** part of this repository. Unless you supply signature files yourself (`binary_reconstruction.external_signature_paths` in `karadul.yaml`, or `sigs/` and `signatures_*.json` in the project root; see `karadul/analyzers/signature_db.py`), only the signatures built into the source tree are used.

## Installation

```bash
git clone https://github.com/berketez/black-widow.git
cd black-widow
python -m venv .venv && source .venv/bin/activate

# Native binaries: Ghidra bridge + binary parsing + the reconstruction stage's dependencies
pip install -e ".[ghidra,binary,perf]"
```

Plain `pip install -e .` is enough to import every stage; the extras add the Ghidra bridge (`ghidra`), binary parsers (`binary`) and the LMDB signature backend (`perf`).

Other extras (defined in `pyproject.toml`):

| Extra | Installs | Used for |
|---|---|---|
| `computation` | z3-solver, sympy, networkx | Struct constraint solving, CFG isomorphism, formula extraction |
| `deobf` | z3-solver | Deobfuscation passes |
| `cpp` | cxxfilt | C++ name demangling |
| `yara` | yara-python | YARA scanning |
| `dynamic` | frida-tools | `--dynamic` |
| `python` | decompyle3, xdis | Python bytecode fallback |
| `decompilers` | angr | `--decompiler-backend angr` |
| `ml` | torch, transformers, ... | Not used by the analysis engine |
| `app` | pywebview | macOS desktop window |
| `dev` | pytest, pytest-cov, mypy | Tests |
| `full` / `all` | everything above | |

## Quick start

```bash
karadul --help                      # also: python -m karadul --help
karadul analyze --help

# Full pipeline: identify -> static (Ghidra) -> dynamic (skipped without --dynamic)
#                -> deobfuscate -> reconstruct -> report
karadul analyze /path/to/binary

# Same, and also write a clean output directory
karadul analyze /path/to/binary --output ./out

# Stop after a given stage (here: after Ghidra decompilation)
karadul analyze /path/to/binary --stage static

# Machine-readable summary on stdout (can be combined with --output)
karadul analyze /path/to/binary --json

# Detection only: type, language, size, SHA-256
karadul info /path/to/binary

# Previous analyses, active configuration
karadul list
karadul config show
karadul config validate
```

`karadul analyze` writes a workspace under `./workspaces/` in the current directory. `--output-dir DIR` moves it to `DIR/workspaces/`. Note that the same directory is where external signature files (`sigs/`, `signatures_*.json`) are looked up, so `--output-dir` also changes which signature files are loaded.

### Commands that run code

- `karadul analyze --dynamic` runs the target program under Frida. Use it only on binaries you trust.
- `karadul run <target>` runs `npm install && npm start` in a reconstructed JavaScript project, i.e. code derived from the target. It asks for confirmation unless you pass `-y`.

`karadul batch analyze` analyses fixed target paths written into `karadul/batch.py` (applications on the author's machine). It is not useful elsewhere yet.

## Output

Workspace (`karadul/core/workspace.py`):

```
workspaces/<target>/<UTC timestamp>/
  raw/            # target info, extracted inputs
  static/         # static analysis output, including Ghidra's
  dynamic/        # Frida output (only with --dynamic)
  deobfuscated/
  reconstructed/  # renamed and commented sources, naming_map.json
  reports/        # report files
```

Clean output with `--output DIR` (`karadul/core/output_formatter.py`):

```
DIR/
  src/
  naming_map.json
  dependency_graph.json
  report.json
  report.html
  README.md
```

## Python API

`import karadul` exposes `analyze`, `Pipeline`, `Config`, `__version__`. See [`docs/API.md`](docs/API.md).

## Desktop app (macOS)

A local web console and a native macOS wrapper live in `ui/` and `packaging/macos/`:

```bash
python ui/server.py                                 # http://127.0.0.1:8000 (port: KARADUL_PORT)
bash packaging/macos/build_mac_app.sh               # app bundle without Ghidra/JDK
bash packaging/macos/build_mac_app.sh --full        # bundles Ghidra, a JDK and the signature DB
bash packaging/macos/build_dmg.sh                   # -> dist/BlackWidow-*.dmg
```

`build_dmg.sh` signs with a Developer ID if one is available, otherwise ad-hoc; notarization is not done. An ad-hoc signed app copied to another Mac is blocked by Gatekeeper on first launch; clear the quarantine flag with:

```bash
xattr -dr com.apple.quarantine "/Applications/Black Widow.app"
```

The app's update check reads `appcast.json` from the latest GitHub release by default (`KARADUL_UPDATE_MANIFEST_URL` overrides it; see `ui/server.py`). No release has been published yet, so the check finds nothing.

## Known issues

- `Config.load(path)` falls back to the defaults when `path` does not exist; it logs a warning but does not raise.
- `karadul batch analyze` only knows target paths from the author's machine (see above).
- Flow simplification (`binary_reconstruction.enable_flow_simplification`) is off by default. The earlier implementation corrupted the C text of most functions that contain `goto`. The step was rewritten and now checks a post-condition on every function it changes (the original text is kept if the check fails), but with the flag on it has been run end-to-end on one binary only.
- C++ targets are written as a flat list of functions; classes are not reconstructed.
- An output audit on 119 binaries ([`docs/arge/2026-11-10_cikti_saglamligi/rapor.md`](docs/arge/2026-11-10_cikti_saglamligi/rapor.md), in Turkish) lists further open issues, among them: function names that are C keywords or collide with an imported name, `naming_map.json` listing renames that were not applied to the code, and report counters that are wrong (`pipeline_iterations_run`, `convergence_reason`).

## Tests

What CI runs (`.github/workflows/ci.yml`), on Ubuntu (Python 3.11 and 3.12) and macOS (Python 3.12), from a full-history checkout (`fetch-depth: 0`):

```bash
pip install -e ".[dev,perf,binary,computation,cpp]" pyelftools pyfiglet
npm install --prefix scripts --no-audit --no-fund
python -m pytest -q -rfEs --ignore=tests/test_pipeline_e2e_real_binary.py
```

- `pyproject.toml` deselects tests marked `integration` and `benchmark` by default; `.github/workflows/benchmark.yml` runs the `benchmark` ones (metric code on committed fixtures, no accuracy threshold).
- `pyelftools` is needed by the measurement tests and `pyfiglet` by one banner test; no extra declares them.
- `tests/test_ngram_db_v2_smoke.py` needs `sigs/ngram_name_db/`, which is not in the repository, and skips without it; `tests/test_pipeline_e2e_real_binary.py` runs the full pipeline and needs Ghidra.
- Tests that need something the machine lacks skip and say why (`-rs` lists the reasons): `otool` and an `nm` that reads Mach-O (not on the Linux runners), `synchrony` (optional; not installed on any runner), and the pre-registration commit `f23f4ea` that two tests in `tests/test_alt_kanal_olc.py` check (absent from a shallow clone or a source archive).
- On a machine with Ghidra installed, some tests run Ghidra or read local measurement data when it is present; they skip otherwise.

## Measurement documents

Research plans, pre-registrations and results are in `docs/arge/` (in Turkish). The current plan is [`docs/arge/2026-10-21_plan_v2_2.md`](docs/arge/2026-10-21_plan_v2_2.md).

## License

MIT License. See [LICENSE](LICENSE).

## Author

**Berke Tezgöçen**
