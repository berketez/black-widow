#!/usr/bin/env python3
"""Mac-native F1 ölçümü — coreutils.

Mac `nm` Apple Mach-O nm; Linux ELF DWARF okuyamıyor. GT'yi Docker'da GNU nm
ile önceden çıkardık (`~/coreutils_gt/<bin>.gt.txt`). benchmark_runner'ın
_extract_symbols_nm'ini o hazır GT ile override edip tüm mantığı (unresolved
FUN_xxx = sahte-F1 fix, metrics) koruyoruz.

Her binary için en yeni `<bin>_clean*` (naming_map) ve `<bin>_ws*` (workspace)
dizinini otomatik seçer. Ölçülecek binary'ler argümanla verilebilir:
    python3 scripts/mac_f1_eval.py cat sort ls
Argüman yoksa GT seti içindeki tüm binary'ler denenir.
"""
import sys, re, glob, os
from pathlib import Path

# Script hangi tree'deyse o tree'nin harness'ini kullan: ana tree = baseline
# (fix öncesi), worktree = fix'li. Böylece aynı script iki ölçümü de yapar.
_TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _TREE)
from tests.benchmark.benchmark_runner import BenchmarkRunner  # noqa: E402

HOME = str(Path.home())
MEAS = f"{HOME}/karadul_meas"
GT_DIR = f"{HOME}/coreutils_gt"
SKIP = ("__", "GCC_", "GLIBC_", "atexit", "frame_dummy",
        "register_tm", "deregister_tm", "_start")
NM_PAT = re.compile(r"^([0-9a-fA-F]+)\s+[TtDdBb]\s+_?(\w+)$", re.MULTILINE)
# Ghidra ELF PIE'yi 0x100000 image-base'e yükler; nm .debug adresleri 0-based.
# GT anahtarlarını Ghidra namespace'ine hizalamak için offset ekle
# (yoksa FUN_00002cf4 vs FUN_00102cf4 -> kesişim boş -> sahte F1=0).
GHIDRA_IMAGE_BASE = 0x100000


def make_gt_extractor(gt_txt: str):
    def _extract(_binary_path):  # Mac nm bypass; GNU nm .gt.txt'ten
        stdout = Path(gt_txt).read_text(encoding="utf-8")
        gt: dict[str, str] = {}
        for m in NM_PAT.finditer(stdout):
            addr_int = int(m.group(1), 16)
            if addr_int == 0:
                continue
            addr = f"{addr_int + GHIDRA_IMAGE_BASE:08x}"
            name = m.group(2)
            if name.startswith(SKIP):
                continue
            gt[f"FUN_{addr}"] = name
        return gt
    return _extract


def latest(pattern: str, leaf: str):
    """pattern eşleşen dizinlerden, `leaf` dosyası olan en yeni (mtime) olanı seç."""
    dirs = glob.glob(pattern)
    dirs = [d for d in dirs if (Path(d) / leaf).is_file()] if leaf else dirs
    if not dirs:
        return None
    return sorted(dirs, key=lambda p: Path(p).stat().st_mtime)[-1]


def find_naming_map(b: str):
    # DOĞRU kaynak: workspace reconstructed/src/naming_map.json — FUN_<addr>→isim
    # eşlemesini {global, per_function} scoped formatında taşır. Clean output'un
    # naming_map.json'u sadece kütüphane import'larını (isim-anahtarlı) içerir.
    ws_hits = glob.glob(
        f"{MEAS}/{b}_ws*/workspaces/{b}/*/reconstructed/src/naming_map.json"
    )
    if ws_hits:
        return Path(sorted(ws_hits, key=lambda p: Path(p).stat().st_mtime)[-1])
    d = latest(f"{MEAS}/{b}_clean*", "naming_map.json")
    return Path(d) / "naming_map.json" if d else None


def find_workspace(b: str):
    hits = glob.glob(f"{MEAS}/{b}_ws*/workspaces/{b}/*/static/ghidra_functions.json")
    if not hits:
        return None
    hits.sort(key=lambda p: Path(p).stat().st_mtime)
    return str(Path(hits[-1]).parent.parent)


def dump(name, result):
    m = result.metrics
    print(f"\n========== {name} ==========")
    for attr in ("total_symbols", "accuracy", "recovery_rate", "precision",
                 "recall", "f1", "f1_score", "renamed_f1", "exact_matches",
                 "semantic_matches", "partial_matches", "missing", "wrong",
                 "fun_residue_pct"):
        if hasattr(m, attr):
            print(f"  {attr:18s}= {getattr(m, attr)}")
    if hasattr(m, "ground_truth_breakdown"):
        print(f"  gt_breakdown      = {m.ground_truth_breakdown}")
    if hasattr(m, "summary"):
        try:
            print("  summary: " + str(m.summary()))
        except Exception:
            pass


def main():
    bins = sys.argv[1:]
    if not bins:
        bins = sorted(Path(p).name[:-7] for p in glob.glob(f"{GT_DIR}/*.gt.txt"))
    measured = {}
    for b in bins:
        nm_map = find_naming_map(b)
        gt_txt = f"{GT_DIR}/{b}.gt.txt"
        if not nm_map or not Path(gt_txt).is_file():
            print(f"\n{b}: naming_map veya GT yok → atlanıyor")
            continue
        ws = find_workspace(b)
        runner = BenchmarkRunner(output_dir=Path(f"{MEAS}/f1_results"))
        runner._extract_symbols_nm = make_gt_extractor(gt_txt)
        try:
            result = runner.run_from_binaries(
                debug_binary=Path(f"{GT_DIR}/{b}.debug"),
                naming_map_json=nm_map,
                workspace_dir=Path(ws) if ws else None,
            )
            dump(b, result)
            measured[b] = result.metrics
        except Exception:
            import traceback
            print(f"\n{b}: HATA")
            traceback.print_exc()

    if measured:
        print("\n\n===== ÖZET =====")
        def g(m, *names):
            for n in names:
                if hasattr(m, n):
                    return getattr(m, n)
            return None
        f1s = []
        for b, m in measured.items():
            f1 = g(m, "f1", "f1_score")
            acc = g(m, "accuracy")
            rec = g(m, "recovery_rate")
            print(f"  {b:8s} F1={f1}  acc={acc}  recovery={rec}")
            if f1 is not None:
                f1s.append(f1)
        if f1s:
            print(f"\n  ORTALAMA F1 = {sum(f1s)/len(f1s):.4f}  ({len(f1s)} binary)")


if __name__ == "__main__":
    main()
