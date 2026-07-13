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
import sys, re, glob, datetime
from pathlib import Path

sys.path.insert(0, "/Users/apple/Desktop/black-widow")
from tests.benchmark.benchmark_runner import BenchmarkRunner  # noqa: E402

HOME = str(Path.home())
MEAS = f"{HOME}/karadul_meas"
GT_DIR = f"{HOME}/coreutils_gt"
SKIP = ("__", "GCC_", "GLIBC_", "atexit", "frame_dummy",
        "register_tm", "deregister_tm", "_start", "_init", "_fini")
# FIX-3 (2026-07-06): Linux ELF nm sentetik '_' oneki EKLEMEZ (o Mach-O
# davranisi). Eski `_?` grubu _start/_init/_fini'nin GERCEK bastaki '_'ini
# yiyor -> "start"/"init"/"fini" hicbir SKIP prefiksine uymuyor -> CRT/linker
# fonksiyonlari GT'de kaliyor -> karadul onlari isimlendirmedigi icin haksiz
# 'missing' -> F1 deflation. `_?` kaldirildi; SKIP ham isim uzerinde calisiyor.
# FIX-4 (2026-07-08): `(\w+)` nokta icermez -> `full_write.constprop.0`,
# `gettext_quote.part.0` gibi GCC-specialize sembolleri satir sonuna kadar
# eslesemez -> GT'den TAMAMEN duser (ne TP ne FN). cat GT'sinin ~%30'u boyle
# gorunmez oluyordu. `([\w.]+)` noktayi kabul eder; sufiks metrics._normalize'da
# soyulur (Katman B), boylece GT `full_write.constprop.0` -> karadul `full_write`.
NM_PAT = re.compile(r"^([0-9a-fA-F]+)\s+[TtDdBb]\s+([\w.]+)$", re.MULTILINE)
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


def select_run(b: str):
    """Bir binary için naming_map + workspace'i AYNI run dizininden seç.

    TB-3 fix (2026-07-13, test denetimi): Eskiden naming_map (find_naming_map) ve
    ghidra_functions (find_workspace) BAĞIMSIZ mtime ile seçiliyordu → ikisi farklı
    koşulardan gelip adres/fonksiyon-kümesi uyuşmazlığı → sessiz YANLIŞ F1. Artık
    tek run dizini seçilir, ikisi de ondan türer.
    Döner: (naming_map_path | None, workspace_dir | None).
    """
    nm_hits = glob.glob(
        f"{MEAS}/{b}_ws*/workspaces/{b}/*/reconstructed/src/naming_map.json"
    )
    if nm_hits:
        nm = Path(sorted(nm_hits, key=lambda p: Path(p).stat().st_mtime)[-1])
        run_dir = nm.parents[2]  # .../workspaces/<b>/<ts>
        ws = str(run_dir) if (run_dir / "static/ghidra_functions.json").is_file() else None
        return nm, ws
    # clean fallback (workspace yok, sadece naming_map)
    d = latest(f"{MEAS}/{b}_clean*", "naming_map.json")
    return (Path(d) / "naming_map.json" if d else None), None


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
        nm_map, ws = select_run(b)
        gt_txt = f"{GT_DIR}/{b}.gt.txt"
        if not nm_map or not Path(gt_txt).is_file():
            print(f"\n{b}: naming_map veya GT yok → atlanıyor")
            continue
        # Şeffaflık (TB-3): hangi run ölçüldü + ne zaman (bayat/uyumsuz workspace teşhisi)
        _mt = datetime.datetime.fromtimestamp(nm_map.stat().st_mtime).strftime("%m-%d %H:%M")
        print(f"  [{b}] run: …{str(nm_map.parents[2])[-44:]}  (naming_map mtime {_mt})")
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
