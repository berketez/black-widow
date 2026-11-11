"""Deney 3: decompiled.json'ın 500 fonksiyonda kesilmesi -> tip kurtarmanın Ghidra high-var kanalı.

Sınır: headless.py:1055 (paralel) ve :1330 (seri) ``"functions": results[:500]``. decompiled.json
yalnız ilk 500 kaydı (bitiş sırasıyla) taşır; CTypeRecoverer._load_ghidra_high_vars
(c_type_recoverer.py:1667-1747) yalnız bu kayıtlardaki ``pcode_high_vars``'ı okur; 2e katmanı
(c_type_recoverer.py:2217-2241) ``undefinedN <ad>`` bildirimini Ghidra'nın çözdüğü tiple değiştirir.

Kesilen fonksiyonların high-var verisi kaybolmamıştır: aynı veri pcode.jsonl'de bütün fonksiyonlar
için durur (headless.py:1651-1697, ``vars`` alanı). Deney bu veriyi "büyük bütçe" girdisi olarak alır.

Ölçülen: ürünün kendi kodu (_load_ghidra_high_vars + 2e döngüsünün eşi + _apply_per_func_replacements)
kaç bildirimi DEĞİŞTİRİRDİ.
  * Ürüne sadık metin: reconstructed/merged (tip kurtarma iter0 girdisi; _feedback_loop_iter.py:172-194).
  * En elverişli metin: static/ghidra_output/decompiled (adlandırma öncesi ham Ghidra C).
Kontrol kolu: decompiled.json'da LİSTELİ fonksiyonlar (kanalın gerçekten çalıştığı yer).

Örneklem (önceden yazıldı): listede olmayan fonksiyonların havuzu (ikili, adres) sırasına dizilir;
random.Random(20261111).sample(havuz, 30). Bütün havuz sayımı denetim olarak ayrıca verilir.
"""

from __future__ import annotations

import argparse
import json
import random

import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from karadul.config import Config  # noqa: E402
from karadul.reconstruction.c_type_recoverer import (  # noqa: E402
    CTypeRecoverer,
    _TYPE_SIZES,
    _apply_per_func_replacements,
)
from say_sinirlar import BINARIES, workspace  # noqa: E402

SEED = 20261111
SAMPLE = 30
UNDEF_VARIANTS = ("undefined8", "undefined4", "undefined", "undefined8 *", "undefined4 *")


def per_func_from_high_vars(high_vars: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    """c_type_recoverer.py:2222-2237 döngüsünün birebir eşi (yalnız 2e katmanı)."""
    per_func: dict[str, dict[str, str]] = {}
    for func_name, var_types in high_vars.items():
        per_func.setdefault(func_name, {})
        for var_name, resolved_type in var_types.items():
            for undef in UNDEF_VARIANTS:
                old_decl = f"{undef} {var_name}"
                if old_decl not in per_func[func_name]:
                    if undef in ("undefined4", "undefined4 *"):
                        resolved_size = _TYPE_SIZES.get(resolved_type, 8)
                        if resolved_size > 4 and "*" not in resolved_type:
                            continue
                    per_func[func_name][old_decl] = f"{resolved_type} {var_name}"
    return per_func


def load_high_vars(entries: list[dict], tmp: Path) -> dict[str, dict[str, str]]:
    """Ürünün okuyucusunu çağır: girdileri decompiled.json biçiminde yazıp yükle."""
    tmp.write_text(json.dumps({"functions": entries}, ensure_ascii=False), encoding="utf-8")
    tr = CTypeRecoverer(Config())
    errs: list[str] = []
    tr._load_ghidra_high_vars(tmp, errs)
    return dict(tr._ghidra_high_vars)


def changed_decls(text_dir: Path, per_func: dict[str, dict[str, str]]) -> tuple[int, int, float]:
    """Dizindeki her .c dosyasına _apply_per_func_replacements uygula; değişen satır sayısı."""
    changed_lines = 0
    changed_files = 0
    t0 = time.monotonic()
    for cfile in sorted(text_dir.rglob("*.c")):
        content = cfile.read_text(encoding="utf-8", errors="replace")
        if "undefined" not in content:
            continue  # 2e yalnız "undefinedN <ad>" bildirimini değiştirir
        new = _apply_per_func_replacements(content, per_func)
        if new != content:
            changed_files += 1
            a, b = content.splitlines(), new.splitlines()
            changed_lines += sum(1 for x, y in zip(a, b) if x != y)
    return changed_lines, changed_files, time.monotonic() - t0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tmp", required=True, help="geçici decompiled.json yazılacak dizin")
    args = ap.parse_args()
    tmpdir = Path(args.tmp)
    tmpdir.mkdir(parents=True, exist_ok=True)

    census: dict = {}
    pool: list[dict] = []
    per_binary_entries: dict = {}
    for label, base in BINARIES.items():
        ws = workspace(base)
        gout = ws / "static/ghidra_output"
        dj = json.loads((gout / "decompiled.json").read_text(encoding="utf-8"))
        listed = dj.get("functions", [])
        listed_addrs = {f.get("address") for f in listed}
        all_entries = []
        with open(gout / "pcode.jsonl", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    all_entries.append({"name": rec["n"], "address": rec["a"], "pcode_high_vars": rec.get("vars", [])})
        unlisted = [e for e in all_entries if e["address"] not in listed_addrs]
        per_binary_entries[label] = (ws, listed, unlisted)
        for e in unlisted:
            pool.append({"binary": label, **e})

        hv_listed = load_high_vars(listed, tmpdir / f"{label.replace('/', '_')}_listed.json")
        hv_unlisted = load_high_vars(unlisted, tmpdir / f"{label.replace('/', '_')}_unlisted.json")
        merged = ws / "reconstructed/merged"
        raw = gout / "decompiled"
        res = {}
        for arm, hv in (("listed", hv_listed), ("unlisted", hv_unlisted)):
            pf = per_func_from_high_vars(hv)
            m_lines, m_files, m_t = changed_decls(merged, pf)
            r_lines, r_files, r_t = changed_decls(raw, pf)
            res[arm] = {
                "functions_with_resolved_vars": len(hv),
                "resolved_vars": sum(len(v) for v in hv.values()),
                "merged_changed_lines": m_lines, "merged_changed_files": m_files,
                "raw_changed_lines": r_lines, "raw_changed_files": r_files,
                "seconds": round(m_t + r_t, 2),
            }
        census[label] = res
        print(label, json.dumps(res), flush=True)

    pool.sort(key=lambda e: (e["binary"], e["address"]))
    sample = random.Random(SEED).sample(pool, min(SAMPLE, len(pool)))
    rows = []
    for e in sample:
        ws, _listed, _unl = per_binary_entries[e["binary"]]
        t0 = time.monotonic()
        hv = load_high_vars([{k: v for k, v in e.items() if k != "binary"}],
                            tmpdir / "sample_one.json")
        pf = per_func_from_high_vars(hv)
        m_lines, _, _ = changed_decls(ws / "reconstructed/merged", pf)
        r_lines, _, _ = changed_decls(ws / "static/ghidra_output/decompiled", pf)
        rows.append({
            "binary": e["binary"], "name": e["name"], "address": e["address"],
            "resolved_vars": sum(len(v) for v in hv.values()),
            "merged_changed_lines": m_lines, "raw_changed_lines": r_lines,
            "seconds": round(time.monotonic() - t0, 3),
        })
    out = {
        "seed": SEED, "pool_size": len(pool), "census": census,
        "sample": {
            "n": len(rows),
            "functions_with_change_merged": sum(1 for r in rows if r["merged_changed_lines"]),
            "functions_with_change_raw": sum(1 for r in rows if r["raw_changed_lines"]),
            "rows": rows,
        },
    }
    print("sample", {k: v for k, v in out["sample"].items() if k != "rows"})
    Path(args.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
