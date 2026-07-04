#!/usr/bin/env python3
"""Stripped binary'de hızlı F1 yaklaşımı:
nm -D ile dynamic sembol tablosundan exports al → karadul naming_map ile karşılaştır.

Kullanim:
    python quick_f1_eval.py <binary> <naming_map.json>
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from karadul.core.safe_subprocess import resolve_tool as _resolve_tool
except Exception:  # pragma: no cover
    _resolve_tool = None  # type: ignore[assignment]


def _which(name: str) -> str | None:
    if _resolve_tool is not None:
        found = _resolve_tool(name)
        if found:
            return found
    return shutil.which(name)


def get_nm_symbols(binary: Path) -> dict[int, str]:
    """nm -D dynamic exports → {address: name}

    v1.15.5: Platform-aware. macOS sistem nm ``-D``'yi desteklemez; llvm-nm
    ya da ``nm -gU`` (defined external) fallback'ine düşeriz.
    """
    proc = None
    if sys.platform != "darwin":
        # Linux: binutils nm -D.
        nm = _which("nm") or "nm"
        try:
            proc = subprocess.run(
                [nm, "-D", "--defined-only", str(binary)],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError:
            proc = None
    else:
        # macOS: llvm-nm -D destekler; yoksa nm -gU (defined external).
        llvm_nm = _which("llvm-nm")
        if llvm_nm:
            try:
                proc = subprocess.run(
                    [llvm_nm, "-D", "--defined-only", str(binary)],
                    capture_output=True, text=True, timeout=30,
                )
            except FileNotFoundError:
                proc = None

    if proc is None or proc.returncode != 0:
        nm = _which("nm") or "nm"
        try:
            proc = subprocess.run(
                [nm, "-gU", str(binary)],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError:
            return {}
    if proc.returncode != 0:
        return {}
    syms = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        # v1.15.5: "U" (undefined / libc import) GT'den ÇIKARILIR. Import'lar
        # karadul'un rename görevi değil; GT'ye katılınca sahte FN üretip
        # recall'u yapay düşürüyordu. Sadece defined text/weak semboller kalır.
        if parts[1].upper() not in ("T", "W"):
            continue
        name = parts[-1].lstrip("_")
        if addr == 0 or not name:
            continue
        syms[addr] = name
    return syms


def _is_substring_partial(gt_name: str, karadul_name: str, min_len: int = 4) -> bool:
    """İki isim arasında substring partial eşleşme var mı?

    v1.15.5: İki isimden KISA olanı en az `min_len` karakter olmalı; aksi
    halde "io", "id", "fd" gibi çok kısa isimler her şeyin içinde geçip
    gevşek (sahte) partial eşleşme üretiyordu.
    """
    g = gt_name.lower()
    k = karadul_name.lower()
    if not g or not k:
        return False
    if min(len(g), len(k)) < min_len:
        return False
    return g in k or k in g


def load_naming_map(path: Path) -> dict[str, str]:
    """naming_map.json'dan FUN_xxx → name dict çek."""
    d = json.loads(path.read_text())
    if "global" in d and isinstance(d["global"], dict):
        return d["global"]
    return d


def compute_f1(binary: Path, naming_map_path: Path) -> dict:
    """nm exports vs karadul naming_map karşılaştır."""
    nm_syms = get_nm_symbols(binary)
    naming = load_naming_map(naming_map_path)

    # GT: nm export'ları FUN_<addr> formatına çevir
    gt = {f"FUN_{addr:08x}": name for addr, name in nm_syms.items()}
    # Karadul aynı FUN_xxx key ile rename önerdi mi?
    tp: float = 0.0  # partial eşleşmede 0.5 eklenebildiği için float
    fp = fn = 0
    exact_matches = []
    partial_matches = []
    missed = []

    for key, gt_name in gt.items():
        karadul_name = naming.get(key)
        if not karadul_name or karadul_name.startswith(("FUN_", "sub_", "thunk_")):
            fn += 1
            missed.append((key, gt_name))
            continue
        # Tam eşleşme veya yarı eşleşme
        if karadul_name == gt_name:
            tp += 1
            exact_matches.append((key, gt_name))
        elif _is_substring_partial(gt_name, karadul_name):
            # v1.15.5: substring partial yalnız iki isimden KISA olanı en az
            # 4 karakter ise sayılır. Aksi halde "a", "io" gibi kısa isimler
            # gevşekçe tp+0.5 üretip F1'i şişiriyordu.
            tp += 0.5
            partial_matches.append((key, gt_name, karadul_name))
        else:
            fp += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "binary": str(binary.name),
        "gt_count": len(gt),
        "karadul_renames": len([v for v in naming.values() if v and not v.startswith(("FUN_", "sub_", "thunk_"))]),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "exact_count": len(exact_matches),
        "partial_count": len(partial_matches),
        "exact_samples": exact_matches[:5],
        "partial_samples": partial_matches[:5],
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: quick_f1_eval.py <binary> <naming_map.json>")
        sys.exit(1)
    binary = Path(sys.argv[1])
    naming_map = Path(sys.argv[2])
    result = compute_f1(binary, naming_map)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
