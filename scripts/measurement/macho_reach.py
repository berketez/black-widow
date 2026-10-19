#!/usr/bin/env python3
"""İsim bekleyen fonksiyonlardan kaçı iç çağrı zinciriyle bir kütüphane çağrısına ulaşıyor.

Aşağıdan yukarı yayılımın (kütüphane çağrısından çağıranlara isim/kanıt taşıma)
erişebileceği üst sınır. 15 Ekim oturumundaki ``tarif/reach.py``'nin depoya
taşınmış hâli; sayım kuralları aynen korunur:

- ``ext``: Ghidra fonksiyon listesinde ``is_external`` ya da ``is_thunk`` olanların
  adları (baştaki ``_`` soyulmuş). Not: iç thunk'lar (``thunk_FUN_...``) da bu
  kümeye girer; özgün betik böyleydi, sayıların sürekliliği için değiştirilmedi.
- ``direct``: çağrılanlarından biri ``ext``'te olan düğümler.
- ``reach``: ``direct``'ten geriye doğru sabit noktaya kadar yayılım (bir fonksiyon
  ``reach``'teki bir iç fonksiyonu çağırıyorsa o da ulaşır).
- Popülasyon: koşunun ``macho_score.json`` satırları (isim bekleyenler).

Tek fark: statik dizin ``function_f1.find_run_artifacts``'ten alınır (puanlayıcının
okuduğu çalışma alanının aynısı); özgün betik ilk ``glob`` eşleşmesini alıyordu.
Koşu dizininde tek çalışma alanı varken (ölçüm hattı her koşuda dizini temizler)
ikisi aynıdır.

Kullanım: ``python scripts/measurement/macho_reach.py <koşu_dizini>``
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from function_f1 import find_run_artifacts  # noqa: E402
from macho_f1 import SCORE_FILE_NAME  # noqa: E402


def _key(addr: str) -> str:
    return addr.replace("0x", "").lower()


def reach_stats(cg_nodes: dict[str, Any], funcs: list[dict[str, Any]],
                rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Çağrı grafiği düğümleri + fonksiyon listesi + puan satırları -> erişim sayıları."""
    ext = {f["name"].lstrip("_") for f in funcs if f.get("is_external") or f.get("is_thunk")}
    direct = {k for k, n in cg_nodes.items()
              if any(c["name"].lstrip("_") in ext for c in n["callees"])}
    reach = set(direct)
    changed = True
    while changed:
        changed = False
        for k, n in cg_nodes.items():
            if k in reach:
                continue
            for c in n["callees"]:
                if _key(c.get("address", "") or "") in reach:
                    reach.add(k)
                    changed = True
                    break
    pop = [_key(r["addr"]) for r in rows]
    callers: dict[str, set[str]] = {}
    for k, n in cg_nodes.items():
        for c in n["callees"]:
            callers.setdefault(_key(c.get("address", "") or ""), set()).add(k)
    return {
        "population": len(pop),
        "direct_library_call": sum(1 for a in pop if a in direct),
        "reaches_library": sum(1 for a in pop if a in reach),
        "no_reach": sum(1 for a in pop if a not in reach),
        "no_reach_called_by_reaching": sum(
            1 for a in pop if a not in reach and callers.get(a, set()) & reach),
    }


def run_reach(run_dir: Path, rows: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
    """Koşu dizininden erişim sayıları (satırlar verilmezse ``macho_score.json``'dan)."""
    run_dir = Path(run_dir)
    ts_dir = find_run_artifacts(run_dir)["ts_dir"]
    if ts_dir is None:
        raise FileNotFoundError(f"{run_dir}: çalışma alanında static/ yok")
    static = ts_dir / "static"
    cg = json.loads((static / "ghidra_call_graph.json").read_text(encoding="utf-8"))["nodes"]
    funcs = json.loads((static / "ghidra_functions.json").read_text(encoding="utf-8"))["functions"]
    if rows is None:
        rows = json.loads((run_dir / SCORE_FILE_NAME).read_text(encoding="utf-8"))["rows"]
    return reach_stats(cg, funcs, rows)


def _pct(k: int, n: int) -> str:
    return f"{k / n:.0%}" if n else "—"


def format_line(st: dict[str, Any]) -> str:
    """Özgün betiğin yazdırdığı cümle (aynı biçim)."""
    n = st["population"]
    d, r = st["direct_library_call"], st["reaches_library"]
    return (f"isim bekleyen {n}: doğrudan kütüphane çağıran {d} ({_pct(d, n)}), "
            f"çağrı zinciriyle kütüphaneye ulaşan {r} ({_pct(r, n)}), hiç ulaşmayan {st['no_reach']}; "
            f"bunların {st['no_reach_called_by_reaching']}'i en azından kanıtlı bir fonksiyon "
            f"tarafından çağrılıyor (yukarıdan bağlam)")


def main(argv: Optional[list[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(__doc__.split("\n")[0])
        print("Kullanım: macho_reach.py <koşu_dizini>")
        return 2
    print(format_line(run_reach(Path(args[0]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
