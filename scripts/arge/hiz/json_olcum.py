#!/usr/bin/env python3
"""HIZ kalem 4 (disk / serileştirme): ürünün JSON yazım biçiminin maliyeti.

Ürün Ghidra çıktılarını ``json.dumps(data, indent=2, ensure_ascii=False, default=str)``
(``karadul/ghidra/headless.py:2454``) ve ``indent=2, ensure_ascii=True``
(``karadul/core/workspace.py:248``) ile yazar. CPython 3.12'de ``indent`` verilince C
kodlayıcı kullanılmaz (``json/encoder.py`` ``iterencode``: ``c_make_encoder`` yalnız
``indent is None``). Bu betik aynı veriyi farklı yollarla serileştirip süreleri ve
bayt eşitliğini ölçer. Girdi dosyaları salt okunur; hiçbir şey diske yazılmaz (yalnız
sonuç JSON'u ``--cikti``).

Kullanım:
    python scripts/arge/hiz/json_olcum.py --tekrar 3 \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/hiz/json_olcum.json \
        <dosya.json> [<dosya.json> ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import time
from pathlib import Path


def _olc(fn, tekrar: int) -> tuple[float, float, bytes]:
    duvar, islemci, son = [], [], b""
    for _ in range(tekrar):
        t0, c0 = time.perf_counter(), time.process_time()
        out = fn()
        duvar.append(time.perf_counter() - t0)
        islemci.append(time.process_time() - c0)
        son = out if isinstance(out, bytes) else out.encode("utf-8")
    return statistics.median(duvar), statistics.median(islemci), son


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dosyalar", nargs="+", type=Path)
    ap.add_argument("--tekrar", type=int, default=3)
    ap.add_argument("--cikti", type=Path)
    a = ap.parse_args()
    try:
        import orjson
    except ImportError:  # pragma: no cover
        orjson = None
    sonuc = {"python": platform.python_version(), "makine": platform.machine(),
             "orjson": getattr(orjson, "__version__", None), "dosyalar": []}
    print("| Dosya | MB | yükleme sn | indent=2 ascii=False (ürün, ghidra_output) | indent=2 ascii=True (ürün, static/) | indent=None | orjson INDENT_2 | orjson = ürün baytı? |")
    print("|---|---|---|---|---|---|---|---|")
    for p in a.dosyalar:
        p = p.expanduser()
        raw = p.read_bytes()
        t0 = time.perf_counter()
        data = json.loads(raw)
        yuk = time.perf_counter() - t0
        r = {"dosya": str(p), "bayt": len(raw), "yukleme_sn": yuk}
        d1, c1, b1 = _olc(lambda: json.dumps(data, indent=2, ensure_ascii=False, default=str), a.tekrar)
        d2, c2, b2 = _olc(lambda: json.dumps(data, indent=2, ensure_ascii=True, default=str), a.tekrar)
        d3, c3, _ = _olc(lambda: json.dumps(data, ensure_ascii=False, default=str), a.tekrar)
        r.update({"indent2_utf8": [d1, c1], "indent2_ascii": [d2, c2], "indent_none": [d3, c3],
                  "urun_bayt_ayni_mi_dosyayla": b1 == raw,
                  "sha256_urun": hashlib.sha256(b1).hexdigest()})
        if orjson is not None:
            d4, c4, b4 = _olc(lambda: orjson.dumps(data, option=orjson.OPT_INDENT_2, default=str), a.tekrar)
            r["orjson_indent2"] = [d4, c4]
            r["orjson_bayt_ayni"] = b4 == b1
            if b4 != b1:
                # ilk fark konumu
                i = next((k for k, (x, y) in enumerate(zip(b4, b1)) if x != y), min(len(b4), len(b1)))
                r["orjson_ilk_fark"] = {"konum": i, "orjson": b4[max(0, i - 40):i + 40].decode("utf-8", "replace"),
                                        "urun": b1[max(0, i - 40):i + 40].decode("utf-8", "replace")}
        else:
            d4 = c4 = None
        sonuc["dosyalar"].append(r)
        f = lambda d, c: "%.2f sn (işlemci %.2f)" % (d, c)
        print("| %s | %.1f | %.2f | %s | %s | %s | %s | %s |" % (
            p.name, len(raw) / 1e6, yuk, f(d1, c1), f(d2, c2), f(d3, c3),
            f(d4, c4) if d4 is not None else "—",
            r.get("orjson_bayt_ayni", "—")))
        if "orjson_ilk_fark" in r:
            print("   ilk fark:", r["orjson_ilk_fark"])
        print("   ürün çıktısı dosyayla bayt bayt aynı mı (yeniden üretim denetimi):", r["urun_bayt_ayni_mi_dosyayla"])
        del data
    if a.cikti:
        c = a.cikti.expanduser()
        c.parent.mkdir(parents=True, exist_ok=True)
        c.write_text(json.dumps(sonuc, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
