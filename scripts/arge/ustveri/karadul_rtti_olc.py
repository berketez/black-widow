"""Karadul'un VAR OLAN `cpp_rtti.CppRttiAnalyzer`'ı aynı ikililerde ne veriyor? (ürün kodu yalnız çağrılır)

Kullanım:
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python scripts/arge/ustveri/karadul_rtti_olc.py <ikili> [<ikili> …]
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def main():
    from karadul.analyzers.cpp_rtti import CppRttiAnalyzer
    for path in sys.argv[1:]:
        t = time.time()
        try:
            res = CppRttiAnalyzer().analyze(Path(path))
            cls = res.hierarchy.classes
            r = {"ikili": path, "abi": res.abi, "sinif": len(cls),
                 "vtable_olan": sum(1 for c in cls if c.vtable_addr),
                 "yontem": sum(len(c.methods) for c in cls),
                 "adli_yontem": sum(1 for c in cls for m in c.methods if m.get("name")),
                 "sure_sn": round(time.time() - t, 1)}
        except Exception as exc:  # ürün kodunun hatası da bir ölçümdür
            r = {"ikili": path, "hata": f"{type(exc).__name__}: {exc}"[:200], "sure_sn": round(time.time() - t, 1)}
        print(json.dumps(r, ensure_ascii=False))


if __name__ == "__main__":
    main()
