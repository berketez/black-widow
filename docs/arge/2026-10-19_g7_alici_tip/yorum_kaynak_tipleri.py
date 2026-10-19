#!/usr/bin/env python3
"""YORUM İÇİN (ön kayıt dışı, ölçüt değil): en kötü 5 kümenin üyelerinin kaynaktaki 1. parametre tipi.

Kullanım:
    python3 -B yorum_kaynak_tipleri.py <veri_dizini> <çıktı.json>

Ölçümden SONRA yazıldı (2026-10-19, sonuç görüldükten sonra). Amaç yalnız saflığı
düşük kümelerin neden düşük olduğunu yorumlamak: küme tip olarak mı yanlış, yoksa aynı
tipi farklı modül önekleriyle adlandıran fonksiyonları mı topluyor? Kaynak tipleri hiçbir
ölçüte ve karara girmez. Yalnız V1, Ö1, saflığı %90'ın altındaki en büyük 5 küme.

Kaynaktan tanım çıkarımı basit bir düzenli ifadedir: satır başında (girintisiz) ad, ayraç
içinde iç içe ayraç içermeyen parametre listesi, ardından `{`. İşlev işaretçili parametre
listeleri ve makroyla üretilen tanımlar (RB_GENERATE) bulunamaz; "bulunamadı" diye sayılır.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from olcut import PURITY_THRESHOLD, cluster_purity, prefix_set  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
SRC = {
    "tmux": REPO / "workspaces/2026-10-15_oturum_scratchpad/src/tmux-dl/tmux-3.8",
    "htop": REPO / "workspaces/2026-10-15_oturum_scratchpad/src/htop-dl/htop-3.5.3",
}
_DEF = re.compile(r"(?m)^(?![ \t#])(?:[\w*][\w*\s]*?[\s*])?(\w+)\s*\(([^()]*)\)\s*\{")
_KW = {"if", "while", "for", "switch", "return", "sizeof", "do", "else"}


def first_param_types(root: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for path in root.rglob("*.c"):
        text = path.read_text(errors="replace")
        for m in _DEF.finditer(text):
            name, params = m.group(1), m.group(2)
            if name in _KW:
                continue
            first = params.split(",")[0].strip()
            first = re.sub(r"\b(const|__unused|volatile)\b", "", first)
            ids = re.findall(r"\w+", first)
            if not ids or first.strip() == "void":
                out[name].add("(parametre yok)")
                continue
            typ = first[: first.rfind(ids[-1])] if len(ids) > 1 else first
            typ = re.sub(r"\s+", " ", typ.replace("*", " * ")).strip()
            typ = re.sub(r"(\* )+\*", lambda x: x.group(0).replace(" ", ""), typ)
            out[name].add(typ.replace(" *", " *").strip())
    return out


def main() -> int:
    veri, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    result = {}
    for prog, root in SRC.items():
        types = first_param_types(root)
        dump = json.loads((veri / f"{prog}_V1_kumeler.json").read_text())
        cand = []
        for ms in dump["kumeler"]:
            ev = [m for m in ms if m["bekleyen"] and prefix_set(m["gt"], 1)]
            if len(ev) < 2:
                continue
            best, n, _ = cluster_purity([prefix_set(m["gt"], 1) for m in ev])
            if best / n < PURITY_THRESHOLD:
                cand.append((-n, best / n, min(m["adres"] for m in ms), ev))
        cand.sort(key=lambda x: x[:3])
        # Bütün değerlendirilen V1 kümeleri (yorum): kaynak tipine göre ağırlıklı saflık
        tb = tn = clusters = 0
        for ms in dump["kumeler"]:
            ev = [m for m in ms if m["bekleyen"] and prefix_set(m["gt"], 1)]
            if len(ev) < 2:
                continue
            tys = []
            for m in ev:
                ts = set()
                for g in m["gt"]:
                    ts |= types.get(g, set())
                if len(ts) == 1:
                    tys.append(next(iter(ts)))
            if len(tys) >= 2:
                clusters += 1
                tb += Counter(tys).most_common(1)[0][1]
                tn += len(tys)
        result.setdefault("_tum_kumeler", {})[prog] = {
            "kume": clusters, "tipi_bulunan_uye": tn,
            "agirlikli_tip_saflik": tb / tn if tn else None}
        rows = []
        for negn, pur, _, ev in cand[:5]:
            cnt: Counter = Counter()
            for m in ev:
                ts = set()
                for g in m["gt"]:
                    ts |= types.get(g, set())
                cnt["bulunamadı" if not ts else (next(iter(ts)) if len(ts) == 1
                                                 else "belirsiz: " + " | ".join(sorted(ts)))] += 1
            found = sum(v for k, v in cnt.items() if k != "bulunamadı")
            top = [k for k, _ in cnt.most_common() if k != "bulunamadı"]
            rows.append({"uye": -negn, "o1_saflik": pur, "tipler": cnt.most_common(8),
                         "bulunan": found,
                         "en_sik_tip_payi_bulunanlar_icinde": (cnt[top[0]] / found) if found else None})
        result[prog] = rows
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    for prog, rows in result.items():
        if prog.startswith("_"):
            print("==", prog, rows)
            continue
        print("==", prog)
        for r in rows:
            print(f"  üye {r['uye']}, Ö1 {r['o1_saflik']:.3f}, tip payı "
                  f"{r['en_sik_tip_payi_bulunanlar_icinde']}, bulunan {r['bulunan']}: {r['tipler']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
