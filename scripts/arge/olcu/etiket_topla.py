#!/usr/bin/env python3
"""ÖLÇÜ hattı kalem 1: var olan (aday ad, GT adı, hüküm) üçlülerini tek tabloda topla.

Bütün kümeler geliştirme setidir ve bütün hükümler vekil (Claude Opus ajanı) hükmüdür; insan
etiketi yoktur (``DEFTER.md`` §1). Kilitli setlerin hiçbir dosyası okunmaz.

Çıktı: ``etiketler.jsonl`` (satır başına bir üçlü) + ``etiket_envanteri.json`` (sayımlar, sha256).

Kullanım (depo kökünden):
    PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcu/etiket_topla.py \
        --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcu
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
G4 = REPO / "docs" / "arge" / "2026-10-19_g4_etiketleme" / "veri"
P15C = Path.home() / "karadul_olcum" / "runs" / "onarim-2026-11-18" / "P15c"
V1 = REPO / "workspaces" / "2026-10-15_oturum_scratchpad" / "tarif"
RUBRIK_ETIKETLERI_V2 = ("tam", "dogru_tarif", "yalniz_alan", "yanlis")

G4_KUMELERI = (
    # (küme adı, anahtar, etiket, program, etiketçi, kör mü)
    ("G4-L1-tmux", "anahtar_tmux_385_kor.json", "etiket_L1_tmux385.jsonl", "tmux", "L1", True),
    ("G4-L3-tmux", "anahtar_tmux_200_kor.json", "etiket_L3_tmux200.jsonl", "tmux", "L3", True),
    ("G4-L2-tmux-gt", "anahtar_tmux_200_gt.json", "etiket_L2_tmux200gt.jsonl", "tmux", "L2", False),
    ("G4-L3-htop", "anahtar_htop_kor.json", "etiket_L3_htop.jsonl", "htop", "L3", True),
)


def sha256(yol: Path) -> str:
    return hashlib.sha256(yol.read_bytes()).hexdigest()


def jsonl(yol: Path) -> list[dict]:
    return [json.loads(s) for s in yol.read_text(encoding="utf-8").splitlines() if s.strip()]


def g4() -> tuple[list[dict], dict]:
    satirlar, kunye = [], {}
    for kume, anahtar, etiket, program, etiketci, kor in G4_KUMELERI:
        ogeler = json.loads((G4 / anahtar).read_text(encoding="utf-8"))["ogeler"]
        etiketler = {e["id"]: e for e in jsonl(G4 / etiket)}
        for kimlik, o in sorted(ogeler.items()):
            hukum = etiketler[kimlik]["etiket"]
            # etiket_puan.py kuralı: ``tam`` anahtardaki tam eşleşmeden gelir (status == tp)
            son = "tam" if o["status"] == "tp" else hukum
            if son == "tam" and o["status"] != "tp":
                son = "dogru_tarif"     # GT görünür kipte değerlendiricinin biçim farkına verdiği ``tam``
            satirlar.append({"kume": kume, "id": kimlik, "birim": f"mac/{program}", "program": program,
                             "adres": o["addr"], "aday": o["aday"], "gt": o["gt"], "etiket": son,
                             "ham_etiket": hukum, "yem": bool(o["yem"]), "etiketci": etiketci, "kor": kor,
                             "rubrik": 2, "kanal": "taban-v2-62ad154"})
        kunye[kume] = {"anahtar_sha256": sha256(G4 / anahtar), "etiket_sha256": sha256(G4 / etiket)}
    return satirlar, kunye


def p15c() -> tuple[list[dict], dict]:
    kayitlar = json.loads((P15C / "ozellik_gelistirme_T.json").read_text(encoding="utf-8"))
    satirlar, gorulen = [], set()
    for i, k in enumerate(kayitlar):
        cift = (k["ad"], k["gt"])
        program = k["ikili"].split("/")[-2] if k["ikili"].count("/") == 2 else k["ikili"].split("/")[-1]
        satirlar.append({"kume": "P15c", "id": f"p15c-{i:03d}", "birim": k["ikili"], "program": program,
                         "adres": k["adres"], "aday": k["ad"], "gt": [k["gt"]], "etiket": k["etiket"],
                         "ham_etiket": k["etiket"], "yem": False, "etiketci": "P15c", "kor": False, "rubrik": 2,
                         "kanal": f"imza:{k['yontem']}", "tekil_cift": cift not in gorulen})
        gorulen.add(cift)
    return satirlar, {"P15c": {"ozellik_sha256": sha256(P15C / "ozellik_gelistirme_T.json"),
                               "etiket_sha256": sha256(P15C / "etiket_gelistirme.json")}}


def v1() -> tuple[list[dict], dict]:
    satirlar, kunye = [], {}
    for program in ("tmux", "htop"):
        ogeler = jsonl(V1 / f"etiket_{program}.jsonl")
        ajan = {e["id"]: e for e in jsonl(V1 / f"etiket_ajan_{program}.jsonl")}
        insan_dolu = sum(1 for o in ogeler if o.get("etiket") is not None)
        for o in ogeler:
            satirlar.append({"kume": f"V1-ajan-{program}", "id": o["id"], "birim": f"mac/{program}",
                             "program": program, "adres": o["addr"], "aday": o["pred"], "gt": o["gt"],
                             "etiket": "tam" if o["otomatik"] == "tp" else ajan[o["id"]]["etiket"],
                             "ham_etiket": ajan[o["id"]]["etiket"], "yem": False, "etiketci": "V1-ajan",
                             "kor": True, "rubrik": 1, "kanal": "urun-2026-10-15"})
        kunye[f"V1-ajan-{program}"] = {"insan_alani_dolu": insan_dolu, "satir": len(ogeler),
                                       "ana_oturum_etiketi_dolu": sum(1 for o in ogeler if o.get("etiket_claude")),
                                       "etiket_sha256": sha256(V1 / f"etiket_ajan_{program}.jsonl")}
    return satirlar, kunye


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cikti", type=Path, required=True)
    a = ap.parse_args()
    a.cikti.mkdir(parents=True, exist_ok=True)
    satirlar, kunye = [], {}
    for kaynak in (g4, p15c, v1):
        s, k = kaynak()
        satirlar.extend(s)
        kunye.update(k)
    for s in satirlar:
        if s["etiket"] not in RUBRIK_ETIKETLERI_V2:
            raise SystemExit(f"beklenmeyen etiket: {s}")
    (a.cikti / "etiketler.jsonl").write_text(
        "".join(json.dumps(s, ensure_ascii=False, sort_keys=True) + "\n" for s in satirlar), encoding="utf-8")
    envanter = {}
    for kume in sorted({s["kume"] for s in satirlar}):
        ks = [s for s in satirlar if s["kume"] == kume]
        ana = [s for s in ks if not s["yem"]]
        envanter[kume] = {
            "satir": len(ks), "ana": len(ana), "yem": len(ks) - len(ana),
            "tekil_cift": len({(s["aday"], tuple(s["gt"])) for s in ana}),
            "etiket": dict(sorted(Counter(s["etiket"] for s in ana).items())),
            "birim": dict(sorted(Counter(s["birim"] for s in ana).items())),
            "etiketci": sorted({s["etiketci"] for s in ks}), "kor": ks[0]["kor"], "rubrik": ks[0]["rubrik"],
            "insan_etiketi": 0, **kunye.get(kume, {})}
    l1 = {s["adres"] for s in satirlar if s["kume"] == "G4-L1-tmux" and not s["yem"]}
    l3 = {s["adres"] for s in satirlar if s["kume"] == "G4-L3-tmux" and not s["yem"]}
    envanter["_ortak_L1_L3_tmux"] = len(l1 & l3)
    envanter["_toplam_ana_uclu"] = sum(v["ana"] for k, v in envanter.items() if isinstance(v, dict))
    (a.cikti / "etiket_envanteri.json").write_text(
        json.dumps(envanter, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(envanter, ensure_ascii=False, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
