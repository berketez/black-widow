"""G4 etiketleme analizi (ön kayıt: onkayit.md §3).

Girdi: bu dizindeki veri/ (anahtarlar, amaç ve etiket dosyaları; gövdeli paketler depoda değil,
onkayit.md §1'deki komutla yeniden üretilir).
Çıktı: bu dizinde sonuc.json; özet terminale.

Oranlar ve Wilson aralıkları scripts/measurement/etiket_puan.py'den gelir (tek kaynak);
burada yalnız ön kayıttaki ek analizler hesaplanır: kör-kör uyum (Cohen kappa) ve
çapraz atıflı öğelerin bileşimi.
"""
from __future__ import annotations

import importlib.util
import json
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
V = Path(__file__).resolve().parent / "veri"
OUT = Path(__file__).resolve().parent / "sonuc.json"
BOOT_SEED = 2026101905  # ön kayıt §3 madde 2

_spec = importlib.util.spec_from_file_location("etiket_puan", REPO / "scripts" / "measurement" / "etiket_puan.py")
ep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ep)

YAKIN = {"tam", "dogru_tarif"}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def key_items(pkg: str) -> dict:
    return json.loads((V / f"anahtar_{pkg}.json").read_text(encoding="utf-8"))["ogeler"]


def labels_by_addr(pkg: str, folder: str) -> dict[str, str]:
    """Ana öğelerin nihai etiketi (tam anahtardan), adrese göre."""
    key = key_items(pkg)
    out = {}
    for r in load_jsonl(V / f"etiket_{folder}.jsonl"):
        item = key[r["id"]]
        if item["yem"]:
            continue
        out[item["addr"]] = "tam" if item["status"] == "tp" else r["etiket"]
    return out


def cohen_kappa(a: list[str], b: list[str]) -> float:
    n = len(a)
    cats = sorted(set(a) | set(b))
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[c] * cb[c] for c in cats) / (n * n)
    return (po - pe) / (1 - pe) if pe < 1 else 1.0


def composition(pkg: str, folder: str) -> dict:
    """Çapraz atıflı ve atıfsız öğelerde tam ve doğru tarif payı (bileşim mi, hoşgörü mü?)."""
    key = key_items(pkg)
    groups: dict[str, Counter] = {"capraz": Counter(), "atifsiz": Counter()}
    for r in load_jsonl(V / f"etiket_{folder}.jsonl"):
        item = key[r["id"]]
        if item["yem"]:
            continue
        g = "capraz" if item.get("capraz_atif", 0) > 0 else "atifsiz"
        final = "tam" if item["status"] == "tp" else r["etiket"]
        groups[g][final] += 1
        groups[g]["n"] += 1
    return {g: {"n": c["n"], "tam": c["tam"], "dogru_tarif": c["dogru_tarif"],
                "yalniz_alan": c["yalniz_alan"], "yanlis": c["yanlis"],
                "tam_payi": round(c["tam"] / c["n"], 4) if c["n"] else None,
                "dogru_tarif_payi": round(c["dogru_tarif"] / c["n"], 4) if c["n"] else None}
            for g, c in groups.items()}


def main() -> int:
    res: dict = {"onkayit": "docs/arge/2026-10-19_g4_etiketleme/onkayit.md"}

    # 1) Kör-kör uyum: L1 (tmux_385_kor) ile L3 (tmux_200_kor) ortak ana öğeleri
    l1 = labels_by_addr("tmux_385_kor", "L1_tmux385")
    l3 = labels_by_addr("tmux_200_kor", "L3_tmux200")
    common = sorted(set(l1) & set(l3))
    a = [l1[x] for x in common]
    b = [l3[x] for x in common]
    a_bin = ["yakin" if x in YAKIN else "degil" for x in a]
    b_bin = ["yakin" if x in YAKIN else "degil" for x in b]
    res["uyum_L1_L3"] = {
        "ortak_oge": len(common),
        "kappa_dort_etiket": round(cohen_kappa(a, b), 3),
        "kappa_yakin_degil": round(cohen_kappa(a_bin, b_bin), 3),
        "ham_uyum_dort_etiket": round(sum(x == y for x, y in zip(a, b)) / len(common), 3),
        "ham_uyum_yakin_degil": round(sum(x == y for x, y in zip(a_bin, b_bin)) / len(common), 3),
        "L1_yakin": sum(x == "yakin" for x in a_bin), "L3_yakin": sum(x == "yakin" for x in b_bin),
    }

    # 2) Bileşim: çapraz atıflı öğeler neden farklı?
    res["bilesim_tmux_L1"] = composition("tmux_385_kor", "L1_tmux385")
    res["bilesim_htop_L3"] = composition("htop_kor", "L3_htop")

    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
