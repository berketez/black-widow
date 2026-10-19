#!/usr/bin/env python3
"""Kör etiket puanlayıcısı (protokol v2) — plan v2 G4.

Yordam: ``docs/arge/etiket_protokolu_v2.md``. Paket: ``etiket_paketi.py``.

Kullanım
--------
    # Program başına oranlar (Wilson %95) ve yem kabul oranı. Bir değerlendiricinin
    # bir dalgadaki bütün paketleri birlikte verilirse ``yem_toplam`` o
    # değerlendiricinin birleşik yem kabul oranıdır.
    python scripts/measurement/etiket_puan.py puan \
        --anahtar paket/tmux_kor/anahtar.json --etiket etiket_tmux.jsonl \
        [--amac amac_tmux.jsonl] [--capraz-atifsiz] [--cikti puan.json]

    # Çok adaylı kip (G6/G7): sistem başına oranlar, sistem çiftleri arasında eşli
    # yakın farkı (program içinde katmanlı bootstrap, kesin McNemar), yem kabulü,
    # güven varsa risk-kapsam eşik tablosu (protokol §13)
    python scripts/measurement/etiket_puan.py puan-cok \
        --anahtar paket/tmux_cok/anahtar.json --etiket etiket_cok.jsonl \
        [--amac amac_cok.jsonl] [--capraz-atifsiz] [--tohum N] [--cikti puan_cok.json]

    # Cömertlik deneyi: aynı id'ler, gt'li ve gt'siz iki etiket dosyası
    python scripts/measurement/etiket_puan.py comertlik \
        --anahtar-gtli paket/tmux_gt/anahtar.json --etiket-gtli etiket_gt.jsonl \
        --anahtar-gtsiz paket/tmux_kor/anahtar.json --etiket-gtsiz etiket_kor.jsonl \
        [--tohum 20261019] [--tekrar 10000] [--cikti comertlik.json]

Girdi
-----
Etiket dosyası (jsonl), her satır: ``id``, ``amac`` (aşama 1'de yazılan amaç
cümlesi), ``etiket`` (``tam`` | ``dogru_tarif`` | ``yalniz_alan`` | ``yanlis``),
``gerekce``. Ek alanlar yok sayılır. Eksik ya da fazla id, yinelenen id,
geçersiz etiket ve boş amaç açık hatadır. ``--amac`` verilirse etiket
dosyasındaki amaç cümleleri aşama 1 dosyasıyla aynı olmak zorundadır
(aday görüldükten sonra değiştirilmemiş).

Nihai etiket
------------
- Yem öğeleri ana sayılara girmez; ``tam``/``dogru_tarif`` etiketlenen yem
  "kabul edilmiş" sayılır.
- ``tam`` = özgün adın kendisi (rubrik). Kör kipte değerlendirici özgün adı
  bilemez; bu yüzden anahtardaki otomatik tam eşleşme (``status == "tp"``)
  ``tam`` olur, değerlendiricinin ``tp`` olmayan öğeye verdiği ``tam``
  ``dogru_tarif`` sayılır. İki durum da ``tutarlilik`` altında listelenir.
- yakın = tam + dogru_tarif.

Duyarlılık analizi
------------------
``--capraz-atifsiz``: anahtarda ``capraz_atif > 0`` olan öğeler (gerçek adı
paketteki başka bir öğenin gövdesinde geçenler; ana ve yem) dışarıda bırakılır,
oranlar yeniden hesaplanır. Dışarıda kalan sayılar çıktıda yazar.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from statistics import NormalDist
from typing import Any, Iterable, Optional

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from etiket_paketi import (  # noqa: E402
    KIP_COK, KIP_GT, KIP_KOR, LISTE_SINIRI, PAKET_SEMASI, PAKET_SEMASI_COK,
)

PUAN_SEMASI = "karadul-etiket-puan/1"
GECERLI_ETIKETLER = ("tam", "dogru_tarif", "yalniz_alan", "yanlis")
YAKIN_ETIKETLER = frozenset({"tam", "dogru_tarif"})
RAPOR_ORANLARI = ("tam", "yakin", "yalniz_alan", "yanlis")
ETIKET_ALANLARI = ("id", "amac", "etiket", "gerekce")
OTOMATIK_TAM_DURUMU = "tp"
# Çok adaylı kip
PUAN_SEMASI_COK = "karadul-etiket-puan-cok/1"
COK_ETIKET_ALANLARI = ("id", "aday_id", "amac", "etiket", "gerekce")
CEKIMSER = "cekimser"

GUVEN_DUZEYI = 0.95
BOOTSTRAP_TEKRAR = 10_000
BOOTSTRAP_TOHUM = 20261019
ONDALIK = 6


class PuanHatasi(ValueError):
    """Girdi ya da protokol ihlali (açık hata)."""


# ---------------------------------------------------------------------------
# İstatistik
# ---------------------------------------------------------------------------

def z_degeri(guven: float = GUVEN_DUZEYI) -> float:
    return NormalDist().inv_cdf(1 - (1 - guven) / 2)


def wilson(k: int, n: int, guven: float = GUVEN_DUZEYI) -> tuple[float, float]:
    """Oran k/n için Wilson skor aralığı."""
    if n <= 0:
        raise PuanHatasi("Wilson aralığı: n = 0")
    if not 0 <= k <= n:
        raise PuanHatasi(f"Wilson aralığı: k={k}, n={n}")
    z = z_degeri(guven)
    z2 = z * z
    p = k / n
    den = 1 + z2 / n
    center = (p + z2 / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / den
    # k = 0 ve k = n uçları kesin olarak 0 ve 1'dir (kayan nokta artığı bırakılmaz).
    lo = 0.0 if k == 0 else max(0.0, center - half)
    hi = 1.0 if k == n else min(1.0, center + half)
    return lo, hi


def oran_ozeti(k: int, n: int, guven: float = GUVEN_DUZEYI) -> dict[str, Any]:
    if n == 0:
        return {"k": 0, "n": 0, "oran": None, "alt": None, "ust": None}
    lo, hi = wilson(k, n, guven)
    return {"k": k, "n": n, "oran": round(k / n, ONDALIK), "alt": round(lo, ONDALIK), "ust": round(hi, ONDALIK)}


def _yuzdelik(sirali: list[float], q: float) -> float:
    """Doğrusal aradeğerli yüzdelik (sıralı liste)."""
    pos = q * (len(sirali) - 1)
    lo = math.floor(pos)
    hi = min(lo + 1, len(sirali) - 1)
    return sirali[lo] + (sirali[hi] - sirali[lo]) * (pos - lo)


def bootstrap_fark(farklar: list[int], tohum: int, tekrar: int = BOOTSTRAP_TEKRAR,
                   guven: float = GUVEN_DUZEYI) -> tuple[float, float]:
    """Eşli öğe farklarının (gtli - gtsiz, her biri -1/0/1) ortalaması için yüzdelik aralık.

    Öğeler yerine koyarak yeniden örneklenir; ``tohum`` aynıysa sonuç aynıdır.
    """
    if not farklar:
        raise PuanHatasi("bootstrap: öğe yok")
    if tekrar <= 0:
        raise PuanHatasi("bootstrap: tekrar sayısı pozitif olmalı")
    rng = random.Random(tohum)
    n = len(farklar)
    ornek = sorted(sum(rng.choices(farklar, k=n)) / n for _ in range(tekrar))
    alfa = (1 - guven) / 2
    return _yuzdelik(ornek, alfa), _yuzdelik(ornek, 1 - alfa)


# ---------------------------------------------------------------------------
# Girdi
# ---------------------------------------------------------------------------

def _read_jsonl(path: Path) -> list[tuple[int, Any]]:
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append((n, json.loads(line)))
        except json.JSONDecodeError as e:
            raise PuanHatasi(f"{path}:{n}: JSON değil ({e})") from None
    return out


def _short(ids: Iterable[str]) -> str:
    ids = sorted(ids)
    more = f" ... (+{len(ids) - LISTE_SINIRI})" if len(ids) > LISTE_SINIRI else ""
    return ", ".join(ids[:LISTE_SINIRI]) + more


def load_labels(paths: Iterable[Path]) -> dict[str, dict[str, Any]]:
    labels: dict[str, dict[str, Any]] = {}
    for path in paths:
        for n, rec in _read_jsonl(path):
            where = f"{path}:{n}"
            if not isinstance(rec, dict):
                raise PuanHatasi(f"{where}: kayıt nesne değil")
            lacking = [k for k in ETIKET_ALANLARI if k not in rec]
            if lacking:
                raise PuanHatasi(f"{where}: eksik alan {lacking}")
            iid = rec["id"]
            if not isinstance(iid, str) or not iid:
                raise PuanHatasi(f"{where}: id geçersiz: {iid!r}")
            if rec["etiket"] not in GECERLI_ETIKETLER:
                raise PuanHatasi(f"{where} ({iid}): geçersiz etiket {rec['etiket']!r}; "
                                 f"geçerli: {', '.join(GECERLI_ETIKETLER)}")
            if not isinstance(rec["amac"], str) or not rec["amac"].strip():
                raise PuanHatasi(f"{where} ({iid}): amaç cümlesi boş")
            if not isinstance(rec["gerekce"], str):
                raise PuanHatasi(f"{where} ({iid}): gerekçe metin olmalı")
            if iid in labels:
                raise PuanHatasi(f"{where}: id iki kez etiketlenmiş: {iid}")
            labels[iid] = rec
    return labels


def load_keys(paths: Iterable[Path]) -> dict[str, dict[str, Any]]:
    """Anahtar dosyaları -> id -> öğe (``_program`` ve ``_kip`` eklenmiş)."""
    keys: dict[str, dict[str, Any]] = {}
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        kunye = data.get("kunye") if isinstance(data, dict) else None
        ogeler = data.get("ogeler") if isinstance(data, dict) else None
        if not isinstance(kunye, dict) or not isinstance(ogeler, dict):
            raise PuanHatasi(f"{path}: anahtar dosyası değil (kunye/ogeler yok)")
        if kunye.get("sema") != PAKET_SEMASI:
            raise PuanHatasi(f"{path}: şema {kunye.get('sema')!r}, beklenen {PAKET_SEMASI!r}")
        if kunye.get("kip") not in (KIP_KOR, KIP_GT):
            raise PuanHatasi(f"{path}: bilinmeyen kip {kunye.get('kip')!r}")
        for iid, item in ogeler.items():
            if iid in keys:
                raise PuanHatasi(f"{path}: id başka bir anahtarda da var: {iid}")
            for k in ("gt", "status", "yem"):
                if k not in item:
                    raise PuanHatasi(f"{path} ({iid}): anahtar öğesinde '{k}' yok")
            keys[iid] = {**item, "_program": kunye.get("program"), "_kip": kunye["kip"]}
    return keys


def check_ids(labels: dict[str, Any], keys: dict[str, Any], what: str = "etiket") -> None:
    missing = set(keys) - set(labels)
    extra = set(labels) - set(keys)
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"eksik {len(missing)} id: {_short(missing)}")
        if extra:
            parts.append(f"fazla {len(extra)} id: {_short(extra)}")
        raise PuanHatasi(f"{what} dosyası anahtarla uyuşmuyor: " + "; ".join(parts))


def load_stage1(paths: Iterable[Path]) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in paths:
        for n, rec in _read_jsonl(path):
            if not isinstance(rec, dict) or not isinstance(rec.get("id"), str) or not isinstance(rec.get("amac"), str):
                raise PuanHatasi(f"{path}:{n}: aşama 1 kaydı id + amac içermeli")
            if rec["id"] in out:
                raise PuanHatasi(f"{path}:{n}: id iki kez: {rec['id']}")
            out[rec["id"]] = rec["amac"]
    return out


def check_amac_unchanged(labels: dict[str, dict[str, Any]], stage1: dict[str, str]) -> None:
    missing = sorted(set(labels) - set(stage1))
    if missing:
        raise PuanHatasi(f"aşama 1 dosyasında amaç cümlesi yok: {_short(missing)}")
    changed = sorted(i for i in labels if labels[i]["amac"].strip() != stage1[i].strip())
    if changed:
        raise PuanHatasi(f"amaç cümlesi aday görüldükten sonra değişmiş: {_short(changed)}")


# ---------------------------------------------------------------------------
# Puanlama
# ---------------------------------------------------------------------------

def final_label(item: dict[str, Any], etiket: str) -> str:
    """Rubrikteki nihai etiket (bkz. modül belgesi, "Nihai etiket")."""
    if item["yem"]:
        return etiket
    if item["status"] == OTOMATIK_TAM_DURUMU:
        return "tam"
    if etiket == "tam":
        return "dogru_tarif"
    return etiket


def _programs(keys: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    by_prog: dict[str, list[str]] = defaultdict(list)
    for iid, item in keys.items():
        by_prog[str(item["_program"])].append(iid)
    return {p: sorted(ids) for p, ids in sorted(by_prog.items())}


def has_cross_reference(item: dict[str, Any]) -> bool:
    """Öğenin gerçek adı paketteki başka bir öğenin gövdesinde geçiyor mu (anahtardaki ``capraz_atif``)."""
    if "capraz_atif" not in item:
        raise PuanHatasi("anahtarda 'capraz_atif' yok: paket bu araç sürümüyle yeniden üretilmeli")
    return item["capraz_atif"] > 0


def _drop_cross_referenced(ids: list[str], keys: dict[str, dict[str, Any]]) -> tuple[list[str], dict[str, int]]:
    kept, dropped = [], {"ana": 0, "yem": 0}
    for i in ids:
        if has_cross_reference(keys[i]):
            dropped["yem" if keys[i]["yem"] else "ana"] += 1
        else:
            kept.append(i)
    return kept, dropped


def score(labels: dict[str, dict[str, Any]], keys: dict[str, dict[str, Any]],
          guven: float = GUVEN_DUZEYI, *, capraz_atifsiz: bool = False) -> dict[str, Any]:
    """Program başına oranlar; ``yem_toplam`` verilen bütün paketlerin yemlerini birleştirir.

    ``capraz_atifsiz``: gerçek adı başka bir öğenin gövdesinde geçen öğeler (ana ve
    yem) dışarıda bırakılarak oranlar yeniden hesaplanır (duyarlılık analizi).
    """
    check_ids(labels, keys)
    out: dict[str, Any] = {"sema": PUAN_SEMASI, "guven_duzeyi": guven,
                           "capraz_atifsiz": capraz_atifsiz, "programlar": {}}
    all_decoys: list[str] = []
    for prog, ids in _programs(keys).items():
        kips = sorted({keys[i]["_kip"] for i in ids})
        if len(kips) != 1:
            raise PuanHatasi(f"{prog}: aynı programda farklı kipler karışmış: {kips}")
        dropped = {"ana": 0, "yem": 0}
        if capraz_atifsiz:
            ids, dropped = _drop_cross_referenced(ids, keys)
        main = [i for i in ids if not keys[i]["yem"]]
        decoys = [i for i in ids if keys[i]["yem"]]
        if not main:
            raise PuanHatasi(f"{prog}: ana öğe yok")
        final = {i: final_label(keys[i], labels[i]["etiket"]) for i in main}
        counts = Counter(final.values())
        n = len(main)
        k = {"tam": counts["tam"], "yakin": sum(counts[e] for e in YAKIN_ETIKETLER),
             "yalniz_alan": counts["yalniz_alan"], "yanlis": counts["yanlis"]}
        raw = Counter(labels[i]["etiket"] for i in main)
        accepted = [i for i in decoys if labels[i]["etiket"] in YAKIN_ETIKETLER]
        out["programlar"][prog] = {
            "kip": kips[0],
            "n": n,
            "oranlar": {name: oran_ozeti(k[name], n, guven) for name in RAPOR_ORANLARI},
            "ham_etiketler": {e: raw[e] for e in GECERLI_ETIKETLER},
            "tutarlilik": {
                "tp_yakin_disi": [i for i in main
                                  if keys[i]["status"] == OTOMATIK_TAM_DURUMU
                                  and labels[i]["etiket"] not in YAKIN_ETIKETLER],
                "tam_ama_tp_degil": [i for i in main
                                     if keys[i]["status"] != OTOMATIK_TAM_DURUMU and labels[i]["etiket"] == "tam"],
            },
            "yem": {"n": len(decoys), "kabul": oran_ozeti(len(accepted), len(decoys), guven),
                    "kabul_edilen": accepted},
            "dislanan_capraz_atifli": dropped,
        }
        all_decoys.extend(decoys)
    accepted_all = [i for i in all_decoys if labels[i]["etiket"] in YAKIN_ETIKETLER]
    out["yem_toplam"] = {"n": len(all_decoys), "kabul": oran_ozeti(len(accepted_all), len(all_decoys), guven)}
    return out


_KEY_FIELDS_SAME = ("addr", "gt", "pred", "status", "aday", "yem", "capraz_atif", "_program")


def _comertlik_ozeti(ids: list[str], keys: dict[str, dict[str, Any]], lab_gt: dict[str, Any],
                     lab_kor: dict[str, Any], tohum: int, tekrar: int, guven: float) -> dict[str, Any]:
    a = [int(final_label(keys[i], lab_gt[i]["etiket"]) in YAKIN_ETIKETLER) for i in ids]
    b = [int(final_label(keys[i], lab_kor[i]["etiket"]) in YAKIN_ETIKETLER) for i in ids]
    n = len(ids)
    lo, hi = bootstrap_fark([x - y for x, y in zip(a, b)], tohum, tekrar, guven)
    return {
        "n": n,
        "yakin_gtli": oran_ozeti(sum(a), n, guven),
        "yakin_gtsiz": oran_ozeti(sum(b), n, guven),
        "fark": round((sum(a) - sum(b)) / n, ONDALIK),
        "fark_alt": round(lo, ONDALIK),
        "fark_ust": round(hi, ONDALIK),
        "ciftler": {
            "ikisi_yakin": sum(1 for x, y in zip(a, b) if x and y),
            "yalniz_gtli_yakin": sum(1 for x, y in zip(a, b) if x and not y),
            "yalniz_gtsiz_yakin": sum(1 for x, y in zip(a, b) if y and not x),
            "ikisi_yakin_degil": sum(1 for x, y in zip(a, b) if not x and not y),
        },
    }


def comertlik(lab_gt: dict[str, Any], lab_kor: dict[str, Any], keys_gt: dict[str, Any],
              keys_kor: dict[str, Any], *, tohum: int = BOOTSTRAP_TOHUM, tekrar: int = BOOTSTRAP_TEKRAR,
              guven: float = GUVEN_DUZEYI, capraz_atifsiz: bool = False) -> dict[str, Any]:
    """Aynı öğelerin gt'li ve gt'siz etiketleri -> yakın oran farkı ve eşli bootstrap aralığı."""
    if set(keys_gt) != set(keys_kor):
        raise PuanHatasi("gt'li ve gt'siz anahtarların id kümeleri farklı: aynı tohumla üretilmemiş")
    for iid in sorted(keys_gt):
        if {f: keys_gt[iid].get(f) for f in _KEY_FIELDS_SAME} != {f: keys_kor[iid].get(f) for f in _KEY_FIELDS_SAME}:
            raise PuanHatasi(f"{iid}: gt'li ve gt'siz anahtarda öğe farklı")
    if {v["_kip"] for v in keys_gt.values()} != {KIP_GT}:
        raise PuanHatasi("--anahtar-gtli gt_goster kipinde üretilmemiş")
    if {v["_kip"] for v in keys_kor.values()} != {KIP_KOR}:
        raise PuanHatasi("--anahtar-gtsiz kör kipte üretilmemiş")
    check_ids(lab_gt, keys_gt, "gt'li etiket")
    check_ids(lab_kor, keys_kor, "gt'siz etiket")
    keys = keys_kor
    ids_all = sorted(keys)
    dropped = {"ana": 0, "yem": 0}
    if capraz_atifsiz:
        ids_all, dropped = _drop_cross_referenced(ids_all, keys)
    main = [i for i in ids_all if not keys[i]["yem"]]
    decoys = [i for i in ids_all if keys[i]["yem"]]
    if not main:
        raise PuanHatasi("ana öğe yok")
    out: dict[str, Any] = {
        "sema": PUAN_SEMASI, "guven_duzeyi": guven,
        "capraz_atifsiz": capraz_atifsiz, "dislanan_capraz_atifli": dropped,
        "bootstrap": {"tohum": tohum, "tekrar": tekrar},
        "toplam": _comertlik_ozeti(main, keys, lab_gt, lab_kor, tohum, tekrar, guven),
        "programlar": {},
        "yem": {
            "gtli": oran_ozeti(sum(1 for i in decoys if lab_gt[i]["etiket"] in YAKIN_ETIKETLER), len(decoys), guven),
            "gtsiz": oran_ozeti(sum(1 for i in decoys if lab_kor[i]["etiket"] in YAKIN_ETIKETLER), len(decoys), guven),
        },
    }
    kept = set(main)
    for prog, ids in _programs(keys).items():
        pmain = [i for i in ids if i in kept]
        if pmain:
            out["programlar"][prog] = _comertlik_ozeti(pmain, keys, lab_gt, lab_kor, tohum, tekrar, guven)
    return out


# ---------------------------------------------------------------------------
# Çok adaylı kip (G6 LLM pilotu, G7 kanıt tavanı)
# ---------------------------------------------------------------------------

def bootstrap_fark_katmanli(katmanlar: list[list[int]], tohum: int, tekrar: int = BOOTSTRAP_TEKRAR,
                            guven: float = GUVEN_DUZEYI) -> tuple[float, float]:
    """Katmanlı eşli bootstrap: öğeler her katmanın (programın) içinde yeniden örneklenir.

    Tek katmanda ``bootstrap_fark`` ile aynı rastgele adımları izler, sonucu aynıdır.
    """
    katmanlar = [k for k in katmanlar if k]
    if not katmanlar:
        raise PuanHatasi("bootstrap: öğe yok")
    if tekrar <= 0:
        raise PuanHatasi("bootstrap: tekrar sayısı pozitif olmalı")
    rng = random.Random(tohum)
    n = sum(len(k) for k in katmanlar)
    ornek = sorted(sum(sum(rng.choices(katman, k=len(katman))) for katman in katmanlar) / n
                   for _ in range(tekrar))
    alfa = (1 - guven) / 2
    return _yuzdelik(ornek, alfa), _yuzdelik(ornek, 1 - alfa)


def mcnemar_kesin(b: int, c: int) -> float:
    """Kesin (binom) McNemar testi; uyuşmazlık çiftleri b ve c, iki yönlü p."""
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n)


def load_multi_keys(paths: Iterable[Path]) -> tuple[dict[str, dict[str, Any]], dict[str, tuple[str, dict[str, Any]]]]:
    """Çok adaylı anahtarlar -> (fonksiyon id -> öğe (+``_program``), aday_id -> (fonksiyon id, aday))."""
    funcs: dict[str, dict[str, Any]] = {}
    cands: dict[str, tuple[str, dict[str, Any]]] = {}
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        kunye = data.get("kunye") if isinstance(data, dict) else None
        ogeler = data.get("ogeler") if isinstance(data, dict) else None
        if not isinstance(kunye, dict) or not isinstance(ogeler, dict):
            raise PuanHatasi(f"{path}: anahtar dosyası değil (kunye/ogeler yok)")
        if kunye.get("sema") != PAKET_SEMASI_COK or kunye.get("kip") != KIP_COK:
            raise PuanHatasi(f"{path}: çok adaylı anahtar değil (şema {kunye.get('sema')!r}, kip {kunye.get('kip')!r})")
        for fid, item in ogeler.items():
            if fid in funcs:
                raise PuanHatasi(f"{path}: fonksiyon id başka bir anahtarda da var: {fid}")
            for k in ("gt", "adaylar", "sistemler", "capraz_atif"):
                if k not in item:
                    raise PuanHatasi(f"{path} ({fid}): anahtar öğesinde '{k}' yok")
            for aid, a in item["adaylar"].items():
                if aid in cands:
                    raise PuanHatasi(f"{path}: aday_id iki kez: {aid}")
                for k in ("aday", "tam", "yem", "sistemler"):
                    if k not in a:
                        raise PuanHatasi(f"{path} ({aid}): adayda '{k}' yok")
                cands[aid] = (fid, a)
            for system, entry in item["sistemler"].items():
                if entry.get("durum") == "aday" and entry.get("aday_id") not in item["adaylar"]:
                    raise PuanHatasi(f"{path} ({fid}): {system} adayı anahtarda yok")
            funcs[fid] = {**item, "_program": kunye.get("program")}
    return funcs, cands


def load_multi_labels(paths: Iterable[Path]) -> dict[str, dict[str, Any]]:
    """Çok adaylı etiketler -> aday_id -> kayıt (``id``, ``aday_id``, ``amac``, ``etiket``, ``gerekce``)."""
    labels: dict[str, dict[str, Any]] = {}
    for path in paths:
        for n, rec in _read_jsonl(path):
            where = f"{path}:{n}"
            if not isinstance(rec, dict):
                raise PuanHatasi(f"{where}: kayıt nesne değil")
            lacking = [k for k in COK_ETIKET_ALANLARI if k not in rec]
            if lacking:
                raise PuanHatasi(f"{where}: eksik alan {lacking}")
            aid = rec["aday_id"]
            if not isinstance(aid, str) or not aid:
                raise PuanHatasi(f"{where}: aday_id geçersiz: {aid!r}")
            if rec["etiket"] not in GECERLI_ETIKETLER:
                raise PuanHatasi(f"{where} ({aid}): geçersiz etiket {rec['etiket']!r}; "
                                 f"geçerli: {', '.join(GECERLI_ETIKETLER)}")
            if not isinstance(rec["amac"], str) or not rec["amac"].strip():
                raise PuanHatasi(f"{where} ({aid}): amaç cümlesi boş")
            if not isinstance(rec["gerekce"], str):
                raise PuanHatasi(f"{where} ({aid}): gerekçe metin olmalı")
            if aid in labels:
                raise PuanHatasi(f"{where}: aday iki kez etiketlenmiş: {aid}")
            labels[aid] = rec
    return labels


def check_multi_labels(labels: dict[str, dict[str, Any]], cands: dict[str, tuple[str, dict[str, Any]]],
                       stage1: Optional[dict[str, str]] = None) -> None:
    """Her aday bir kez etiketlenmiş, doğru fonksiyona bağlı; bir fonksiyonun bütün adaylarında
    aynı amaç cümlesi (verilmişse aşama 1 dosyasındakiyle aynı)."""
    check_ids(labels, cands, "çok adaylı etiket")
    wrong_owner = sorted(a for a in labels if labels[a]["id"] != cands[a][0])
    if wrong_owner:
        raise PuanHatasi(f"aday_id ile id uyuşmuyor: {_short(wrong_owner)}")
    amac_of: dict[str, set[str]] = defaultdict(set)
    for aid, rec in labels.items():
        amac_of[cands[aid][0]].add(rec["amac"].strip())
    split = sorted(f for f, s in amac_of.items() if len(s) > 1)
    if split:
        raise PuanHatasi(f"aynı fonksiyonun adaylarında farklı amaç cümlesi: {_short(split)}")
    if stage1 is not None:
        missing = sorted(set(amac_of) - set(stage1))
        if missing:
            raise PuanHatasi(f"aşama 1 dosyasında amaç cümlesi yok: {_short(missing)}")
        changed = sorted(f for f, s in amac_of.items() if s != {stage1[f].strip()})
        if changed:
            raise PuanHatasi(f"amaç cümlesi aday görüldükten sonra değişmiş: {_short(changed)}")


def final_multi_label(cand: dict[str, Any], etiket: str) -> str:
    """Tek adaylı ``final_label``'ın karşılığı: ``tam`` anahtardaki otomatik eşleşmeden gelir."""
    if cand["yem"]:
        return etiket
    if cand["tam"]:
        return "tam"
    if etiket == "tam":
        return "dogru_tarif"
    return etiket


def _system_outcomes(funcs: dict[str, dict[str, Any]], cands: dict[str, tuple[str, dict[str, Any]]],
                     labels: dict[str, dict[str, Any]], fids: list[str]) -> dict[str, dict[str, tuple]]:
    """sistem -> fonksiyon -> (sonuç, güven, çekimser nedeni); sonuç nihai etiket ya da ``cekimser``."""
    out: dict[str, dict[str, tuple]] = defaultdict(dict)
    for fid in fids:
        for system, entry in sorted(funcs[fid]["sistemler"].items()):
            aid = entry.get("aday_id")
            if entry.get("durum") != "aday" or aid is None:
                out[system][fid] = (CEKIMSER, entry.get("guven"), entry.get("neden") or "bos")
            else:
                out[system][fid] = (final_multi_label(cands[aid][1], labels[aid]["etiket"]), entry.get("guven"), None)
    return dict(sorted(out.items()))


def _system_stats(outcomes: dict[str, tuple], guven: float) -> dict[str, Any]:
    n = len(outcomes)
    named = Counter(o for o, _g, _r in outcomes.values() if o != CEKIMSER)
    v = sum(named.values())
    k_yakin = sum(named[e] for e in YAKIN_ETIKETLER)
    reasons = Counter(r for o, _g, r in outcomes.values() if o == CEKIMSER)
    return {
        "n": n,
        "verilen": v,
        "cekimser": n - v,
        "cekimser_nedenleri": dict(sorted(reasons.items())),
        "fonksiyon_paydasi": {"tam": oran_ozeti(named["tam"], n, guven), "yakin": oran_ozeti(k_yakin, n, guven),
                              "kapsam": oran_ozeti(v, n, guven), "cekimser": oran_ozeti(n - v, n, guven)},
        "verilen_paydasi": {"tam": oran_ozeti(named["tam"], v, guven), "yakin": oran_ozeti(k_yakin, v, guven),
                            "yalniz_alan": oran_ozeti(named["yalniz_alan"], v, guven),
                            "yanlis": oran_ozeti(named["yanlis"], v, guven)},
    }


def risk_coverage(outcomes: dict[str, tuple]) -> dict[str, Any]:
    """Güven eşiği tablosu: her eşikte verilen ad sayısı, kapsam, yanlış oranı ve yakın kapsamı.

    Eşikler adların güven değerleridir (azalan); güveni eşikten küçük olmayan adlar verilir.
    Güven hiç yoksa ``durum: yok``; bazı adlarda eksikse ``durum: eksik`` (tablo yok).
    """
    n = len(outcomes)
    named = [(g, o) for o, g, _r in outcomes.values() if o != CEKIMSER]
    with_conf = [x for x in named if x[0] is not None]
    if not with_conf:
        return {"durum": "yok", "esikler": []}
    if len(with_conf) != len(named):
        return {"durum": "eksik", "guvensiz_ad": len(named) - len(with_conf), "esikler": []}
    rows = []
    for t in sorted({g for g, _o in named}, reverse=True):
        acc = [o for g, o in named if g >= t]
        k = len(acc)
        rows.append({"esik": t, "verilen": k, "kapsam": round(k / n, ONDALIK),
                     "yanlis_orani": round(sum(o == "yanlis" for o in acc) / k, ONDALIK),
                     "yakin_kapsam": round(sum(o in YAKIN_ETIKETLER for o in acc) / n, ONDALIK)})
    return {"durum": "tamam", "esikler": rows}


def _pair_stats(ids_by_prog: dict[str, list[str]], oa: dict[str, tuple], ob: dict[str, tuple],
                tohum: int, tekrar: int, guven: float) -> dict[str, Any]:
    ids = [f for p in sorted(ids_by_prog) for f in ids_by_prog[p]]
    a = {f: int(oa[f][0] in YAKIN_ETIKETLER) for f in ids}
    b = {f: int(ob[f][0] in YAKIN_ETIKETLER) for f in ids}
    n = len(ids)
    lo, hi = bootstrap_fark_katmanli([[a[f] - b[f] for f in ids_by_prog[p]] for p in sorted(ids_by_prog)],
                                     tohum, tekrar, guven)
    n10 = sum(1 for f in ids if a[f] and not b[f])
    n01 = sum(1 for f in ids if b[f] and not a[f])
    return {
        "n": n,
        "yakin_a": oran_ozeti(sum(a.values()), n, guven),
        "yakin_b": oran_ozeti(sum(b.values()), n, guven),
        "fark": round((sum(a.values()) - sum(b.values())) / n, ONDALIK),
        "fark_alt": round(lo, ONDALIK),
        "fark_ust": round(hi, ONDALIK),
        "ciftler": {"ikisi_yakin": sum(1 for f in ids if a[f] and b[f]), "yalniz_a_yakin": n10,
                    "yalniz_b_yakin": n01, "ikisi_yakin_degil": sum(1 for f in ids if not a[f] and not b[f])},
        "mcnemar_p": round(mcnemar_kesin(n10, n01), ONDALIK),
    }


def score_multi(labels: dict[str, dict[str, Any]], funcs: dict[str, dict[str, Any]],
                cands: dict[str, tuple[str, dict[str, Any]]], *, tohum: int = BOOTSTRAP_TOHUM,
                tekrar: int = BOOTSTRAP_TEKRAR, guven: float = GUVEN_DUZEYI,
                capraz_atifsiz: bool = False) -> dict[str, Any]:
    """Sistem başına oranlar, sistem çiftleri arasında eşli yakın farkı, yem kabulü, risk-kapsam.

    Bir sistemin n'i, o sistemin satırı olan fonksiyonlardır (çekimser dahil). Çiftlerde iki
    sistemin de satırı olan fonksiyonlar kullanılır; bootstrap program içinde katmanlıdır.
    """
    check_multi_labels(labels, cands)
    fids = sorted(funcs)
    dropped = 0
    if capraz_atifsiz:
        kept = [f for f in fids if not has_cross_reference(funcs[f])]
        dropped, fids = len(fids) - len(kept), kept
    if not fids:
        raise PuanHatasi("puanlanacak fonksiyon yok")
    progs = _programs({f: funcs[f] for f in fids})
    outcomes = _system_outcomes(funcs, cands, labels, fids)
    out: dict[str, Any] = {
        "sema": PUAN_SEMASI_COK, "guven_duzeyi": guven, "capraz_atifsiz": capraz_atifsiz,
        "dislanan_capraz_atifli": dropped, "bootstrap": {"tohum": tohum, "tekrar": tekrar},
        "sistemler": {}, "ciftler": [], "risk_kapsam": {},
    }
    for system, o in outcomes.items():
        by_prog = {p: {f: o[f] for f in ids if f in o} for p, ids in progs.items()}
        by_prog = {p: v for p, v in by_prog.items() if v}
        out["sistemler"][system] = {"toplam": _system_stats(o, guven),
                                    "programlar": {p: _system_stats(v, guven) for p, v in by_prog.items()}}
        out["risk_kapsam"][system] = {"toplam": risk_coverage(o),
                                      "programlar": {p: risk_coverage(v) for p, v in by_prog.items()}}
    systems = list(outcomes)
    for i, sa in enumerate(systems):
        for sb in systems[i + 1:]:
            common = {p: [f for f in ids if f in outcomes[sa] and f in outcomes[sb]] for p, ids in progs.items()}
            common = {p: ids for p, ids in common.items() if ids}
            if not common:
                continue
            out["ciftler"].append({
                "a": sa, "b": sb,
                "toplam": _pair_stats(common, outcomes[sa], outcomes[sb], tohum, tekrar, guven),
                "programlar": {p: _pair_stats({p: ids}, outcomes[sa], outcomes[sb], tohum, tekrar, guven)
                               for p, ids in common.items()},
            })
    kept = set(fids)
    decoys = sorted(a for a, (f, c) in cands.items() if c["yem"] and f in kept)
    accepted = [a for a in decoys if labels[a]["etiket"] in YAKIN_ETIKETLER]
    decoys_by_prog: dict[str, Any] = {}
    for p, ids in progs.items():
        idset = set(ids)
        d = [a for a in decoys if cands[a][0] in idset]
        if d:
            decoys_by_prog[p] = {"n": len(d), "kabul": oran_ozeti(sum(a in accepted for a in d), len(d), guven)}
    out["yem"] = {"toplam": {"n": len(decoys), "kabul": oran_ozeti(len(accepted), len(decoys), guven),
                             "kabul_edilen": accepted},
                  "programlar": decoys_by_prog}
    real = sorted(a for a, (f, c) in cands.items() if not c["yem"] and f in kept)
    out["tutarlilik"] = {
        "tam_yakin_disi": [a for a in real if cands[a][1]["tam"] and labels[a]["etiket"] not in YAKIN_ETIKETLER],
        "tam_ama_otomatik_degil": [a for a in real if not cands[a][1]["tam"] and labels[a]["etiket"] == "tam"],
    }
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _pct(x: Optional[float]) -> str:
    return "—" if x is None else f"%{100 * x:.1f}".replace(".", ",")


def _fmt(o: dict[str, Any]) -> str:
    if not o["n"]:
        return "0/0"
    return f"{o['k']}/{o['n']}  {_pct(o['oran'])}  [{_pct(o['alt'])} – {_pct(o['ust'])}]"


def _print_score(res: dict[str, Any]) -> None:
    names = {"tam": "tam", "yakin": "yakın", "yalniz_alan": "yalnız alan", "yanlis": "yanlış"}
    for prog, r in res["programlar"].items():
        print(f"{prog} (kip: {r['kip']}, n={r['n']})")
        for k in RAPOR_ORANLARI:
            print(f"  {names[k]:<12} {_fmt(r['oranlar'][k])}")
        print(f"  {'yem kabul':<12} {_fmt(r['yem']['kabul'])}")
        if res["capraz_atifsiz"]:
            d = r["dislanan_capraz_atifli"]
            print(f"  çapraz atıflı öğeler dışarıda: {d['ana']} ana, {d['yem']} yem")
        t = r["tutarlilik"]
        print(f"  tutarlılık: tp öğede yakın dışı etiket {len(t['tp_yakin_disi'])}; "
              f"tp olmayan öğede 'tam' {len(t['tam_ama_tp_degil'])} (dogru_tarif sayıldı)")
    print(f"yem kabul, bütün paketler birleşik: {_fmt(res['yem_toplam']['kabul'])}")


def _print_comertlik(res: dict[str, Any]) -> None:
    def one(title: str, r: dict[str, Any]) -> None:
        c = r["ciftler"]
        print(f"{title} (n={r['n']} ana öğe, yemler hariç)")
        print(f"  yakın, gt'li   {_fmt(r['yakin_gtli'])}")
        print(f"  yakın, gt'siz  {_fmt(r['yakin_gtsiz'])}")
        fark = f"{100 * r['fark']:+.1f}".replace(".", ",")
        print(f"  fark (gt'li − gt'siz): {fark} puan, bootstrap %{round(100 * res['guven_duzeyi'])} "
              f"[{100 * r['fark_alt']:+.1f} – {100 * r['fark_ust']:+.1f}]".replace(".", ","))
        print(f"  çiftler: ikisi yakın {c['ikisi_yakin']}, yalnız gt'li yakın {c['yalniz_gtli_yakin']}, "
              f"yalnız gt'siz yakın {c['yalniz_gtsiz_yakin']}, ikisi de değil {c['ikisi_yakin_degil']}")
    if res["capraz_atifsiz"]:
        d = res["dislanan_capraz_atifli"]
        print(f"çapraz atıflı öğeler dışarıda: {d['ana']} ana, {d['yem']} yem")
    one("toplam", res["toplam"])
    if len(res["programlar"]) > 1:
        for prog, r in res["programlar"].items():
            one(prog, r)
    print(f"yem kabul: gt'li {_fmt(res['yem']['gtli'])}; gt'siz {_fmt(res['yem']['gtsiz'])}")
    b = res["bootstrap"]
    print(f"bootstrap: {b['tekrar']} tekrar, tohum {b['tohum']}")


def _print_multi(res: dict[str, Any]) -> None:
    if res["capraz_atifsiz"]:
        print(f"çapraz atıflı fonksiyonlar dışarıda: {res['dislanan_capraz_atifli']}")
    for system, r in res["sistemler"].items():
        t = r["toplam"]
        f, v = t["fonksiyon_paydasi"], t["verilen_paydasi"]
        print(f"{system} (n={t['n']}, verilen={t['verilen']}, çekimser={t['cekimser']})")
        print(f"  kapsam       {_fmt(f['kapsam'])}")
        print(f"  tam          {_fmt(f['tam'])}")
        print(f"  yakın        {_fmt(f['yakin'])}")
        print(f"  yalnız alan  {_fmt(v['yalniz_alan'])}  (verilen adlar)")
        print(f"  yanlış       {_fmt(v['yanlis'])}  (verilen adlar)")
        rk = res["risk_kapsam"][system]["toplam"]
        if rk["durum"] == "tamam":
            print(f"  risk-kapsam: {len(rk['esikler'])} eşik")
    for c in res["ciftler"]:
        t = c["toplam"]
        fark = f"{100 * t['fark']:+.1f}".replace(".", ",")
        print(f"{c['a']} − {c['b']} (n={t['n']}): yakın farkı {fark} puan, bootstrap %"
              f"{round(100 * res['guven_duzeyi'])} [{100 * t['fark_alt']:+.1f} – {100 * t['fark_ust']:+.1f}]".replace(".", ",")
              + f"; McNemar p={t['mcnemar_p']:.4f}".replace(".", ","))
    y = res["yem"]["toplam"]
    print(f"yem kabul: {_fmt(y['kabul'])}")
    t = res["tutarlilik"]
    print(f"tutarlılık: otomatik tam adaya yakın dışı etiket {len(t['tam_yakin_disi'])}; "
          f"otomatik tam olmayan adaya 'tam' {len(t['tam_ama_otomatik_degil'])} (dogru_tarif sayıldı)")


def _write(path: Optional[Path], res: dict[str, Any]) -> None:
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(res, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Kör etiket puanlayıcısı (protokol v2).")
    sub = ap.add_subparsers(dest="komut", required=True)
    p = sub.add_parser("puan", help="program başına oranlar ve yem kabulü")
    p.add_argument("--anahtar", type=Path, action="append", required=True, help="anahtar.json (tekrarlanabilir)")
    p.add_argument("--etiket", type=Path, action="append", required=True, help="etiket jsonl (tekrarlanabilir)")
    p.add_argument("--amac", type=Path, action="append", help="aşama 1 amaç dosyası (tekrarlanabilir)")
    p.add_argument("--capraz-atifsiz", action="store_true",
                   help="gerçek adı başka bir öğenin gövdesinde geçen öğeleri dışarıda bırak (duyarlılık)")
    p.add_argument("--cikti", type=Path)
    c = sub.add_parser("comertlik", help="gt'li ve gt'siz etiket farkı")
    c.add_argument("--anahtar-gtli", type=Path, action="append", required=True)
    c.add_argument("--etiket-gtli", type=Path, action="append", required=True)
    c.add_argument("--anahtar-gtsiz", type=Path, action="append", required=True)
    c.add_argument("--etiket-gtsiz", type=Path, action="append", required=True)
    c.add_argument("--tohum", type=int, default=BOOTSTRAP_TOHUM)
    c.add_argument("--tekrar", type=int, default=BOOTSTRAP_TEKRAR)
    c.add_argument("--capraz-atifsiz", action="store_true",
                   help="gerçek adı başka bir öğenin gövdesinde geçen öğeleri dışarıda bırak (duyarlılık)")
    c.add_argument("--cikti", type=Path)
    m = sub.add_parser("puan-cok", help="çok adaylı kip: sistem başına oranlar, eşli farklar, risk-kapsam")
    m.add_argument("--anahtar", type=Path, action="append", required=True, help="çok adaylı anahtar (tekrarlanabilir)")
    m.add_argument("--etiket", type=Path, action="append", required=True, help="etiket jsonl (tekrarlanabilir)")
    m.add_argument("--amac", type=Path, action="append", help="aşama 1 amaç dosyası (tekrarlanabilir)")
    m.add_argument("--tohum", type=int, default=BOOTSTRAP_TOHUM)
    m.add_argument("--tekrar", type=int, default=BOOTSTRAP_TEKRAR)
    m.add_argument("--capraz-atifsiz", action="store_true",
                   help="gerçek adı başka bir öğenin gövdesinde geçen fonksiyonları dışarıda bırak (duyarlılık)")
    m.add_argument("--cikti", type=Path)
    a = ap.parse_args(argv)
    try:
        if a.komut == "puan":
            labels = load_labels(a.etiket)
            keys = load_keys(a.anahtar)
            if a.amac:
                check_amac_unchanged(labels, load_stage1(a.amac))
            res = score(labels, keys, capraz_atifsiz=a.capraz_atifsiz)
            _print_score(res)
        elif a.komut == "puan-cok":
            labels = load_multi_labels(a.etiket)
            funcs, cands = load_multi_keys(a.anahtar)
            check_multi_labels(labels, cands, load_stage1(a.amac) if a.amac else None)
            res = score_multi(labels, funcs, cands, tohum=a.tohum, tekrar=a.tekrar,
                              capraz_atifsiz=a.capraz_atifsiz)
            _print_multi(res)
        else:
            res = comertlik(load_labels(a.etiket_gtli), load_labels(a.etiket_gtsiz),
                            load_keys(a.anahtar_gtli), load_keys(a.anahtar_gtsiz),
                            tohum=a.tohum, tekrar=a.tekrar, capraz_atifsiz=a.capraz_atifsiz)
            _print_comertlik(res)
        _write(a.cikti, res)
        return 0
    except (PuanHatasi, OSError, json.JSONDecodeError) as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
