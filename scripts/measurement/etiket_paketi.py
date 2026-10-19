#!/usr/bin/env python3
"""Kör etiket paketi (protokol v2) ve sızıntı denetimi — plan v2 G4.

Yordam: ``docs/arge/etiket_protokolu_v2.md``. Rubrik: ``docs/arge/etiket_rehberi.md``
(sürüm 2). Puanlama: ``scripts/measurement/etiket_puan.py``.

Kullanım
--------
    # Kör paket
    python scripts/measurement/etiket_paketi.py uret \
        --satirlar runs_apple/tmux/macho_score.json --kaynak src/tmux-3.8 \
        --ikili tmux --orneklem 200 --tohum 20261019 --cikti paket/tmux_kor

    # Cömertlik deneyi: aynı tohum, aynı id'ler; gövde karartılmaz, gerçek ad görünür
    python scripts/measurement/etiket_paketi.py uret ... --gt-goster --cikti paket/tmux_gt

    # Değerlendiriciye vermeden önce
    python scripts/measurement/etiket_paketi.py sizinti-denetimi --paket paket/tmux_kor

Girdi
-----
Puanlayıcının ``rows`` listesi (``{"rows": [...]}`` ya da düz liste). Okunan
anahtarlar: ``addr`` (hex), ``gt`` (gerçek adlar; Mac'te baştaki ``_`` ile),
``pred`` (Karadul'un adı ya da null), ``status`` (``tp``/``wrong``/``unnamed``).
Diğer anahtarlar yok sayılır.

Çıktılar (``--cikti``)
----------------------
amac_paketi.jsonl
    Aşama 1, değerlendiriciye: ``id``, ``dosya``, ``govde``; ``--gt-goster``
    kipinde ayrıca ``gt``.
aday_paketi.jsonl
    Aşama 2, amaç cümleleri teslim alındıktan sonra: ``id``, ``aday``.
anahtar.json
    GİZLİ, değerlendiriciye verilmez: ``kunye`` (girdi özetleri, sayılar) ve
    ``ogeler`` (id -> gerçek ad, Karadul tahmini, durum, yem bilgisi,
    ``capraz_atif``).

Kurallar
--------
Örneklem
    İsim verilmiş (``tp`` + ``wrong``) ve gövdesi kaynakta tek anlamlı bulunan
    fonksiyonlardan tohumlu rastgele N (0 = hepsi). Gövdesi bulunamayanlar
    (makroyla üretilen, ``.cold`` parçası ...) ve birden çok farklı tanımı
    olanlar (platforma özgü dosyalar) paydaya girmez; künyede listelenir.
Karartma (kör kip; 2026-10-19 ana oturum kararı)
    Yalnız öğenin kendi gerçek adları (baştaki ``_`` olan ve olmayan biçimleri)
    gövdenin her yerinde tam sözcük eşleşmesiyle ``FONKSIYON`` olur. Kaynak
    dosya adının uzantısız hâli bu biçimlerden birine eşitse dosya adı da
    karartılır (``xmalloc.c`` -> ``FONKSIYON.c``); diğer dosya adları kalır
    (rubrik kural 7). Paketteki başka öğelerin adları gövdelerde görünür kalır;
    bunlar anahtarda ``capraz_atif`` ile işaretlenir: öğenin gerçek adının
    paketteki kaç başka öğenin gövdesinde geçtiği (duyarlılık analizi için,
    ``etiket_puan.py --capraz-atifsiz``).
Yem
    Ana örneklemin %10'u kadar (yukarı yuvarlanır) ek öğe: örneklemde olmayan bir
    fonksiyonun gövdesi + başka kaynak dosyasındaki, pakette olmayan bir
    fonksiyonun gerçek adı. Aday ile öğenin gerçek adının normalize token
    kesişimi boştur; aday paketteki hiçbir gövdede tanımlayıcı olarak geçmez ve
    başka bir adayla (normalize) aynı değildir. Yemler ana öğelerle karıştırılır,
    biçimleri aynıdır.
Belirlenimcilik
    Aynı girdi + tohum (+ aynı Python sürümü) -> bayt bayt aynı çıktı. Kör ve
    ``--gt-goster`` kipleri aynı rastgele adımları izler; id'ler aynıdır.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Optional

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from csrc_index import index_tree  # noqa: E402
from function_f1 import normalize_name  # noqa: E402

PAKET_SEMASI = "karadul-etiket-paketi/2"
RUBRIK_SURUMU = 2

KIP_KOR = "kor"
KIP_GT = "gt_goster"

ISIMLI_DURUMLAR = ("tp", "wrong")
# Ana örneklemin yüzde kaçı kadar ek yem öğe konur (yukarı yuvarlanır).
YEM_YUZDE = 10
# v1 paketiyle aynı kırpma; 0 = kırpma yok.
GOVDE_AZAMI_SATIR = 60
KIRPMA_IZI = "/* ... */"
KENDI_ADI_MASKESI = "FONKSIYON"
ID_AZ_HANE = 3

AMAC_DOSYASI = "amac_paketi.jsonl"
ADAY_DOSYASI = "aday_paketi.jsonl"
ANAHTAR_DOSYASI = "anahtar.json"
PAKET_DOSYALARI = (AMAC_DOSYASI, ADAY_DOSYASI, ANAHTAR_DOSYASI)

# Değerlendirici dosyalarında izin verilen alanlar (beyaz liste).
AMAC_ALANLARI = {
    KIP_KOR: ("id", "dosya", "govde"),
    KIP_GT: ("id", "dosya", "govde", "gt"),
}
ADAY_ALANLARI = ("id", "aday")
# Sızıntı denetiminde aday alanı serbesttir (öğenin kendi adı aday olabilir).
_ADAY_ALANI = "aday"
_GOVDE_ALANI = "govde"
_DOSYA_ALANI = "dosya"

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WS_RE = re.compile(r"\s+")


class PaketHatasi(ValueError):
    """Girdi ya da paket kuralı ihlali (açık hata)."""


# ---------------------------------------------------------------------------
# Ad yardımcıları
# ---------------------------------------------------------------------------

def c_name(gt_name: str) -> str:
    """Mach-O sembolündeki derleyici önekini (tek ``_``) atar: ``_foo`` -> ``foo``."""
    return gt_name[1:] if gt_name.startswith("_") else gt_name


def name_forms(gt_names: Iterable[str]) -> set[str]:
    """Karartılacak biçimler: her gerçek adın baştaki ``_`` olan ve olmayan hâli."""
    forms: set[str] = set()
    for g in gt_names:
        base = c_name(g)
        if base:
            forms.add(base)
            forms.add("_" + base)
    return forms


def name_tokens(name: str) -> frozenset[str]:
    """Normalize edilmiş ad parçaları (``function_f1.normalize_name``, ``_`` ile bölünür)."""
    return frozenset(t for t in normalize_name(name).split("_") if t)


def word_pattern(words: Iterable[str]) -> Optional[re.Pattern[str]]:
    """Verilen tanımlayıcıların herhangi biriyle tam sözcük eşleşen desen."""
    ws = sorted(set(words), key=lambda s: (-len(s), s))
    if not ws:
        return None
    return re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(map(re.escape, ws)) + r")(?![A-Za-z0-9_])")


def mask_own(text: str, own_forms: set[str]) -> tuple[str, int]:
    """Yalnız öğenin kendi adlarını karartır -> (metin, karartılan geçiş sayısı)."""
    pattern = word_pattern(own_forms)
    if pattern is None:
        return text, 0
    return pattern.subn(KENDI_ADI_MASKESI, text)


def mask_file(rel_path: str, own_forms: set[str]) -> tuple[str, bool]:
    """Dosya adının uzantısız hâli öğenin kendi adıysa karartır: ``a/xmalloc.c`` -> ``a/FONKSIYON.c``."""
    p = PurePosixPath(rel_path)
    if p.stem in own_forms:
        return str(p.with_name(KENDI_ADI_MASKESI + p.suffix)), True
    return rel_path, False


def cross_references(texts: dict[Any, str], forms_of: dict[Any, set[str]]) -> tuple[dict[Any, set[Any]], dict[Any, int]]:
    """Öğeler arası ad geçişleri.

    ``texts``: öğe -> değerlendiricinin gördüğü metin; ``forms_of``: öğe -> kendi ad biçimleri.
    Döner: (öğe -> adının geçtiği BAŞKA öğeler, öğe -> metnindeki başka-öğe adı geçiş sayısı).
    """
    owners: dict[str, set[Any]] = {}
    for item, forms in forms_of.items():
        for f in forms:
            owners.setdefault(f, set()).add(item)
    seen_in: dict[Any, set[Any]] = {item: set() for item in forms_of}
    occurrences: dict[Any, int] = {item: 0 for item in forms_of}
    pattern = word_pattern(owners)
    if pattern is None:
        return seen_in, occurrences
    for item, text in texts.items():
        for m in pattern.finditer(text):
            if m.group(0) in forms_of[item]:
                continue
            occurrences[item] += 1
            for owner in owners[m.group(0)]:
                if owner != item:
                    seen_in[owner].add(item)
    return seen_in, occurrences


def truncate(text: str, max_lines: int) -> tuple[str, bool]:
    """İlk ``max_lines`` satır + kırpma izi (v1 paketiyle aynı). 0 = kırpma yok."""
    if max_lines <= 0:
        return text, False
    lines = text.split("\n")
    if len(lines) <= max_lines:
        return text, False
    return "\n".join(lines[:max_lines]) + "\n" + KIRPMA_IZI, True


# ---------------------------------------------------------------------------
# Girdi
# ---------------------------------------------------------------------------

def _addr_key(row: dict[str, Any]) -> int:
    return int(str(row["addr"]), 16)


def validate_rows(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise PaketHatasi("puanlama satırları liste olmalı")
    seen: set[int] = set()
    for n, r in enumerate(rows):
        if not isinstance(r, dict):
            raise PaketHatasi(f"satır {n}: nesne değil")
        for k in ("addr", "gt", "pred", "status"):
            if k not in r:
                raise PaketHatasi(f"satır {n}: '{k}' anahtarı yok")
        if not isinstance(r["addr"], str):
            raise PaketHatasi(f"satır {n}: addr hex metin olmalı: {r['addr']!r}")
        try:
            a = _addr_key(r)
        except ValueError:
            raise PaketHatasi(f"satır {n}: addr hex değil: {r['addr']!r}") from None
        if a in seen:
            raise PaketHatasi(f"satır {n}: aynı adres iki kez: {r['addr']}")
        seen.add(a)
        gt = r["gt"]
        if not isinstance(gt, list) or not gt or not all(isinstance(g, str) and g for g in gt):
            raise PaketHatasi(f"satır {n} ({r['addr']}): gt boş olmayan ad listesi olmalı")
        if r["status"] in ISIMLI_DURUMLAR and not (isinstance(r["pred"], str) and r["pred"].strip()):
            raise PaketHatasi(f"satır {n} ({r['addr']}): '{r['status']}' durumunda pred boş")
    return rows


def load_rows(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("rows") if isinstance(data, dict) else data
    return validate_rows(rows)


@dataclass(frozen=True)
class Body:
    name: str      # kaynaktaki tanım adı
    file: str      # kaynak köküne göre göreli yol (posix)
    line: int
    text: str
    n_defs: int


def resolve_body(gt_names: list[str], idx: dict[str, list[dict]], root: Path) -> tuple[Optional[Body], str, list[str]]:
    """Gerçek adla kaynaktaki gövdeyi bulur -> (gövde, durum, dosyalar).

    Durum: ``tek`` | ``ozdes`` (birden çok aynı metinli tanım) | ``yok`` | ``belirsiz``
    (farklı metinli tanımlar; hangisinin derlendiği bilinmiyor).
    """
    for g in gt_names:
        for cand in dict.fromkeys((c_name(g), g)):
            defs = idx.get(cand)
            if not defs:
                continue
            files = [Path(d["file"]).relative_to(root).as_posix() for d in defs]
            if len({_WS_RE.sub(" ", d["text"]).strip() for d in defs}) > 1:
                return None, "belirsiz", files
            d = defs[0]
            body = Body(name=d["name"], file=files[0], line=d["line"], text=d["text"], n_defs=len(defs))
            return body, ("tek" if len(defs) == 1 else "ozdes"), files
    return None, "yok", []


def tree_digest(root: Path) -> str:
    """Dizinlenen dosyaların (``*.c``, ``*.h``) göreli yol + sha256 özetinin özeti."""
    h = hashlib.sha256()
    for p in sorted([*root.rglob("*.c"), *root.rglob("*.h")]):
        h.update(p.relative_to(root).as_posix().encode("utf-8") + b"\0")
        h.update(hashlib.sha256(p.read_bytes()).hexdigest().encode("ascii") + b"\n")
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Paket
# ---------------------------------------------------------------------------

def _display_gt(gt_names: list[str], body: Body) -> list[str]:
    out = [body.name]
    for g in gt_names:
        base = c_name(g)
        if base not in out:
            out.append(base)
    return out


def build_package(
    rows: list[dict[str, Any]],
    idx: dict[str, list[dict]],
    root: Path,
    *,
    binary: str,
    sample_size: int,
    seed: int,
    show_gt: bool = False,
    max_lines: int = GOVDE_AZAMI_SATIR,
    provenance: Optional[dict[str, Any]] = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Paketi bellekte kurar -> (amaç kayıtları, aday kayıtları, anahtar)."""
    if sample_size < 0:
        raise PaketHatasi("örneklem sayısı negatif olamaz")
    rows = sorted(validate_rows(rows), key=_addr_key)
    res = {_addr_key(r): resolve_body(r["gt"], idx, root) for r in rows}
    bodies: dict[int, Body] = {k: b for k, (b, _st, _f) in res.items() if b is not None}

    named = [r for r in rows if r["status"] in ISIMLI_DURUMLAR]
    eligible = [r for r in named if _addr_key(r) in bodies]
    missing = [r for r in named if res[_addr_key(r)][1] == "yok"]
    ambiguous = [r for r in named if res[_addr_key(r)][1] == "belirsiz"]

    rng = random.Random(seed)

    # 1) ana örneklem
    if sample_size == 0 or sample_size >= len(eligible):
        main = list(eligible)
    else:
        main = rng.sample(eligible, sample_size)
    if not main:
        raise PaketHatasi("örneklem boş: isim verilmiş ve gövdesi bulunan fonksiyon yok")

    # 2) yem gövdeleri: önce aynı popülasyondan (isimli), yetmezse isimsizlerden
    n_decoy = (len(main) * YEM_YUZDE + 99) // 100
    main_keys = {_addr_key(r) for r in main}
    pool_named = [r for r in eligible if _addr_key(r) not in main_keys]
    if len(pool_named) >= n_decoy:
        decoys = rng.sample(pool_named, n_decoy)
        decoy_pool = "isimli"
    else:
        pool_other = [r for r in rows if r["status"] not in ISIMLI_DURUMLAR and _addr_key(r) in bodies]
        need = n_decoy - len(pool_named)
        if need > len(pool_other):
            raise PaketHatasi(f"yem için yeterli gövde yok: {n_decoy} gerekli, {len(pool_named) + len(pool_other)} var")
        decoys = pool_named + rng.sample(pool_other, need)
        decoy_pool = "isimli+isimsiz"

    package = sorted(main, key=_addr_key) + sorted(decoys, key=_addr_key)
    package_keys = {_addr_key(r) for r in package}
    forms_of = {_addr_key(r): name_forms(r["gt"]) for r in package}
    package_forms: set[str] = set().union(*forms_of.values())
    shown = {_addr_key(r): truncate(bodies[_addr_key(r)].text, max_lines) for r in package}
    idents_in_bodies: set[str] = set()
    for text, _cut in shown.values():
        idents_in_bodies.update(_IDENT_RE.findall(text))
    # Öğeler arası ad geçişleri. Yalnız kendi ad karartıldığı için başka öğelerin
    # adları kör kipte de görünür; sayım iki kipte aynıdır (gösterilen ham gövde).
    seen_in, other_occ = cross_references({k: t for k, (t, _cut) in shown.items()}, forms_of)
    file_seen_in, _file_occ = cross_references({k: bodies[k].file for k in package_keys}, forms_of)

    # 3) yem adayları: başka dosya, boş token kesişimi, pakette yok ve hiçbir
    # gövdede tanımlayıcı olarak geçmiyor
    used_norm = {normalize_name(r["pred"]) for r in main}
    cand_pool = []
    for c in rows:
        cb = bodies.get(_addr_key(c))
        if cb is None or _addr_key(c) in package_keys:
            continue
        toks = name_tokens(cb.name)
        if toks and cb.name not in idents_in_bodies and cb.name not in package_forms:
            cand_pool.append((c, cb, toks, normalize_name(cb.name)))
    decoy_cand: dict[int, tuple[dict[str, Any], Body]] = {}
    for d in sorted(decoys, key=_addr_key):
        d_file = bodies[_addr_key(d)].file
        d_tokens: frozenset[str] = frozenset().union(*(name_tokens(g) for g in d["gt"]))
        options = [(c, cb, norm) for c, cb, toks, norm in cand_pool
                   if cb.file != d_file and not (toks & d_tokens) and norm not in used_norm]
        if not options:
            raise PaketHatasi(f"yem adayı bulunamadı: {d['addr']} {d['gt']}")
        c, cb, norm = rng.choice(options)
        used_norm.add(norm)
        decoy_cand[_addr_key(d)] = (c, cb)

    # 4) karıştır, id ver
    items = [("ana", r) for r in sorted(main, key=_addr_key)] + [("yem", r) for r in sorted(decoys, key=_addr_key)]
    rng.shuffle(items)
    width = max(ID_AZ_HANE, len(str(len(items) - 1)))

    amac_recs: list[dict[str, Any]] = []
    aday_recs: list[dict[str, Any]] = []
    ogeler: dict[str, Any] = {}
    tot_own = n_cut = n_file_masked = 0
    for i, (kind, r) in enumerate(items):
        k = _addr_key(r)
        iid = f"{binary}-{i:0{width}d}"
        body = bodies[k]
        text, cut = shown[k]
        if show_gt:
            govde, n_own = text, 0
            dosya, file_masked = body.file, False
        else:
            govde, n_own = mask_own(text, forms_of[k])
            dosya, file_masked = mask_file(body.file, forms_of[k])
        tot_own += n_own
        n_cut += cut
        n_file_masked += file_masked
        amac = {"id": iid, "dosya": dosya, "govde": govde}
        if show_gt:
            amac["gt"] = _display_gt(r["gt"], body)
        if kind == "ana":
            aday = r["pred"]
            yem_kaynagi = None
        else:
            c, cb = decoy_cand[k]
            aday = cb.name
            yem_kaynagi = {"aday_addr": c["addr"], "aday_gt": c["gt"], "aday_dosya": cb.file,
                           "govde_status": r["status"]}
        amac_recs.append(amac)
        aday_recs.append({"id": iid, "aday": aday})
        ogeler[iid] = {
            "addr": r["addr"],
            "gt": r["gt"],
            "pred": r["pred"] if kind == "ana" else None,
            "status": r["status"] if kind == "ana" else None,
            "aday": aday,
            "yem": kind == "yem",
            "yem_kaynagi": yem_kaynagi,
            "dosya": body.file,
            "satir": body.line,
            "tanim_sayisi": body.n_defs,
            "kirpildi": cut,
            "karartilan_kendi": n_own,
            "dosya_karartildi": file_masked,
            "capraz_atif": len(seen_in[k]),
        }

    kunye: dict[str, Any] = {
        "sema": PAKET_SEMASI,
        "rubrik_surumu": RUBRIK_SURUMU,
        "program": binary,
        "kip": KIP_GT if show_gt else KIP_KOR,
        "tohum": seed,
        "orneklem_istenen": sample_size,
        "govde_azami_satir": max_lines,
        "yem_yuzde": YEM_YUZDE,
        "yem_govde_havuzu": decoy_pool,
        "python_surumu": platform.python_version(),
        "sayilar": {
            "satir": len(rows),
            "isimli": len(named),
            "uygun": len(eligible),
            "govdesi_bulunamayan": len(missing),
            "govdesi_belirsiz": len(ambiguous),
            "ana": len(main),
            "yem": len(decoys),
            "toplam": len(items),
            "kirpilan": n_cut,
            "karartilan_kendi": tot_own,
            "dosya_karartilan": n_file_masked,
            "capraz_atifli_oge": sum(1 for k in seen_in if seen_in[k]),
            "baska_ad_gecen_govde": sum(1 for k in other_occ if other_occ[k]),
            "baska_ad_gecis": sum(other_occ.values()),
            "dosya_adi_capraz_atifli_oge": sum(1 for k in file_seen_in if file_seen_in[k]),
        },
        "govdesi_bulunamayan": [{"addr": r["addr"], "gt": r["gt"]} for r in missing],
        "govdesi_belirsiz": [{"addr": r["addr"], "gt": r["gt"], "dosyalar": res[_addr_key(r)][2]} for r in ambiguous],
    }
    if provenance:
        kunye["girdi"] = provenance
    return amac_recs, aday_recs, {"kunye": kunye, "ogeler": ogeler}


def _jsonl(records: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)


def write_package(out_dir: Path, amac: list[dict[str, Any]], aday: list[dict[str, Any]],
                  key: dict[str, Any], *, overwrite: bool = False) -> None:
    existing = [n for n in PAKET_DOSYALARI if (out_dir / n).exists()]
    if existing and not overwrite:
        raise PaketHatasi(f"{out_dir} içinde paket dosyası var ({', '.join(existing)}); --uzerine-yaz verilmedi")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / AMAC_DOSYASI).write_text(_jsonl(amac), encoding="utf-8")
    (out_dir / ADAY_DOSYASI).write_text(_jsonl(aday), encoding="utf-8")
    (out_dir / ANAHTAR_DOSYASI).write_text(
        json.dumps(key, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Sızıntı denetimi
# ---------------------------------------------------------------------------

def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def leak_check(amac: list[Any], aday: list[Any], key: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Değerlendirici dosyalarını denetler -> (hatalar, uyarılar).

    Hata:
      - beyaz liste dışı ya da eksik alan; id kümesi anahtarla aynı değil;
      - kör kipte öğenin KENDİ gerçek adı kendi kaydında ``aday`` dışındaki bir
        alanda geçiyor (gövde, dosya adı, id);
      - yem adayı paketteki bir öğenin gerçek adı ya da bir gövdede tanımlayıcı
        olarak geçiyor (seçim kuralı bunu önler; ihlal bozulmuş paket demektir).
    Uyarı (kör kip): başka bir öğenin gerçek adı gövdelerde ya da dosya
    adlarında geçiyor; öğe ve geçiş sayısıyla. Yalnız kendi ad karartıldığı için
    beklenen durumdur; anahtardaki ``capraz_atif`` ile duyarlılık analizi yapılır.
    """
    errors: list[str] = []
    warnings: list[str] = []
    kip = (key.get("kunye") or {}).get("kip")
    ogeler = key.get("ogeler")
    if kip not in AMAC_ALANLARI or not isinstance(ogeler, dict):
        return [f"anahtar geçersiz: kip={kip!r}, ogeler {'var' if isinstance(ogeler, dict) else 'yok'}"], warnings

    for fname, recs, allowed in ((AMAC_DOSYASI, amac, AMAC_ALANLARI[kip]), (ADAY_DOSYASI, aday, ADAY_ALANLARI)):
        seen: set[Any] = set()
        for n, rec in enumerate(recs, 1):
            if not isinstance(rec, dict):
                errors.append(f"{fname}:{n}: kayıt nesne değil")
                continue
            extra = sorted(set(rec) - set(allowed))
            lacking = sorted(set(allowed) - set(rec))
            if extra:
                errors.append(f"{fname}:{n}: yasak alan {extra}")
            if lacking:
                errors.append(f"{fname}:{n}: eksik alan {lacking}")
            iid = rec.get("id")
            if iid in seen:
                errors.append(f"{fname}:{n}: id iki kez: {iid}")
            seen.add(iid)
        if seen != set(ogeler):
            errors.append(f"{fname}: id kümesi anahtarla aynı değil "
                          f"(eksik {len(set(ogeler) - seen)}, fazla {len(seen - set(ogeler))})")

    forms_of = {iid: name_forms(v.get("gt") or []) for iid, v in ogeler.items()}
    if kip == KIP_GT:
        warnings.append("gt-goster kipi: gerçek adlar bilerek görünür; ad sızıntısı denetlenmedi")
    else:
        # öğenin kendi adı kendi kaydında -> hata
        for fname, recs in ((AMAC_DOSYASI, amac), (ADAY_DOSYASI, aday)):
            for n, rec in enumerate(recs, 1):
                if not isinstance(rec, dict) or rec.get("id") not in forms_of:
                    continue
                own = word_pattern(forms_of[rec["id"]])
                if own is None:
                    continue
                for field, value in rec.items():
                    if field == _ADAY_ALANI:
                        continue
                    hits = sorted(set(own.findall(_as_text(value))))
                    if hits:
                        errors.append(f"öğenin kendi adı sızıyor: {fname}:{n} ({rec['id']}) '{field}': {', '.join(hits)}")
        # başka öğelerin adları -> uyarı (öğe ve geçiş sayısı)
        for field, where in ((_GOVDE_ALANI, "gövdelerde"), (_DOSYA_ALANI, "dosya adlarında")):
            texts = {rec["id"]: _as_text(rec.get(field, "")) for rec in amac
                     if isinstance(rec, dict) and rec.get("id") in forms_of}
            seen_in, occ = cross_references(texts, forms_of)
            n_items = sum(1 for i in occ if occ[i])
            if n_items:
                warnings.append(f"başka öğenin gerçek adı {where} geçiyor: {n_items} öğede {sum(occ.values())} geçiş; "
                                f"adı başka kayıtta görünen öğe {sum(1 for i in seen_in if seen_in[i])}")

    # yem adayı kuralları (iki kipte de)
    all_forms: set[str] = set().union(*forms_of.values()) if forms_of else set()
    decoy_names = sorted({v["aday"] for v in ogeler.values() if v.get("yem") and isinstance(v.get("aday"), str)})
    for name in decoy_names:
        if name in all_forms:
            errors.append(f"yem adayı paketteki bir öğenin gerçek adı: {name}")
    dpat = word_pattern(decoy_names)
    if dpat is not None:
        for n, rec in enumerate(amac, 1):
            if isinstance(rec, dict):
                hits = sorted(set(dpat.findall(_as_text(rec.get(_GOVDE_ALANI, "")))))
                if hits:
                    errors.append(f"yem adayı bir gövdede tanımlayıcı olarak geçiyor: "
                                  f"{AMAC_DOSYASI}:{n} ({rec.get('id')}): {', '.join(hits)}")
    return errors, warnings


def _read_jsonl(path: Path) -> list[Any]:
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise PaketHatasi(f"{path.name}:{n}: JSON değil ({e})") from None
    return out


def check_package_dir(pkg: Path) -> tuple[list[str], list[str]]:
    for n in PAKET_DOSYALARI:
        if not (pkg / n).is_file():
            raise PaketHatasi(f"{pkg / n} yok")
    key = json.loads((pkg / ANAHTAR_DOSYASI).read_text(encoding="utf-8"))
    return leak_check(_read_jsonl(pkg / AMAC_DOSYASI), _read_jsonl(pkg / ADAY_DOSYASI), key)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _report_check(errors: list[str], warnings: list[str]) -> int:
    for w in warnings:
        print(f"UYARI: {w}")
    for e in errors:
        print(f"HATA: {e}")
    print(f"sızıntı denetimi: {len(errors)} hata, {len(warnings)} uyarı")
    return 1 if errors else 0


def _cmd_uret(a: argparse.Namespace) -> int:
    rows = load_rows(a.satirlar)
    idx = index_tree(a.kaynak)
    provenance = {
        "satirlar": str(a.satirlar),
        "satirlar_sha256": hashlib.sha256(a.satirlar.read_bytes()).hexdigest(),
        "kaynak": str(a.kaynak),
        "kaynak_ozeti": tree_digest(a.kaynak),
    }
    amac, aday, key = build_package(
        rows, idx, a.kaynak, binary=a.ikili, sample_size=a.orneklem, seed=a.tohum,
        show_gt=a.gt_goster, max_lines=a.azami_satir, provenance=provenance)
    write_package(a.cikti, amac, aday, key, overwrite=a.uzerine_yaz)
    s = key["kunye"]["sayilar"]
    print(f"{a.cikti}: kip={key['kunye']['kip']} ana={s['ana']} yem={s['yem']} toplam={s['toplam']}")
    print(f"  isimli={s['isimli']} uygun={s['uygun']} gövdesi bulunamayan={s['govdesi_bulunamayan']} "
          f"belirsiz={s['govdesi_belirsiz']} kırpılan={s['kirpilan']}")
    print(f"  karartılan: kendi adı={s['karartilan_kendi']} geçiş, dosya adı={s['dosya_karartilan']} öğe")
    print(f"  çapraz atıf: adı başka gövdede geçen öğe={s['capraz_atifli_oge']}, başka öğe adı geçen gövde="
          f"{s['baska_ad_gecen_govde']} ({s['baska_ad_gecis']} geçiş), adı başka dosya adında geçen öğe="
          f"{s['dosya_adi_capraz_atifli_oge']}")
    return _report_check(*leak_check(amac, aday, key))


def _cmd_sizinti(a: argparse.Namespace) -> int:
    return _report_check(*check_package_dir(a.paket))


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Kör etiket paketi (protokol v2) ve sızıntı denetimi.")
    sub = ap.add_subparsers(dest="komut", required=True)
    u = sub.add_parser("uret", help="paket üret")
    u.add_argument("--satirlar", type=Path, required=True, help="puanlama dosyası (rows)")
    u.add_argument("--kaynak", type=Path, required=True, help="C kaynak kökü")
    u.add_argument("--ikili", required=True, help="program adı (id öneki)")
    u.add_argument("--orneklem", type=int, required=True, help="ana öğe sayısı (0 = hepsi)")
    u.add_argument("--tohum", type=int, required=True)
    u.add_argument("--cikti", type=Path, required=True, help="paket dizini")
    u.add_argument("--gt-goster", action="store_true",
                   help="cömertlik deneyi: gövde karartılmaz, gerçek ad görünür (aynı id'ler)")
    u.add_argument("--azami-satir", type=int, default=GOVDE_AZAMI_SATIR, help="gövde satır sınırı (0 = yok)")
    u.add_argument("--uzerine-yaz", action="store_true", help="var olan paket dosyalarının üzerine yaz")
    s = sub.add_parser("sizinti-denetimi", help="değerlendirici dosyalarını denetle")
    s.add_argument("--paket", type=Path, required=True, help="paket dizini")
    a = ap.parse_args(argv)
    try:
        return _cmd_uret(a) if a.komut == "uret" else _cmd_sizinti(a)
    except (PaketHatasi, OSError, json.JSONDecodeError) as e:
        print(f"HATA: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
