#!/usr/bin/env python3
"""G6 LLM pilotu (plan v2 G6): örneklem, istem, yerel model çağrısı, ayrıştırma, aday listesi.

Ön kayıt: ``docs/arge/2026-10-19_g6_pilot/pilot_protokolu.md`` (istem sürümü P2).
Model seçimi: ``docs/arge/2026-10-19_g6_pilot/model_secimi.md``.

Alt komutlar
------------
    orneklem         taban v2 popülasyonundan 150+150 ana örneklem ve alt kümeler (tohumlu)
    istem            Ghidra C'si, kanıt paketi, sızıntı taraması, Karadul adayları (A0, A1)
    kos              LM Studio'nun OpenAI uyumlu yerel sunucusuyla koşullar; kaldığı yerden sürer
    adaylar          aday listesi: id, kosul, aday, cekimser (gerçek ad içermez)
    belirlenimcilik  aynı girdinin iki tekrarını karşılaştırır
    kapilar          kuru koşu kapıları (ön kayıt §8)
    kunye            koşu künyesi: commit, model dosyalarının sha256'sı, çalışma zamanı sürümleri
    pilot            arka plan koşusu (model başına: ana koşullar, belirlenimcilik, düşünme kipi)

Gerçek adlar (GT) yalnız örneklem dışlama kuralı ve sızıntı taraması için okunur. Hiçbir
istem, aday ya da künye dosyasına yazılmaz; sızıntı bulunursa yalnız sayısı ve özeti yazılır.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

SEMA = "karadul-llm-pilot/1"
ISTEM_SURUMU = "P2"
TOHUM_ORNEKLEM_METNI = "karadul-g6-pilot-orneklem-2026-10-19"
TOHUM_YEM_METNI = "karadul-g6-yem-2026-10-19"
MODEL_TOHUMU = 20261019
PROGRAMLAR = ("htop", "tmux")
ANA_N = 150
KURU_N = 5          # program başına; ön kayıtta 10 idi, koordinatör kararıyla 5 (2026-10-19)
SONDA_N = 10        # program başına
BELLEK_N = 5
BELLEK_DUSUNME_N = 2  # bellek denemesinde C-D'de de koşulan en uzun istem sayısı (ön kayıt §8)
DUSUNME_N = 50      # program başına, ana örneklemin çekim sırasındaki ilk N
INSAN_N = 15        # program başına
YEM_N = 30
KOD_SINIR = 9000    # bayt; aşarsa baştan KOD_BAS + sondan KOD_SON bayta kadar tam satırlar
KOD_BAS = 7000
KOD_SON = 2000
MAX_TOKENS = 256
MAX_TOKENS_DUSUNME = 2304
BELLEK_ESIGI_GB = 20.0
CAGRI_ZAMAN_ASIMI = 900
SONDA_SOZCUKLERI = ("pass", "auth", "key", "crypt", "priv", "exec", "sock", "root", "uid")
RET_KALIPLARI = ("i can't", "i cannot", "i won't", "unable to assist", "not able to help",
                 "against policy", "malicious")
KARADUL_BASLIK = re.compile(r"^// (Function|Address|Size|Callers|Callees|Stack):")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ISIM = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

# --- İstem metinleri (P2). Her biri bir dosyanın bayt bayt içeriğidir; tek satır sonuyla biter.
SISTEM_ORTAK = (
    "You are an experienced reverse engineer. You will see one function from a stripped macOS arm64 "
    "executable, decompiled to C by Ghidra. The executable is an open-source program; this analysis is "
    "part of an academic study on naming functions in stripped binaries.\n"
    "\n"
    "In the decompiled code, functions that belong to the program have placeholder names such as "
    "FUN_100012340, global data has placeholder names such as DAT_100056780, and functions imported from "
    "system libraries keep their real names (for example _malloc, _strlen, _ioctl).\n"
    "\n"
    "Your task: propose the name that the function's author most likely gave it in the original source code.\n"
    "\n"
    "Rules:\n"
    "1. Use only what you are shown: the code's behaviour, library calls, string literals, constants and data flow.\n"
    "2. Prefer a name that states the function's main action and its object (verb + object), for example "
    "parse_header_field or hash_table_insert.\n"
    "3. The name must be a valid C identifier: letters, digits and underscores, starting with a letter, at most "
    "64 characters.\n"
    "4. Do not answer with a placeholder (FUN_..., sub_..., func, function, handler, helper, do_work), and do not "
    "answer with the name of a well-known library function (for example memcpy, qsort, sigaction) unless the "
    "function really is that library function.\n"
    "5. Reply with exactly one JSON object and nothing else.\n"
)
ZORUNLU_EK = (
    "\n"
    "Answer format:\n"
    '{"isim": "<name>", "gerekce": "<one sentence, at most 30 words>", "cekimser": false}\n'
    "You must give a name.\n"
)
CEKIMSER_EK = (
    "\n"
    "Answer format:\n"
    '{"isim": "<name>", "gerekce": "<one sentence, at most 30 words>", "cekimser": false}\n'
    "If what you are shown does not give enough evidence to state the function's main purpose, abstain instead:\n"
    '{"isim": null, "gerekce": "<what is missing, at most 30 words>", "cekimser": true}\n'
    "A wrong or misleading name is worse than no name.\n"
)
KULLANICI_B = "Decompiled function:\n```c\n{KOD}\n```\n"
KULLANICI_C = (
    "Facts about this function, computed by a static analysis tool from the same stripped binary. A name "
    "marked [proven] was recovered with direct evidence; a name marked [inferred] was derived from behaviour "
    "and may be imprecise; FUN_ addresses without a name are unknown.\n"
    "- Library functions called (count): {APIS}\n"
    "- Program functions it calls: {CAGIRILANLAR}\n"
    "- Called by: {CAGIRANLAR}\n"
    "- Passes these functions as callbacks: {GERI_CAGRI_VERIR}\n"
    "- Is passed as a callback to: {GERI_CAGRI_OLUR}\n"
    "- String literals used: {DIZGILER}\n"
    "- Large constants: {SABITLER}\n"
    "\n"
    "Decompiled function:\n```c\n{KOD}\n```\n"
)
ISTEM_DOSYALARI = {
    "sistem_ortak.txt": SISTEM_ORTAK,
    "zorunlu_ek.txt": ZORUNLU_EK,
    "cekimser_ek.txt": CEKIMSER_EK,
    "kullanici_b.txt": KULLANICI_B,
    "kullanici_c.txt": KULLANICI_C,
}
_YER_TUTUCU = re.compile(r"\{(APIS|CAGIRILANLAR|CAGIRANLAR|GERI_CAGRI_VERIR|GERI_CAGRI_OLUR|DIZGILER|SABITLER|KOD)\}")

KOSULLAR: dict[str, dict[str, Any]] = {
    "B": {"ek": "zorunlu", "kanit": False, "dusunme": False, "dizin": "B"},
    "B-Ç": {"ek": "cekimser", "kanit": False, "dusunme": False, "dizin": "B-cekimser"},
    "C": {"ek": "zorunlu", "kanit": True, "dusunme": False, "dizin": "C"},
    "C-Ç": {"ek": "cekimser", "kanit": True, "dusunme": False, "dizin": "C-cekimser"},
    "B-D": {"ek": "zorunlu", "kanit": False, "dusunme": True, "dizin": "B-dusunme"},
    "C-D": {"ek": "zorunlu", "kanit": True, "dusunme": True, "dizin": "C-dusunme"},
}
ANA_KOSULLAR = ("B", "B-Ç", "C", "C-Ç")

# Model kayıtları: LM Studio anahtarı, yükleme kimliği ve diskteki dosyalar (künye için sha256).
_LMS_MODELLER = Path.home() / ".lmstudio" / "models"
MODELLER: dict[str, dict[str, Any]] = {
    "qwen38": {
        "anahtar": "qwen/qwen3.8-27b",
        "kimlik": "g6-qwen38",
        "uretici_deposu": "Qwen/Qwen3.8-27B",
        "dosya_deposu": "lmstudio-community/Qwen3.8-27B-GGUF",
        "dizin": _LMS_MODELLER / "lmstudio-community" / "Qwen3.8-27B-GGUF",
        "gguf": "Qwen3.8-27B-Q4_K_M.gguf",
        "bicim": "gguf",
    },
    "gemma4": {
        "anahtar": "google/gemma-4-26b-a4b-qat",
        "kimlik": "g6-gemma4",
        "uretici_deposu": "google/gemma-4-26B-A4B-it (QAT)",
        "dosya_deposu": "lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit",
        "dizin": _LMS_MODELLER / "lmstudio-community" / "gemma-4-26B-A4B-it-QAT-MLX-4bit",
        "bicim": "mlx",
    },
}
BAGLAM = 10240
# Düşünme kipi (B-D, C-D) için üreticinin önerdiği örnekleme ve kısa düşünme çabası. Açgözlü çözme
# düşünme kipinde tekrar döngüsüne giriyor ve bütçeyi dolduruyordu (kuru koşu, 2026-10-19; ön kayıt §0.1).
DUSUNME_AYARLARI: dict[str, dict[str, Any]] = {
    "g6-qwen38": {"temperature": 1.0, "top_p": 0.95, "top_k": 20, "cabasi": "low"},   # Qwen3.8 kartı
    "g6-gemma4": {"temperature": 1.0, "top_p": 0.95, "top_k": 64, "cabasi": None},    # Gemma 4 kartı
}


class PilotHatasi(RuntimeError):
    """Koşuyu durduran hata (sızıntı, bellek eşiği, eksik girdi)."""


# ---------------------------------------------------------------------------------------------
# Küçük yardımcılar


def tohum(metin: str) -> int:
    """Ön kayıttaki tohum yöntemi: SHA-256(metin)'in ilk 16 hex basamağı."""
    return int(hashlib.sha256(metin.encode("utf-8")).hexdigest()[:16], 16)


def sha256_metin(metin: str) -> str:
    return hashlib.sha256(metin.encode("utf-8")).hexdigest()


def sha256_dosya(yol: Path, blok: int = 1 << 22) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        while True:
            b = f.read(blok)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def adres_anahtari(addr: str) -> str:
    return str(addr).lower().replace("0x", "")


def c_bicimi(sembol: str) -> str:
    """Mach-O sembolünün C adı: baştaki tek ``_`` atılır."""
    return sembol[1:] if sembol.startswith("_") else sembol


def atomik_yaz(yol: Path, veri: Any) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    gecici = yol.with_name(yol.name + ".tmp")
    gecici.write_text(json.dumps(veri, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(gecici, yol)


def jsonl_ekle(yol: Path, kayit: dict) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    with open(yol, "a", encoding="utf-8") as f:
        f.write(json.dumps(kayit, ensure_ascii=False) + "\n")


def simdi() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# ---------------------------------------------------------------------------------------------
# Örneklem


def uygun_populasyon(
    rows: list[dict],
    c_var: Callable[[str], bool],
    govde_durumu: Callable[[list[str]], str],
) -> tuple[list[str], dict[str, list[str]]]:
    """``sinif == "program"`` satırlardan uygun adresler (adrese göre artan) ve dışlananlar.

    Dışlama (ön kayıt §2.2): kaynakta gövdesi bulunamayan (``yok``) ya da farklı metinli birden
    çok tanımı olan (``belirsiz``) fonksiyonlar ve Ghidra C dosyası olmayanlar.
    """
    uygun: list[str] = []
    dislanan: dict[str, list[str]] = {"govde_yok": [], "govde_belirsiz": [], "c_yok": []}
    for r in sorted(rows, key=lambda r: int(adres_anahtari(r["addr"]), 16)):
        if r.get("sinif", "program") != "program":
            continue
        a = adres_anahtari(r["addr"])
        durum = govde_durumu(list(r.get("gt") or []))
        if durum == "yok":
            dislanan["govde_yok"].append(a)
            continue
        if durum == "belirsiz":
            dislanan["govde_belirsiz"].append(a)
            continue
        if not c_var(a):
            dislanan["c_yok"].append(a)
            continue
        uygun.append(a)
    return uygun, dislanan


def cekim(
    uygun: dict[str, list[str]],
    c_metni: Callable[[str, str], str],
    tohum_degeri: int,
    ana_n: int = ANA_N,
    kuru_n: int = KURU_N,
    sonda_n: int = SONDA_N,
) -> dict[str, Any]:
    """Ön kayıt §2.3-2.4: tek ``random.Random``; önce ana (htop, tmux), sonra kuru, sonra sonda."""
    rng = random.Random(tohum_degeri)
    ana: dict[str, list[str]] = {}
    for p in PROGRAMLAR:
        liste = sorted(uygun.get(p, []), key=lambda a: int(a, 16))
        ana[p] = rng.sample(liste, min(ana_n, len(liste)))
    kuru: dict[str, list[str]] = {}
    for p in PROGRAMLAR:
        kalan = [a for a in sorted(uygun.get(p, []), key=lambda a: int(a, 16)) if a not in set(ana[p])]
        kuru[p] = rng.sample(kalan, min(kuru_n, len(kalan)))
    sonda: dict[str, list[str]] = {}
    for p in PROGRAMLAR:
        kullanilan = set(ana[p]) | set(kuru[p])
        kalan = [a for a in sorted(uygun.get(p, []), key=lambda a: int(a, 16)) if a not in kullanilan]
        aday = [a for a in kalan if any(s in c_metni(p, a).lower() for s in SONDA_SOZCUKLERI)]
        secilen = rng.sample(aday, min(sonda_n, len(aday)))
        if len(secilen) < sonda_n:
            geri = [a for a in kalan if a not in set(secilen)]
            secilen += rng.sample(geri, min(sonda_n - len(secilen), len(geri)))
        sonda[p] = secilen
    dusunme = {p: ana[p][:DUSUNME_N] for p in PROGRAMLAR}
    insan = {p: ana[p][:INSAN_N] for p in PROGRAMLAR}
    tum_ana = sorted(f"{p}-{a}" for p in PROGRAMLAR for a in ana[p])
    yem = random.Random(tohum(TOHUM_YEM_METNI)).sample(tum_ana, min(YEM_N, len(tum_ana)))
    return {"ana": ana, "kuru": kuru, "sonda": sonda, "dusunme": dusunme, "insan": insan, "yem": sorted(yem)}


# ---------------------------------------------------------------------------------------------
# Kod: başlık, kırpma, maskeleme, sızıntı taraması


def baslik_sil(kod: str) -> str:
    """Karadul'un Ghidra dışa aktarımına eklediği baştaki ``// Function: ...`` satırları silinir."""
    satirlar = kod.splitlines(keepends=True)
    i = 0
    while i < len(satirlar) and KARADUL_BASLIK.match(satirlar[i]):
        i += 1
    if i == 0:
        return kod
    while i < len(satirlar) and not satirlar[i].strip():
        i += 1
    return "".join(satirlar[i:])


def kirp(kod: str, sinir: int = KOD_SINIR, bas: int = KOD_BAS, son: int = KOD_SON) -> tuple[str, bool, int]:
    """Bayt sınırını aşan kodun baştan ``bas`` ve sondan ``son`` bayta kadarki tam satırları."""
    if len(kod.encode("utf-8")) <= sinir:
        return kod, False, 0
    satirlar = kod.splitlines(keepends=True)
    on: list[str] = []
    n = 0
    for s in satirlar:
        b = len(s.encode("utf-8"))
        if n + b > bas:
            break
        on.append(s)
        n += b
    arka: list[str] = []
    m = 0
    for s in reversed(satirlar[len(on):]):
        b = len(s.encode("utf-8"))
        if m + b > son:
            break
        arka.append(s)
        m += b
    arka.reverse()
    atlanan = len(satirlar) - len(on) - len(arka)
    return "".join(on) + f"/* [karadul-g6] {atlanan} lines omitted */\n" + "".join(arka), True, atlanan


def _bolumler(kod: str) -> list[tuple[str, int, int]]:
    """Kodun yorum, dizgi ve karakter sabiti bölümleri: (tür, başlangıç, bitiş)."""
    out: list[tuple[str, int, int]] = []
    i, n = 0, len(kod)
    while i < n:
        if kod.startswith("/*", i):
            j = kod.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(("yorum", i, j))
        elif kod.startswith("//", i):
            j = kod.find("\n", i)
            j = n if j < 0 else j
            out.append(("yorum", i, j))
        elif kod[i] in "\"'":
            q = kod[i]
            j = i + 1
            while j < n and kod[j] != q and kod[j] != "\n":
                j += 2 if kod[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(("dizgi" if q == '"' else "karakter", i, j))
        else:
            i += 1
            continue
        i = j
    return out


def maskele(kod: str) -> str:
    """Yorumlar, dizgi ve karakter sabitleri aynı uzunlukta boşlukla örtülür (satırlar korunur)."""
    out = list(kod)
    for _, b, s in _bolumler(kod):
        for k in range(b, s):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def dizgi_sabitleri(kod: str) -> list[str]:
    """Koddaki dizgi sabitlerinin içerikleri (yorumlardakiler hariç)."""
    return [kod[b + 1:s - 1] if kod[s - 1:s] == '"' else kod[b + 1:s].rstrip("\n")
            for tur, b, s in _bolumler(kod) if tur == "dizgi"]


def tanimlayici_sizintisi(metin: str, adlar: set[str], maskeli: bool = True) -> list[str]:
    """Metinde (kodda dizgi ve yorum dışında) tam sözcük olarak geçen yasak adlar."""
    hedef = maskele(metin) if maskeli else metin
    bulunan = set()
    for m in _IDENT.finditer(hedef):
        t = m.group(0)
        for aday in (t, t.lstrip("_")):
            if aday in adlar:
                bulunan.add(aday)
    return sorted(bulunan)


def sabit_metin_sizintisi(metin: str, adlar: set[str]) -> list[str]:
    """Sabit istem metninde, tanımlayıcıya benzeyen (``_`` ya da rakam içeren) sözcüklerden yasak olanlar."""
    bulunan = set()
    for m in _IDENT.finditer(metin):
        t = m.group(0)
        if "_" not in t.strip("_") and not any(ch.isdigit() for ch in t):
            continue
        for aday in (t, t.lstrip("_")):
            if aday in adlar:
                bulunan.add(aday)
    return sorted(bulunan)


def sizinti_adlari(tanimli: Iterable[str], kopyada: Iterable[str], en_kisa: int = 4) -> set[str]:
    """Özgün ikilide tanımlı olup strip'li kopyada bulunmayan sembollerin C adları."""
    var = {c_bicimi(s) for s in kopyada}
    out = set()
    for s in tanimli:
        c = c_bicimi(s)
        if len(c) < en_kisa or not _IDENT.fullmatch(c) or c.startswith("ltmp"):
            continue
        if c in var:
            continue
        out.add(c)
    return out


def nm_adlari(ikili: Path, yalniz_tanimli: bool) -> set[str]:
    args = ["/usr/bin/nm", "-j"] + (["-U"] if yalniz_tanimli else []) + [str(ikili)]
    r = subprocess.run(args, capture_output=True, text=True, check=True)
    return {s.strip() for s in r.stdout.splitlines() if s.strip()}


# ---------------------------------------------------------------------------------------------
# Kanıt paketi


def kanit_alanlari(pack: Any, ad_bul: Callable[[str], Optional[tuple[str, str]]], hedef: str) -> dict[str, str]:
    """``EvidencePack``'ten ön kayıt §3.2 metin biçimi; hedefin kendi Karadul adı asla girmez."""

    def etiketli(addr: str) -> str:
        a = adres_anahtari(addr)
        if a == hedef:
            return f"FUN_{a}"
        r = ad_bul(a)
        if r is None:
            return f"FUN_{a}"
        ad, etiket = r
        return f"FUN_{a} [{etiket}: {ad}]"

    def liste(ogeler: list[str], sinir: int) -> str:
        if not ogeler:
            return "none"
        s = ", ".join(ogeler[:sinir])
        if len(ogeler) > sinir:
            s += f", ... and {len(ogeler) - sinir} more"
        return s

    dizgiler: list[str] = []
    gorulen = set()
    for s in getattr(pack, "strings", []) or []:
        if not s or s in gorulen:
            continue
        gorulen.add(s)
        dizgiler.append(json.dumps(s[:120], ensure_ascii=False))
    return {
        "APIS": liste([f"{k} x{v}" for k, v in sorted((pack.api_counts or {}).items())], 10**6),
        "CAGIRILANLAR": liste([etiketli(a) for a in pack.internal_callees], 40),
        "CAGIRANLAR": liste([etiketli(a) for a in pack.callers], 30),
        "GERI_CAGRI_VERIR": liste([f"{r['api']}({etiketli(r['target'])})" for r in pack.callback_registrations], 20),
        "GERI_CAGRI_OLUR": liste([f"{r['api']} by {etiketli(r['registrar'])}" for r in pack.registered_as_callback], 20),
        "DIZGILER": liste(dizgiler, 40),
        "SABITLER": liste(list(pack.large_constants), 20),
    }


def kanit_hedef_sizintisi(kanit: dict[str, str], hedef_adlari: set[str]) -> list[str]:
    """Kanıt metninde, dizgi satırı ve komşu adı etiketleri dışında hedefin gerçek adı geçiyor mu?"""
    metin = "\n".join(v for k, v in kanit.items() if k != "DIZGILER")
    metin = re.sub(r"\[(?:proven|inferred): [^\]]*\]", "", metin)
    return tanimlayici_sizintisi(metin, hedef_adlari, maskeli=False)


def doldur(sablon: str, degerler: dict[str, str]) -> str:
    """Yer tutucular tek geçişte doldurulur (değer içindeki ``{KOD}`` gibi metinler yeniden işlenmez)."""
    return _YER_TUTUCU.sub(lambda m: degerler[m.group(1)], sablon)


def mesajlar(kosul: str, kayit: dict) -> list[dict[str, str]]:
    k = KOSULLAR[kosul]
    sistem = SISTEM_ORTAK + (ZORUNLU_EK if k["ek"] == "zorunlu" else CEKIMSER_EK)
    if k["kanit"]:
        kullanici = doldur(KULLANICI_C, dict(kayit["kanit"], KOD=kayit["kod"]))
    else:
        kullanici = doldur(KULLANICI_B, {"KOD": kayit["kod"]})
    return [{"role": "system", "content": sistem}, {"role": "user", "content": kullanici}]


# ---------------------------------------------------------------------------------------------
# Ayrıştırma ve güven


# Qwen ``<think>…</think>``, Gemma 4 ``<|channel>thought…<channel|>`` (modelin sohbet şablonundaki işaretler).
# Kapanmamış blok metnin sonuna kadar sürer: model düşünürken bütçe bitti, cevap yok.
_DUSUNME_BLOKU = re.compile(r"<think>.*?(?:</think>|\Z)|<\|channel>.*?(?:<channel\|>|\Z)", re.S)


def dusunme_sonu(metin: str) -> int:
    """Son düşünme bloğunun bittiği konum (blok yoksa 0); cevap bu konumdan sonra aranır."""
    son = 0
    for m in _DUSUNME_BLOKU.finditer(metin):
        son = m.end()
    return son


def ilk_json(metin: str, bas: int = 0) -> tuple[Optional[dict], int, int]:
    dec = json.JSONDecoder()
    i = metin.find("{", bas)
    while i != -1:
        try:
            obj, son = dec.raw_decode(metin, i)
            if isinstance(obj, dict):
                return obj, i, son
        except json.JSONDecodeError:
            pass
        i = metin.find("{", i + 1)
    return None, -1, -1


def ayristir(icerik: Optional[str], bitis: Optional[str], kosul: str, adres: str) -> dict[str, Any]:
    """Ön kayıt §5'teki durum sınıfları."""
    from function_f1 import is_generic_name  # noqa: E402  (tek kaynak)

    ek = KOSULLAR[kosul]["ek"]
    metin = icerik or ""
    cevap_bas = dusunme_sonu(metin)
    # Konumlar ham içerikte: isim_guveni log-olasılık jetonlarını aynı metin üzerinde hizalar.
    obj, bas, son = ilk_json(metin, cevap_bas)
    sonuc: dict[str, Any] = {"durum": "gecersiz", "isim": None, "gerekce": None, "cekimser": None,
                             "json_bas": bas, "json_son": son}
    if obj is None:
        if bitis == "length":
            sonuc["durum"] = "butce_asimi"
        elif any(k in metin[cevap_bas:].lower() for k in RET_KALIPLARI):
            sonuc["durum"] = "ret"
        return sonuc
    if not {"isim", "gerekce", "cekimser"} <= set(obj) or not isinstance(obj["cekimser"], bool):
        return sonuc
    sonuc["gerekce"] = obj["gerekce"] if isinstance(obj["gerekce"], str) else None
    sonuc["cekimser"] = obj["cekimser"]
    if obj["cekimser"]:
        if ek == "zorunlu":
            sonuc["durum"] = "zorunluyken_cekimser"
        elif obj["isim"] is None:
            sonuc["durum"] = "cekimser"
        return sonuc
    isim = obj["isim"]
    if not isinstance(isim, str) or not _ISIM.match(isim):
        return sonuc
    sonuc["isim"] = isim
    sonuc["durum"] = "jenerik" if is_generic_name(isim, [int(adres, 16)]) else "gecerli"
    return sonuc


def isim_guveni(icerik: str, logprob_jetonlari: list[dict], json_bas: int, isim: str) -> tuple[Optional[float], Optional[float]]:
    """İsim değerinin jetonlarının ortalama log-olasılığı ve en küçük olasılığı (bayt hizalı)."""
    if not icerik or not logprob_jetonlari or json_bas < 0 or not isim:
        return None, None
    parcalar = []
    for t in logprob_jetonlari:
        b = bytes(t["bytes"]) if t.get("bytes") is not None else str(t.get("token", "")).encode("utf-8")
        parcalar.append((b, t.get("logprob")))
    icerik_b = icerik.encode("utf-8")
    if b"".join(p[0] for p in parcalar) != icerik_b:
        return None, None
    on_ek = icerik[:json_bas].encode("utf-8")
    m = re.compile(rb'"isim"\s*:\s*"').search(icerik_b, len(on_ek))
    if not m:
        return None, None
    v_bas, v_son = m.end(), m.end() + len(isim.encode("utf-8"))
    if icerik_b[v_bas:v_son] != isim.encode("utf-8"):
        return None, None
    lps: list[float] = []
    konum = 0
    for b, lp in parcalar:
        t_bas, t_son = konum, konum + len(b)
        konum = t_son
        if t_son > v_bas and t_bas < v_son and lp is not None:
            lps.append(float(lp))
    if not lps:
        return None, None
    return sum(lps) / len(lps), math.exp(min(lps))


# ---------------------------------------------------------------------------------------------
# LM Studio istemcisi ve bellek


def _footprint_gb(pid: int) -> Optional[float]:
    try:
        r = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"Footprint:\s*([\d.]+)\s*(KB|MB|GB)", r.stdout)
    if not m:
        return None
    return float(m.group(1)) * {"KB": 1 / 1048576, "MB": 1 / 1024, "GB": 1.0}[m.group(2)]


def model_bellegi() -> dict[str, Any]:
    """LM Studio motor süreçlerinden en büyüğünün belleği: max(RSS, phys_footprint), GB (1024³).

    llama.cpp ağırlıkları mmap ile tutar (RSS'te görünür, footprint'te görünmez); MLX ise Metal
    tamponlarında (footprint'te görünür). İkisinin büyüğü modelin bellekteki payıdır.
    """
    r = subprocess.run(["ps", "-axo", "pid=,rss=,comm="], capture_output=True, text=True)
    adaylar = []
    for satir in r.stdout.splitlines():
        parca = satir.strip().split(None, 2)
        if len(parca) < 3 or "/.lmstudio/" not in parca[2]:
            continue
        pid, rss_kb, komut = int(parca[0]), int(parca[1]), parca[2]
        adaylar.append((pid, rss_kb / 1048576, Path(komut).name))
    en = {"pid": None, "surec": None, "rss_gb": 0.0, "footprint_gb": None, "bellek_gb": 0.0, "bellek_ust_gb": 0.0}
    for pid, rss, ad in adaylar:
        if rss < 0.5 and ad not in ("llama-server", "node"):
            continue
        fp = _footprint_gb(pid) if rss >= 0.2 else None
        bellek = max(rss, fp or 0.0)
        # Üst sınır: llama.cpp'de RSS (kilitli, mmap'li ağırlıklar) + footprint (kirli ve sıkıştırılmış
        # bellek: KV, ana bellek istem önbelleği, kontrol noktaları). Yerleşik kirli kısmı iki kez sayar.
        # MLX'te ağırlıklar footprint'tedir; orada üst sınır max(RSS, footprint) ile aynıdır.
        ust = (rss + (fp or 0.0)) if ad == "llama-server" else bellek
        if ust > en["bellek_ust_gb"]:
            en = {"pid": pid, "surec": ad, "rss_gb": round(rss, 3), "footprint_gb": None if fp is None else round(fp, 3),
                  "bellek_gb": round(bellek, 3), "bellek_ust_gb": round(ust, 3)}
    return en


class LMStudio:
    def __init__(self, taban: str = "http://localhost:1234", lms: Path = Path.home() / ".lmstudio" / "bin" / "lms"):
        self.taban = taban.rstrip("/")
        self.lms = lms

    def _post(self, yol: str, govde: dict, zaman_asimi: int = CAGRI_ZAMAN_ASIMI) -> dict:
        istek = urllib.request.Request(self.taban + yol, data=json.dumps(govde).encode("utf-8"),
                                       headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(istek, timeout=zaman_asimi) as yanit:
            return json.load(yanit)

    def govde(self, model_kimlik: str, mesaj: list[dict], dusunme: bool) -> dict:
        g = {"model": model_kimlik, "messages": mesaj, "temperature": 0, "seed": MODEL_TOHUMU,
             "max_tokens": MAX_TOKENS_DUSUNME if dusunme else MAX_TOKENS, "logprobs": True, "stream": False}
        if not dusunme:
            g["reasoning_effort"] = "none"
            return g
        ayar = DUSUNME_AYARLARI.get(model_kimlik)
        if ayar:
            g.update({k: ayar[k] for k in ("temperature", "top_p", "top_k")})
            if ayar["cabasi"]:
                g["reasoning_effort"] = ayar["cabasi"]
        return g

    def sohbet(self, model_kimlik: str, mesaj: list[dict], dusunme: bool) -> tuple[dict, float, dict]:
        g = self.govde(model_kimlik, mesaj, dusunme)
        t0 = time.time()
        yanit = self._post("/v1/chat/completions", g)
        return yanit, time.time() - t0, {k: v for k, v in g.items() if k != "messages"}

    def calisma_zamani(self, model_kimlik: str) -> dict:
        g = {"model": model_kimlik, "messages": [{"role": "user", "content": "ok"}], "temperature": 0,
             "seed": MODEL_TOHUMU, "max_tokens": 1, "reasoning_effort": "none", "stream": False}
        d = self._post("/api/v0/chat/completions", g, zaman_asimi=300)
        return {"runtime": d.get("runtime"), "model_info": d.get("model_info")}

    def _lms(self, *args: str, zaman_asimi: int = 1200) -> str:
        r = subprocess.run([str(self.lms), *args], capture_output=True, text=True, timeout=zaman_asimi)
        cikti = (r.stdout + r.stderr).replace("\r", "\n")
        satirlar = [s for s in cikti.splitlines() if s.strip() and "Loading" not in s]
        if r.returncode != 0:
            raise PilotHatasi(f"lms {' '.join(args[:2])} başarısız: {' | '.join(satirlar[-3:])}")
        return "\n".join(satirlar[-5:])

    def yukle(self, model: dict) -> str:
        return self._lms("load", model["anahtar"], "-c", str(BAGLAM), "--gpu", "max", "--parallel", "1",
                         "--no-speculative-draft-mtp", "--identifier", model["kimlik"], "-y")

    def bosalt(self, model: dict) -> None:
        try:
            self._lms("unload", model["kimlik"], zaman_asimi=300)
        except PilotHatasi:
            pass


LLAMA_SUNUCU = (Path.home() / ".lmstudio" / "extensions" / "backends"
                / "llama.cpp-mac-arm64-apple-metal-advsimd-2.60.0" / "llama-server")


class LlamaSunucu(LMStudio):
    """LM Studio'nun llama.cpp motorundaki ``llama-server`` ikilisini yalın bayraklarla doğrudan çalıştırır.

    LM Studio'nun yüklemesinden farkı: ana bellek istem önbelleği (``--cache-ram 0``) ve bağlam kontrol
    noktaları (``--ctx-checkpoints 0``) kapalı; görüntü kodlayıcı (mmproj) yüklenmez. Motor ikilisi, model
    dosyası, sohbet şablonu (LM Studio'nun ürettiği şablonun kopyası), bağlam, toplu işlem ve KV ayarları aynı.
    Düşünme ``chat_template_kwargs.enable_thinking`` ile denetlenir (LM Studio'daki ``reasoning_effort: none``
    şablonda aynı yola gider).
    """

    def __init__(self, ikili: Path = LLAMA_SUNUCU, sablon: Optional[Path] = None, port: int = 8137,
                 gunluk_yolu: Optional[Path] = None, pid_yolu: Optional[Path] = None):
        super().__init__(taban=f"http://127.0.0.1:{port}")
        self.ikili, self.sablon, self.port, self.gunluk_yolu = Path(ikili), sablon, port, gunluk_yolu
        self.pid_yolu = pid_yolu
        self.surec: Optional[subprocess.Popen] = None

    def _kayitli_pid(self) -> Optional[int]:
        """PID dosyasındaki süreç hâlâ bizim llama-server'ımız mı (ikili yolu ve port eşleşmeli)?"""
        if self.pid_yolu is None or not self.pid_yolu.is_file():
            return None
        try:
            pid = int(self.pid_yolu.read_text().strip())
        except ValueError:
            return None
        r = subprocess.run(["ps", "-o", "args=", "-p", str(pid)], capture_output=True, text=True)
        args = r.stdout.strip()
        if str(self.ikili) in args and f"--port {self.port}" in args:
            return pid
        return None

    def komut(self, model: dict) -> list[str]:
        k = [str(self.ikili), "--model", str(Path(model["dizin"]) / model["gguf"]), "--host", "127.0.0.1",
             "--port", str(self.port), "--ctx-size", str(BAGLAM), "--n-gpu-layers", "999", "--parallel", "1",
             "--jinja", "--flash-attn", "on", "--cache-ram", "0", "--ctx-checkpoints", "0",
             "--batch-size", "2048", "--ubatch-size", "512", "--threads", "10", "--cache-type-k", "f16",
             "--cache-type-v", "f16", "--load-mode", "mmap+mlock", "--reasoning-format", "deepseek",
             "--no-webui", "--seed", str(MODEL_TOHUMU)]
        if self.sablon is not None:
            k += ["--chat-template-file", str(self.sablon)]
        return k

    def govde(self, model_kimlik: str, mesaj: list[dict], dusunme: bool) -> dict:
        g = {"model": model_kimlik, "messages": mesaj, "temperature": 0, "seed": MODEL_TOHUMU,
             "max_tokens": MAX_TOKENS_DUSUNME if dusunme else MAX_TOKENS, "logprobs": True, "stream": False}
        if not dusunme:
            g["chat_template_kwargs"] = {"enable_thinking": False}
            return g
        ayar = DUSUNME_AYARLARI.get(model_kimlik)
        if ayar:
            g.update({k: ayar[k] for k in ("temperature", "top_p", "top_k")})
            if ayar["cabasi"]:
                g["chat_template_kwargs"] = {"reasoning_effort": ayar["cabasi"]}
        return g

    def yukle(self, model: dict) -> str:
        self.bosalt(model)
        cikti = open(self.gunluk_yolu, "ab") if self.gunluk_yolu else subprocess.DEVNULL
        self.surec = subprocess.Popen(self.komut(model), stdout=cikti, stderr=subprocess.STDOUT, start_new_session=True)
        if self.pid_yolu is not None:
            self.pid_yolu.write_text(str(self.surec.pid))
        t0 = time.time()
        while time.time() - t0 < 900:
            if self.surec.poll() is not None:
                raise PilotHatasi(f"llama-server erken çıktı (kod {self.surec.returncode})")
            try:
                with urllib.request.urlopen(self.taban + "/health", timeout=5) as r:
                    if r.status == 200:
                        return f"llama-server hazır (pid {self.surec.pid}, {time.time() - t0:.0f} sn)"
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(2)
        raise PilotHatasi("llama-server 900 saniyede hazır olmadı")

    def bosalt(self, model: dict) -> None:
        if self.surec is not None and self.surec.poll() is None:
            self.surec.terminate()
            try:
                self.surec.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.surec.kill()
                self.surec.wait(timeout=60)
        self.surec = None
        pid = self._kayitli_pid()
        if pid is not None:
            import signal
            os.kill(pid, signal.SIGTERM)
            for _ in range(60):
                if self._kayitli_pid() is None:
                    break
                time.sleep(1)
            else:
                os.kill(pid, signal.SIGKILL)
        if self.pid_yolu is not None and self.pid_yolu.is_file():
            self.pid_yolu.unlink()

    def calisma_zamani(self, model_kimlik: str) -> dict:
        r = subprocess.run([str(self.ikili), "--version"], capture_output=True, text=True)
        surum = [s for s in (r.stdout + r.stderr).splitlines() if s.startswith(("version", "built"))]
        return {"runtime": {"name": "llama-server (LM Studio llama.cpp motoru, doğrudan, yalın bayraklar)",
                            "version": " | ".join(surum), "ikili": str(self.ikili),
                            "ikili_sha256": sha256_dosya(self.ikili)},
                "model_info": {"baglam": BAGLAM, "bayraklar": self.komut({"dizin": "<model>", "gguf": ""})[3:],
                               "sablon_sha256": sha256_dosya(self.sablon) if self.sablon else None}}


def istemci_kur(tur: str, kok: Path) -> LMStudio:
    if tur == "lmstudio":
        return LMStudio()
    if tur == "llama":
        sablon = kok / "sablon" / "qwen38_chat-template.jinja"
        if not sablon.is_file():
            raise PilotHatasi(f"sohbet şablonu yok: {sablon}")
        return LlamaSunucu(sablon=sablon, gunluk_yolu=kok / "llama_server.log", pid_yolu=kok / "llama_server.pid")
    raise PilotHatasi(f"bilinmeyen istemci: {tur}")


# ---------------------------------------------------------------------------------------------
# Koşu (kaldığı yerden devam eder)


def ham_yolu(kok: Path, model: str, kume: str, kosul: str, tekrar: int, program: str, adres: str) -> Path:
    return kok / "ham" / model / kume / KOSULLAR[kosul]["dizin"] / f"t{tekrar}" / f"{program}_{adres}.json"


def ham_tamam_mi(yol: Path) -> bool:
    if not yol.is_file():
        return False
    try:
        return bool(json.loads(yol.read_text(encoding="utf-8")).get("tamam"))
    except (OSError, json.JSONDecodeError):
        return False


def istem_kayitlari(kok: Path) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for p in PROGRAMLAR:
        yol = kok / "istemler" / f"{p}.jsonl"
        if not yol.is_file():
            continue
        for satir in yol.read_text(encoding="utf-8").splitlines():
            if satir.strip():
                k = json.loads(satir)
                out[(k["program"], k["adres"])] = k
    return out


def kume_ogeleri(kok: Path, kume: str) -> list[tuple[str, str]]:
    ornek = json.loads((kok / "orneklem.json").read_text(encoding="utf-8"))
    if kume == "bellek":
        return [tuple(x) for x in ornek["bellek"]]
    return [(p, a) for p in PROGRAMLAR for a in ornek[kume][p]]


def kos(
    kok: Path,
    model_adi: str,
    kume: str,
    kosullar: Iterable[str],
    tekrar: int,
    ters: bool,
    istemci: Any,
    bellek_olc: Optional[Callable[[], dict]] = None,
    bellek_esigi: float = BELLEK_ESIGI_GB,
    gunluk: Optional[Callable[[str], None]] = None,
    ogeler: Optional[list[tuple[str, str]]] = None,
    geri_bildirim: Optional[Callable[[dict], None]] = None,
    bellek_alani: str = "bellek_gb",
) -> dict[str, Any]:
    """Bir kümede, verilen koşulları çağırır. Tamamlanmış (``tamam``) çıktıları atlar."""
    model = MODELLER[model_adi] if model_adi in MODELLER else {"kimlik": model_adi}
    bellek_olc = bellek_olc or model_bellegi
    kayitlar = istem_kayitlari(kok)
    ogeler = list(ogeler if ogeler is not None else kume_ogeleri(kok, kume))
    if ters:
        ogeler.reverse()
    kosullar = list(kosullar)
    ozet = {"yapilan": 0, "atlanan": 0, "en_yuksek_bellek_gb": 0.0, "sure_sn": 0.0}
    ilerleme = kok / "ilerleme.jsonl"
    for program, adres in ogeler:
        kayit = kayitlar.get((program, adres))
        if kayit is None:
            raise PilotHatasi(f"istem kaydı yok: {program} {adres}")
        if kayit.get("sizinti_kod_sayisi") or kayit.get("sizinti_kanit_sayisi"):
            raise PilotHatasi(f"sızıntı işaretli istem çalıştırılmaz: {program} {adres}")
        for kosul in kosullar:
            yol = ham_yolu(kok, model_adi, kume, kosul, tekrar, program, adres)
            if ham_tamam_mi(yol):
                ozet["atlanan"] += 1
                continue
            mesaj = mesajlar(kosul, kayit)
            dusunme = KOSULLAR[kosul]["dusunme"]
            yanit, sure, ayar = istemci.sohbet(model["kimlik"], mesaj, dusunme)
            secim = (yanit.get("choices") or [{}])[0]
            ileti = secim.get("message") or {}
            icerik = ileti.get("content") or ""
            akil = ileti.get("reasoning_content") or ""
            ayr = ayristir(icerik, secim.get("finish_reason"), kosul, adres)
            lp = ((secim.get("logprobs") or {}).get("content")) or []
            ort, en_kucuk = (isim_guveni(icerik, lp, ayr["json_bas"], ayr["isim"]) if ayr["isim"] else (None, None))
            bellek = bellek_olc()
            kullanim = yanit.get("usage") or {}
            cikti = {
                "sema": SEMA, "tamam": True, "model": model_adi, "kume": kume, "kosul": kosul, "tekrar": tekrar,
                "program": program, "adres": adres, "istem_surumu": ISTEM_SURUMU,
                "istem_sha256": sha256_metin(json.dumps(mesaj, ensure_ascii=False)),
                "ayarlar": ayar, "zaman": simdi(), "sure_sn": round(sure, 3),
                "kullanim": kullanim, "bitis": secim.get("finish_reason"),
                "icerik": icerik, "akil_yurutme": akil, "icerik_sha256": sha256_metin(icerik),
                "logprob_jeton_sayisi": len(lp), "logproblar": lp,
                "ayristirma": {k: v for k, v in ayr.items()},
                "guven_ort_logprob": ort, "guven_min_prob": en_kucuk,
                "bellek": bellek,
            }
            atomik_yaz(yol, cikti)
            jsonl_ekle(ilerleme, {"zaman": cikti["zaman"], "model": model_adi, "kume": kume, "kosul": kosul,
                                  "tekrar": tekrar, "program": program, "adres": adres, "durum": ayr["durum"],
                                  "sure_sn": cikti["sure_sn"], "bellek_gb": bellek.get("bellek_gb"),
                                  "girdi_jeton": kullanim.get("prompt_tokens"),
                                  "cikti_jeton": kullanim.get("completion_tokens")})
            ozet["yapilan"] += 1
            ozet["sure_sn"] += sure
            ozet["en_yuksek_bellek_gb"] = max(ozet["en_yuksek_bellek_gb"], bellek.get("bellek_gb") or 0.0)
            if gunluk:
                gunluk(f"{model_adi} {kume} {kosul} t{tekrar} {program} {adres}: {ayr['durum']} "
                       f"{sure:.1f} sn, bellek {bellek.get('bellek_gb')} GB")
            if geri_bildirim:
                geri_bildirim({"sure_sn": sure, "bellek_gb": bellek.get("bellek_gb")})
            if (bellek.get(bellek_alani) or 0.0) > bellek_esigi:
                raise PilotHatasi(f"model belleği eşiği aştı ({bellek_alani}): {bellek.get(bellek_alani)} GB > {bellek_esigi} GB")
    return ozet


# ---------------------------------------------------------------------------------------------
# Adaylar, belirlenimcilik, kapılar


def ham_okuyucu(kok: Path) -> Iterable[dict]:
    for yol in sorted((kok / "ham").rglob("*.json")):
        try:
            d = json.loads(yol.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if d.get("tamam"):
            yield d


def aday_listesi(kok: Path, kumeler: Iterable[str] = ("ana", "dusunme"), tekrar: int = 1) -> list[dict]:
    """Etiket paketinin girdisi: id, kosul, aday, cekimser (+ künye alanları). Gerçek ad içermez."""
    kumeler = set(kumeler)
    satirlar: list[dict] = []
    ornek = json.loads((kok / "orneklem.json").read_text(encoding="utf-8"))
    ana = {(p, a) for p in PROGRAMLAR for a in ornek["ana"][p]}
    for (p, a), k in sorted(istem_kayitlari(kok).items()):
        if (p, a) not in ana:
            continue
        for kod, ad, kaynak in (("A0", k.get("a0"), "naming_map"), ("A1", k.get("a1"), k.get("a1_kaynak"))):
            satirlar.append({"id": f"{p}-{a}", "program": p, "adres": a, "kosul": kod, "model": "karadul",
                             "aday": ad, "cekimser": False, "durum": "gecerli" if ad else "isimsiz",
                             "kaynak": kaynak if ad else None, "guven_ort_logprob": None, "guven_min_prob": None,
                             "kirpildi": k.get("kirpildi"), "tekrar": None})
    for d in ham_okuyucu(kok):
        if d["kume"] not in kumeler or d["tekrar"] != tekrar or (d["program"], d["adres"]) not in ana:
            continue
        ayr = d["ayristirma"]
        satirlar.append({"id": f"{d['program']}-{d['adres']}", "program": d["program"], "adres": d["adres"],
                         "kosul": d["kosul"], "model": d["model"],
                         "aday": ayr["isim"] if ayr["durum"] == "gecerli" else None,
                         "cekimser": ayr["durum"] in ("cekimser", "zorunluyken_cekimser"), "durum": ayr["durum"],
                         "kaynak": None, "guven_ort_logprob": d.get("guven_ort_logprob"),
                         "guven_min_prob": d.get("guven_min_prob"), "kirpildi": None, "tekrar": d["tekrar"]})
    return satirlar


def belirlenimcilik(kok: Path, model: str, kume: str, kosullar: Iterable[str]) -> dict[str, Any]:
    out: dict[str, Any] = {"model": model, "kume": kume, "kosullar": {}}
    for kosul in kosullar:
        t1, t2 = {}, {}
        for d in ham_okuyucu(kok):
            if d["model"] != model or d["kume"] != kume or d["kosul"] != kosul:
                continue
            (t1 if d["tekrar"] == 1 else t2)[(d["program"], d["adres"])] = d
        ortak = sorted(set(t1) & set(t2))
        ayni_ham = sum(1 for k in ortak if t1[k]["icerik_sha256"] == t2[k]["icerik_sha256"])
        ayni_isim = sum(1 for k in ortak if t1[k]["ayristirma"]["isim"] == t2[k]["ayristirma"]["isim"]
                        and t1[k]["ayristirma"]["durum"] == t2[k]["ayristirma"]["durum"])
        farklar = [f"{p}-{a}" for (p, a) in ortak if t1[(p, a)]["icerik_sha256"] != t2[(p, a)]["icerik_sha256"]]
        out["kosullar"][kosul] = {"cift": len(ortak), "ayni_ham": ayni_ham, "ayni_isim": ayni_isim,
                                  "farkli_idler": farklar}
    return out


def bellek_ust(b: dict) -> float:
    """Kayıttaki bellek ölçümünden üst sınır (eski kayıtlarda ``bellek_ust_gb`` yoksa yeniden hesaplanır)."""
    if b.get("bellek_ust_gb") is not None:
        return float(b["bellek_ust_gb"])
    if b.get("surec") == "llama-server":
        return float(b.get("rss_gb") or 0.0) + float(b.get("footprint_gb") or 0.0)
    return float(b.get("bellek_gb") or 0.0)


def kapilar(kok: Path, model: str, saat_tahmini: Optional[float] = None) -> dict[str, Any]:
    """Ön kayıt §8'deki kapılar; kuru koşu kümesi 5+5 (koordinatör kararı) için oranlar korunur."""
    kayitlar = [d for d in ham_okuyucu(kok) if d["model"] == model]
    kuru = [d for d in kayitlar if d["kume"] == "kuru" and d["tekrar"] == 1 and d["kosul"] in ANA_KOSULLAR]
    kuru_bc = [d for d in kuru if d["kosul"] in ("B", "C")]
    sonda = [d for d in kayitlar if d["kume"] == "sonda" and d["tekrar"] == 1 and d["kosul"] in ("B", "C")]
    sonda_beklenen = len(kume_ogeleri(kok, "sonda")) * 2
    n_bellek = len(kume_ogeleri(kok, "bellek"))
    bellek_say = {k: sum(1 for d in kayitlar if d["kume"] == "bellek" and d["kosul"] == k and d["tekrar"] == 1)
                  for k in ("C", "C-D")}
    bellek_beklenen = {"C": n_bellek, "C-D": min(BELLEK_DUSUNME_N, n_bellek)}
    dusunmesiz = [d for d in kayitlar if not KOSULLAR[d["kosul"]]["dusunme"]]
    # Ön kayıt "40 / 40 çağrı tamamlanıyor": ham_okuyucu yalnız tamamlanmış kayıtları verdiği için
    # eksiksizlik beklenen çağrı sayısıyla denetlenir (her (öğe, koşul) çiftinin tek dosyası var).
    beklenen = len(kume_ogeleri(kok, "kuru")) * len(ANA_KOSULLAR)
    k1 = (bool(kuru) and len(kuru) == beklenen
          and all(not (d.get("akil_yurutme") or "").strip() for d in dusunmesiz)
          and all(d["logprob_jeton_sayisi"] > 0 for d in dusunmesiz if d["icerik"]))
    gecerli = sum(1 for d in kuru_bc  # JSON geçerliliği: şemaya uyan her yanıt (çekimserlik dahil)
                  if d["ayristirma"]["durum"] in ("gecerli", "jenerik", "zorunluyken_cekimser", "cekimser"))
    ret = sum(1 for d in sonda if d["ayristirma"]["durum"] == "ret")
    bel = belirlenimcilik(kok, model, "kuru", ANA_KOSULLAR)
    cift = sum(v["cift"] for v in bel["kosullar"].values())
    ayni = sum(v["ayni_ham"] for v in bel["kosullar"].values())
    tepe = max((bellek_ust(d.get("bellek") or {}) for d in kayitlar), default=None)
    sonuc = {
        "K-1": {"gecti": k1, "kuru_cagri": len(kuru), "beklenen": beklenen, "dusunmesiz_akil_yurutme": sum(
            1 for d in dusunmesiz if (d.get("akil_yurutme") or "").strip())},
        "K-2": {"gecti": bool(kuru_bc) and gecerli / len(kuru_bc) >= 0.95, "gecerli": gecerli, "toplam": len(kuru_bc)},
        "K-3": {"gecti": bool(sonda) and len(sonda) == sonda_beklenen and ret / len(sonda) <= 1 / 40,
                "ret": ret, "toplam": len(sonda), "beklenen": sonda_beklenen},
        "K-4": {"gecti": cift > 0 and ayni / cift >= 0.95, "ayni_ham": ayni, "cift": cift},
        # Bellek kapısının asıl ölçüsü en uzun istemlerle yapılan bellek denemesi; o koşulmadan geçilmez.
        "K-5": {"gecti": tepe is not None and tepe <= BELLEK_ESIGI_GB and bellek_say == bellek_beklenen,
                "tepe_bellek_gb": tepe, "bellek_denemesi": bellek_say, "bellek_beklenen": bellek_beklenen},
        "K-6": {"saat_tahmini": saat_tahmini, "dusunme_alt_kumesi": DUSUNME_N if (saat_tahmini or 0) <= 24 else 25},
    }
    sonuc["hepsi"] = all(v.get("gecti", True) for k, v in sonuc.items() if k != "K-6")
    return sonuc


# ---------------------------------------------------------------------------------------------
# Gerçek veriyle çalışan adımlar (taban v2 koşusu)


def _statik_dizin(kosu: Path, program: str) -> Path:
    adaylar = sorted((kosu / program).glob(f"ws/workspaces/{program}/*/static"))
    if len(adaylar) != 1:
        raise PilotHatasi(f"{program}: tek bir static dizini bekleniyordu, bulunan {len(adaylar)}")
    return adaylar[0]


def _c_yolu(statik: Path, adres: str) -> Path:
    return statik / "ghidra_output" / "decompiled" / f"FUN_{adres}.c"


def _satirlar(kosu: Path, program: str) -> list[dict]:
    return json.loads((kosu / program / "macho_score.json").read_text(encoding="utf-8"))["rows"]


def orneklem_uret(kosu: Path, kaynaklar: dict[str, Path], kok: Path) -> dict[str, Any]:
    sys.path.insert(0, str(_HERE))
    from csrc_index import index_tree  # noqa: E402
    from etiket_paketi import resolve_body, tree_digest  # noqa: E402

    uygun: dict[str, list[str]] = {}
    kunye: dict[str, Any] = {}
    c_onbellek: dict[tuple[str, str], str] = {}
    for p in PROGRAMLAR:
        statik = _statik_dizin(kosu, p)
        idx = index_tree(kaynaklar[p])
        rows = _satirlar(kosu, p)
        u, dis = uygun_populasyon(
            rows,
            c_var=lambda a, s=statik: _c_yolu(s, a).is_file(),
            govde_durumu=lambda g, i=idx, r=kaynaklar[p]: resolve_body(g, i, r)[1],
        )
        uygun[p] = u
        for a in u:
            c_onbellek[(p, a)] = _c_yolu(statik, a).read_text(errors="replace")
        kunye[p] = {"skor": str(kosu / p / "macho_score.json"),
                    "skor_sha256": sha256_dosya(kosu / p / "macho_score.json"),
                    "kaynak": str(kaynaklar[p]), "kaynak_ozeti": tree_digest(kaynaklar[p]),
                    "program_satiri": sum(1 for r in rows if r.get("sinif", "program") == "program"),
                    "uygun": len(u), "dislanan_sayi": {k: len(v) for k, v in dis.items()}, "dislanan": dis}
    t = tohum(TOHUM_ORNEKLEM_METNI)
    secim = cekim(uygun, lambda p, a: c_onbellek[(p, a)], t)
    veri = {"sema": SEMA + "/orneklem", "tohum": {"metin": TOHUM_ORNEKLEM_METNI, "deger": t},
            "yem_tohumu": {"metin": TOHUM_YEM_METNI, "deger": tohum(TOHUM_YEM_METNI)},
            "kume_boyutlari": {"ana": ANA_N, "kuru": KURU_N, "sonda": SONDA_N, "dusunme": DUSUNME_N,
                               "insan": INSAN_N, "yem": YEM_N},
            "python": platform.python_version(), "kosu": str(kosu), "programlar": kunye, **secim}
    atomik_yaz(kok / "orneklem.json", veri)
    return veri


def karadul_adlari(kosu: Path, program: str, statik: Path, rows: list[dict]) -> tuple[dict, dict, Any]:
    """A0 (taban v2 ``naming_map``) ve A1 (A0 + tarif katmanı, ``tarif_olc.py`` yolu)."""
    sys.path.insert(0, str(_HERE))
    sys.path.insert(0, str(_ROOT))
    from function_f1 import is_generic_name, load_naming_map  # noqa: E402
    from karadul.reconstruction.tarif import build_evidence, run_tarif  # noqa: E402
    import tarif_olc  # noqa: E402

    kosu_p = kosu / program
    harita = load_naming_map(next(kosu_p.glob("ws/workspaces/*/*/reconstructed/src/naming_map.json")))
    a0: dict[str, str] = {}
    for r in rows:
        a = adres_anahtari(r["addr"])
        if r.get("status") in ("tp", "wrong") and r.get("pred"):
            a0[a] = r["pred"]
    for k, v in harita.items():
        if k.startswith("FUN_"):
            a = k[4:].lower()
            if a not in a0 and not is_generic_name(v, [int(a, 16)]):
                a0[a] = v
    packs = build_evidence(statik)
    ikili = kosu.parent.parent / "corpus" / program / "bin" / program
    kesin = tarif_olc.reliable_names(kosu_p, ikili)
    populasyon = {adres_anahtari(r["addr"]) for r in rows}
    tarif = run_tarif(packs, kesin, populasyon)
    a1: dict[str, tuple[str, str]] = {}
    for a in populasyon:
        n = tarif.get(a)
        if n is not None and not n.is_hint:
            a1[a] = (n.name, "kesin" if n.source.startswith("kesin") else "tarif")
        elif a in a0:
            a1[a] = (a0[a], "A0")
    return a0, a1, packs


def kayit_bayraklari(kayit: dict, yasak: set[str], hedef: set[str]) -> dict[str, Any]:
    """Bir istem kaydının sızıntı sayıları ve katman bayrakları (gerçek adın kendisi yazılmaz)."""
    sk = tanimlayici_sizintisi(kayit["kod"], yasak)
    sp = kanit_hedef_sizintisi(kayit["kanit"], hedef)
    dizgiler = dizgi_sabitleri(kayit["kod"]) + [kayit["kanit"]["DIZGILER"]]
    oz_ad = any(re.search(r"\b" + re.escape(h) + r"\b", s) for h in hedef for s in dizgiler)
    komsu = any(re.search(r"\[(?:proven|inferred): " + re.escape(h) + r"\]", v)
                for h in hedef for kk, v in kayit["kanit"].items() if kk != "DIZGILER")
    return {"kod_bayt": len(kayit["kod"].encode("utf-8")), "kod_sha256": sha256_metin(kayit["kod"]),
            "kanit_sha256": sha256_metin(json.dumps(kayit["kanit"], sort_keys=True, ensure_ascii=False)),
            "sizinti_kod_sayisi": len(sk), "sizinti_kod_ozeti": sha256_metin("\n".join(sk)) if sk else None,
            "sizinti_kanit_sayisi": len(sp), "sizinti_kanit_ozeti": sha256_metin("\n".join(sp)) if sp else None,
            "oz_ad_dizgisi": oz_ad, "komsu_hedef_adi": komsu}


def istem_uret(kosu: Path, kok: Path) -> dict[str, Any]:
    """Uygun popülasyonun bütün istem kayıtları hesaplanır ve taranır; örneklem kümeleri yazılır."""
    ornek = json.loads((kok / "orneklem.json").read_text(encoding="utf-8"))
    corpus = kosu.parent.parent / "corpus"
    (kok / "istemler").mkdir(parents=True, exist_ok=True)
    for ad, metin in ISTEM_DOSYALARI.items():
        (kok / "istemler" / ad).write_text(metin, encoding="utf-8")
    ozet: dict[str, Any] = {"istem_surumu": ISTEM_SURUMU,
                            "istem_dosyalari": {k: sha256_metin(v) for k, v in ISTEM_DOSYALARI.items()},
                            "programlar": {}}
    bos_kanit = {k: "none" for k in ("APIS", "CAGIRILANLAR", "CAGIRANLAR", "GERI_CAGRI_VERIR",
                                     "GERI_CAGRI_OLUR", "DIZGILER", "SABITLER")}
    tum: dict[str, dict[str, dict]] = {}
    uzunluklar: list[tuple[int, str, str]] = []
    for p in PROGRAMLAR:
        statik = _statik_dizin(kosu, p)
        rows = _satirlar(kosu, p)
        gt_ad = {adres_anahtari(r["addr"]): {c_bicimi(g) for g in (r.get("gt") or [])} for r in rows}
        yasak = sizinti_adlari(nm_adlari(corpus / p / "orig" / p, True), nm_adlari(corpus / p / "bin" / p, False))
        if sabit_metin_sizintisi("".join(ISTEM_DOSYALARI.values()), yasak):
            raise PilotHatasi(f"{p}: sabit istem metninde programın gerçek bir adı geçiyor; istem değişmeli")
        a0, a1, packs = karadul_adlari(kosu, p, statik, rows)

        def ad_bul(a: str, a0=a0, a1=a1) -> Optional[tuple[str, str]]:
            if a in a1:
                ad, kaynak = a1[a]
                return ad, ("proven" if kaynak == "kesin" else "inferred")
            if a in a0:
                return a0[a], "inferred"
            return None

        dislanan = set().union(*map(set, ornek["programlar"][p]["dislanan"].values()))
        tum[p] = {}
        for r in rows:
            a = adres_anahtari(r["addr"])
            if r.get("sinif", "program") != "program" or a in dislanan or not _c_yolu(statik, a).is_file():
                continue
            kod, kirpildi, atlanan = kirp(baslik_sil(_c_yolu(statik, a).read_text(errors="replace")))
            pack = packs.get(a)
            kanit = kanit_alanlari(pack, ad_bul, a) if pack is not None else dict(bos_kanit)
            kayit = {"program": p, "adres": a, "kod": kod, "kirpildi": kirpildi, "atlanan_satir": atlanan,
                     "kanit": kanit, "a0": a0.get(a), "a1": a1[a][0] if a in a1 else None,
                     "a1_kaynak": a1[a][1] if a in a1 else None}
            kayit.update(kayit_bayraklari(kayit, yasak, gt_ad.get(a, set())))
            tum[p][a] = kayit
            uzunluklar.append((len(doldur(KULLANICI_C, dict(kanit, KOD=kod)).encode("utf-8")), p, a))
        ozet["programlar"][p] = {
            "yasak_ad_sayisi": len(yasak), "uygun_kayit": len(tum[p]),
            "sizinti_kod": sum(1 for k in tum[p].values() if k["sizinti_kod_sayisi"]),
            "sizinti_kanit": sum(1 for k in tum[p].values() if k["sizinti_kanit_sayisi"]),
            "kirpilan": sum(1 for k in tum[p].values() if k["kirpildi"]),
            "oz_ad_dizgisi": sum(1 for k in tum[p].values() if k["oz_ad_dizgisi"]),
            "komsu_hedef_adi": sum(1 for k in tum[p].values() if k["komsu_hedef_adi"]),
            "a1_kaynaklari": {s: sum(1 for k in tum[p].values() if k["a1_kaynak"] == s) for s in ("kesin", "tarif", "A0")},
        }
    uzunluklar.sort(key=lambda x: (-x[0], x[1], int(x[2], 16)))
    ornek["bellek"] = [[p, a] for _, p, a in uzunluklar[:BELLEK_N]]
    atomik_yaz(kok / "orneklem.json", ornek)
    for p in PROGRAMLAR:
        tut = set(ornek["ana"][p]) | set(ornek["kuru"][p]) | set(ornek["sonda"][p])
        tut |= {a for pp, a in ornek["bellek"] if pp == p}
        eksik = sorted(a for a in tut if a not in tum[p])
        if eksik:
            raise PilotHatasi(f"{p}: örneklemdeki {len(eksik)} adresin istem kaydı yok")
        satirlar = [json.dumps(tum[p][a], ensure_ascii=False) for a in sorted(tut, key=lambda x: int(x, 16))]
        (kok / "istemler" / f"{p}.jsonl").write_text("\n".join(satirlar) + "\n", encoding="utf-8")
        ozet["programlar"][p]["yazilan_kayit"] = len(satirlar)
        ozet["programlar"][p]["orneklemde_sizinti"] = sum(
            1 for a in tut if tum[p][a]["sizinti_kod_sayisi"] or tum[p][a]["sizinti_kanit_sayisi"])
    ozet["bellek_kumesi"] = ornek["bellek"]
    atomik_yaz(kok / "istem_ozeti.json", ozet)
    return ozet


# ---------------------------------------------------------------------------------------------
# Künye


def _git(*args: str) -> str:
    r = subprocess.run(["git", "-C", str(_ROOT), *args], capture_output=True, text=True)
    return r.stdout.strip()


def _sohbet_sablonu_ozeti() -> Optional[str]:
    """llama-server'ın ``--chat-template-file`` dosyasının sha256'sı (komut satırının geri kalanı yazılmaz)."""
    r = subprocess.run(["ps", "-axo", "pid=,args="], capture_output=True, text=True)
    for satir in r.stdout.splitlines():
        if "llama-server" in satir and "--chat-template-file" in satir:
            m = re.search(r"--chat-template-file\s+(\S+)", satir)
            if m and Path(m.group(1)).is_file():
                return sha256_dosya(Path(m.group(1)))
    return None


def cozme_ayarlari(istemci: LMStudio, model_kimlik: str) -> dict[str, Any]:
    """İstemcinin gerçekte gönderdiği çözme ayarları (mesajlar hariç): künye ve ham kayıt aynı kaynaktan."""

    def ayar(dusunme: bool) -> dict:
        return {k: v for k, v in istemci.govde(model_kimlik, [], dusunme).items() if k != "messages"}

    return {"dusunmesiz": ayar(False), "dusunme": ayar(True),
            "onek_onbellegi": ("--cache-ram 0 --ctx-checkpoints 0; yuvadaki son istemin öneki yeniden kullanılabilir"
                               if isinstance(istemci, LlamaSunucu) else "LM Studio varsayılanı (kapatılamıyor)")}


def kunye_uret(kok: Path, model_adi: str, istemci: LMStudio, dosya_ozeti: bool = True) -> dict[str, Any]:
    model = MODELLER[model_adi]
    dosyalar = {}
    if dosya_ozeti:
        for f in sorted(model["dizin"].iterdir()):
            if f.is_file() and not f.name.startswith("."):
                dosyalar[f.name] = {"bayt": f.stat().st_size, "sha256": sha256_dosya(f)}
    plist = Path("/Applications/LM Studio.app/Contents/Info.plist")
    surum = subprocess.run(["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", str(plist)],
                           capture_output=True, text=True).stdout.strip()
    motorlar = subprocess.run([str(istemci.lms), "runtime", "ls"], capture_output=True, text=True).stdout
    secili = [s.split()[0] for s in motorlar.splitlines() if "✓" in s]
    sablon = _sohbet_sablonu_ozeti() if model["bicim"] == "gguf" else (
        sha256_dosya(model["dizin"] / "chat_template.jinja") if (model["dizin"] / "chat_template.jinja").is_file()
        else None)
    tarif_dosyalari = {f.name: sha256_dosya(f) for f in sorted((_ROOT / "karadul" / "reconstruction" / "tarif").glob("*.py"))}
    olcum = {n: sha256_dosya(_HERE / n) for n in ("llm_pilot.py", "tarif_olc.py", "function_f1.py",
                                                    "etiket_paketi.py", "csrc_index.py") if (_HERE / n).is_file()}
    veri = {
        "sema": SEMA + "/kunye", "zaman": simdi(), "model_adi": model_adi,
        "model": {k: (str(v) if isinstance(v, Path) else v) for k, v in model.items()},
        "model_dosyalari": dosyalar, "sohbet_sablonu_sha256": sablon, "baglam": BAGLAM,
        "calisma_zamani": istemci.calisma_zamani(model["kimlik"]),
        "lm_studio": {"uygulama": surum, "secili_motorlar": secili,
                      "istemci": type(istemci).__name__,
                      "yol": ("LM Studio'nun llama.cpp motorundaki llama-server, doğrudan ve yalın bayraklarla; "
                              "/v1/chat/completions (log-olasılık)") if isinstance(istemci, LlamaSunucu) else
                             ("LM Studio OpenAI uyumlu yerel sunucusu /v1/chat/completions (log-olasılık), "
                              "künye için /api/v0/chat/completions")},
        "cozme": cozme_ayarlari(istemci, model["kimlik"]),
        "istem": {"surum": ISTEM_SURUMU, "dosyalar": {k: sha256_metin(v) for k, v in ISTEM_DOSYALARI.items()}},
        "depo": {"commit": _git("rev-parse", "HEAD"), "kirli": _git("status", "--porcelain").splitlines()},
        "olcum_dosyalari": olcum, "tarif_dosyalari": tarif_dosyalari,
        "python": platform.python_version(), "platform": platform.platform(),
        "strings": shutil.which("strings"), "bellek_simdi": model_bellegi(),
        "tohumlar": {"orneklem": tohum(TOHUM_ORNEKLEM_METNI), "yem": tohum(TOHUM_YEM_METNI), "model": MODEL_TOHUMU},
    }
    atomik_yaz(kok / "kunye" / f"{model_adi}_{time.strftime('%Y%m%d_%H%M%S')}.json", veri)
    return veri


# ---------------------------------------------------------------------------------------------
# Arka plan pilotu


@dataclasses.dataclass
class Adim:
    ad: str
    kume: str
    kosullar: tuple[str, ...]
    tekrar: int
    ters: bool
    yeniden_yukle: bool


def pilot_adimlari(dusunme: bool = True) -> list[Adim]:
    adimlar = [Adim("ana", "ana", ANA_KOSULLAR, 1, False, True),
               Adim("belirlenimcilik", "ana", ("B", "C"), 2, True, True)]
    if dusunme:
        adimlar.append(Adim("dusunme", "dusunme", ("B-D", "C-D"), 1, False, False))
    return adimlar


def pilot_plani(kok: Path, modeller: list[str], dusunme: bool, dusunme_n: int) -> list[tuple[str, Adim, list]]:
    """Adım öncelikli sıra: önce bütün modellerin ana koşuları, sonra belirlenimcilik, sonra düşünme kipi.

    Süre aşılırsa en değerli veri (ana koşular) önce tamamlanmış olur.
    """
    plan = []
    for adim in pilot_adimlari(dusunme):
        for model_adi in modeller:
            ogeler = kume_ogeleri(kok, adim.kume)
            if adim.kume == "dusunme":
                ornek = json.loads((kok / "orneklem.json").read_text(encoding="utf-8"))
                ogeler = [(p, a) for p in PROGRAMLAR for a in ornek["dusunme"][p][:dusunme_n]]
            plan.append((model_adi, adim, ogeler))
    return plan


def pilot(kok: Path, modeller: list[str], istemci: Any, dusunme: bool = True, dusunme_n: int = DUSUNME_N,
          bellek_alani: str = "bellek_ust_gb") -> int:
    """``istemci``: tek istemci ya da {model_adi: istemci}. Bellek eşiği ``bellek_alani`` üzerinden denetlenir."""
    istemci_bul = (lambda m: istemci[m]) if isinstance(istemci, dict) else (lambda m: istemci)
    gunluk_yolu = kok / "gunluk.log"

    def gunluk(m: str) -> None:
        with open(gunluk_yolu, "a", encoding="utf-8") as f:
            f.write(f"{simdi()} {m}\n")

    durum_yolu = kok / "pilot_durumu.json"
    durum = json.loads(durum_yolu.read_text(encoding="utf-8")) if durum_yolu.is_file() else {"adimlar": {}}
    durum.update({"pid": os.getpid(), "baslangic": durum.get("baslangic") or simdi(), "son_guncelleme": simdi(),
                  "durum": "calisiyor", "dusunme_n": dusunme_n, "modeller": modeller})
    atomik_yaz(durum_yolu, durum)
    plan = pilot_plani(kok, modeller, dusunme, dusunme_n)
    toplam = sum(len(o) * len(a.kosullar) for _, a, o in plan)
    sayac = {"bitti": sum(1 for m, a, o in plan for (p, ad) in o for k in a.kosullar
                          if ham_tamam_mi(ham_yolu(kok, m, a.kume, k, a.tekrar, p, ad))),
             "sure": 0.0, "yeni": 0}

    def bildir(olay: dict) -> None:
        sayac["bitti"] += 1
        sayac["yeni"] += 1
        sayac["sure"] += olay["sure_sn"]
        ort = sayac["sure"] / sayac["yeni"]
        kalan = toplam - sayac["bitti"]
        atomik_yaz(kok / "ilerleme_ozeti.json", {
            "zaman": simdi(), "pid": os.getpid(), "toplam_cagri": toplam, "biten_cagri": sayac["bitti"],
            "bu_oturumda_ort_sn": round(ort, 2), "kalan_cagri": kalan,
            "kaba_kalan_saat": round(kalan * ort / 3600, 2), "son_bellek_gb": olay.get("bellek_gb"),
            "not": "Kaba tahmin bu oturumun çağrı ortalamasıyla; düşünme kipi çağrıları daha uzun sürer."})

    gunluk(f"pilot başladı, pid {os.getpid()}, modeller {modeller}, düşünme {dusunme} (n={dusunme_n}), "
           f"toplam {toplam} çağrı, biten {sayac['bitti']}")
    aktif: Optional[dict] = None
    aktif_adi: Optional[str] = None

    def durdur(e: BaseException, ek: str) -> None:
        """Durum ve günlük yazılır, yüklü model boşaltılır (yalın llama-server ayrı oturumda yetim kalmasın)."""
        durum["durum"] = f"durdu{ek}: {type(e).__name__}: {e}"
        durum["son_guncelleme"] = simdi()
        atomik_yaz(durum_yolu, durum)
        gunluk(f"DURDU{ek}: {type(e).__name__}: {e}")
        m, ad = aktif, aktif_adi
        if m is not None and ad is not None:
            istemci_bul(ad).bosalt(m)
            gunluk(f"{m['kimlik']} boşaltıldı (bellek serbest)")

    try:
        for model_adi, adim, ogeler in plan:
            model = MODELLER[model_adi]
            istemci_m = istemci_bul(model_adi)
            anahtar = f"{model_adi}:{adim.ad}"
            if durum["adimlar"].get(anahtar) == "tamam":
                continue
            if aktif_adi is not None and aktif_adi != model_adi:
                istemci_bul(aktif_adi).bosalt(MODELLER[aktif_adi])
                gunluk(f"{aktif_adi}: boşaltıldı")
                aktif, aktif_adi = None, None
            if adim.yeniden_yukle or aktif_adi is None:
                istemci_m.bosalt(model)
                gunluk(f"{model_adi}: yükleniyor ({adim.ad})")
                gunluk(istemci_m.yukle(model))
                aktif, aktif_adi = model, model_adi
                kunye_uret(kok, model_adi, istemci_m, dosya_ozeti=(adim.ad == "ana"))
            durum["adimlar"][anahtar] = "calisiyor"
            durum["son_guncelleme"] = simdi()
            atomik_yaz(durum_yolu, durum)
            t0 = time.time()
            ozet = kos(kok, model_adi, adim.kume, adim.kosullar, adim.tekrar, adim.ters, istemci_m,
                       gunluk=gunluk, ogeler=ogeler, geri_bildirim=bildir, bellek_alani=bellek_alani)
            durum["adimlar"][anahtar] = "tamam"
            durum.setdefault("ozetler", {})[anahtar] = dict(ozet, gecen_sn=round(time.time() - t0, 1))
            durum["son_guncelleme"] = simdi()
            atomik_yaz(durum_yolu, durum)
            gunluk(f"{anahtar} tamam: {ozet}")
        if aktif_adi is not None:
            istemci_bul(aktif_adi).bosalt(MODELLER[aktif_adi])
            gunluk(f"{aktif_adi}: boşaltıldı")
            aktif, aktif_adi = None, None
        durum["durum"] = "bitti"
        durum["bitis"] = simdi()
        atomik_yaz(durum_yolu, durum)
        gunluk("pilot bitti")
        return 0
    except (PilotHatasi, urllib.error.URLError, OSError, subprocess.SubprocessError) as e:
        durdur(e, "")
        return 3
    except BaseException as e:  # beklenmeyen hata ya da kesme: model yine boşaltılır, hata yükselir
        durdur(e, " (beklenmeyen)")
        raise


# ---------------------------------------------------------------------------------------------
# Komut satırı


def _kaynaklar(degerler: list[str]) -> dict[str, Path]:
    out = {}
    for d in degerler:
        p, _, yol = d.partition("=")
        out[p] = Path(yol).expanduser()
    return out


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    o = alt.add_parser("orneklem")
    o.add_argument("--kosu", type=Path, required=True)
    o.add_argument("--kaynak", action="append", required=True, help="program=kaynak_kökü")
    o.add_argument("--kok", type=Path, required=True)
    i = alt.add_parser("istem")
    i.add_argument("--kosu", type=Path, required=True)
    i.add_argument("--kok", type=Path, required=True)
    k = alt.add_parser("kos")
    k.add_argument("--kok", type=Path, required=True)
    k.add_argument("--model", required=True, choices=sorted(MODELLER))
    k.add_argument("--kume", required=True, choices=("ana", "kuru", "sonda", "bellek", "dusunme"))
    k.add_argument("--kosullar", required=True, help="virgülle: B,B-Ç,C,C-Ç,B-D,C-D")
    k.add_argument("--tekrar", type=int, default=1)
    k.add_argument("--ters", action="store_true")
    k.add_argument("--yukle", action="store_true", help="önce boşalt ve yeniden yükle")
    k.add_argument("--en-fazla", type=int, default=0, help="kümenin ilk N öğesi (0 = hepsi)")
    k.add_argument("--istemci", default="lmstudio", choices=("lmstudio", "llama"))
    k.add_argument("--bellek-alani", default="bellek_ust_gb", choices=("bellek_gb", "bellek_ust_gb"))
    k.add_argument("--bosalt", action="store_true", help="bitince modeli boşalt")
    a = alt.add_parser("adaylar")
    a.add_argument("--kok", type=Path, required=True)
    b = alt.add_parser("belirlenimcilik")
    b.add_argument("--kok", type=Path, required=True)
    b.add_argument("--model", required=True)
    b.add_argument("--kume", required=True)
    b.add_argument("--kosullar", required=True)
    g = alt.add_parser("kapilar")
    g.add_argument("--kok", type=Path, required=True)
    g.add_argument("--model", required=True)
    g.add_argument("--saat", type=float, default=None)
    n = alt.add_parser("kunye")
    n.add_argument("--kok", type=Path, required=True)
    n.add_argument("--model", required=True, choices=sorted(MODELLER))
    n.add_argument("--dosya-ozeti", action="store_true")
    n.add_argument("--istemci", default="lmstudio", choices=("lmstudio", "llama"))
    p = alt.add_parser("pilot")
    p.add_argument("--kok", type=Path, required=True)
    p.add_argument("--modeller", default="qwen38,gemma4")
    p.add_argument("--dusunmesiz", action="store_true")
    p.add_argument("--dusunme-n", type=int, default=DUSUNME_N, help="program başına düşünme kipi fonksiyonu (K-6)")
    p.add_argument("--istemci", default="qwen38=llama,gemma4=lmstudio", help="model=istemci,... (lmstudio|llama)")
    ns = ap.parse_args(argv)
    sys.path.insert(0, str(_HERE))
    if ns.komut == "orneklem":
        v = orneklem_uret(ns.kosu, _kaynaklar(ns.kaynak), ns.kok)
        print(json.dumps({p: v["programlar"][p]["uygun"] for p in PROGRAMLAR}, ensure_ascii=False))
        return 0
    if ns.komut == "istem":
        print(json.dumps(istem_uret(ns.kosu, ns.kok), ensure_ascii=False, indent=1))
        return 0
    if ns.komut == "kos":
        istemci = istemci_kur(ns.istemci, ns.kok)
        model = MODELLER[ns.model]
        if ns.yukle:
            istemci.bosalt(model)
            print(istemci.yukle(model))
        ogeler = kume_ogeleri(ns.kok, ns.kume)
        if ns.en_fazla:
            ogeler = ogeler[: ns.en_fazla]
        try:
            ozet = kos(ns.kok, ns.model, ns.kume, ns.kosullar.split(","), ns.tekrar, ns.ters, istemci,
                       gunluk=lambda m: print(m, flush=True), ogeler=ogeler, bellek_alani=ns.bellek_alani)
        except PilotHatasi:
            istemci.bosalt(model)
            raise
        if ns.bosalt:
            istemci.bosalt(model)
        print(json.dumps(ozet, ensure_ascii=False))
        return 0
    if ns.komut == "adaylar":
        satirlar = aday_listesi(ns.kok)
        (ns.kok / "adaylar.jsonl").write_text("".join(json.dumps(s, ensure_ascii=False) + "\n" for s in satirlar),
                                             encoding="utf-8")
        print(len(satirlar))
        return 0
    if ns.komut == "belirlenimcilik":
        print(json.dumps(belirlenimcilik(ns.kok, ns.model, ns.kume, ns.kosullar.split(",")), ensure_ascii=False, indent=1))
        return 0
    if ns.komut == "kapilar":
        print(json.dumps(kapilar(ns.kok, ns.model, ns.saat), ensure_ascii=False, indent=1))
        return 0
    if ns.komut == "kunye":
        v = kunye_uret(ns.kok, ns.model, istemci_kur(ns.istemci, ns.kok), dosya_ozeti=ns.dosya_ozeti)
        print(json.dumps({"calisma_zamani": v["calisma_zamani"], "lm_studio": v["lm_studio"]}, ensure_ascii=False))
        return 0
    if ns.komut == "pilot":
        secim = dict(x.split("=", 1) for x in ns.istemci.split(","))
        istemciler = {m: istemci_kur(secim.get(m, "lmstudio"), ns.kok) for m in ns.modeller.split(",")}
        return pilot(ns.kok, ns.modeller.split(","), istemciler, dusunme=not ns.dusunmesiz, dusunme_n=ns.dusunme_n)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
