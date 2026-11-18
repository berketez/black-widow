#!/usr/bin/env python3
"""P05 ölçümü: anlamsal parametre adlandırıcısının (``semantic_namer``) adlarını sayar.

İki kaynak:

1. **Kayıtlı çıktı** (``say``): bir ürün koşusunun ``out/src`` imzalarındaki
   ``<ad> /* was: param_N */`` adları (bu yorumu yalnız ``semantic_namer`` yazar) ve
   ``reconstructed/param_naming_map.json`` adları. Ghidra ve adlandırıcı koşmaz.
2. **Yeniden oynatma** (``kos``): kayıtlı koşunun çalışma dizinindeki girdilerle
   ``SemanticParameterNamer.rename`` ölçülen ağacın (betiğin bulunduğu worktree) koduyla koşar.
   Girdiler ``SemanticNamingStep``'in verdiğinin aynısıdır: ``reconstructed/struct_recovered/*.c``
   (adımın girdi dizini; ``semantic_named/`` sonradan ``flow_simplify`` ile yerinde değiştiği
   için çıktı dizini karşılaştırmaya uygun değildir), ``ghidra_functions.json`` ve
   ``ghidra_call_graph.json`` (``deobfuscated/`` önce, sonra ``static/``), algoritma eşleşmeleri
   (``reconstructed/algorithms.json`` + ``engineering_algorithms.json``) ve imza eşleşmeleri
   (``reconstructed/signature_matches.json``). **Doğrulama:** yeniden oynatılan
   ``param_naming_map.json``'ın ``functions → renames`` kısmı kayıtlıyla aynı mı (taban kolda
   anlamlı: kayıtlı koşuyu üreten kodla aynı davranan ağaçta ``ayni`` beklenir).

Ad sınıfları (``ad_sinifi``; ilk tutan kazanır)
------------------------------------------------
``gecersiz`` / ``anahtar`` / ``tip``
    Ürünün ad süzgecinin sözcük kuralları (``name_validity.lexical_reject_reason(local=True)``):
    geçerli C tanımlayıcısı değil, C anahtar sözcüğü, gövdede tip olarak geçebilen sözcük.
``ghidra_oto``
    Ghidra'nın kendi ürettiği ad biçimi (``GHIDRA_OTO``): ``DAT_``/``PTR_``/``FUN_``/``LAB_``…
    ``_<onaltılık>``, ``local_``, ``param_N``, ``uVarN``, ``auStack_``, ``in_``, ``extraout_``,
    ``unaff_``. Parametreye verilince küresel ya da yerel bir değişken okunuyormuş gibi görünür.
``govde_cakismasi`` (yalnız yeniden oynatmada)
    Yeni ad fonksiyonun girdi kodunda (dizgi ve yorumlar örtülü) yeniden adlandırılan
    parametreden başka bir tanımlayıcı olarak zaten geçiyor: yeniden adlandırma iki ayrı şeyi tek
    ada çöker.
``matris_vektor``
    ``(M|K|A)_matrix`` / ``(v|u|phi)_vector`` biçimi (MUH-02'nin adları; ``_N`` eki dahil).
    Geçerli addır; ayrı sayılır.

DWARF hükmü (``kos --hizalama``)
---------------------------------
T0b hizalama belgesi (``parametre_hizala.py``; ``karadul-parametre-hizalama/1``) olan ikililerde,
belgenin ``ghidra_ikili_sha256``'sı koşunun girdi sha256'sıyla aynıysa: fonksiyon girdi
dosyasındaki ``// Address:`` başlığıyla bulunur; ``eslesme == "tam"`` parametresinin
``depolama_ortagi`` = k ise ``param_k``'nın DWARF adı GT'dir. İmzadaki parametre sayısı belgedeki
``ghidra_parametre`` ile tutmazsa ad ``imza_uyusmadi`` sayılır (hüküm yok). Ad hükmü
(``ad_hukmu``; ön kayıt ``docs/arge/2026-11-18_onarim/P05_on_kayit.md``):

- ``tam``: ``normal(ad) == normal(gt)``; ``normal``: küçük harf, baş/son ``_`` atılır, sondaki
  tek ``_<sayı>`` eki atılır.
- ``yakin``: tam değil; adın ve GT'nin belirteçlerinden (``_``, büyük harf ve rakam sınırlarında
  bölünür, küçük harf, sondaki ``_<sayı>`` eki atılmış adda) en az biri ortak: eşit (en az 2
  harf) ya da biri öbürünün en az 3 harflik öneki (``buf`` ↔ ``buffer``, ``str`` ↔ ``string``).
- ``yanlis``: geri kalan.

P05b ek ölçüleri (``kos``; ön kayıt ``docs/arge/2026-11-18_onarim/P05b_on_kayit.md``)
------------------------------------------------------------------------------------------
Her ad için parametrenin girdi imzasındaki bildirilen tipi (``imza_tipleri``: betiğin KENDİ
ayrıştırıcısı; ürünün ``_PARAM_PARSE_RE``'sinden bağımsız) ve tip sınıfı (``tip_sinifi``):
``isaretci`` (``*``, dizi ya da işlev göstericisi), ``tamsayi8`` (Ghidra'nın işaretçi istisnası
olabilen 8 baytlık tamsayı: ``long`` / ``ulong`` / ``undefined8`` / ``uint64_t`` / ``int64_t`` /
``longlong`` / ``ulonglong``), ``diger``.

``str_ailesi``
    Ad tabanı (``_N`` eki atılmış) ``str`` / ``text`` / ``name`` / ``string``. Sınıf:
    ``char_isaretci`` (bildirilen tip ``char *`` / ``const char *``: Ghidra'nın tip kanıtı),
    ``kanitli`` (başka tip, betiğin bağımsız dizgi kanıtı var), ``kanitsiz`` (başka tip, kanıt yok).
    Bağımsız dizgi kanıtı (``dizgi_kaniti``): parametre (çıplak ya da tek cast'li) bir dizgi
    işlevinin dizgi konumunda argüman (``STR_FONK``), ``*(char *)`` erişimi ya da ``*p`` /
    ``p[i]`` bir karakter sabitiyle karşılaştırılıyor.
``isaretciye_skaler``
    ``type_heuristic`` adı skaler bir şablondan (``SKALER_ADLAR``) ve parametrenin bildirilen tipi
    ``isaretci``: ürün işaretçiyi taban tip okuduğu için ``char *`` → ``enabled`` (bool şablonu),
    ``int *`` → ``count`` gibi adlar.
``ipucu``
    Gerekçesi ``Caller hint`` olan ad (``CALLER_NAME_HINTS``).

DWARF hükmünde parametre sayısı betiğin kendi imza ayrıştırıcısından alınır (ürünün
ayrıştırıcısı P05b'de değişiyor; ölçü ondan bağımsız kalmalı). Değişmemiş kodda iki sayım aynı
sonucu verir (``once`` kolunda P05 ``k2`` ile aynı hüküm sayıları beklenir).

Alt komutlar
------------
    say          --kosu <kayıtlı koşu kökü> [--yalniz a,b] [--json <yol>]
    kos          --kosu <kayıtlı koşu kökü> --kok <çıktı kökü> --etiket <ad> [--yalniz a,b]
                 [--hizalama <t0b hizalama dizini>] [--taban-debian <dizin>] [--taban-mac <dizin>]
    karsilastir  --kok <çıktı kökü> --once <etiket> --sonra <etiket> [--json <yol>]
    kural_payi   --kok <çıktı kökü> --once <etiket> --sonra <etiket>
                 --p05-kayip <P05 fark_once_k2.json> [--json <yol>]   (P05b Kalem 3)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable

ARAC = "p05_olc/2"
DEPO = Path(__file__).resolve().parents[2]
if str(DEPO) not in sys.path:
    sys.path.insert(0, str(DEPO))

import karadul  # noqa: E402

if DEPO not in Path(karadul.__file__).resolve().parents:
    raise ImportError(f"karadul {karadul.__file__} yolundan yüklendi; beklenen depo {DEPO}")

from karadul.reconstruction import name_validity  # noqa: E402

BITTI = "BITTI"

GHIDRA_OTO = re.compile(
    r"^(?:(?:DAT|PTR|FUN|LAB|SUB|EXT|OFF|UNK|BYTE|WORD|DWORD|QWORD|switchD|caseD|thunk_FUN"
    r"|PTR_FUN|s|u|ds|unicode)_[0-9A-Za-z_]*[0-9a-fA-F]{4,}"
    r"|local_[0-9a-fA-F]+|param_\d+|src_\d+|dest_\d+|[a-z]{1,2}Var\d+"
    r"|[a-z]{1,3}Stack_[0-9a-fA-F]+|in_\w+|extraout_\w+|unaff_\w+|in_stack_[0-9a-fA-F]+)$"
)
MATRIS_VEKTOR = re.compile(r"^(?:[MKA]_matrix|(?:v|u|phi)_vector)(?:_\d+)?$")
WAS_IMZA = re.compile(r"([^\s,()*]+) /\* was: (\w+) \*/")
KOD_DISI = re.compile(
    r'"(?:\\.|[^"\\\n])*(?:"|(?=\n)|\Z)'
    r"|'(?:\\.|[^'\\\n])*(?:'|(?=\n)|\Z)"
    r"|//[^\n]*"
    r"|/\*.*?(?:\*/|\Z)",
    re.DOTALL,
)
TANIMLAYICI = re.compile(r"\b[A-Za-z_]\w*\b")
ADRES = re.compile(r"^// Address:\s*([0-9a-fA-F]+)\s*$", re.MULTILINE)
SAYI_EKI = re.compile(r"_\d+$")
BELIRTEC = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")

# P05b ölçüleri (ön kayıt P05b_on_kayit.md §2)
STR_AILESI = frozenset({"str", "text", "name", "string"})
SKALER_ADLAR = frozenset({
    "count", "value", "status", "counter", "n_size", "enabled", "threshold", "scalar",
    "factor", "flags", "buffer_size", "handle",
})
TAMSAYI8 = frozenset({"long", "ulong", "undefined8", "uint64_t", "int64_t", "longlong",
                      "ulonglong"})
CHAR_ISARETCI = frozenset({"char *", "const char *"})
# Dizgi işlevi → dizgi argümanının konumları (C / POSIX prototipleri). ``_`` önekli Mach-O
# biçimi aynı konumları kullanır; ``__X_chk`` sürümlerinde biçim dizgisi bayrak + uzunluk
# argümanları yüzünden kayar (ayrı yazıldı).
STR_FONK: dict[str, tuple[int, ...]] = {
    "strlen": (0,), "strnlen": (0,), "strcmp": (0, 1), "strncmp": (0, 1),
    "strcasecmp": (0, 1), "strncasecmp": (0, 1), "strcoll": (0, 1), "strcpy": (0, 1),
    "strncpy": (0, 1), "stpcpy": (0, 1), "strcat": (0, 1), "strncat": (0, 1),
    "strchr": (0,), "strrchr": (0,), "strstr": (0, 1), "strspn": (0, 1), "strcspn": (0, 1),
    "strpbrk": (0, 1), "strtok": (0, 1), "strdup": (0,), "strndup": (0,), "strtol": (0,),
    "strtoul": (0,), "strtoll": (0,), "strtoull": (0,), "strtod": (0,), "atoi": (0,),
    "atol": (0,), "atof": (0,), "puts": (0,), "fputs": (0,), "getenv": (0,), "fopen": (0, 1),
    "open": (0,), "printf": (0,), "fprintf": (1,), "sprintf": (1,), "snprintf": (2,),
    "__printf_chk": (1,), "__fprintf_chk": (2,), "__sprintf_chk": (3,),
    "__snprintf_chk": (4,), "__strcpy_chk": (0, 1), "__strcat_chk": (0, 1),
}


# ---------------------------------------------------------------------------
# Sınıflar ve hüküm
# ---------------------------------------------------------------------------

def ad_sinifi(ad: str) -> str | None:
    """Adın kusur sınıfı (``gecersiz`` / ``anahtar`` / ``tip`` / ``ghidra_oto``); kusursuzsa None."""
    neden = name_validity.lexical_reject_reason(ad, local=True)
    if neden == name_validity.REASON_NOT_IDENTIFIER:
        return "gecersiz"
    if neden == name_validity.REASON_KEYWORD:
        return "anahtar"
    if neden == name_validity.REASON_TYPE_NAME:
        return "tip"
    if GHIDRA_OTO.match(ad):
        return "ghidra_oto"
    return None


def kod_ort(metin: str) -> str:
    """Dizgi, karakter sabiti ve yorumları boşlukla ört (satırlar korunur)."""
    return KOD_DISI.sub(lambda m: "".join("\n" if c == "\n" else " " for c in m.group(0)), metin)


def normal(ad: str) -> str:
    ad = ad.strip("_").lower()
    return SAYI_EKI.sub("", ad).strip("_")


def belirtecler(ad: str) -> set[str]:
    taban = SAYI_EKI.sub("", ad.strip("_"))
    return {b.lower() for b in BELIRTEC.findall(taban) if not b.isdigit()}


def ad_hukmu(ad: str, gt: str) -> str:
    if normal(ad) == normal(gt):
        return "tam"
    a, g = belirtecler(ad), belirtecler(gt)
    for x in a:
        for y in g:
            if len(x) >= 2 and x == y:
                return "yakin"
            kisa, uzun = (x, y) if len(x) <= len(y) else (y, x)
            if len(kisa) >= 3 and uzun.startswith(kisa):
                return "yakin"
    return "yanlis"


def _arg_bol(metin: str, ac: int) -> list[str] | None:
    """``metin[ac] == '('`` olan ayraç içindeki üst düzey argümanlar (dizgi içi sayılmaz)."""
    derin, bas, out, i = 0, ac + 1, [], ac
    while i < len(metin):
        c = metin[i]
        if c in "\"'":
            j = i + 1
            while j < len(metin) and metin[j] != c:
                j += 2 if metin[j] == "\\" else 1
            i = j + 1
            continue
        if c in "([{":
            derin += 1
        elif c in ")]}":
            derin -= 1
            if derin == 0:
                son = metin[bas:i].strip()
                if son or out:
                    out.append(son)
                return out
        elif c == "," and derin == 1:
            out.append(metin[bas:i].strip())
            bas = i + 1
        i += 1
    return None


def imza_tipleri(kod: str, fonk: str) -> dict[str, str]:
    """Fonksiyonun imzasındaki parametre adı → bildirilen tip (betiğin kendi ayrıştırıcısı).

    Tip, bildirimden ad çıkarılarak yazılır; ``*`` öncesi tek boşluk (``char *``,
    ``char **``); dizi parametresi işaretçiye iner (``char buf[16]`` → ``char *``); işlev
    göstericisi (``void (*cb)(int)``) ``fn *``.
    """
    ortu = kod_ort(kod)
    m = re.search(rf"\b{re.escape(fonk)}\s*\(", ortu)
    if not m:
        return {}
    args = _arg_bol(ortu, m.end() - 1)
    out: dict[str, str] = {}
    for a in args or []:
        a = " ".join(a.split())
        fp = re.fullmatch(r"(.*?)\(\s*\*+\s*(\w+)\s*\)\s*\(.*\)", a)
        if fp:
            out[fp.group(2)] = "fn *"
            continue
        # Dizi göstericisi: ``uint8_t (*p) [16]`` (Ghidra yazar)
        dg = re.fullmatch(r"(.*?)\(\s*(\*+)\s*(\w+)\s*\)\s*(?:\[[^\]]*\]\s*)+", a)
        if dg:
            out[dg.group(3)] = " ".join(dg.group(1).split()) + " " + dg.group(2) + "*"
            continue
        ad = re.search(r"(\w+)\s*((?:\[[^\]]*\]\s*)*)$", a)
        if not ad or ad.group(1) == "void":
            continue
        tip = a[:ad.start()].strip()
        if ad.group(2):
            tip += " *"
        tip = re.sub(r"\s*\*", " *", tip)
        tip = re.sub(r"\*\s+\*", "**", tip)
        tip = re.sub(r"\*\s+\*", "**", tip)
        out[ad.group(1)] = " ".join(tip.split())
    return out


def tip_sinifi(tip: str | None) -> str:
    if not tip:
        return "bilinmiyor"
    if "*" in tip:
        return "isaretci"
    if tip in TAMSAYI8:
        return "tamsayi8"
    return "diger"


_CAST_AT = re.compile(r"^\(\s*(?:const\s+)?(?:unsigned\s+)?\w+\s*\*+\s*\)\s*")


def dizgi_kaniti(kod: str, p: str) -> bool:
    """Betiğin bağımsız dizgi kanıtı (ön kayıt §2): dizgi işlevine dizgi argümanı,
    ``*(char *)`` erişimi ya da karakter sabitiyle karşılaştırma."""
    # Yorum örtülür, dizgi sabiti boş dizgiye iner (içindeki metin çağrı sayılmaz), karakter
    # sabiti kalır (karşılaştırma kanıtı)
    ortu = KOD_DISI.sub(
        lambda m: m.group(0) if m.group(0)[0] == "'" else ('""' if m.group(0)[0] == '"' else " "),
        kod,
    )
    ad = re.escape(p)
    for m in re.finditer(r"\b(_?\w+)\s*\(", ortu):
        f = m.group(1)
        konum = STR_FONK.get(f) or (STR_FONK.get(f[1:]) if f.startswith("_") else None)
        if not konum:
            continue
        args = _arg_bol(ortu, m.end() - 1) or []
        for k in konum:
            if k < len(args) and _CAST_AT.sub("", args[k]) == p:
                return True
    if re.search(rf"\*\s*\(\s*(?:const\s+)?char\s*\*\s*\)\s*\(?\s*{ad}\b", ortu):
        return True
    if re.search(rf"(?:\*\s*{ad}\b|\b{ad}\s*\[[^\]]*\])\s*[!=]=\s*'", ortu):
        return True
    return False


# ---------------------------------------------------------------------------
# Koşu dizinleri
# ---------------------------------------------------------------------------

def kosulari_bul(kok: Path, yalniz: Iterable[str] | None = None) -> dict[str, Path]:
    secili = set(yalniz) if yalniz else None
    sonuc: dict[str, Path] = {}
    for bitti in sorted(kok.rglob(BITTI)):
        d = bitti.parent
        anahtar = d.relative_to(kok).as_posix()
        if secili is None or anahtar in secili:
            sonuc[anahtar] = d
    if secili is not None:
        eksik = sorted(secili - set(sonuc))
        if eksik:
            raise SystemExit(f"koşu bulunamadı: {eksik}")
    return sonuc


def ws_bul(kosu: Path) -> Path | None:
    adaylar = sorted(p for p in (kosu / "ws" / "workspaces").glob("*/*") if p.is_dir())
    return adaylar[-1] if adaylar else None


def _sec(ws: Path, ad: str) -> Path:
    p = ws / "deobfuscated" / ad
    return p if p.exists() else ws / "static" / ad


# ---------------------------------------------------------------------------
# say: kayıtlı çıktı
# ---------------------------------------------------------------------------

def say_kayitli(kosu: Path) -> dict[str, Any]:
    imza: Counter = Counter()
    for c in sorted((kosu / "out" / "src").rglob("*.c")):
        metin = c.read_text(encoding="utf-8", errors="replace")
        for m in WAS_IMZA.finditer(metin):
            ad = m.group(1)
            imza["toplam"] += 1
            imza[ad_sinifi(ad) or "gecerli"] += 1
            if MATRIS_VEKTOR.match(ad):
                imza["matris_vektor"] += 1
    harita: Counter = Counter()
    ws = ws_bul(kosu)
    pm = ws / "reconstructed" / "param_naming_map.json" if ws else None
    if pm is not None and pm.exists():
        veri = json.loads(pm.read_text(encoding="utf-8"))
        for f in veri.get("functions", {}).values():
            for ad in f.get("renames", {}).values():
                harita["toplam"] += 1
                harita[ad_sinifi(ad) or "gecerli"] += 1
                if MATRIS_VEKTOR.match(ad):
                    harita["matris_vektor"] += 1
    else:
        harita["harita_yok"] = 1
    return {"imza": dict(imza), "harita": dict(harita)}


def kusurlu(sayac: dict[str, int]) -> int:
    return sum(sayac.get(k, 0) for k in ("gecersiz", "anahtar", "tip", "ghidra_oto"))


def cmd_say(args: argparse.Namespace) -> int:
    kosular = kosulari_bul(args.kosu, args.yalniz.split(",") if args.yalniz else None)
    ikililer = {a: say_kayitli(d) for a, d in kosular.items()}
    top_i: Counter = Counter()
    top_h: Counter = Counter()
    ikili_sayilari: Counter = Counter()
    for s in ikililer.values():
        top_i.update(s["imza"])
        top_h.update(s["harita"])
        if s["imza"].get("gecersiz", 0) + s["imza"].get("anahtar", 0) + s["imza"].get("tip", 0):
            ikili_sayilari["imza_gecersiz_anahtar_tip"] += 1
        if s["harita"].get("matris_vektor", 0):
            ikili_sayilari["harita_matris_vektor"] += 1
        if kusurlu(s["harita"]):
            ikili_sayilari["harita_kusurlu"] += 1
    ozet = {"arac": ARAC, "kosu": str(args.kosu), "ikili": len(ikililer),
            "imza": dict(top_i), "harita": dict(top_h), "ikili_sayilari": dict(ikili_sayilari),
            "ikililer": ikililer}
    metin = json.dumps(ozet, ensure_ascii=False, indent=1, sort_keys=True)
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(metin, encoding="utf-8")
    print(json.dumps({k: v for k, v in ozet.items() if k != "ikililer"}, ensure_ascii=False,
                     indent=1, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# kos: yeniden oynatma
# ---------------------------------------------------------------------------

def _algoritmalar(ws: Path) -> list[Any]:
    out: list[Any] = []
    for ad in ("algorithms.json", "engineering_algorithms.json"):
        p = ws / "reconstructed" / ad
        if not p.exists():
            continue
        veri = json.loads(p.read_text(encoding="utf-8"))
        for a in veri.get("algorithms", []) or []:
            out.append(SimpleNamespace(
                function_name=a.get("function") or a.get("function_name", ""),
                name=a.get("name", ""), confidence=float(a.get("confidence", 0.0)),
            ))
    return out


def _imzalar(ws: Path) -> list[Any] | None:
    p = ws / "reconstructed" / "signature_matches.json"
    if not p.exists():
        return None
    veri = json.loads(p.read_text(encoding="utf-8"))
    out = [SimpleNamespace(original_name=m.get("original", ""), matched_name=m.get("matched", ""),
                           library=m.get("library", ""), confidence=float(m.get("confidence", 0.0)),
                           params=m.get("params"))
           for m in veri.get("matches", []) or []]
    return out or None


def _adresler(girdi: Path) -> dict[str, int]:
    """Girdi dizinindeki her ``.c`` dosyasının tanımladığı fonksiyon adı → ``// Address:``."""
    from karadul.reconstruction.engineering.semantic_namer import _FUNC_SIG_RE

    out: dict[str, int] = {}
    for c in sorted(girdi.glob("*.c")):
        metin = c.read_text(encoding="utf-8", errors="replace")
        m = ADRES.search(metin)
        s = _FUNC_SIG_RE.search(metin)
        if m and s:
            out.setdefault(s.group(1), int(m.group(1), 16))
    return out


def _gt_yukle(hizalama: Path | None, sha: str | None, ikili: str) -> dict[int, dict] | None:
    if hizalama is None or sha is None:
        return None
    p = hizalama / f"{ikili}.json"
    if not p.exists():
        return None
    veri = json.loads(p.read_text(encoding="utf-8"))
    if veri.get("girdi", {}).get("ghidra_ikili_sha256") != sha:
        return None
    out: dict[int, dict] = {}
    for f in veri.get("fonksiyonlar", []):
        g = f.get("ghidra") or {}
        if not g.get("giris"):
            continue
        params = {}
        for prm in f.get("parametreler", []) or []:
            if prm.get("eslesme") == "tam" and isinstance(prm.get("depolama_ortagi"), int):
                params[prm["depolama_ortagi"]] = prm["dwarf"]["ad"]
        out[int(g["giris"], 16)] = {"n": f.get("ghidra_parametre"), "params": params}
    return out


def _girdi_sha(taban_debian: Path, taban_mac: Path) -> dict[str, str]:
    sys.path.insert(0, str(DEPO / "scripts" / "measurement"))
    import urun_kos  # noqa: E402

    return {i["anahtar"]: i["sha256"] for i in urun_kos.isleri_topla(taban_debian, taban_mac)}


def yeniden_oynat(kosu: Path, hedef: Path, gt: dict[int, dict] | None) -> dict[str, Any]:
    from karadul.config import Config
    from karadul.reconstruction.engineering.semantic_namer import SemanticParameterNamer

    ws = ws_bul(kosu)
    if ws is None:
        return {"durum": "ws_yok"}
    girdi = ws / "reconstructed" / "struct_recovered"
    if not girdi.is_dir():
        return {"durum": "girdi_yok"}
    namer = SemanticParameterNamer(Config())
    sem = hedef / "semantic_named"
    t0 = time.monotonic()
    sonuc = namer.rename(
        decompiled_dir=girdi, functions_json=_sec(ws, "ghidra_functions.json"),
        call_graph_json=_sec(ws, "ghidra_call_graph.json"), output_dir=sem,
        algorithm_matches=_algoritmalar(ws), signature_matches=_imzalar(ws),
    )
    sure = round(time.monotonic() - t0, 2)
    yeni_harita = json.loads((hedef / "param_naming_map.json").read_text(encoding="utf-8"))
    kayitli_p = ws / "reconstructed" / "param_naming_map.json"
    dogrulama = "kayitli_yok"
    if kayitli_p.exists():
        kayitli = json.loads(kayitli_p.read_text(encoding="utf-8"))
        a = {f: v.get("renames", {}) for f, v in kayitli.get("functions", {}).items()}
        b = {f: v.get("renames", {}) for f, v in yeni_harita.get("functions", {}).items()}
        dogrulama = "ayni" if a == b else "farkli"
    # Köken kaydı (P05 sonrası kod): kabul edilen ad sayısı = yeniden adlandırma sayısı mı
    koken = getattr(sonuc, "provenance", None)
    koken_esit = (len(koken.get("accepted", [])) == sonuc.total_renamed) if koken else None
    # Çıktı dizinini tutma: yer kaplamasın (harita ve sayım yeter)
    for c in sem.glob("*.c"):
        c.unlink()
    sem.rmdir()

    adresler = _adresler(girdi) if gt is not None else {}
    sayac: Counter = Counter()
    kaynak: Counter = Counter()
    kaynak_hukum: dict[str, Counter] = defaultdict(Counter)
    hukum: Counter = Counter()
    ogeler: list[dict] = []
    str_ailesi: Counter = Counter()
    isaretciye_skaler: Counter = Counter()
    ipucu = 0
    tip_onbellek: dict[str, dict[str, str]] = {}
    for sn in sonuc.names:
        ad = sn.semantic_name
        kod_f = namer._func_codes.get(sn.function_name, "")
        if sn.function_name not in tip_onbellek:
            tip_onbellek[sn.function_name] = imza_tipleri(kod_f, sn.function_name)
        tip = tip_onbellek[sn.function_name].get(sn.original_name)
        tsinif = tip_sinifi(tip)
        taban = SAYI_EKI.sub("", ad)
        kanit = None
        if taban in STR_AILESI:
            if tip in CHAR_ISARETCI:
                kanit = "char_isaretci"
            else:
                kanit = "kanitli" if dizgi_kaniti(kod_f, sn.original_name) else "kanitsiz"
            str_ailesi[f"{sn.source}|{kanit}"] += 1
            str_ailesi[kanit] += 1
        if sn.source == "type_heuristic" and taban in SKALER_ADLAR and tsinif == "isaretci":
            isaretciye_skaler[taban] += 1
        if (sn.reason or "").startswith("Caller hint"):
            ipucu += 1
        sinif = ad_sinifi(ad)
        if sinif is None:
            kod = namer._func_codes.get(sn.function_name, "")
            kimlikler = set(TANIMLAYICI.findall(kod_ort(kod))) - {sn.original_name}
            if ad in kimlikler:
                sinif = "govde_cakismasi"
        sayac["toplam"] += 1
        sayac[sinif or "gecerli"] += 1
        if MATRIS_VEKTOR.match(ad):
            sayac["matris_vektor"] += 1
        kaynak[sn.source] += 1
        h = None
        gt_ad = None
        if gt is not None:
            adr = adresler.get(sn.function_name)
            f = gt.get(adr) if adr is not None else None
            m = re.fullmatch(r"param_(\d+)", sn.original_name)
            if f is None or m is None:
                h = "gt_yok"
            else:
                # Parametre sayısı betiğin kendi imza ayrıştırıcısından (ürününki P05b'de
                # değişiyor; ölçü ondan bağımsız kalmalı)
                if f["n"] != len(tip_onbellek[sn.function_name]):
                    h = "imza_uyusmadi"
                else:
                    gt_ad = f["params"].get(int(m.group(1)))
                    h = ad_hukmu(ad, gt_ad) if gt_ad else "gt_yok"
            hukum[h] += 1
            kaynak_hukum[sn.source][h] += 1
        ogeler.append({"f": sn.function_name, "eski": sn.original_name, "ad": ad,
                       "kaynak": sn.source, "guven": sn.confidence,
                       "sinif": sinif, "hukum": h, "gt": gt_ad, "tip": tip,
                       "tip_sinifi": tsinif, "dizgi": kanit,
                       "gerekce": (sn.reason or "")[:100]})
    return {"durum": "tamam", "sure_sn": sure, "dogrulama": dogrulama, "koken_esit": koken_esit,
            "sayac": dict(sayac), "str_ailesi": dict(str_ailesi),
            "isaretciye_skaler": dict(isaretciye_skaler), "ipucu": ipucu,
            "kaynak": dict(kaynak), "hukum": dict(hukum) if gt is not None else None,
            "kaynak_hukum": {k: dict(v) for k, v in kaynak_hukum.items()},
            "ogeler": ogeler}


def cmd_kos(args: argparse.Namespace) -> int:
    kosular = kosulari_bul(args.kosu, args.yalniz.split(",") if args.yalniz else None)
    shalar = _girdi_sha(args.taban_debian, args.taban_mac) if args.hizalama else {}
    kok = args.kok / args.etiket
    kok.mkdir(parents=True, exist_ok=True)
    ikililer: dict[str, Any] = {}
    for anahtar, kosu in kosular.items():
        hedef = kok / anahtar
        hedef.mkdir(parents=True, exist_ok=True)
        gt = _gt_yukle(args.hizalama, shalar.get(anahtar), anahtar.rsplit("/", 1)[-1])
        try:
            sonuc = yeniden_oynat(kosu, hedef, gt)
        except Exception as exc:  # ölçüm sürer; hata kayda geçer
            sonuc = {"durum": "hata", "hata": f"{type(exc).__name__}: {exc}"}
        (hedef / "sonuc.json").write_text(
            json.dumps(sonuc, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")
        ikililer[anahtar] = {k: v for k, v in sonuc.items() if k != "ogeler"}
        print(f"{anahtar}: {sonuc.get('durum')} {sonuc.get('dogrulama', '')} "
              f"{sonuc.get('sayac', {})} {sonuc.get('hukum') or ''}", flush=True)
    toplam: Counter = Counter()
    hukum: Counter = Counter()
    kaynak: Counter = Counter()
    kaynak_hukum: dict[str, Counter] = defaultdict(Counter)
    dogrulama: Counter = Counter()
    durum: Counter = Counter()
    ikili_sayilari: Counter = Counter()
    str_ailesi: Counter = Counter()
    isaretciye_skaler: Counter = Counter()
    ipucu = 0
    for s in ikililer.values():
        str_ailesi.update(s.get("str_ailesi", {}))
        isaretciye_skaler.update(s.get("isaretciye_skaler", {}))
        ipucu += s.get("ipucu", 0)
        durum[s.get("durum")] += 1
        dogrulama[s.get("dogrulama", "-")] += 1
        ikili_sayilari[f"koken_esit_{s.get('koken_esit')}"] += 1
        toplam.update(s.get("sayac", {}))
        kaynak.update(s.get("kaynak", {}))
        if s.get("hukum"):
            hukum.update(s["hukum"])
            ikili_sayilari["gt_li"] += 1
        for k, v in (s.get("kaynak_hukum") or {}).items():
            kaynak_hukum[k].update(v)
        sayac = s.get("sayac", {})
        if kusurlu(sayac) + sayac.get("govde_cakismasi", 0):
            ikili_sayilari["kusurlu"] += 1
        if sayac.get("matris_vektor", 0):
            ikili_sayilari["matris_vektor"] += 1
    ozet = {"arac": ARAC, "kosu": str(args.kosu), "etiket": args.etiket,
            "hizalama": str(args.hizalama) if args.hizalama else None,
            "ikili": len(ikililer), "durum": dict(durum), "dogrulama": dict(dogrulama),
            "sayac": dict(toplam), "kaynak": dict(kaynak), "hukum": dict(hukum),
            "kaynak_hukum": {k: dict(v) for k, v in kaynak_hukum.items()},
            "ikili_sayilari": dict(ikili_sayilari), "str_ailesi": dict(str_ailesi),
            "isaretciye_skaler": dict(isaretciye_skaler),
            "isaretciye_skaler_toplam": sum(isaretciye_skaler.values()), "ipucu": ipucu,
            "ikililer": ikililer}
    (kok / "ozet.json").write_text(json.dumps(ozet, ensure_ascii=False, indent=1, sort_keys=True),
                                   encoding="utf-8")
    print(json.dumps({k: v for k, v in ozet.items() if k != "ikililer"}, ensure_ascii=False,
                     indent=1, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# karsilastir
# ---------------------------------------------------------------------------

def _ogeler(kok: Path) -> dict[tuple[str, str, str], dict]:
    out = {}
    for p in sorted(kok.rglob("sonuc.json")):
        anahtar = p.parent.relative_to(kok).as_posix()
        for o in json.loads(p.read_text(encoding="utf-8")).get("ogeler", []):
            out[(anahtar, o["f"], o["eski"])] = o
    return out


def cmd_karsilastir(args: argparse.Namespace) -> int:
    once = _ogeler(args.kok / args.once)
    sonra = _ogeler(args.kok / args.sonra)
    dogru = {"tam", "yakin"}
    kayip, kazanc, degisen = [], [], Counter()
    for k in sorted(set(once) | set(sonra)):
        a, b = once.get(k), sonra.get(k)
        ha = a.get("hukum") if a else None
        hb = b.get("hukum") if b else None
        if ha in dogru and hb not in dogru:
            kayip.append({"anahtar": k[0], "f": k[1], "eski": k[2], "once": a["ad"],
                          "once_kaynak": a["kaynak"], "sonra": b["ad"] if b else None,
                          "sonra_hukum": hb, "gt": a.get("gt")})
        if hb in dogru and ha not in dogru:
            kazanc.append({"anahtar": k[0], "f": k[1], "eski": k[2], "sonra": b["ad"],
                           "sonra_kaynak": b["kaynak"], "once": a["ad"] if a else None,
                           "once_hukum": ha, "gt": b.get("gt"),
                           "gerekce": b.get("gerekce")})
        if a and b and a["ad"] != b["ad"]:
            degisen["ad_degisti"] += 1
        elif a and not b:
            degisen["ad_dustu"] += 1
        elif b and not a:
            degisen["ad_eklendi"] += 1
    sonuc = {"arac": ARAC, "once": args.once, "sonra": args.sonra, "degisen": dict(degisen),
             "dogru_kayip": len(kayip), "dogru_kazanc": len(kazanc),
             "kayiplar": kayip, "kazanclar": kazanc}
    metin = json.dumps(sonuc, ensure_ascii=False, indent=1, sort_keys=True)
    if args.json:
        Path(args.json).write_text(metin, encoding="utf-8")
    print(json.dumps({k: v for k, v in sonuc.items() if k not in ("kayiplar", "kazanclar")},
                     ensure_ascii=False, indent=1, sort_keys=True))
    return 0


# ---------------------------------------------------------------------------
# kural_payi (P05b Kalem 3): yeni yayılım kurallarının DWARF payı
# ---------------------------------------------------------------------------

# P05.md §1: 29 kaybın 12'si tesadüf (önceki ad çöptü; belirteç ortaklığıyla doğru sayılmıştı)
P05_TESADUF = frozenset({
    "len_57_0xffffffff", "pos_13_field_ptr_165", "buf_41_accumulator_24", "param_1_0x54",
    "param_1_0x3d", "param_1_0x1d0", "FUN_002e28e0", "FUN_001bcd00", "FUN_001edfe0",
    "ppuVar8_PTR_s_set_window_option_0020f830", "AOF",
})


def _kural(o: dict, onceki: dict | None) -> str | None:
    """Sonraki kolun adının gerekçesinden kural (ön kayıt P05b §2 'kural payı')."""
    g = o.get("gerekce") or ""
    if g.startswith("Source text call"):
        return "string_call"
    if g.startswith("Propagated (deref)"):
        return "deref"
    if g.startswith("Named symbol"):
        return "named_symbol"
    if (g.startswith("Propagated from caller") and onceki is not None
            and onceki["ad"] != o["ad"]
            and (onceki.get("gerekce") or "").startswith("Propagated from caller")):
        return "vote"
    return None


def cmd_kural_payi(args: argparse.Namespace) -> int:
    """Kural başına D payı: kuralın adını verdiği hükümlü parametrelerde önceki kolun hükmüyle
    karşılaştırma. Kalma ölçütü (ön kayıt K3): Δdoğru ≥ 1 VE Δyanlış ≤ 0. Ayrıca P05'in 17
    gerçek kaybının bu koldaki hükmü."""
    once = _ogeler(args.kok / args.once)
    sonra = _ogeler(args.kok / args.sonra)
    dogru = {"tam", "yakin"}
    hukumlu = dogru | {"yanlis"}
    pay: dict[str, Counter] = defaultdict(Counter)
    ornek: dict[str, list] = defaultdict(list)
    for k, o in sonra.items():
        b = once.get(k)
        r = _kural(o, b)
        if r is None:
            continue
        pay[r]["ad_y"] += 1
        if o.get("hukum") not in hukumlu:
            continue
        hb = b.get("hukum") if b else None
        pay[r]["D_hukumlu"] += 1
        pay[r]["sonra_dogru"] += o["hukum"] in dogru
        pay[r]["sonra_yanlis"] += o["hukum"] == "yanlis"
        pay[r]["once_dogru"] += hb in dogru
        pay[r]["once_yanlis"] += hb == "yanlis"
        ornek[r].append({"k": list(k), "once": b["ad"] if b else None, "once_h": hb,
                         "sonra": o["ad"], "sonra_h": o["hukum"], "gt": o.get("gt")})
    karar = {}
    for r, c in pay.items():
        c["delta_dogru"] = c["sonra_dogru"] - c["once_dogru"]
        c["delta_yanlis"] = c["sonra_yanlis"] - c["once_yanlis"]
        karar[r] = "kalir" if c["delta_dogru"] >= 1 and c["delta_yanlis"] <= 0 else "tutmadi"
    p05 = json.loads(args.p05_kayip.read_text(encoding="utf-8"))
    geri = []
    for k in p05["kayiplar"]:
        if k["once"] in P05_TESADUF:
            continue
        key = (k["anahtar"], k["f"], k["eski"])
        o = sonra.get(key)
        geri.append({"anahtar": k["anahtar"], "f": k["f"], "eski": k["eski"],
                     "p05_oncesi": k["once"], "sonra": o["ad"] if o else None,
                     "hukum": o.get("hukum") if o else None, "gt": o.get("gt") if o else None,
                     "kural": _kural(o, once.get(key)) if o else None})
    sonuc = {"arac": ARAC, "once": args.once, "sonra": args.sonra,
             "pay": {r: dict(c) for r, c in sorted(pay.items())}, "karar": karar,
             "p05_gercek_kayip": len(geri),
             "p05_geri_dogru": sum(1 for g in geri if g["hukum"] in dogru),
             "p05_geri": geri, "ornek": ornek}
    if args.json:
        Path(args.json).write_text(json.dumps(sonuc, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
    print(json.dumps({k: v for k, v in sonuc.items() if k not in ("ornek", "p05_geri")},
                     ensure_ascii=False, indent=1))
    for g in geri:
        print(g)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    s = alt.add_parser("say")
    s.add_argument("--kosu", type=Path, required=True)
    s.add_argument("--yalniz")
    s.add_argument("--json")
    k = alt.add_parser("kos")
    k.add_argument("--kosu", type=Path, required=True)
    k.add_argument("--kok", type=Path, required=True)
    k.add_argument("--etiket", required=True)
    k.add_argument("--yalniz")
    k.add_argument("--hizalama", type=Path)
    k.add_argument("--taban-debian", type=Path,
                   default=Path.home() / "karadul_olcum/n1_debian13")
    k.add_argument("--taban-mac", type=Path,
                   default=Path.home() / "Black_Widow/workspaces/olcum_mac/runs/ol7-c-b7faeac")
    c = alt.add_parser("karsilastir")
    c.add_argument("--kok", type=Path, required=True)
    c.add_argument("--once", required=True)
    c.add_argument("--sonra", required=True)
    c.add_argument("--json")
    r = alt.add_parser("kural_payi")
    r.add_argument("--kok", type=Path, required=True)
    r.add_argument("--once", required=True)
    r.add_argument("--sonra", required=True)
    r.add_argument("--p05-kayip", type=Path, required=True)
    r.add_argument("--json")
    args = ap.parse_args(argv)
    return {"say": cmd_say, "kos": cmd_kos, "karsilastir": cmd_karsilastir,
            "kural_payi": cmd_kural_payi}[args.komut](args)


if __name__ == "__main__":
    sys.exit(main())
