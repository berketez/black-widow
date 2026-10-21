#!/usr/bin/env python3
"""Ghidra parametreleri ↔ DWARF parametreleri hizalaması (plan v2.2 T0b, ÖL-4'ün parametre kısmı).

Girdiler:
- ``dwarf_tip.py toplu`` belgeleri (``karadul-dwarf-tip/1``): DWARF fonksiyonları, parametre
  tipleri ve girişteki konum (``giris``);
- ``ghidra_parametre.py`` belgeleri (``karadul-ghidra-parametre/1``): Ghidra fonksiyonları, liste
  imzası ve decompiler parametreleri (C'deki ``param_N``), depolamalarıyla.
İki belge ikilinin build-id'siyle eşlenir (DWARF: ana ``.debug``'ın build-id'si; Ghidra: ikilinin).

Yöntem
------
1. **Yükleme tabanı (PIE).** Ghidra ELF'i bir görüntü tabanıyla yükler; DWARF adresleri bağlama
   zamanı adresidir (PIE'de 0 tabanlı). Fark varsayılmaz, üç bağımsız yoldan ölçülür ve
   karşılaştırılır: (i) Ghidra ``image_base`` − ELF'in en küçük ``PT_LOAD`` ``p_vaddr``'ı;
   (ii) Ghidra'nın ``.text`` bloğu − ELF ``.text`` ``sh_addr``'ı; (iii) tarama: DWARF
   adreslerinden tohumlu örneklem × bütün Ghidra girişleri, farkların en sık değeri. Seçilen fark
   ayrıca bayt düzeyinde doğrulanır: eşlenen her fonksiyonda ikili dosyanın DWARF adresindeki
   (``PT_LOAD`` ile dosya ofsetine çevrilmiş) ilk 16 baytı Ghidra'nın o girişteki baytlarıyla aynı
   mı.
2. **Fonksiyon.** DWARF fonksiyonu (``low_pc``'li somut gövde) ``low_pc + fark`` adresinde girişi
   olan Ghidra fonksiyonuyla eşlenir. Eşlenmeyenler: ``govde_icinde`` (başka bir Ghidra
   fonksiyonunun gövdesinde) ya da ``yok``.
3. **Parametre: depolamayla.** DWARF tarafında anahtar girişteki konumdan çıkar: AAPCS64 argüman
   yazmacı (``x0-x7``, ``v0-v7``), gelen yığın ofseti (CFA'ya göre), ``dolayli`` yapı kopyasında
   işaretçiyi taşıyan yazmaç, parçalı konumda parçaların yazmaçları. Ghidra tarafında depolama
   adları normalleştirilir (``w3``/``x3`` → ``x3``; ``b/h/s/d/q/v3`` → ``v3``; ``Stack[N]`` →
   yığın N). Eşleşme anahtar eşitliğidir. DWARF konumu girişi anlatmıyorsa (``konumsuz``,
   ``yerel_yuva``, argüman dışı yazmaç, ``sabit``, ``deger``; ayrıca ``exprloc`` ile yazılmış
   ``dolayli`` konum: GCC yapı kopyasının adresini prolog sonrası yazmaçla yazar, geliştirme
   setinde 49 vakanın 24'ünde ABI yazmacından farklı) ve fonksiyon klon değilse ikinci kaynak
   **AAPCS64 beklentisi**dir (bildirim sırası ve tiplerden; ``aapcs64``); bu eşleşmeler ayrı
   sayılır (``abi``). DWARF konumu ile ABI beklentisi ikisi de varsa uyumları sayılır
   (``dwarf_abi_uyumu``): okuyucunun ve ABI hesabının bağımsız sınaması.
4. **Parametre: sırayla** (karşılaştırma için). DWARF'ın ``sira``'sı k olan parametresi
   ``param_k`` ile eşlenseydi ne olurdu: ``uyumlu`` (depolama ortağıyla aynı), ``celiski``
   (farklı parametre ya da depolamada ortak yokken başka bir parametre), ``yalniz_sira``
   (depolama bilgisi yok, yalnız sıra eşler), ``ortaksiz``.
5. **Sınıflar.** Eşleşmeyen DWARF parametreleri: ``klon``, ``decompile_yok``,
   ``ghidra_thunk`` (Ghidra fonksiyonu thunk sayıyor: tek sıçramalık gövde, C'si
   ``thunk_FUN_…()``), ``kullanilmayan_ya_da_optimize`` (girişte yeri yok ve ABI de eşlemiyor),
   ``ghidra_az`` (Ghidra
   o sınıfta daha az parametre görmüş: sayı farkı), ``ghidra_atladi`` (Ghidra aynı sınıfta daha
   yüksek argüman yazmacını görmüş ama bunu görmemiş; x8 sayılmaz), ``yigin_eksik``, ``diger``
   (girişte yeri var ama güvenilir anahtar yok). Ghidra'da parametre olmayan yazmaç C'de
   ``in_x4`` gibi bir girdi olarak görünüyorsa ``c_girdisi`` yazılır. Eşlenen ama tek parçalı
   olmayanlar:
   ``yapi_bolunmesi`` (değerle geçen yapı birden çok Ghidra parametresine bölünmüş), ``kismi``.
   DWARF karşılığı olmayan Ghidra parametreleri: ``degisken_arguman``, ``x8_donus``, ``klon``,
   ``fazla``. Sıra çelişkileri ayrıca ``yazmac_sinifi_farki`` olarak işaretlenir (sıra ortağının
   yazmaç sınıfı farklı: x ↔ v). Fonksiyon başına ``fonksiyon_sinifi``
   (``FONKSIYON_SINIFLARI``) ve gövde boyu karşılaştırması (``govde``: DWARF ``high_pc - low_pc``
   ↔ Ghidra gövdesi) yazılır.
6. **Klon.** ``.isra``/``.constprop``/``.part``/``.cold`` soneki, ``sira ≠ somut_sira``, tekrar
   DIE ya da bildirimden düşen parametre (plan v2.2 T0 (c)). ``abstract_origin`` tek başına klon
   sayılmaz (T0a §4).

Alt komutlar
------------
    secim   [--debian13 <dizin>] [--tohum-metni ..] [--n 12] -o <liste.json>
            (8 programın ikilileri; coreutils'ten tohumla 12)
    hizala  --dwarf <dizin...> --ghidra <dizin...> -o <çıktı dizini>
    ozet    <hizalama dizini> [--json <yol>]
    denetim <hizalama dizini> --dwarf <dizin...> --ghidra <dizin...> -o <paket.json>
            [--evren hepsi|zor] [--n N] [--tohum-metni ..] [--kararlar <json>]
            (hepsi: 50 örnek, zor: sıra çelişkisi / ABI / bölünme, 15 örnek; ayrı tohumlar.
            Kararlar örnek numarası ve kimliğiyle bağlanır; kimlik uyuşmazsa işaretlenir)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import re
import subprocess
import sys
from bisect import bisect_right
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional

HIZALAMA_SEMA = "karadul-parametre-hizalama/1"
HIZALAMA_OZET_SEMA = "karadul-parametre-hizalama-ozet/1"
DENETIM_SEMA = "karadul-parametre-hizalama-denetim/1"
DWARF_SEMA = "karadul-dwarf-tip/1"
GHIDRA_SEMA = "karadul-ghidra-parametre/1"

SECIM_TOHUM_METNI = "karadul-g10-t0b-coreutils-secimi-2026-10-21"
SECIM_N = 12
TARAMA_TOHUM_METNI = "karadul-g10-t0b-pie-tarama-2026-10-21"
TARAMA_ORNEK = 200
DENETIM_TOHUM_METNI = "karadul-g10-t0b-hizalama-denetimi-2026-10-21"
DENETIM_N = 50
ZOR_TOHUM_METNI = "karadul-g10-t0b-zor-vaka-denetimi-2026-10-21"
ZOR_N = 15
DENETIM_C_SATIR = 15
DENETIM_ILGILI_SATIR = 14
DWARFDUMP_YOLU = "/usr/bin/dwarfdump"      # Apple llvm-dwarfdump; conda araçlarına güvenilmez

# Debian 13 geliştirme seti (dogrulama_seti_onkayit.md §8.1): paket -> (sürüm, ikili alt yolları)
GELISTIRME_PAKETLERI: dict[str, tuple[str, tuple[str, ...]]] = {
    "tmux": ("3.5a-3", ("usr/bin/tmux",)),
    "htop": ("3.4.1-5", ("usr/bin/htop",)),
    "tree": ("2.2.1-1", ("usr/bin/tree",)),
    "zstd": ("1.5.7+dfsg-1", ("usr/bin/zstd", "usr/bin/pzstd")),
    "sqlite3": ("3.46.1-7+deb13u2", ("usr/bin/sqlite3",)),
    "openssl": ("3.5.7-1~deb13u2", ("usr/bin/openssl",)),
    # redis-check-rdb, redis-check-aof ile aynı ikili (aynı build-id); bir kez sayılır
    "redis-tools": ("5:8.0.2-3+deb13u2", ("usr/bin/redis-cli", "usr/bin/redis-benchmark",
                                          "usr/bin/redis-check-aof")),
    "coreutils": ("9.7-3", ()),             # tohumla seçilir
}

ARGUMAN_GPR = 8
ARGUMAN_SIMD = 8
X8 = ("x", 8)
_YAZMAC_RE = re.compile(r"([xwbhsdqv])(\d+)")
C_DILLERI = {0x01: "C", 0x02: "C", 0x0C: "C", 0x1D: "C", 0x2C: "C"}
CPP_DILLERI = {0x04: "C++", 0x19: "C++", 0x1A: "C++", 0x21: "C++", 0x2A: "C++", 0x2B: "C++"}

# Eşleşmeyen DWARF parametresi sınıfları ve DWARF karşılığı olmayan Ghidra parametresi sınıfları
DWARF_SINIFLARI = ("klon", "decompile_yok", "ghidra_thunk", "kullanilmayan_ya_da_optimize",
                   "ghidra_az", "ghidra_atladi", "yigin_eksik", "diger")
GHIDRA_SINIFLARI = ("degisken_arguman", "x8_donus", "klon", "fazla")
SIRA_DURUMLARI = ("uyumlu", "celiski", "yalniz_sira", "ortaksiz")
# DWARF'a göre girişte var olmayan parametre (``dwarf_tip`` ``giris.tur``)
GIRISTE_YOK = frozenset({"konumsuz", "sabit", "deger"})
FONKSIYON_SINIFLARI = ("tam_uyum", "sira_bozuk", "ghidra_eksik", "ghidra_fazla",
                       "eksik_ve_fazla", "klon", "ghidra_thunk", "decompile_yok")


def tohum(metin: str) -> int:
    """Ön kayıtlardaki tohum yöntemi: SHA-256(metin)'in ilk 16 hex basamağı."""
    return int(hashlib.sha256(metin.encode("utf-8")).hexdigest()[:16], 16)


def sha256_dosya(yol: Path) -> str:
    h = hashlib.sha256()
    with open(yol, "rb") as f:
        for parca in iter(lambda: f.read(1 << 20), b""):
            h.update(parca)
    return h.hexdigest()


def _git_head() -> Optional[str]:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent,
                              capture_output=True, text=True, timeout=10,
                              check=False).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def arac_kunyesi() -> dict[str, Any]:
    return {"betik": "scripts/measurement/parametre_hizala.py",
            "betik_sha256": sha256_dosya(Path(__file__).resolve()), "git_head": _git_head(),
            "python": platform.python_version()}


def _yaz_json(yol: Path, veri: Any, girinti: Optional[int] = 1) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(json.dumps(veri, ensure_ascii=False, indent=girinti) + "\n", encoding="utf-8")


def _pay(k: int, n: int) -> Optional[float]:
    return round(k / n, 6) if n else None


# ---------------------------------------------------------------------------
# Depolama anahtarları
# ---------------------------------------------------------------------------

def yazmac_anahtari(ad: Optional[str]) -> Optional[tuple[str, int]]:
    """``x3``/``w3`` -> ("x", 3); ``b3``/``h3``/``s3``/``d3``/``q3``/``v3`` -> ("v", 3)."""
    if not ad:
        return None
    m = _YAZMAC_RE.fullmatch(ad.lower())
    if not m:
        return None
    n = int(m.group(2))
    if m.group(1) in "xw":
        return ("x", n) if n <= 30 else None
    return ("v", n) if n <= 31 else None


_C_GIRDI_RE = re.compile(r"\bin_([xwbhsdqv]\d+)\b")


def c_girdi_yazmaclari(c: str) -> dict[tuple[str, int], str]:
    """Decompile edilmiş C'de parametre yapılmamış yazmaç girdileri (``in_x4``, ``in_d0``):
    anahtar -> değişken adı. Decompiler girdiyi gördü ama prototipe koymadı."""
    sonuc: dict[tuple[str, int], str] = {}
    for m in _C_GIRDI_RE.finditer(c):
        k = yazmac_anahtari(m.group(1))
        if k is not None:
            sonuc.setdefault(k, "in_" + m.group(1))
    return sonuc


def anahtar_metni(k: Optional[tuple]) -> Optional[str]:
    if k is None:
        return None
    if k[0] == "yigin":
        return f"Stack[{k[1]}]"
    return f"{k[0]}{k[1]}"


def ghidra_anahtarlari(parametre: dict[str, Any]) -> list[tuple]:
    """Ghidra parametresinin depolama parçaları -> anahtarlar (sırasıyla)."""
    sonuc: list[tuple] = []
    for p in (parametre.get("depolama") or {}).get("parcalar") or []:
        if p["tur"] == "yazmac":
            k = yazmac_anahtari(p.get("ad"))
            sonuc.append(k if k is not None else ("diger", p.get("ad")))
        elif p["tur"] == "yigin":
            sonuc.append(("yigin", p["ofset"]))
        else:
            sonuc.append(("diger", f"{p['tur']}:{p.get('ofset')}"))
    return sonuc


def dwarf_anahtarlari(giris: Optional[dict[str, Any]]) -> Optional[list[Optional[tuple]]]:
    """DWARF girişteki konumu -> anahtarlar; konum girişi anlatmıyorsa None.

    Parçalı konumda her parça bir anahtardır (konumsuz parça None). Argüman yazmacı dışındaki
    yazmaç (``exprloc`` ile tüm fonksiyon için yazılmış ``DW_OP_breg22 0`` gibi) girişte
    parametreyi tutmaz: None. ``exprloc`` ile yazılmış ``dolayli`` konum da None: argüman
    yazmacı olsa bile prolog sonrasının yazmacı olabilir (``error_tail``'in ``va_list``'i
    ``DW_OP_breg4 0``, ABI x3)."""
    if not giris:
        return None
    tur = giris.get("tur")
    if tur == "dolayli" and giris.get("kaynak") == "exprloc":
        # GCC yapı kopyasının adresini tüm fonksiyon için prolog SONRASI yazmaçla yazar; giriş
        # yazmacı olmayabilir (geliştirme setinde ABI'yle 25 uyumlu, 24 farklı): anahtar değil.
        return None
    if tur in ("yazmac", "dolayli"):
        if not giris.get("arguman"):
            return None
        k = yazmac_anahtari(giris.get("yazmac"))
        return [k] if k is not None else None
    if tur == "yigin":
        return [("yigin", giris["ofset"])]
    if tur == "parcali":
        anahtarlar: list[Optional[tuple]] = []
        for p in giris.get("parcalar") or []:
            if p.get("tur") == "yazmac" and p.get("arguman"):
                anahtarlar.append(yazmac_anahtari(p.get("yazmac")))
            elif p.get("tur") == "yigin":
                anahtarlar.append(("yigin", p["ofset"]))
            else:
                anahtarlar.append(None)
        return anahtarlar if any(a is not None for a in anahtarlar) else None
    return None


# ---------------------------------------------------------------------------
# AAPCS64 beklentisi (Linux; C; bildirimdeki adlı parametreler)
# ---------------------------------------------------------------------------

def _hizala(n: int, h: int) -> int:
    return (n + h - 1) // h * h


def yapi_tanimi(kok: dict[str, Any], yapilar: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Yapının üyeli tam tanımı: kendisi ya da (bildirimse) erişilen birimlerdeki ilk tanımı."""
    y = yapilar.get(kok.get("konum") or "")
    if y is None or y.get("hata"):
        return None
    if not y.get("bildirim") and y.get("uyeler") is not None:
        return y
    for t in y.get("tanimlar") or []:
        ty = yapilar.get(t)
        if ty and not ty.get("bildirim") and ty.get("uyeler") is not None:
            return ty
    return None


_DIZI_RE = re.compile(r"^(.*?)((?:\[\d*\])+)$")
_KAYAN_BOYUT = {"float": 4, "double": 8, "long double": 16, "_Float16": 2}
_HIZALAMA_16 = ("long double", "__int128", "__int128 unsigned", "_Float128")


def _uye_kayanlari(kanonik: str) -> Optional[tuple[str, int]]:
    """Üye kanonik tipi kayan noktalı mı (dizisi dahil): (taban tip, eleman sayısı)."""
    m = _DIZI_RE.match(kanonik)
    taban, n = kanonik, 1
    if m:
        taban = m.group(1)
        for b in re.findall(r"\[(\d*)\]", m.group(2)):
            if not b:
                return None
            n *= int(b)
    return (taban, n) if taban in _KAYAN_BOYUT else None


def hfa_uyeleri(y: dict[str, Any], yapilar: dict[str, Any], derinlik: int = 0
                ) -> Optional[tuple[str, int]]:
    """Homojen kayan noktalı küme (HFA): bütün yaprak üyeler aynı kayan tip ise (tip, sayı).

    Kayan olmayan bir üye (işaretçi, tamsayı, enum, bit alanı…) varsa None (HFA değil); bu karar
    iç içe yapılar açılmadan verilir. Yalnız kayan üyeler ve iç içe yapılar varsa iç yapılar
    yapı tablosundan açılır; tanımı yoksa ``ValueError`` (belirsiz)."""
    if derinlik > 4:
        raise ValueError("iç içe yapı derinliği")
    kayanlar: list[tuple[str, int]] = []
    icler: list[str] = []
    for u in y.get("uyeler") or []:
        k = u.get("kanonik") or ""
        if u.get("bit_boyutu") is not None:
            return None
        kayan = _uye_kayanlari(k)
        if kayan is not None:
            kayanlar.append(kayan)
        elif u.get("sinif") == "yapi_degerle" or k.startswith(("struct ", "union ")):
            icler.append(k)
        else:
            return None
    for k in icler:
        m = re.search(r"<anon@([^>]+)>", k)
        ic = yapilar.get(m.group(1)) if m else None
        if ic is None or ic.get("uyeler") is None:
            adli = [v for v in yapilar.values()
                    if v.get("kimlik") == k and v.get("uyeler") is not None
                    and not v.get("bildirim")]
            ic = adli[0] if len(adli) == 1 else None
        if ic is None:
            raise ValueError(f"iç yapı tanımı yok: {k}")
        alt = hfa_uyeleri(ic, yapilar, derinlik + 1)
        if alt is None:
            return None
        kayanlar.append(alt)
    if not kayanlar or len({t for t, _ in kayanlar}) != 1:
        return None
    # Birlikte üyeler üst üste biner: üye sayısı en büyük üyeninkidir; yapıda toplanır.
    toplam = (max(n for _, n in kayanlar) if y.get("tur") == "union"
              else sum(n for _, n in kayanlar))
    return (kayanlar[0][0], toplam) if 1 <= toplam <= 4 else None


def abi_sinifi(tip: dict[str, Any], yapilar: dict[str, Any]
               ) -> Optional[tuple[str, int, int, int]]:
    """(sınıf ``x``|``v``|``ref``, boyut, hizalama, yazmaç sayısı); belirsizse None."""
    if not tip or not tip.get("cozuldu"):
        return None
    if tip.get("derinlik", 0) >= 1:
        return ("x", 8, 8, 1)
    kok = tip.get("kok") or {}
    tur = kok.get("tur")
    if tur == "temel":
        b = kok.get("boyut") or 0
        kod = kok.get("kodlama")
        if kod == "float":
            return ("v", b, b, 1) if b in (2, 4, 8, 16) else None
        if kod == "complex_float":
            return ("v", b, b // 2, 2) if b in (8, 16, 32) else None
        if b in (1, 2, 4, 8):
            return ("x", b, b, 1)
        if b == 16:
            return ("x", 16, 16, 2)
        return None
    if tur == "enum":
        b = kok.get("boyut") or 4
        return ("x", b, b, 1)
    if tur in ("struct", "union"):
        y = yapi_tanimi(kok, yapilar)
        if y is None or not isinstance(y.get("boyut"), int):
            return None
        boyut = y["boyut"]
        try:
            hfa = hfa_uyeleri(y, yapilar)
        except ValueError:
            return None
        if hfa is not None:
            return ("v", boyut, _KAYAN_BOYUT[hfa[0]], hfa[1])
        if boyut > 16:
            return ("ref", 8, 8, 1)
        hiz = 16 if any(any(t in (u.get("kanonik") or "") for t in _HIZALAMA_16)
                        for u in y.get("uyeler") or []) else 8
        return ("x", boyut, hiz, 1 if boyut <= 8 else 2)
    if tur == "belirsiz":
        return ("x", 8, 8, 1)
    return None                          # sınıf (C++), dizi, fonksiyon tipi: belirsiz


def aapcs64(parametreler: list[dict[str, Any]], yapilar: dict[str, Any]
            ) -> list[Optional[dict[str, Any]]]:
    """Bildirim sırasındaki parametrelerin AAPCS64 (Linux) yerleri.

    Her öğe ``{"anahtarlar": [...], "dolayli": bool}`` ya da None (belirsiz). Bir parametre
    belirsizse sonrakiler de belirsizdir (yazmaç sayaçları bilinmez)."""
    ngrn = nsrn = nsaa = 0
    sonuc: list[Optional[dict[str, Any]]] = []
    for i, p in enumerate(parametreler):
        s = abi_sinifi(p.get("tip") or {}, yapilar)
        if s is None:
            sonuc += [None] * (len(parametreler) - i)
            break
        sinif, boyut, hiz, n = s
        if sinif == "v":
            if nsrn + n <= ARGUMAN_SIMD:
                anahtarlar = [("v", nsrn + j) for j in range(n)]
                nsrn += n
            else:
                nsrn = ARGUMAN_SIMD
                nsaa = _hizala(nsaa, 16 if hiz >= 16 else 8)
                anahtarlar = [("yigin", nsaa)]
                nsaa += _hizala(boyut, 8)
            sonuc.append({"anahtarlar": anahtarlar, "dolayli": False})
            continue
        dolayli = sinif == "ref"
        if n == 2 and hiz == 16:
            ngrn = _hizala(ngrn, 2)
        if ngrn + n <= ARGUMAN_GPR:
            anahtarlar = [("x", ngrn + j) for j in range(n)]
            ngrn += n
        else:
            ngrn = ARGUMAN_GPR
            nsaa = _hizala(nsaa, 16 if hiz >= 16 else 8)
            anahtarlar = [("yigin", nsaa)]
            nsaa += _hizala(boyut, 8)
        sonuc.append({"anahtarlar": anahtarlar, "dolayli": dolayli})
    return sonuc


# ---------------------------------------------------------------------------
# Klon ve dil
# ---------------------------------------------------------------------------

def klon_nedenleri(f: dict[str, Any]) -> list[str]:
    """Plan v2.2 T0 (c): sonek, sıra değişimi, tekrar DIE, düşen parametre."""
    nedenler: list[str] = list((f.get("klon") or {}).get("sonekler") or [])
    asil = [p for p in f.get("parametreler") or [] if not p.get("tekrar")]
    if any(p.get("somut_sira") is not None and p.get("sira") != p.get("somut_sira")
           for p in asil):
        nedenler.append("sira_degisik")
    if len(asil) < len(f.get("parametreler") or []):
        nedenler.append("tekrar_die")
    soyut_n = f.get("soyut_parametre_sayisi")
    if soyut_n is not None and len({p.get("sira") for p in asil} - {None}) < soyut_n:
        nedenler.append("dusen_parametre")
    return nedenler


def dil_adi(kod: Any) -> Optional[str]:
    if kod is None:
        return None
    if isinstance(kod, int):
        return C_DILLERI.get(kod) or CPP_DILLERI.get(kod) or f"diger:0x{kod:x}"
    return str(kod)


# ---------------------------------------------------------------------------
# Yükleme tabanı (PIE)
# ---------------------------------------------------------------------------

def elf_bilgisi(ikili: Path) -> dict[str, Any]:
    """ELF türü, PT_LOAD bölütleri ve bölüm adresleri (pyelftools)."""
    from elftools.elf.elffile import ELFFile
    with open(ikili, "rb") as f:
        elf = ELFFile(f)
        yukler = [{"vaddr": s["p_vaddr"], "memsz": s["p_memsz"], "offset": s["p_offset"],
                   "filesz": s["p_filesz"], "flags": s["p_flags"]}
                  for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        bolumler = {s.name: {"addr": s["sh_addr"], "size": s["sh_size"], "offset": s["sh_offset"]}
                    for s in elf.iter_sections() if s.name}
        return {"e_type": elf["e_type"], "yukler": yukler, "bolumler": bolumler}


def vaddr_dosya_ofseti(yukler: list[dict[str, Any]], vaddr: int) -> Optional[int]:
    for s in yukler:
        if s["vaddr"] <= vaddr < s["vaddr"] + s["filesz"]:
            return s["offset"] + (vaddr - s["vaddr"])
    return None


def tarama_farklari(dwarf_adresleri: list[int], ghidra_girisleri: list[int],
                    tohum_metni: str = TARAMA_TOHUM_METNI, n: int = TARAMA_ORNEK) -> Counter:
    """Tohumlu DWARF örneklemi × bütün Ghidra girişleri: fark -> sayı."""
    evren = sorted(set(dwarf_adresleri))
    ornek = random.Random(tohum(tohum_metni)).sample(evren, min(n, len(evren)))
    farklar: Counter = Counter()
    for d in ornek:
        for g in ghidra_girisleri:
            farklar[g - d] += 1
    return farklar


def pie_tabani(ghidra: dict[str, Any], elf: dict[str, Any], dwarf_adresleri: list[int],
               *, tohum_metni: str = TARAMA_TOHUM_METNI) -> dict[str, Any]:
    image_base = int(ghidra["program"]["image_base"], 16)
    en_kucuk = min((s["vaddr"] for s in elf["yukler"]), default=0)
    aday_taban = image_base - en_kucuk
    text_g = next((int(b["bas"], 16) for b in ghidra["program"]["bloklar"]
                   if b["ad"] == ".text"), None)
    text_e = (elf["bolumler"].get(".text") or {}).get("addr")
    aday_text = text_g - text_e if text_g is not None and text_e is not None else None
    girisler = [int(f["giris"], 16) for f in ghidra["fonksiyonlar"]]
    farklar = tarama_farklari(dwarf_adresleri, girisler, tohum_metni)
    ilk = farklar.most_common(2)
    giris_kumesi = set(girisler)
    adaylar = sorted({aday_taban, 0, aday_taban + 0x1000, aday_taban - 0x1000}
                     | ({aday_text} if aday_text is not None else set())
                     | ({ilk[0][0]} if ilk else set()))
    paylar = {f"0x{d:x}" if d >= 0 else f"-0x{-d:x}":
              _pay(sum(1 for a in dwarf_adresleri if a + d in giris_kumesi), len(dwarf_adresleri))
              for d in adaylar}
    return {"image_base": f"0x{image_base:x}", "elf_e_type": elf["e_type"],
            "elf_en_kucuk_vaddr": f"0x{en_kucuk:x}",
            "fark_image_base": aday_taban, "fark_text": aday_text,
            "tarama_en_sik": ilk[0][0] if ilk else None,
            "tarama_en_sik_sayi": ilk[0][1] if ilk else 0,
            "tarama_ikinci_sayi": ilk[1][1] if len(ilk) > 1 else 0,
            "tarama_ornek": min(TARAMA_ORNEK, len(set(dwarf_adresleri))),
            "aday_eslesme_paylari": paylar,
            "uc_yol_ayni": aday_taban == aday_text == (ilk[0][0] if ilk else None),
            "secilen": aday_taban}


def bayt_dogrulamasi(ikili: Path, elf: dict[str, Any],
                     ciftler: Iterable[tuple[int, Optional[str]]]) -> dict[str, Any]:
    """(DWARF adresi, Ghidra ilk baytları) çiftlerinde dosyadaki baytlar aynı mı."""
    sayac: Counter = Counter()
    farkli: list[str] = []
    veri = ikili.read_bytes()
    for adres, ghidra_hex in ciftler:
        ofset = vaddr_dosya_ofseti(elf["yukler"], adres)
        if ofset is None or not ghidra_hex:
            sayac["okunamadi"] += 1
            continue
        g = bytes.fromhex(ghidra_hex)
        if veri[ofset:ofset + len(g)] == g:
            sayac["ayni"] += 1
        else:
            sayac["farkli"] += 1
            if len(farkli) < 10:
                farkli.append(f"0x{adres:x}")
    return {**{k: sayac.get(k, 0) for k in ("ayni", "farkli", "okunamadi")},
            "farkli_ornek": farkli}


# ---------------------------------------------------------------------------
# Fonksiyon eşleme
# ---------------------------------------------------------------------------

class GovdeIndeksi:
    """Ghidra fonksiyon gövde aralıkları: adres hangi fonksiyonun içinde."""

    def __init__(self, fonksiyonlar: list[dict[str, Any]]) -> None:
        aralik = sorted((a, b, f["giris"]) for f in fonksiyonlar for a, b in f.get("govde") or [])
        self._baslar = [a for a, _, _ in aralik]
        self._aralik = aralik

    def icinde(self, adres: int) -> Optional[str]:
        i = bisect_right(self._baslar, adres) - 1
        while i >= 0:
            a, b, giris = self._aralik[i]
            if a <= adres <= b:
                return giris
            if b < adres and a < adres - (1 << 20):
                break
            i -= 1
        return None


# ---------------------------------------------------------------------------
# Parametre hizalaması
# ---------------------------------------------------------------------------

def _dwarf_parametre_ozeti(p: dict[str, Any]) -> dict[str, Any]:
    g = p.get("giris") or {}
    t = p.get("tip") or {}
    return {"sira": p.get("sira"), "somut_sira": p.get("somut_sira"), "ad": p.get("ad"),
            "konum": p.get("konum"), "tekrar": bool(p.get("tekrar")),
            "tip": t.get("kanonik"), "sinif": t.get("sinif"), "giris_turu": g.get("tur"),
            "giris": g.get("ifade"), "yapay": bool(p.get("yapay"))}


def _ghidra_parametre_ozeti(p: dict[str, Any]) -> dict[str, Any]:
    return {"sira": p["sira"], "ad": p["ad"], "tip": p["tip"], "boyut": p["boyut"],
            "depolama": (p.get("depolama") or {}).get("metin")}


def parametre_hizala(df: dict[str, Any], gf: Optional[dict[str, Any]],
                     yapilar: dict[str, Any]) -> dict[str, Any]:
    """Bir DWARF fonksiyonunun parametrelerini eşlenen Ghidra fonksiyonununkilerle hizala."""
    klon = klon_nedenleri(df)
    dec = (gf or {}).get("decompile") or {}
    gp: list[dict[str, Any]] = dec.get("parametreler") or [] if dec.get("basarili") else []
    g_anahtar = [ghidra_anahtarlari(p) for p in gp]
    tek: dict[tuple, int] = {}            # tek parçalı Ghidra parametresi: anahtar -> indeks
    parca_sahibi: dict[tuple, int] = {}   # çok parçalı Ghidra parametresinin parçaları
    for i, ks in enumerate(g_anahtar):
        if len(ks) == 1:
            tek.setdefault(ks[0], i)
        for k in ks:
            parca_sahibi.setdefault(k, i)
    dps = df.get("parametreler") or []
    asil_sirali = sorted((p for p in dps if not p.get("tekrar") and p.get("sira") is not None),
                         key=lambda p: p["sira"])
    abi: dict[str, Optional[dict[str, Any]]] = {}
    if not klon and len(asil_sirali) == len([p for p in dps if not p.get("tekrar")]):
        for p, a in zip(asil_sirali, aapcs64(asil_sirali, yapilar)):
            abi[p["konum"]] = a
    kullanilan: set[int] = set()
    satirlar = []
    for p in dps:
        dk = dwarf_anahtarlari(p.get("giris"))
        a = abi.get(p["konum"])
        ak = a["anahtarlar"] if a else None
        satir: dict[str, Any] = {"dwarf": _dwarf_parametre_ozeti(p),
                                 "dwarf_anahtar": [anahtar_metni(k) for k in dk] if dk else None,
                                 "abi_anahtar": [anahtar_metni(k) for k in ak] if ak else None,
                                 "abi_dolayli": bool(a and a.get("dolayli")),
                                 "depolama_ortagi": None, "depolama_kaynagi": None,
                                 "eslesme": None, "sinif": None}
        if dk is not None and ak is not None:
            satir["abi_uyumu"] = dk == ak
        for kaynak, anahtarlar in (("dwarf", dk), ("abi", ak)):
            if not anahtarlar or not dec.get("basarili"):
                continue
            gecerli = [k for k in anahtarlar if k is not None]
            if len(anahtarlar) == 1:
                k = anahtarlar[0]
                if k in tek:
                    satir.update(depolama_ortagi=tek[k] + 1, eslesme="tam")
                elif k in parca_sahibi:
                    satir.update(depolama_ortagi=parca_sahibi[k] + 1, eslesme="kismi")
            else:
                hedef = [i for i, ks in enumerate(g_anahtar) if ks == gecerli]
                if hedef and len(gecerli) == len(anahtarlar):
                    satir.update(depolama_ortagi=hedef[0] + 1, eslesme="tam")
                else:
                    parcalar = [tek.get(k, parca_sahibi.get(k)) for k in gecerli]
                    bulunan = [i for i in parcalar if i is not None]
                    if bulunan:
                        satir.update(depolama_ortagi=bulunan[0] + 1,
                                     eslesme="yapi_bolunmesi" if len(set(bulunan)) > 1
                                     or len(bulunan) < len(anahtarlar) else "kismi",
                                     ortak_parcalar=[i + 1 for i in bulunan])
            if satir["depolama_ortagi"] is not None:
                satir["depolama_kaynagi"] = kaynak
                kullanilan.update(i - 1 for i in satir.get("ortak_parcalar")
                                  or [satir["depolama_ortagi"]])
                break
        satirlar.append(satir)
    # sınıflar (eşleşmeyen DWARF parametreleri)
    g_sinif_en_yuksek: dict[str, int] = {}
    for ks in g_anahtar:
        for k in ks:
            if k[0] in ("x", "v") and k[1] < ARGUMAN_GPR:      # x8 (dönüş işaretçisi) sayılmaz
                g_sinif_en_yuksek[k[0]] = max(g_sinif_en_yuksek.get(k[0], -1), k[1])
    c_girdileri = c_girdi_yazmaclari(dec.get("c") or "")
    for s in satirlar:
        if s["depolama_ortagi"] is not None:
            continue
        anahtar = None
        for metinler in (s["dwarf_anahtar"], s["abi_anahtar"]):
            if metinler:
                anahtar = next((m for m in metinler if m), None)
                break
        if not dec.get("basarili"):
            s["sinif"] = "decompile_yok"
        elif klon:
            s["sinif"] = "klon"
        elif (gf or {}).get("thunk"):
            s["sinif"] = "ghidra_thunk"     # Ghidra gövdeyi başka fonksiyona sıçrama sayıyor
        elif s["dwarf"]["giris_turu"] in GIRISTE_YOK or anahtar is None:
            # DWARF: girişte yeri yok (optimize edilmiş, sabit, hesaplanmış) ve ABI de eşlemedi
            s["sinif"] = ("kullanilmayan_ya_da_optimize"
                          if s["dwarf"]["giris_turu"] in GIRISTE_YOK else "diger")
        elif anahtar.startswith("Stack["):
            s["sinif"] = "yigin_eksik"
        else:
            k = yazmac_anahtari(anahtar)
            en_yuksek = g_sinif_en_yuksek.get(k[0], -1) if k else -1
            s["sinif"] = "ghidra_az" if k and k[1] > en_yuksek else "ghidra_atladi"
            if k in c_girdileri:
                s["c_girdisi"] = c_girdileri[k]      # C'de parametre değil, in_<yazmaç> olarak
    # sırayla eşleme (karşılaştırma)
    for s in satirlar:
        d = s["dwarf"]
        if d["tekrar"]:
            s["sira_durumu"] = None
            continue
        k = d["sira"]
        ortak = k if k is not None and 1 <= k <= len(gp) else None
        s["sira_ortagi"] = ortak
        konumlu = bool(s["dwarf_anahtar"] or s["abi_anahtar"])
        if s["depolama_ortagi"] is not None:
            s["sira_durumu"] = ("uyumlu" if ortak == s["depolama_ortagi"]
                                else "celiski" if ortak is not None else "ortaksiz")
        elif ortak is not None:
            s["sira_durumu"] = "celiski" if konumlu else "yalniz_sira"
        else:
            s["sira_durumu"] = "ortaksiz"
        if s["sira_durumu"] == "celiski" and ortak is not None:
            benim = next((m for m in (s["dwarf_anahtar"] or s["abi_anahtar"] or []) if m), None)
            bk = yazmac_anahtari(benim) if benim else None
            ok = g_anahtar[ortak - 1][0] if g_anahtar[ortak - 1] else None
            s["yazmac_sinifi_farki"] = bool(bk and ok and ok[0] in ("x", "v")
                                            and bk[0] != ok[0])
    # DWARF karşılığı olmayan Ghidra parametreleri
    adli_en_yuksek: dict[str, int] = {}
    for s in satirlar:
        for m in (s["dwarf_anahtar"] or s["abi_anahtar"] or []):
            k = yazmac_anahtari(m) if m else None
            if k:
                adli_en_yuksek[k[0]] = max(adli_en_yuksek.get(k[0], -1), k[1])
    fazlalar = []
    for i, p in enumerate(gp):
        if i in kullanilan:
            continue
        ks = g_anahtar[i]
        k0 = ks[0] if ks else None
        if df.get("degisken_arguman") and k0 and k0[0] in ("x", "v", "yigin") and (
                k0[0] == "yigin" or k0[1] > adli_en_yuksek.get(k0[0], -1)):
            sinif = "degisken_arguman"
        elif k0 == X8:
            sinif = "x8_donus"
        elif klon:
            sinif = "klon"
        else:
            sinif = "fazla"
        fazlalar.append({**_ghidra_parametre_ozeti(p), "sinif": sinif})
    return {"klon": klon, "decompile": bool(dec.get("basarili")), "ghidra_parametre": len(gp),
            "dwarf_parametre": len(dps), "parametreler": satirlar, "ghidra_fazlasi": fazlalar,
            "fonksiyon_sinifi": fonksiyon_sinifi(klon, bool(dec.get("basarili")), satirlar,
                                                 fazlalar, thunk=bool((gf or {}).get("thunk")))}


def fonksiyon_sinifi(klon: list[str], decompile: bool, satirlar: list[dict[str, Any]],
                     fazlalar: list[dict[str, Any]], *, thunk: bool = False) -> str:
    """``FONKSIYON_SINIFLARI``. Değişken argüman fazlası ve DWARF'ta girişte olmayan
    parametrenin Ghidra'da da olmaması uyumsuzluk sayılmaz."""
    if not decompile:
        return "decompile_yok"
    if klon:
        return "klon"
    if thunk:
        return "ghidra_thunk"
    eksik = any(s["sinif"] in ("ghidra_az", "ghidra_atladi", "yigin_eksik", "diger")
                for s in satirlar)
    fazla = any(g["sinif"] in ("fazla", "x8_donus") for g in fazlalar)
    if eksik and fazla:
        return "eksik_ve_fazla"
    if eksik:
        return "ghidra_eksik"
    if fazla:
        return "ghidra_fazla"
    if any(s.get("sira_durumu") == "celiski" or s.get("eslesme") not in (None, "tam")
           for s in satirlar):
        return "sira_bozuk"
    return "tam_uyum"


# ---------------------------------------------------------------------------
# İkili başına hizalama
# ---------------------------------------------------------------------------

def hizala_ikili(dwarf: dict[str, Any], ghidra: dict[str, Any], *,
                 elf: Optional[dict[str, Any]] = None, ikili: Optional[Path] = None
                 ) -> dict[str, Any]:
    dfonks = dwarf["fonksiyonlar"]
    dwarf_adresleri = [int(f["adres"], 16) for f in dfonks]
    if elf is None and ikili is not None:
        elf = elf_bilgisi(ikili)
    taban = pie_tabani(ghidra, elf, dwarf_adresleri) if elf is not None else None
    fark = taban["secilen"] if taban else 0
    g_giris = {int(f["giris"], 16): f for f in ghidra["fonksiyonlar"]}
    govde = GovdeIndeksi(ghidra["fonksiyonlar"])
    yapilar = dwarf.get("yapilar") or {}
    adres_coklugu = Counter(dwarf_adresleri)
    kayitlar = []
    bayt_ciftleri = []
    for df in dfonks:
        adres = int(df["adres"], 16)
        gf = g_giris.get(adres + fark)
        kayit: dict[str, Any] = {
            "dwarf": {"ad": df.get("ad"), "adres": df["adres"], "konum": df["konum"],
                      "semboller": df.get("semboller"), "degisken_arguman": df.get("degisken_arguman"),
                      "dil": dil_adi(df.get("dil")),
                      "parametre_kaynagi": df.get("parametre_kaynagi")},
            "ayni_adreste_dwarf": adres_coklugu[adres],
        }
        if gf is None:
            icinde = govde.icinde(adres + fark)
            kayit["eslesme"] = "govde_icinde" if icinde else "yok"
            if icinde:
                kayit["kapsayan_ghidra"] = icinde
            kayitlar.append(kayit)
            continue
        kayit["eslesme"] = "adres"
        dec = gf.get("decompile") or {}
        g_boyut = sum(b - a + 1 for a, b in gf.get("govde") or [])
        kayit["govde"] = {"dwarf": df.get("boyut"), "ghidra": g_boyut,
                          "ayni": df.get("boyut") == g_boyut}
        kayit["ghidra"] = {"ad": gf["ad"], "giris": gf["giris"], "thunk": gf["thunk"],
                           "imza_kaynagi": gf["imza_kaynagi"],
                           "liste_parametre": len(gf.get("liste_parametreleri") or []),
                           "decompile": bool(dec.get("basarili")), "imza": dec.get("imza"),
                           "model": dec.get("model")}
        bayt_ciftleri.append((adres, gf.get("ilk_baytlar")))
        kayit.update(parametre_hizala(df, gf, yapilar))
        kayitlar.append(kayit)
    bayt = (bayt_dogrulamasi(ikili, elf, bayt_ciftleri)
            if ikili is not None and elf is not None else None)
    return {"sema": HIZALAMA_SEMA, "arac": arac_kunyesi(),
            "girdi": {"ikili": (dwarf["girdi"].get("ikili") or {}).get("ad"),
                      "build_id": dwarf["girdi"]["ana"]["build_id"],
                      "dwarf_betik_sha256": (dwarf.get("arac") or {}).get("betik_sha256"),
                      "ghidra_betik_sha256": (ghidra.get("arac") or {}).get("betik_sha256"),
                      "ghidra_ikili_sha256": ghidra["girdi"]["sha256"]},
            "pie_tabani": taban, "bayt_dogrulamasi": bayt,
            "ghidra_fonksiyon": len(ghidra["fonksiyonlar"]),
            "ghidra_thunk_olmayan": sum(1 for f in ghidra["fonksiyonlar"] if not f["thunk"]),
            "fonksiyonlar": kayitlar}


# ---------------------------------------------------------------------------
# Özet
# ---------------------------------------------------------------------------

def ozet_sayimlari(belgeler: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Bir ikili grubunun (a) ve (b) ölçüleri, sınıf dağılımları."""
    t: Counter = Counter()
    dsinif: Counter = Counter()
    dsinif_klonsuz: Counter = Counter()
    gsinif: Counter = Counter()
    sira: Counter = Counter()
    sira_klonsuz: Counter = Counter()
    eslesme: Counter = Counter()
    giris_turu: Counter = Counter()
    abi_uyum: Counter = Counter()
    fonk_esl: Counter = Counter()
    fsinif: Counter = Counter()
    tip_kapsami: dict[str, Counter] = defaultdict(Counter)
    dil_kapsami: dict[str, Counter] = defaultdict(Counter)
    for b in belgeler:
        t["ikili"] += 1
        t["ghidra_fonksiyon"] += b["ghidra_fonksiyon"]
        t["ghidra_thunk_olmayan"] += b["ghidra_thunk_olmayan"]
        for f in b["fonksiyonlar"]:
            t["dwarf_fonksiyon"] += 1
            fonk_esl[f["eslesme"]] += 1
            if f["eslesme"] != "adres":
                continue
            t["govde_farkli"] += not (f.get("govde") or {}).get("ayni", True)
            t["klon_fonksiyon"] += bool(f["klon"])
            t["decompile_basarisiz"] += not f["decompile"]
            fsinif[f["fonksiyon_sinifi"]] += 1
            for s in f["parametreler"]:
                d = s["dwarf"]
                klonlu = bool(f["klon"])
                t["dwarf_parametre"] += 1
                t["dwarf_parametre_klonsuz"] += not klonlu
                eslendi = s["depolama_ortagi"] is not None
                for kap, anahtar in ((tip_kapsami, str(d.get("sinif"))),
                                     (dil_kapsami, str(f["dwarf"].get("dil")))):
                    kap[anahtar]["toplam"] += 1
                    kap[anahtar]["eslenen"] += eslendi
                    if not klonlu:
                        kap[anahtar]["klonsuz_toplam"] += 1
                        kap[anahtar]["klonsuz_eslenen"] += eslendi
                giris_turu[d["giris_turu"]] += 1
                if "abi_uyumu" in s:
                    abi_uyum["uyumlu" if s["abi_uyumu"] else "farkli"] += 1
                if s["depolama_ortagi"] is not None:
                    t[f"depolama_{s['depolama_kaynagi']}"] += 1
                    if not klonlu:
                        t[f"depolama_{s['depolama_kaynagi']}_klonsuz"] += 1
                    eslesme[s["eslesme"]] += 1
                else:
                    dsinif[s["sinif"]] += 1
                    if s.get("c_girdisi"):
                        t["c_girdisi"] += 1
                        t["c_girdisi_klonsuz"] += not klonlu
                    if not klonlu:
                        dsinif_klonsuz[s["sinif"]] += 1
                if s.get("sira_durumu"):
                    sira[s["sira_durumu"]] += 1
                    if not klonlu:
                        sira_klonsuz[s["sira_durumu"]] += 1
                    if s.get("yazmac_sinifi_farki"):
                        t["sira_celiski_yazmac_sinifi"] += 1
            for g in f["ghidra_fazlasi"]:
                gsinif[g["sinif"]] += 1
            t["ghidra_parametre"] += f["ghidra_parametre"]
    n_d = t["dwarf_fonksiyon"]
    n_p = t["dwarf_parametre"]
    n_pk = t["dwarf_parametre_klonsuz"]
    return {
        "ikili": t["ikili"], "dwarf_fonksiyon": n_d,
        "fonksiyon_eslesmesi": {k: fonk_esl.get(k, 0) for k in ("adres", "govde_icinde", "yok")},
        "a_adresle_eslenen_payi": _pay(fonk_esl.get("adres", 0), n_d),
        "ghidra_fonksiyon": t["ghidra_fonksiyon"], "ghidra_thunk_olmayan": t["ghidra_thunk_olmayan"],
        "klon_fonksiyon": t["klon_fonksiyon"], "decompile_basarisiz": t["decompile_basarisiz"],
        "govde_farkli_fonksiyon": t["govde_farkli"],
        "dwarf_parametre": n_p, "dwarf_parametre_klonsuz": n_pk,
        "ghidra_parametre": t["ghidra_parametre"],
        "b_depolama_dwarf": t["depolama_dwarf"], "b_depolama_abi": t["depolama_abi"],
        "b_depolama_dwarf_payi": _pay(t["depolama_dwarf"], n_p),
        "b_depolama_toplam_payi": _pay(t["depolama_dwarf"] + t["depolama_abi"], n_p),
        "b_klonsuz_depolama_dwarf": t["depolama_dwarf_klonsuz"],
        "b_klonsuz_depolama_abi": t["depolama_abi_klonsuz"],
        "b_klonsuz_depolama_toplam_payi": _pay(t["depolama_dwarf_klonsuz"]
                                               + t["depolama_abi_klonsuz"], n_pk),
        "b_sira": {k: sira.get(k, 0) for k in SIRA_DURUMLARI},
        "b_sira_klonsuz": {k: sira_klonsuz.get(k, 0) for k in SIRA_DURUMLARI},
        "b_sira_celiski_yazmac_sinifi": t["sira_celiski_yazmac_sinifi"],
        "eslesme_turu": dict(sorted(eslesme.items())),
        "eslesmeyen_dwarf": {k: dsinif.get(k, 0) for k in DWARF_SINIFLARI if dsinif.get(k)},
        "eslesmeyen_dwarf_klonsuz": {k: dsinif_klonsuz.get(k, 0) for k in DWARF_SINIFLARI
                                     if dsinif_klonsuz.get(k)},
        "eslesmeyen_c_girdisi": t["c_girdisi"], "eslesmeyen_c_girdisi_klonsuz": t["c_girdisi_klonsuz"],
        "ghidra_fazlasi": {k: gsinif.get(k, 0) for k in GHIDRA_SINIFLARI if gsinif.get(k)},
        "giris_turu": dict(sorted(giris_turu.items(), key=lambda kv: str(kv[0]))),
        "dwarf_abi_uyumu": dict(abi_uyum),
        "fonksiyon_sinifi": {k: fsinif.get(k, 0) for k in FONKSIYON_SINIFLARI},
        "tip_sinifi_kapsami": {k: _kapsam(v) for k, v in sorted(tip_kapsami.items())},
        "dil_kapsami": {k: _kapsam(v) for k, v in sorted(dil_kapsami.items())},
    }


def _kapsam(c: Counter) -> dict[str, Any]:
    return {"toplam": c["toplam"], "eslenen": c["eslenen"], "pay": _pay(c["eslenen"], c["toplam"]),
            "klonsuz_toplam": c["klonsuz_toplam"], "klonsuz_eslenen": c["klonsuz_eslenen"],
            "klonsuz_pay": _pay(c["klonsuz_eslenen"], c["klonsuz_toplam"])}


# ---------------------------------------------------------------------------
# Girdi bulma ve CLI
# ---------------------------------------------------------------------------

def _belgeler(girdiler: Iterable[Path], sema: str) -> list[tuple[Path, dict[str, Any]]]:
    sonuc = []
    for g in girdiler:
        yollar = sorted(g.rglob("*.json")) if g.is_dir() else [g]
        for y in yollar:
            try:
                b = json.loads(y.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(b, dict) and b.get("sema") == sema:
                sonuc.append((y, b))
    return sonuc


def secim(debian13: Path, *, n: int = SECIM_N, tohum_metni: str = SECIM_TOHUM_METNI
          ) -> dict[str, Any]:
    """8 programın ikilileri; coreutils'ten tohumla ``n`` tane."""
    ikililer: list[dict[str, Any]] = []
    secilen: list[str] = []
    evren: list[str] = []
    for paket, (surum, yollar) in GELISTIRME_PAKETLERI.items():
        dizin_surum = surum.split(":", 1)[-1]
        kok = debian13 / f"x_{paket}_{dizin_surum}_arm64"
        if paket == "coreutils":
            adaylar = sorted(p for p in (kok / "usr").rglob("*")
                             if p.is_file() and not p.is_symlink()
                             and p.read_bytes()[:4] == b"\x7fELF")
            evren = sorted(p.name for p in adaylar)
            secilen = sorted(random.Random(tohum(tohum_metni)).sample(evren, min(n, len(evren))))
            yollar_ = [next(p for p in adaylar if p.name == s) for s in secilen]
        else:
            yollar_ = [kok / y for y in yollar]
        for y in yollar_:
            ikililer.append({"paket": paket, "surum": surum, "ikili": str(y)})
    return {"tohum_metni": tohum_metni, "tohum": tohum(tohum_metni), "n": n,
            "coreutils_evreni": len(evren), "coreutils_secilen": secilen, "ikililer": ikililer}


def hizala_hepsi(dwarf_dizinleri: list[Path], ghidra_dizinleri: list[Path], cikti: Path
                 ) -> dict[str, Any]:
    dwarf = {b["girdi"]["ana"]["build_id"]: (y, b) for y, b in _belgeler(dwarf_dizinleri, DWARF_SEMA)}
    ghidra = {b["girdi"]["build_id"]: (y, b) for y, b in _belgeler(ghidra_dizinleri, GHIDRA_SEMA)}
    satirlar = []
    for bid, (gy, gb) in sorted(ghidra.items(), key=lambda kv: kv[1][1]["girdi"]["ad"]):
        if bid not in dwarf:
            satirlar.append({"ikili": gb["girdi"]["ad"], "durum": "dwarf_yok"})
            continue
        dy, db = dwarf[bid]
        ikili = Path(gb["girdi"]["ikili"])
        h = hizala_ikili(db, gb, ikili=ikili)
        h["girdi"]["paket"] = dy.parent.name
        ad = f"{gb['girdi']['ad']}.json"
        _yaz_json(cikti / ad, h, girinti=None)
        oz = ozet_sayimlari([h])
        satirlar.append({"ikili": gb["girdi"]["ad"], "paket": dy.parent.name, "cikti": ad,
                         "durum": "tamam", "pie_tabani": h["pie_tabani"],
                         "bayt_dogrulamasi": h["bayt_dogrulamasi"], "ozet": oz})
        print(f"{gb['girdi']['ad']}: (a) {oz['fonksiyon_eslesmesi']} "
              f"(b) dwarf={oz['b_depolama_dwarf']} abi={oz['b_depolama_abi']} "
              f"/ {oz['dwarf_parametre']} sıra={oz['b_sira']}", flush=True)
    indeks = {"sema": HIZALAMA_OZET_SEMA, "arac": arac_kunyesi(), "ikililer": satirlar}
    _yaz_json(cikti / "hizalama_indeksi.json", indeks)
    return indeks


def ozet(hizalama_dizini: Path) -> dict[str, Any]:
    belgeler = [b for _, b in _belgeler([hizalama_dizini], HIZALAMA_SEMA)]
    gruplar: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for b in belgeler:
        gruplar[b["girdi"].get("paket") or "?"].append(b)
    return {"sema": HIZALAMA_OZET_SEMA, "arac": arac_kunyesi(),
            "girdi_betikleri": sorted({str(b["arac"]["betik_sha256"]) for b in belgeler}),
            "programlar": {p: ozet_sayimlari(bs) for p, bs in sorted(gruplar.items())},
            "ikililer": {b["girdi"]["ikili"]: ozet_sayimlari([b]) for b in belgeler},
            "toplam": ozet_sayimlari(belgeler)}


# ---------------------------------------------------------------------------
# Elle denetim paketi ve dwarfdump ile bağımsız konum denetimi
# ---------------------------------------------------------------------------

_DD_ARALIK_RE = re.compile(r"^\s*\[0x([0-9a-fA-F]+), 0x([0-9a-fA-F]+)\): (.*?)\)?\s*$")
_DD_KONUM_RE = re.compile(r"^\s+DW_AT_location \[(DW_FORM_\w+)\]\s+\((.*)$")
_DD_YAZMAC_RE = re.compile(r"^(WSP|SP|[WXBHSDQV])(\d*)([+-]\d+)?$")


def _ust_duzey_bol(metin: str) -> list[str]:
    parcalar, derinlik, bas = [], 0, 0
    for i, ch in enumerate(metin):
        if ch == "(":
            derinlik += 1
        elif ch == ")":
            derinlik -= 1
        elif ch == "," and derinlik == 0:
            parcalar.append(metin[bas:i].strip())
            bas = i + 1
    if metin[bas:].strip():
        parcalar.append(metin[bas:].strip())
    return parcalar


def _dd_yazmac_no(harf: str, rakam: str) -> Optional[int]:
    if harf in ("WSP", "SP"):
        return 31
    if not rakam:
        return None
    return int(rakam) if harf in "WX" else 64 + int(rakam)


def ifade_normal(metin: Optional[str]) -> Optional[list[tuple]]:
    """dwarfdump ya da ``dwarf_tip.ifade_metni`` metni -> karşılaştırılabilir biçim.

    Yazmaç adları atılır (işlem kodu numarayı taşır); ``regx``/``bregx``'te ad numaraya
    çevrilir; ``W22+0`` gibi taban+ofset biçiminden ofset alınır; onaltılı ve ondalık sayılar
    tamsayı olur."""
    if metin is None:
        return None
    sonuc: list[tuple] = []
    for op in _ust_duzey_bol(metin.strip()):
        if "(" in op and op.endswith(")"):
            ad, ic = op.split("(", 1)
            sonuc.append((ad.strip(), tuple(ifade_normal(ic[:-1]) or [])))
            continue
        parcalar = op.split()
        ad, islenenler = parcalar[0], []
        for t in parcalar[1:]:
            if re.fullmatch(r"[+-]?\d+", t):
                islenenler.append(int(t))
                continue
            if re.fullmatch(r"0x[0-9a-fA-F]+", t):
                islenenler.append(int(t, 16))
                continue
            m = _DD_YAZMAC_RE.match(t)
            if m:
                if ad in ("DW_OP_regx", "DW_OP_bregx"):
                    no = _dd_yazmac_no(m.group(1), m.group(2))
                    if no is not None:
                        islenenler.append(no)
                if m.group(3) is not None:
                    islenenler.append(int(m.group(3)))
                continue
            islenenler.append(t)
        sonuc.append((ad, tuple(islenenler)))
    return sonuc


def dd_giris_ifadesi(metin: str, adres: int) -> dict[str, Any]:
    """``dwarfdump -v -F --debug-info=<ofset>`` çıktısında parametrenin ``adres``'teki ifadesi."""
    satirlar = metin.splitlines()
    for i, s in enumerate(satirlar):
        m = _DD_KONUM_RE.match(s)
        if not m:
            continue
        bicim, kalan = m.group(1), m.group(2)
        if bicim == "DW_FORM_exprloc":
            return {"bicim": bicim, "ifade": kalan[:-1] if kalan.endswith(")") else kalan}
        for t in satirlar[i + 1:]:
            ma = _DD_ARALIK_RE.match(t)
            if not ma:
                break
            if int(ma.group(1), 16) <= adres < int(ma.group(2), 16):
                return {"bicim": bicim, "ifade": ma.group(3)}
        return {"bicim": bicim, "ifade": None}
    return {"bicim": None, "ifade": None}


def _dwarfdump(debug: str, ofset: int) -> str:
    return subprocess.run([DWARFDUMP_YOLU, "-v", "-F", f"--debug-info=0x{ofset:x}", debug],
                          capture_output=True, text=True, timeout=120, check=False).stdout


DENETIM_EVRENLERI = ("hepsi", "zor")


def zor_vaka_mi(s: dict[str, Any]) -> bool:
    """Sıranın yanılttığı ya da tek parçalı/DWARF konumlu olmayan eşleşmeler."""
    return (s.get("sira_durumu") == "celiski" or s.get("depolama_kaynagi") == "abi"
            or s.get("eslesme") in ("yapi_bolunmesi", "kismi"))


def denetim_evreni(belgeler: list[dict[str, Any]], evren_turu: str = "hepsi"
                   ) -> list[tuple[dict, dict, dict]]:
    """(hizalama belgesi, fonksiyon, parametre satırı): adresle eşlenen fonksiyonlardaki bütün
    DWARF parametreleri (``hepsi``) ya da yalnız zor vakalar (``zor``: ``zor_vaka_mi``); ikili,
    adres ve DIE konumuna göre sıralı."""
    if evren_turu not in DENETIM_EVRENLERI:
        raise ValueError(f"evren {DENETIM_EVRENLERI} içinden olmalı: {evren_turu!r}")
    evren = []
    for b in belgeler:
        for f in b["fonksiyonlar"]:
            if f["eslesme"] != "adres":
                continue
            for s in f["parametreler"]:
                if evren_turu == "hepsi" or zor_vaka_mi(s):
                    evren.append((b, f, s))
    evren.sort(key=lambda x: (x[0]["girdi"]["ikili"], int(x[1]["dwarf"]["adres"], 16),
                              x[2]["dwarf"]["konum"]))
    return evren


def denetim_paketi(dizin: Path, dwarf_dizinleri: list[Path], ghidra_dizinleri: list[Path], *,
                   n: int = DENETIM_N, tohum_metni: str = DENETIM_TOHUM_METNI,
                   kararlar: Optional[Path] = None, evren_turu: str = "hepsi") -> dict[str, Any]:
    """Tohumlu ``n`` hizalama: C, Ghidra imzası, DWARF tanımı ve dwarfdump konum denetimi."""
    belgeler = [b for _, b in _belgeler([dizin], HIZALAMA_SEMA)]
    evren = denetim_evreni(belgeler, evren_turu)
    t = tohum(tohum_metni)
    secilen = random.Random(t).sample(evren, min(n, len(evren)))
    dwarf = {b["girdi"]["ana"]["build_id"]: b for _, b in _belgeler(dwarf_dizinleri, DWARF_SEMA)}
    ghidra = {b["girdi"]["build_id"]: b for _, b in _belgeler(ghidra_dizinleri, GHIDRA_SEMA)}
    karar = json.loads(kararlar.read_text(encoding="utf-8")) if kararlar else {}
    ornekler = []
    for no, (b, f, s) in enumerate(secilen, 1):
        bid = b["girdi"]["build_id"]
        db, gb = dwarf[bid], ghidra[bid]
        df = next(x for x in db["fonksiyonlar"] if x["konum"] == f["dwarf"]["konum"])
        gf = next(x for x in gb["fonksiyonlar"] if x["giris"] == f["ghidra"]["giris"])
        dec = gf.get("decompile") or {}
        c = (dec.get("c") or "").strip().splitlines()
        aranan = []
        if s.get("depolama_ortagi"):
            aranan.append((dec.get("parametreler") or [])[s["depolama_ortagi"] - 1]["ad"])
        if s.get("sira_ortagi") and s.get("sira_ortagi") != s.get("depolama_ortagi"):
            aranan.append((dec.get("parametreler") or [])[s["sira_ortagi"] - 1]["ad"])
        for m in (s.get("dwarf_anahtar") or s.get("abi_anahtar") or []):
            k = yazmac_anahtari(m) if m else None
            if k and not s.get("depolama_ortagi"):
                aranan += [f"in_{h}{k[1]}" for h in ("xw" if k[0] == "x" else "bhsdqv")]
        desen = re.compile(r"\b(" + "|".join(map(re.escape, aranan)) + r")\b") if aranan else None
        ilgili = [x.strip() for x in c if desen and desen.search(x)][:DENETIM_ILGILI_SATIR]
        rol, ofset = s["dwarf"]["konum"].split(":")
        dd = {"bicim": None, "ifade": None}
        if rol == "ana":
            dd = dd_giris_ifadesi(_dwarfdump(db["girdi"]["ana"]["yol"], int(ofset, 16)),
                                  int(f["dwarf"]["adres"], 16))
        benim = s["dwarf"]["giris"]
        tutarli = ifade_normal(dd["ifade"]) == ifade_normal(benim)
        kimlik = f"{b['girdi']['ikili']}|{f['dwarf']['adres']}|{s['dwarf']['konum']}"
        ornek = {
            "no": no, "kimlik": kimlik, "ikili": b["girdi"]["ikili"],
            "paket": b["girdi"].get("paket"),
            "dwarf_fonksiyon": {**f["dwarf"], "klon": f["klon"], "parametreler": [
                {"sira": p.get("sira"), "somut_sira": p.get("somut_sira"), "ad": p.get("ad"),
                 "tip": (p.get("tip") or {}).get("kanonik"),
                 "giris": (p.get("giris") or {}).get("ifade"),
                 "giris_turu": (p.get("giris") or {}).get("tur"), "tekrar": p.get("tekrar")}
                for p in df["parametreler"]]},
            "ghidra_fonksiyon": {"ad": gf["ad"], "giris": gf["giris"], "imza": dec.get("imza"),
                                 "liste_imzasi": [(p["ad"], p["tip"], p["depolama"]["metin"])
                                                  for p in gf["liste_parametreleri"]],
                                 "parametreler": [_ghidra_parametre_ozeti(p) for p in
                                                  dec.get("parametreler") or []],
                                 "c_ilk_satirlar": c[:DENETIM_C_SATIR],
                                 "c_ilgili_satirlar": ilgili},
            "hizalama": {k: v for k, v in s.items() if k != "dwarf"},
            "parametre": s["dwarf"],
            "dwarfdump": {**dd, "tutarli": tutarli},
        }
        if str(no) in karar:
            k = dict(karar[str(no)])
            if k.get("kimlik") not in (None, kimlik):
                k = {"karar": "kimlik_uyusmuyor", "beklenen": k.get("kimlik")}
            ornek["karar"] = k
        ornekler.append(ornek)
    paket: dict[str, Any] = {"sema": DENETIM_SEMA, "arac": arac_kunyesi(),
                             "evren_turu": evren_turu,
                             "tohum_metni": tohum_metni, "tohum": t, "evren": len(evren),
                             "n": len(ornekler),
                             "dwarfdump_tutarli": sum(o["dwarfdump"]["tutarli"] for o in ornekler),
                             "ornekler": ornekler}
    if karar:
        paket["karar_sayimi"] = dict(Counter(o.get("karar", {}).get("karar", "verilmedi")
                                             for o in ornekler))
    return paket


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    s = sub.add_parser("secim", help="8 programın ikilileri; coreutils'ten tohumla seçim")
    s.add_argument("--debian13", type=Path,
                   default=Path.home() / "karadul_olcum" / "downloads" / "debian13")
    s.add_argument("--n", type=int, default=SECIM_N)
    s.add_argument("--tohum-metni", default=SECIM_TOHUM_METNI)
    s.add_argument("-o", "--out", type=Path, required=True)
    h = sub.add_parser("hizala", help="DWARF ve Ghidra belgelerini build-id ile eşle ve hizala")
    h.add_argument("--dwarf", type=Path, nargs="+", required=True)
    h.add_argument("--ghidra", type=Path, nargs="+", required=True)
    h.add_argument("-o", "--out", type=Path, required=True)
    o = sub.add_parser("ozet", help="program başına (a), (b) ve sınıf dağılımı")
    o.add_argument("dizin", type=Path)
    o.add_argument("--json", type=Path, default=None)
    d = sub.add_parser("denetim", help="tohumlu hizalama örneklemi (elle denetim paketi)")
    d.add_argument("dizin", type=Path)
    d.add_argument("--n", type=int, default=None,
                   help=f"örnek sayısı (hepsi {DENETIM_N}, zor {ZOR_N})")
    d.add_argument("--tohum-metni", default=None,
                   help=f"hepsi: {DENETIM_TOHUM_METNI}; zor: {ZOR_TOHUM_METNI}")
    d.add_argument("--ghidra", type=Path, nargs="+", required=True)
    d.add_argument("--dwarf", type=Path, nargs="+", required=True)
    d.add_argument("-o", "--out", type=Path, required=True)
    d.add_argument("--kararlar", type=Path, default=None,
                   help="elle verilen kararlar (JSON: no -> {karar, not})")
    d.add_argument("--evren", choices=DENETIM_EVRENLERI, default="hepsi",
                   help="hepsi: bütün DWARF parametreleri; zor: sıra çelişkisi, ABI ya da bölünme")
    a = ap.parse_args(argv)
    if a.komut == "secim":
        sonuc = secim(a.debian13, n=a.n, tohum_metni=a.tohum_metni)
        _yaz_json(a.out, sonuc)
        print(f"{a.out}: {len(sonuc['ikililer'])} ikili; coreutils {sonuc['coreutils_evreni']} "
              f"içinden {sonuc['coreutils_secilen']}")
        return 0
    if a.komut == "hizala":
        hizala_hepsi(a.dwarf, a.ghidra, a.out)
        return 0
    if a.komut == "ozet":
        oz = ozet(a.dizin)
        for p, v in list(oz["programlar"].items()) + [("TOPLAM", oz["toplam"])]:
            print(f"{p}: {json.dumps(v, ensure_ascii=False)}")
        if a.json:
            _yaz_json(a.json, oz)
        return 0
    zor = a.evren == "zor"
    paket = denetim_paketi(a.dizin, a.dwarf, a.ghidra,
                           n=a.n if a.n is not None else (ZOR_N if zor else DENETIM_N),
                           tohum_metni=a.tohum_metni or (ZOR_TOHUM_METNI if zor
                                                         else DENETIM_TOHUM_METNI),
                           kararlar=a.kararlar, evren_turu=a.evren)
    _yaz_json(a.out, paket)
    print(f"{a.out}: {paket['n']} örnek (evren {paket['evren']}); "
          f"dwarfdump konum denetimi {paket['dwarfdump_tutarli']}/{paket['n']}"
          + (f"; kararlar {paket['karar_sayimi']}" if paket.get("karar_sayimi") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
