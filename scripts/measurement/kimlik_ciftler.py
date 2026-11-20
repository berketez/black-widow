#!/usr/bin/env python
"""KİMLİK hattı — çift (sorgu ↔ başvuru) grupları; kalıcı tanım.

Kaynak: ``scripts/arge/kimlik/ciftler.py`` (tur 1, 2026-11-19; PLAN.md PK-3 taşıma tablosu). Tur 1 grup adları
ve içerikleri AYNEN taşındı. Dalga 0'da (2026-11-20) PK-6 ve PK-11 grupları eklendi; tanımlar ölçümden önce
``docs/arge/2026-11-19_mythos/kimlik/PK-6_on_kayit.md`` ve ``PK-11_on_kayit.md``'de yazıldı.

Kimlik sözdizimi (yükleyici ``scripts/arge/kimlik/veri.py`` ve Dalga 0 eki ``d0_veri.py``):
  ``debian/<program>[/<ikili>]``  Debian 13 arm64, geliştirme seti (ürün a62f15e koşusu)
  ``mac/<program>`` · ``macgnu/<ad>`` · ``macgnu2/<ad>`` · ``macgcc/<ad>`` · ``macsym/<ad>`` · ``korpus/<k>/<ad>``
  ``tabA/<program>/<ikili>``      tabaka A: Debian 13 amd64 (aynı paket sürümü; mimari farkı)
  ``tabB12/<program>/<ikili>``    tabaka B: Debian 12 arm64 (GCC 12; program sürümü de farklı)
  ``tabB24/<program>/<ikili>``    tabaka B: Ubuntu 24.04 arm64 (GCC 13; program sürümü de farklı)
  ``v1gcc/<ikili>`` · ``v1clang/<ikili>``  V1: geliştirme setiyle aynı Debian kaynak sürümü, macOS'ta
                                  Homebrew GCC 16 ve Apple clang ile aynı bayraklarla derlendi
  ``kitaplik/libzstd``            V5: Debian 13 arm64 ``libzstd.so.1.5.7`` (zstd ikilisiyle aynı kaynak sürümü)

Kilitli setler: grup tanımlarındaki her program / ikili adı kilit belgelerindeki adlarla kesişmemeli
(``kilit_denetimi``; ad listesi ``scripts/arge/olcu/tabaka_indir.py`` ``kilitli_adlar`` ile okunur). Kesişim
varsa ``grup`` hata verir (sessiz geçiş yok).
"""
from __future__ import annotations

import importlib.util
import sys
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Callable, Iterable, Optional

REPO = Path(__file__).resolve().parents[2]
OLCUM = Path.home() / "karadul_olcum"
TABAN = OLCUM / "runs" / "urun-onarim-a62f15e"
TABAKA_INDIR = REPO / "scripts" / "arge" / "olcu" / "tabaka_indir.py"

# ------------------------------------------------------------------------------------------------
# Tur 1 grupları (``scripts/arge/kimlik/ciftler.py``'den aynen; DEFTER.md §2, §5.9–§5.11)

CIFT_KESIF_HTOP = [("debian/htop", "mac/htop")]
CIFT_SINAMA_TMUX = [("debian/tmux", "mac/tmux")]
CIFT_SINAMA_CU_MAC = [("debian/coreutils/cat", "macgnu/gcat"),
                      ("debian/coreutils/sort", "macgnu/gsort"),
                      ("debian/coreutils/mktemp", "macgnu/gmktemp")]
KORPUS_ADLARI = ["cat", "cut", "wc", "expr", "comm"]
CIFT_SURUM = [(f"debian/coreutils/{a}", f"korpus/debian-9.4-3/{a}") for a in KORPUS_ADLARI]
CIFT_DERLEME = [(f"korpus/debian-9.4-3/{a}", f"korpus/ubuntu-9.4-3ubuntu6/{a}") for a in KORPUS_ADLARI]
CIFT_DERLEYICI = [("macgcc/tmux", "mac/tmux")]
CIFT_DERLEYICI_HTOP = [("macgcc/htop", "mac/htop")]
CIFT_SURUM_GCC = [("debian/tmux", "macgcc/tmux")]
CIFT_SINAMA_CU_MAC2 = [("debian/coreutils/cat", "macgnu2/gcat"),
                       ("debian/coreutils/sort", "macgnu2/gsort"),
                       ("debian/coreutils/mktemp", "macgnu2/gmktemp")]
CIFT_SEMBOLLU = [("debian/tmux", "macsym/tmux"), ("macgcc/tmux", "macsym/tmux")]
CIFT_SEMBOLLU_ESLI = [("macgcc/tmux", "macsym/tmux")]
CIFT_SEMBOLLU_FARKLI = [("debian/tmux", "macsym/tmux")]
CIFT_IYILESTIRME_O0 = [("macgcc/tmuxO0", "macgcc/tmux")]
CIFT_IYILESTIRME_O3 = [("macgcc/tmuxO3", "macgcc/tmux")]


def coreutils_adlari(taban: Path = TABAN) -> list[str]:
    return sorted(p.name for p in (taban / "debian" / "coreutils").iterdir() if p.is_dir())


def sinama_cu_ic(taban: Path = TABAN) -> list[tuple[str, str]]:
    """Ada göre sıralı 106 ikiliden her 10.'su sorgu, bir sonraki ikili başvuru (GT'den bağımsız seçim)."""
    adlar = coreutils_adlari(taban)
    return [(f"debian/coreutils/{adlar[i]}", f"debian/coreutils/{adlar[i + 1]}")
            for i in range(0, len(adlar) - 1, 10)]


# ------------------------------------------------------------------------------------------------
# PK-6 (Dalga 0): seçim kuralları PK-6_on_kayit.md §2'de; sayılara bakılmadan yazıldı.

CU_ADIM = 10    # coreutils: ada göre sıralı 106 ikiliden her 10.'su (tur 1 ``sinama_cu_ic`` sorgu kümesi)

# (program, ikili) — tabaka gruplarında karşılaştırılan ikililer. Dışarıda kalanlar ``DISARIDA``'da, nedeniyle.
TABAKA_PROGRAMLARI: tuple[tuple[str, str], ...] = (
    ("tree", "tree"), ("htop", "htop"), ("sqlite3", "sqlite3"), ("openssl", "openssl"),
    ("zstd", "zstd"), ("redis-tools", "redis-cli"), ("redis-tools", "redis-benchmark"), ("tmux", "tmux"),
)
DISARIDA = {
    "zstd/pzstd": "C++ ikilisi: tam ad eşitliği tanımsız (PLAN §5 A10)",
    "redis-tools/redis-check-aof": "redis-server kopyası (build-id redis-check-rdb ile aynı); deps/lua içerir — "
                                   "lua kilitli setin stres alt kümesinde (KARARLAR A-23)",
    "redis-tools/redis-check-rdb": "redis-server kopyası; deps/lua içerir (KARARLAR A-23)",
}
TABAKA_KOKLERI = {"tabA": "Debian 13 amd64 (tabaka A)", "tabB12": "Debian 12 arm64 (tabaka B)",
                  "tabB24": "Ubuntu 24.04 arm64 (tabaka B)"}


def coreutils_secimi(taban: Path = TABAN) -> list[str]:
    adlar = coreutils_adlari(taban)
    return [adlar[i] for i in range(0, len(adlar) - 1, CU_ADIM)]


def tabaka_ikilileri(taban: Path = TABAN) -> list[tuple[str, str]]:
    return list(TABAKA_PROGRAMLARI) + [("coreutils", a) for a in coreutils_secimi(taban)]


def _tabaka_grubu(kok: str, taban: Path = TABAN) -> list[tuple[str, str]]:
    return [(f"{kok}/{p}/{b}", f"debian/{p}/{b}") for p, b in tabaka_ikilileri(taban)]


# V1 (``surum_esli``): (program, ikili, Debian 13 geliştirme setindeki karşılığı)
V1_IKILILERI: tuple[tuple[str, str, str], ...] = (
    ("tree", "tree", "debian/tree/tree"),
    ("zstd", "zstd", "debian/zstd/zstd"),
    ("sqlite3", "sqlite3", "debian/sqlite3/sqlite3"),
    ("redis", "redis-cli", "debian/redis-tools/redis-cli"),
    ("redis", "redis-benchmark", "debian/redis-tools/redis-benchmark"),
)
V1_DERLEYICILER = ("v1gcc", "v1clang")

CIFT_GOMULU_KITAPLIK = [("debian/zstd/zstd", "kitaplik/libzstd")]

# Ölçülemeyen gruplar: ad → neden (ölçüm "veri yok" yazar; 0 yazılmaz)
VERI_YOK = {
    "iyilestirme": "tabaka C (ÖLÇÜ P-Ö6, clang iyileştirme merdiveni) yok; Dalga 2'de üretilecek",
}
# Yalnız sorgu → başvuru yönü anlamlı gruplar (PLAN PK-11 adım 3)
TEK_YONLU = frozenset({"gomulu_kitaplik"})

_SABIT_GRUPLAR: dict[str, list[tuple[str, str]]] = {
    "kesif_htop": CIFT_KESIF_HTOP, "sinama_tmux": CIFT_SINAMA_TMUX, "sinama_cu_mac": CIFT_SINAMA_CU_MAC,
    "surum": CIFT_SURUM, "derleme": CIFT_DERLEME, "derleyici": CIFT_DERLEYICI,
    "derleyici_htop": CIFT_DERLEYICI_HTOP, "surum_gcc": CIFT_SURUM_GCC, "sinama_cu_mac2": CIFT_SINAMA_CU_MAC2,
    "sembollu": CIFT_SEMBOLLU, "sembollu_esli": CIFT_SEMBOLLU_ESLI, "sembollu_farkli": CIFT_SEMBOLLU_FARKLI,
    "iyilestirme_o0": CIFT_IYILESTIRME_O0, "iyilestirme_o3": CIFT_IYILESTIRME_O3,
    "gomulu_kitaplik": CIFT_GOMULU_KITAPLIK,
}
_HESAPLI_GRUPLAR: dict[str, Callable[[], list[tuple[str, str]]]] = {
    "sinama_cu_ic": sinama_cu_ic,
    "mimari": lambda: _tabaka_grubu("tabA"),
    "derleyici_surumu_d12": lambda: _tabaka_grubu("tabB12"),
    "derleyici_surumu_u24": lambda: _tabaka_grubu("tabB24"),
    "derleyici_surumu": lambda: _tabaka_grubu("tabB12") + _tabaka_grubu("tabB24"),
    "surum_esli": lambda: [(f"v1gcc/{b}", f"v1clang/{b}") for _, b, _ in V1_IKILILERI],
    # Ek (PLAN §5 A6): Linux GCC 14 (Debian ikilisi) ↔ macOS clang, aynı kaynak sürümü; yalnız rapor.
    "surum_esli_platform": lambda: [(d, f"v1clang/{b}") for _, b, d in V1_IKILILERI],
}
GRUP_ADLARI = tuple(sorted(set(_SABIT_GRUPLAR) | set(_HESAPLI_GRUPLAR) | set(VERI_YOK)))


# ------------------------------------------------------------------------------------------------
# Program adı (program başına satır) ve kilit süzgeci

def program_adi(kimlik: str) -> str:
    """Kimliğin kaynak programı: redis-tools ve V1 ``redis-*`` ikilileri ``redis``; libzstd ``zstd``."""
    p = kimlik.split("/")
    if p[0] in ("v1gcc", "v1clang"):
        for prog, ikili, _ in V1_IKILILERI:
            if ikili == p[1]:
                return prog
        raise ValueError(f"V1'de olmayan ikili: {kimlik}")
    if p[0] == "kitaplik":
        return {"libzstd": "zstd"}[p[1]]
    if p[0] == "korpus":
        return "coreutils"
    if p[0] in ("macgnu", "macgnu2"):
        return "coreutils"
    prog = p[1]
    return "redis" if prog == "redis-tools" else prog


def _modul(ad: str, yol: Path) -> ModuleType:
    if ad in sys.modules:
        return sys.modules[ad]
    spec = importlib.util.spec_from_file_location(ad, yol)
    m = importlib.util.module_from_spec(spec)
    sys.modules[ad] = m
    spec.loader.exec_module(m)
    return m


@lru_cache(maxsize=1)
def kilitli_adlar() -> frozenset[str]:
    """Kilit belgelerindeki program / paket / ikili adları (``tabaka_indir.kilitli_adlar``)."""
    return frozenset(_modul("tabaka_indir", TABAKA_INDIR).kilitli_adlar())


def grup_adlari_kumesi(ciftler: Iterable[tuple[str, str]]) -> set[str]:
    """Bir grubun denetlenecek adları: her kimliğin program, ikili ve kaynak program adı."""
    adlar: set[str] = set()
    for c in ciftler:
        for k in c:
            p = k.split("/")
            adlar.update(x for x in p[1:] if x)
            adlar.add(program_adi(k))
    return adlar


def kilit_suzgeci(adlar: Iterable[str], kilitli: Iterable[str]) -> list[str]:
    """Adlardan kilitli kümede olanlar (büyük / küçük harf duyarsız); boş liste = temiz."""
    k = {a.lower() for a in kilitli}
    return sorted({a for a in adlar if a.lower() in k})


class KilitliAd(RuntimeError):
    """Bir grup kilitli bir programı içeriyor: ölçüm durur."""


def kilit_denetimi(ad: str, ciftler: list[tuple[str, str]],
                   kilitli: Optional[Iterable[str]] = None) -> list[tuple[str, str]]:
    kesisim = kilit_suzgeci(grup_adlari_kumesi(ciftler), kilitli_adlar() if kilitli is None else kilitli)
    if kesisim:
        raise KilitliAd(f"{ad}: kilitli ad(lar) {kesisim} (docs/arge/test_seti_kilidi.md, dogrulama_seti_kilidi.md)")
    return ciftler


def grup(ad: str) -> list[tuple[str, str]]:
    """Grubun (sorgu, başvuru) çiftleri; kilit denetiminden geçmiş. Veri yok grupta hata (sessiz 0 yok)."""
    if ad in VERI_YOK:
        raise LookupError(f"{ad}: veri yok — {VERI_YOK[ad]}")
    if ad in _SABIT_GRUPLAR:
        ciftler = list(_SABIT_GRUPLAR[ad])
    elif ad in _HESAPLI_GRUPLAR:
        ciftler = _HESAPLI_GRUPLAR[ad]()
    else:
        raise KeyError(f"bilinmeyen grup: {ad}")
    return kilit_denetimi(ad, ciftler)


def yonler(ad: str) -> list[tuple[str, str]]:
    """(sorgu, başvuru) yönleri: iki yönlü gruplarda her çift iki kez, tek yönlülerde bir kez."""
    c = grup(ad)
    if ad in TEK_YONLU:
        return list(c)
    return [(x, y) for p in c for x, y in (p, p[::-1])]


if __name__ == "__main__":
    for g in GRUP_ADLARI:
        try:
            print(g, len(grup(g)), grup(g)[:3])
        except LookupError as e:
            print(g, "—", e)
