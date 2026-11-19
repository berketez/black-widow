#!/usr/bin/env python
"""KİMLİK hattı — çift tanımları (DEFTER.md §2'deki bölme; sayılara bakılmadan yazıldı)."""
from __future__ import annotations

from veri import TABAN

# Keşif (ayar) birimi: bütün parametreler burada ayarlanır.
CIFT_KESIF_HTOP = [("debian/htop", "mac/htop")]

# Sınama birimleri: dondurulmuş parametrelerle tek sayım.
CIFT_SINAMA_TMUX = [("debian/tmux", "mac/tmux")]
CIFT_SINAMA_CU_MAC = [("debian/coreutils/cat", "macgnu/gcat"),
                 ("debian/coreutils/sort", "macgnu/gsort"),
                 ("debian/coreutils/mktemp", "macgnu/gmktemp")]


def coreutils_adlari() -> list[str]:
    return sorted(p.name for p in (TABAN / "debian" / "coreutils").iterdir() if p.is_dir())


def sinama_cu_ic() -> list[tuple[str, str]]:
    """Ada göre sıralı 106 ikiliden her 10.'su sorgu, bir sonraki ikili başvuru (GT'den bağımsız seçim)."""
    adlar = coreutils_adlari()
    return [(f"debian/coreutils/{adlar[i]}", f"debian/coreutils/{adlar[i + 1]}")
            for i in range(0, len(adlar) - 1, 10)]


# Öncül 3 (sürüm ↔ derleyici): korpus 9.4 ↔ Debian 13 (9.7).
KORPUS_ADLARI = ["cat", "cut", "wc", "expr", "comm"]
CIFT_SURUM = [(f"debian/coreutils/{a}", f"korpus/debian-9.4-3/{a}") for a in KORPUS_ADLARI]          # sürüm farkı, yakın derleyici
CIFT_DERLEME = [(f"korpus/debian-9.4-3/{a}", f"korpus/ubuntu-9.4-3ubuntu6/{a}") for a in KORPUS_ADLARI]  # aynı sürüm, başka dağıtım derlemesi

# Yalnız derleyici farkı (DEFTER.md §5.9): aynı sürümün Homebrew GCC 16 derlemesi ↔ Homebrew clang şişesi.
CIFT_DERLEYICI = [("macgcc/tmux", "mac/tmux")]
CIFT_DERLEYICI_HTOP = [("macgcc/htop", "mac/htop")]
# Aynı derleyici ailesi (GCC 14 ↔ 16), sürüm (3.5a ↔ 3.8) ve platform farkı.
CIFT_SURUM_GCC = [("debian/tmux", "macgcc/tmux")]

# Aynı kuşak koşularla coreutils ↔ Homebrew (DEFTER.md §5.10)
CIFT_SINAMA_CU_MAC2 = [("debian/coreutils/cat", "macgnu2/gcat"),
                       ("debian/coreutils/sort", "macgnu2/gsort"),
                       ("debian/coreutils/mktemp", "macgnu2/gmktemp")]

# Sembollü başvuru (yalnız sorgu → macsym yönü anlamlı; ters yönde nüfus 0)
CIFT_SEMBOLLU = [("debian/tmux", "macsym/tmux"), ("macgcc/tmux", "macsym/tmux")]
CIFT_SEMBOLLU_ESLI = [("macgcc/tmux", "macsym/tmux")]       # PK-4 (i): aynı sürüm
CIFT_SEMBOLLU_FARKLI = [("debian/tmux", "macsym/tmux")]     # PK-4 (ii): sürüm farklı

# Yalnız iyileştirme düzeyi (DEFTER.md §5.11): tmux 3.8, GCC 16, -O0 / -O3 ↔ -O2
CIFT_IYILESTIRME_O0 = [("macgcc/tmuxO0", "macgcc/tmux")]
CIFT_IYILESTIRME_O3 = [("macgcc/tmuxO3", "macgcc/tmux")]

CIFT_GRUPLARI = {
    "kesif_htop": CIFT_KESIF_HTOP,
    "sinama_tmux": CIFT_SINAMA_TMUX,
    "sinama_cu_mac": CIFT_SINAMA_CU_MAC,
    "sinama_cu_ic": None,     # sinama_cu_ic() ile
    "surum": CIFT_SURUM,
    "derleme": CIFT_DERLEME,
    "derleyici": CIFT_DERLEYICI,
    "derleyici_htop": CIFT_DERLEYICI_HTOP,
    "surum_gcc": CIFT_SURUM_GCC,
    "sinama_cu_mac2": CIFT_SINAMA_CU_MAC2,
    "sembollu": CIFT_SEMBOLLU,
    "sembollu_esli": CIFT_SEMBOLLU_ESLI,
    "sembollu_farkli": CIFT_SEMBOLLU_FARKLI,
    "iyilestirme_o0": CIFT_IYILESTIRME_O0,
    "iyilestirme_o3": CIFT_IYILESTIRME_O3,
}


def grup(ad: str) -> list[tuple[str, str]]:
    if ad == "sinama_cu_ic":
        return sinama_cu_ic()
    return list(CIFT_GRUPLARI[ad])
