#!/usr/bin/env python
"""KİMLİK Dalga 0 (PK-6 / PK-11) — dondurulmuş yükleyiciye (``veri.py``) yeni kimlik kökleri.

``veri.py`` / ``ciftler.py`` DEĞİŞTİRİLMEZ (tur 1'in dondurulmuş betikleri). Bu modül süreç içinde iki şeyi bağlar:
  - ``veri._spec``: yeni önekler (``tabA``, ``tabB12``, ``tabB24``, ``v1gcc``, ``v1clang``, ``kitaplik``) eklenir;
    eski önekler değişmeden özgün işleve gider;
  - ``ciftler.grup``: ``scripts/measurement/kimlik_ciftler.grup`` (tur 1 grupları aynen + PK-6 / PK-11 grupları).
``kur()`` çağrıldıktan sonra ``yayilim_olc`` / ``hata_dok`` / ``ciplak`` / ``tanik`` / ``urun_bindiff`` / ``envanter``
modüllerinin ``main``'i aynı biçimde çalışır.

GT: tabaka ve kitaplık ikilileri ``ks1_olc.gt_elf`` ile okunur. ``gt_elf`` hata ayıklama dosyasını
``<indir>/x_*-dbgsym_*/usr/lib/debug/.build-id/…`` kalıbıyla arar; tabaka dizinleri ``x_<paket>-dbgsym`` adlı
(sonda ``_<sürüm>`` yok). Bu yüzden koşu dizininde salt bağlantılardan bir "indir" kökü kurulur
(``<KOK>/gt_indir/<kök>/x_<paket>-dbgsym_<sürüm>`` → tabakanın dizini); ``gt_elf`` kendisi değişmeden kullanılır.

v2 (tablo yuvası) x86-64'te desteklenmiyor: ``veri.isaretci_yuvalari`` yalnız ``R_AARCH64_RELATIVE`` ve Mach-O
zincirli düzeltmeyi okuyor. ``v2_destekli(kimlik)`` bunu söyler; ölçüm sarmalayıcısı v2 noktalarını o grupta koşmaz.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

_BURASI = Path(__file__).resolve().parent
if str(_BURASI) not in sys.path:
    sys.path.insert(0, str(_BURASI))
REPO = _BURASI.parents[2]
_OLCUM_BETIK = REPO / "scripts" / "measurement"
if str(_OLCUM_BETIK) not in sys.path:
    sys.path.insert(0, str(_OLCUM_BETIK))

import kimlik_ciftler as kc  # noqa: E402
import veri  # noqa: E402

OLCUM = Path.home() / "karadul_olcum"
KOK = OLCUM / "runs" / "dalga0-2026-11-20" / "KIMLIK"        # bu paketin bütün koşu çıktıları
KOSU = KOK / "kosu"                                            # Ghidra koşuları: KOSU/<kimlik>/
GT_INDIR = KOK / "gt_indir"
V1 = KOK / "v1"                                                # V1 derlemeleri: V1/<gcc|clang>/{korpus.json,ozgun,corpus}
N2 = OLCUM / "n2_tabaka"
TABAKA_VERI = N2 / "tabaka_veri.json"
KITAPLIK_VERI = N2 / "kitaplik" / "kitaplik_veri.json"

# kimlik kökü → (tabaka_veri.json'daki (tabaka, alt) anahtarı, açılan paketlerin dizini)
TABAKA_DIZINI = {
    "tabA": (("a", None), N2 / "a"),
    "tabB12": (("b", "debian12_arm64"), N2 / "b" / "debian12_arm64"),
    "tabB24": (("b", "ubuntu2404_arm64"), N2 / "b" / "ubuntu2404_arm64"),
}
V1_DERLEYICI = {"v1gcc": "gcc", "v1clang": "clang"}
KITAPLIK_IKILI = {"libzstd": ("libzstd1", "usr/lib/aarch64-linux-gnu/libzstd.so.1.5.7")}

_OZGUN_SPEC = veri._spec


def _json(yol: Path) -> Any:
    with open(yol, encoding="utf-8") as f:
        return json.load(f)


def _tabaka_satiri(kok: str, program: str, ikili: str) -> dict[str, Any]:
    """tabaka_veri.json'dan (paket, ikili) satırı: yol, sha256, build-id, sürüm."""
    (tabaka, alt), _ = TABAKA_DIZINI[kok]
    for p in _json(TABAKA_VERI)["paketler"]:
        if p["tabaka"] != tabaka or p["paket"] != program:
            continue
        if alt is not None and p.get("alt") != alt:
            continue
        for s in p["buildid"]["satirlar"]:
            if Path(s["yol"]).name == ikili:
                return dict(s, paket=p["paket"])
    raise KeyError(f"tabaka_veri.json'da yok: {kok}/{program}/{ikili}")


def girdi(kimlik: str) -> tuple[Path, Optional[str]]:
    """Kimliğin Ghidra'ya verilecek ikilisi ve (biliniyorsa) beklenen sha256'sı."""
    p = kimlik.split("/")
    if p[0] in TABAKA_DIZINI:
        s = _tabaka_satiri(p[0], p[1], p[2])
        return TABAKA_DIZINI[p[0]][1] / f"x_{p[1]}" / s["yol"], s["sha256"]
    if p[0] in V1_DERLEYICI:
        return V1 / V1_DERLEYICI[p[0]] / "corpus" / p[1] / "bin" / p[1], None
    if p[0] == "kitaplik":
        paket, yol = KITAPLIK_IKILI[p[1]]
        return N2 / "kitaplik" / f"x_{paket}" / yol, None     # künyedeki sha256 .deb'in; .so'nunki koşuda yazılır
    raise ValueError(f"Dalga 0 girdisi değil: {kimlik}")


def gt_indir_kur(kok: str) -> Path:
    """``gt_elf``'in kalıbına uyan salt bağlantı kökü (bir kez kurulur; var olanı doğrular)."""
    hedef = GT_INDIR / kok
    hedef.mkdir(parents=True, exist_ok=True)
    if kok == "kitaplik":
        kaynaklar = {"x_libzstd1-dbgsym_1.5.7+dfsg-1": N2 / "kitaplik" / "x_libzstd1-dbgsym"}
    else:
        dizin = TABAKA_DIZINI[kok][1]
        kaynaklar = {f"{d.name}_tabaka": d for d in sorted(dizin.iterdir())
                     if d.is_dir() and d.name.endswith("-dbgsym")}
    for ad, kaynak in kaynaklar.items():
        b = hedef / ad
        if b.is_symlink():
            if Path(os.readlink(b)) != kaynak:
                raise RuntimeError(f"{b} başka yeri gösteriyor: {os.readlink(b)}")
            continue
        b.symlink_to(kaynak, target_is_directory=True)
    return hedef


def spec(kimlik: str) -> dict[str, Any]:
    p = kimlik.split("/")
    if p[0] in TABAKA_DIZINI:
        if len(p) != 3:
            raise ValueError(f"tabaka kimliği <kök>/<program>/<ikili> olmalı: {kimlik}")
        return dict(platform="debian", program=p[1], ad=p[2], kok=KOSU / p[0] / p[1] / p[2],
                    d0_indir=gt_indir_kur(p[0]))
    if p[0] in V1_DERLEYICI:
        return dict(platform="mac", program=p[1], ad=p[1], kok=KOSU / p[0] / p[1],
                    mac_veri=V1 / V1_DERLEYICI[p[0]])
    if p[0] == "kitaplik":
        return dict(platform="debian", program=p[1], ad=p[1], kok=KOSU / "kitaplik" / p[1],
                    d0_indir=gt_indir_kur("kitaplik"))
    return _OZGUN_SPEC(kimlik)


def _yukle(kimlik: str, pcode: bool = True) -> veri.Ikili:
    """``veri.yukle`` aynen; yalnız Debian GT kökü (``DEBIAN_INDIR``) yeni kimliklerde kendi bağlantı köküne çevrilir."""
    s = spec(kimlik)
    if "d0_indir" not in s:
        return _OZGUN_YUKLE(kimlik, pcode)
    eski = veri.DEBIAN_INDIR
    veri.DEBIAN_INDIR = s["d0_indir"]
    try:
        return _OZGUN_YUKLE(kimlik, pcode)
    finally:
        veri.DEBIAN_INDIR = eski


_OZGUN_YUKLE = veri.yukle


def v2_destekli(kimlik: str) -> bool:
    """Tablo yuvası okuyucusu (``veri.isaretci_yuvalari``) bu kimliğin biçimini okuyabiliyor mu."""
    return not kimlik.startswith("tabA/")


_KURULDU = False


def kur() -> None:
    """Süreç içi bağlama (idempotent): ``veri._spec`` / ``veri.yukle`` ve ``ciftler.grup``."""
    global _KURULDU
    if _KURULDU:
        return
    import ciftler
    veri._spec = spec
    veri.yukle = _yukle
    ciftler.grup = kc.grup
    ciftler.CIFT_GRUPLARI = {g: None for g in kc.GRUP_ADLARI}
    _KURULDU = True


if __name__ == "__main__":
    kur()
    for k in sys.argv[1:]:
        I = veri.yukle(k)
        print(k, json.dumps({"fonk": len(I.fonk), "nufus": len(I.nufus), "kunye": I.kunye}, ensure_ascii=False))
