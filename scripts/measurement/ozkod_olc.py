#!/usr/bin/env python3
"""ÖK-5: ÖZ KOD kurallarının (K1, G1, R1, modül öneki) ölçümü — veri kökü ve birim listesi parametreli.

Plan: ``docs/arge/2026-11-19_mythos/ozkod/PLAN.md`` "ÖK-5" (adım 1–8) ve "ÖK-V" (adım 6).
İlerleme ve hükümler: ``docs/arge/2026-11-19_mythos/ozkod/OK5.md``; ön kayıt: ``on_kayit_OK5.md``.

KURAL KOPYALANMAZ, İÇE AKTARILIR. ``scripts/arge/ozkod/`` betikleri (2026-11-19 ARGE turu) olduğu gibi
yüklenir; sha256'ları DEFTER §4, §7, §10'daki değerlerle karşılaştırılır, tutmazsa hiçbir şey sayılmaz.
Kural işlevleri: ``ek_kurali.adaylar`` / ``tahmin`` / ``_ek_oyu`` / ``olc``, ``kayit_cifti.gt_esit`` /
``say`` / ``ek_cikar``, ``oz_ad_ayrim.ozellikler`` / ``kural_tut``, ``oz_ad_uretici.g1``, ``tavan.main``.
Parametre olan yalnız modül düzeyindeki VERİ KÖKLERİ ve BİRİM LİSTELERİDİR (``etkin``): koşu kökü,
hata ayıklama dizini, önbellek ve çıktı dizinleri, keşif / sınama birimleri, atlanacak ikililer.

Taraf eşlemesi (bağımsız nüfus): ``ayar`` → araştırma betiklerinin ``kesif`` tarafı, ``kör`` → ``sinama``.
Bir sayım yalnız tek tarafı GÖRÜNÜR kılarak yapılır (öbür tarafın birim listesi boş): kör sayımında
ayar birimi, ayar okumasında kör birimi hiçbir döngüye giremez.

KÖRLÜK. Kör tarafta yalnız sayı üretilir. Araştırma betiklerinin örnek / grup dökümleri (GT adı, dizgi,
çağrılan adı taşır) çıktıdan atılır (``temizle``); hiçbir alt komut kör tarafın adını, dizgisini, ELF
yolunu ekrana ya da dosyaya yazmaz. Yalnız ``dokum`` alt komutu (PLAN ÖK-5 adım 7; ölçüm ve
``OK5.md`` commit'inden SONRA) yanlış ad listesini ``~/karadul_olcum/ozkod_nufus/runs/`` altına yazar ve
ekrana yalnız satır sayısını basar. Olgu önbelleği (makine verisi, pickle) adları içerir; okunmaz,
depoya girmez.

Alt komutlar (depo kökünden, ``PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/ozkod_olc.py …``):
  esdeger                    geliştirme setinde araştırma betiklerinin sayılarını yeniden üret (ÖK-5 adım 2)
  kur      --veri nufus      ÖK-V adım 6: GT bağ dizini + olgu önbelleği + tutarlılık (yalnız sayı)
  ayar     --veri nufus      ÖK-5 adım 4: ayar tarafında G1 kapısı ve K1 karakter eki (okuma + dondurma önerisi)
  kor      --veri nufus      ÖK-5 adım 5–6: kör sayım (cift, k1, k1-capa, g1, ozad, tavan; yalnız sayı)
  cift | k1 | k1-capa | ozad | g1 | tavan   tek ölçü (--veri, --taraf)
  hedef                      İ-1/3: gösteri koşusunun (Ollama) Go dışı fonksiyonlarında erişim
  dokum    --veri nufus      PLAN adım 7: yanlışların listesi (yalnız ~/karadul_olcum/ozkod_nufus/runs/)
"""
from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

REPO = Path(__file__).resolve().parents[2]
OZKOD = REPO / "scripts" / "arge" / "ozkod"
OLCUM = REPO / "scripts" / "measurement"
EV = Path.home()
ANA_DEPO = Path("/Users/apple/Black_Widow")           # git'in izlemediği Mac GT verisi (salt okur)

# Dondurulmuş kural betikleri (DEFTER §4, §7, §10). Değişmişse ölçüm yapılmaz.
DONDURULMUS = {
    "ek_kurali.py": "7d02a6b58e05f2dc8c70b8bb0764fd89b59e040079d7f470fca79ac6e994741c",
    "kayit_cifti.py": "69201c56df4b10ed347d3ecfa88337c95b8ba3c68f6ea5dd2580ad22f91e9cbc",
    "ozkod_veri.py": "8767bde0647f411ff092469f6a7dfbd4f148a672d0552283cc63295f9e94e6a9",
    "oz_ad_ayrim.py": "ccc73f5c5dbba90b09f7b5657ea810c5cb24dc24ea375042d94059f22e8c541b",
    "oz_ad_uretici.py": "7ee4edfc59265ea9cce522ab04a0503c9a3ded1fd4876047f9ced82035ac0acb",
}
# Ölçüm kısmı içe aktarılan (dondurulmamış ama değişmeyen) betikler: sha256'ları çıktıya yazılır.
YARDIMCI_BETIKLER = ("tavan.py", "ek_kurali_belirtec.py", "ek_kurali_capa.py", "oz_ad_harf.py")

NUFUS_KOK = EV / "karadul_olcum" / "ozkod_nufus"
NUFUS_KOSU = NUFUS_KOK / "runs" / "taban-b6aceb9"
NUFUS_CIKTI = NUFUS_KOK / "runs" / "ok5"
D0_CIKTI = EV / "karadul_olcum" / "runs" / "dalga0-2026-11-20" / "OK5"
ARGE_ESKI = EV / "karadul_olcum" / "runs" / "arge-2026-11-19" / "ozkod"    # salt okur (araştırma turu)
GOSTERI = EV / "karadul_olcum" / "runs" / "gosteri-2026-11-19" / "ollama"  # salt okur

AYAR, KOR = "ayar", "kör"
TARAF_ESLEME = {AYAR: "kesif", KOR: "sinama"}
# Kaynak grupları (NUFUS.md §2): tekil sayım (A-14) ve program düzeyi makro (İ-7) bunlarla.
KAYNAK_GRUPLARI = (("tcl8.6", "libtcl8.6"), ("lua-socket", "lua-cjson"),
                   ("python3.13-minimal", "libpython3.13-stdlib"))
ASSERT_ICE_AKTARIMLARI = frozenset({"__assert_fail", "__assert_rtn"})   # PLAN ÖK-5 adım 4 (a)

# Geliştirme setinde araştırma betiklerinin sayıları (DEFTER §3–§14; BULGULAR) — eşdeğerlik hedefi.
GELISTIRME_BEKLENEN = {
    "k1_kesif": (754, 740), "k1_sinama": (126, 103),          # PLAN ÖK-5 adım 2 (zorunlu)
    "g1_kesif": (484, 454), "g1_sinama": (143, 114),          # DEFTER §10–§11
    "vc_toplam": (20747, 1279),                               # BULGULAR §2.1 (nüfus, V ∪ C)
    "sandvic_32": (1454, 1212), "sandvic_0": (2545, 2216),    # tavan.json hepsi|hepsi
    "kip_a": (98, 95), "kip_c": (242, 239),                   # ek_kurali_capa.txt hepsi
    "r1_harf": (111, 106),                                    # BULGULAR §1.2
}


# --------------------------------------------------------------------------------------------
# Dondurulmuş betikler


def sha256_dosya(yol: Path) -> str:
    return hashlib.sha256(Path(yol).read_bytes()).hexdigest()


class DondurmaHatasi(RuntimeError):
    pass


def dondurulmus_denetle(dizin: Path = OZKOD, beklenen: Optional[dict[str, str]] = None) -> dict[str, str]:
    beklenen = DONDURULMUS if beklenen is None else beklenen
    out = {}
    for ad, h in beklenen.items():
        gercek = sha256_dosya(dizin / ad)
        if gercek != h:
            raise DondurmaHatasi(f"{ad}: sha256 {gercek[:16]}… ≠ dondurulmuş {h[:16]}…")
        out[ad] = gercek
    return out


_MOD: dict[str, Any] = {}


def kurallar() -> dict[str, Any]:
    """Araştırma betiklerini (dondurma denetiminden sonra) yükle: V, K, E, O, G, T, B."""
    if not _MOD:
        dondurulmus_denetle()
        if str(OZKOD) not in sys.path:
            sys.path.insert(0, str(OZKOD))
        import ozkod_veri
        import kayit_cifti
        import ek_kurali
        import oz_ad_ayrim
        import oz_ad_uretici
        import tavan
        import ek_kurali_belirtec
        _MOD.update(V=ozkod_veri, K=kayit_cifti, E=ek_kurali, O=oz_ad_ayrim, G=oz_ad_uretici,
                    T=tavan, B=ek_kurali_belirtec)
    return _MOD


def betik_kunyesi() -> dict[str, str]:
    return {ad: sha256_dosya(OZKOD / ad) for ad in (*DONDURULMUS, *YARDIMCI_BETIKLER)}


# --------------------------------------------------------------------------------------------
# Veri kökü ve birim listesi


@dataclass(frozen=True)
class Veri:
    ad: str
    kosu_kok: Path                    # ozkod_veri.KOSU_KOKU (``mac/`` ve ``debian/`` altında)
    debian_indir: Path                # ozkod_veri.DEBIAN_INDIR (``ks1_olc.gt_elf``'in aradığı dizin)
    mac_veri: Path                    # ozkod_veri.MAC_VERI
    cikti: Path                       # ozkod_veri.ARGE_KOKU yerine (önbellek ve araştırma çıktıları)
    kesif: tuple[str, ...]            # ayar birimleri (bağımsız nüfusta)
    sinama: tuple[str, ...]           # kör birimleri
    atla: frozenset = frozenset()     # (birim, ikili): sayılmaz (aynı dosya / GT kurulamadı)
    olgu: Optional[Path] = None       # tavan.OLGU (kaynak sınıfı); yoksa boş tablo
    taraf_adi: dict = field(default_factory=lambda: {"kesif": "kesif", "sinama": "sinama"})
    gnu_buildid: bool = False         # BuildID yalnız sahibi GNU olan nottan (NUFUS.md §8 not 3)


def gelistirme_verisi(cikti: Optional[Path] = None) -> Veri:
    V = kurallar()["V"]
    return Veri("gelistirme", EV / "karadul_olcum" / "runs" / "urun-onarim-a62f15e",
                EV / "karadul_olcum" / "downloads" / "debian13", ANA_DEPO / "workspaces" / "olcum_mac",
                cikti or (D0_CIKTI / "gelistirme"), tuple(V.KESIF_BIRIMLERI), tuple(V.SINAMA_BIRIMLERI),
                frozenset(V.AYNI_DOSYA_ATLA), ARGE_ESKI.parent / "olgu" / "olgu.jsonl.gz")


def nufus_birimleri(nufus: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Taraf → ölçülecek ELF'i olan paketlerin birim anahtarları (``debian/<paket>``)."""
    out: dict[str, list[str]] = {AYAR: [], KOR: []}
    for r in nufus["paketler"]:
        if r.get("olculur"):
            out[r["taraf"]].append(f"debian/{r['paket']}")
    return {t: tuple(v) for t, v in out.items()}


def nufus_verisi(nufus_kok: Path = NUFUS_KOK, kosu_kok: Path = NUFUS_KOSU, cikti: Path = NUFUS_CIKTI,
                 atla: Iterable[tuple[str, str]] = ()) -> Veri:
    nufus = json.loads((nufus_kok / "nufus.json").read_text(encoding="utf-8"))
    b = nufus_birimleri(nufus)
    return Veri("nufus", kosu_kok, cikti / "gt_bag", cikti / "mac_yok", cikti,
                kesif=b[AYAR], sinama=b[KOR], atla=frozenset(atla), olgu=cikti / "olgu_bos.jsonl.gz",
                taraf_adi={"kesif": AYAR, "sinama": KOR}, gnu_buildid=True)


def gnu_buildid(yol: Path) -> Optional[str]:
    """Yalnız sahibi ``GNU`` olan ``NT_GNU_BUILD_ID`` notu (``tabaka_indir.elf_bilgisi``)."""
    ti_ = _modul("tabaka_indir", REPO / "scripts" / "arge" / "olcu" / "tabaka_indir.py")
    return (ti_.elf_bilgisi(Path(yol)) or {}).get("build_id")


@contextlib.contextmanager
def _gnu_buildid_baglami(acik: bool) -> Iterator[None]:
    """NUFUS.md §8 not 3: ``function_f1.read_elf_info`` SystemTap (``stapsdt``) notunu da BuildID sanıyor
    (ÖK-V'de iki ELF; ``build_id`` bayt dizisi döner ve ``ks1_olc.gt_elf`` hata ayıklama dosyasını
    bulamaz). Gönderim metninin yolu: BuildID ``tabaka_indir.elf_bilgisi`` ile alınır. Bağlam içinde
    ``read_elf_info``'nun yalnız ``build_id`` alanı GNU notundan gelir; öbür alanlar aynen.
    ``function_f1.py`` değişmez (OLCUM paketinin dosyası). Öbür ELF'lerde iki değer zaten aynı."""
    if not acik:
        yield
        return
    f1 = kurallar()["V"].ks1()._f1()
    asil = f1.read_elf_info

    def sarili(path):
        r = asil(path)
        b = gnu_buildid(Path(path))
        return dict(r, build_id=b) if b else r

    f1.read_elf_info = sarili
    try:
        yield
    finally:
        f1.read_elf_info = asil


@contextlib.contextmanager
def etkin(v: Veri, gorunur: Iterable[str]) -> Iterator[dict[str, Any]]:
    with _etkin(v, gorunur) as m, _gnu_buildid_baglami(v.gnu_buildid):
        yield m


@contextlib.contextmanager
def _etkin(v: Veri, gorunur: Iterable[str]) -> Iterator[dict[str, Any]]:
    """Araştırma betiklerinin veri köklerini ve birim listelerini ``v``'ye çevir; yalnız ``gorunur``
    taraf(lar)ın ("kesif", "sinama") birimleri listede kalır. Çıkışta eski değerler geri yüklenir."""
    m = kurallar()
    V, K, E, O, T = m["V"], m["K"], m["E"], m["O"], m["T"]
    gorunur = set(gorunur)
    if not gorunur <= {"kesif", "sinama"}:
        raise ValueError(f"bilinmeyen taraf: {gorunur}")
    kesif = v.kesif if "kesif" in gorunur else ()
    sinama = v.sinama if "sinama" in gorunur else ()
    yeni = {
        (V, "KOSU_KOKU"): v.kosu_kok, (V, "DEBIAN_INDIR"): v.debian_indir, (V, "MAC_VERI"): v.mac_veri,
        (V, "ARGE_KOKU"): v.cikti, (V, "ONBELLEK"): v.cikti / "onbellek",
        (V, "KESIF_BIRIMLERI"): tuple(kesif), (V, "SINAMA_BIRIMLERI"): tuple(sinama),
        (V, "BIRIMLER"): tuple(kesif) + tuple(sinama), (V, "AYNI_DOSYA_ATLA"): set(v.atla),
        (K, "CAGRI_ONBELLEK"): v.cikti / "onbellek_cagri", (K, "CIKTI"): v.cikti / "kayit_cifti",
        (E, "CIKTI"): v.cikti / "ek_kurali", (O, "DIZIN_ONBELLEK"): v.cikti / "onbellek_c_dizini",
        (T, "OLGU"): v.olgu,
    }
    eski = {k: getattr(k[0], k[1]) for k in yeni}
    v.cikti.mkdir(parents=True, exist_ok=True)
    (v.cikti / "ek_kurali").mkdir(parents=True, exist_ok=True)
    if v.olgu is not None and not v.olgu.exists():
        with gzip.open(v.olgu, "wt", encoding="utf-8"):
            pass
    for (mod, ad), deger in yeni.items():
        setattr(mod, ad, deger)
    try:
        yield m
    finally:
        for (mod, ad), deger in eski.items():
            setattr(mod, ad, deger)


# --------------------------------------------------------------------------------------------
# Sayı yardımcıları


def oran(k_: int, n_: int) -> dict[str, Any]:
    """Wilson %95 (``ks1_olc.oran``; PLAN: "Sayılar betikten; Wilson %95")."""
    o = kurallar()["V"].ks1().oran(k_, n_)
    return {"k": k_, "n": n_, "oran": o["oran"],
            "alt": None if o["aralik"] is None else round(o["aralik"][0], 6),
            "ust": None if o["aralik"] is None else round(o["aralik"][1], 6)}


def yuzde(o: dict[str, Any]) -> str:
    if not o["n"]:
        return f"{o['k']} / 0 (veri yok)"
    return (f"{o['k']} / {o['n']} (%{100 * o['k'] / o['n']:.1f}; Wilson %{100 * o['alt']:.1f}–"
            f"%{100 * o['ust']:.1f})")


def kaynak_grubu(birim: str, gruplar: tuple[tuple[str, ...], ...] = KAYNAK_GRUPLARI) -> str:
    """``debian/<paket>`` → aynı kaynağın ilk paketi (tekil sayım ve program düzeyi makro için)."""
    p = birim.split("/", 1)[-1]
    for g in gruplar:
        if p in g:
            return g[0]
    return p


def temizle(s: dict[str, Any]) -> dict[str, Any]:
    """Araştırma betiği çıktısından ad / dizgi taşıyan alanları at (körlük): yalnız sayaçlar kalır."""
    out = {k: v for k, v in s.items() if k not in ("ornek", "gruplar")}
    if "gruplar" in s:
        out["grup_sayisi"] = len(s["gruplar"])
    return out


def topla(birim: dict[str, dict[str, int]]) -> Counter:
    t: Counter = Counter()
    for c in birim.values():
        t.update(c)
    return t


# --------------------------------------------------------------------------------------------
# G1 kapısı (PLAN ÖK-5 adım 4 (a)) — ikili düzeyinde


def ks1_capa_sayisi(d: dict[str, Any]) -> Optional[int]:
    yol = Path(d["kosu"]) / "reconstructed" / "kesin_capalar.json"
    if not yol.is_file():
        return None
    belge = json.loads(yol.read_text(encoding="utf-8"))
    return len(belge.get("capalar") or [])


def assert_ice_aktarimi(d: dict[str, Any]) -> bool:
    k = kurallar()["V"].ks1()
    return any(k.platform_adi(f["ad"], d["platform"]) in ASSERT_ICE_AKTARIMLARI
               for f in d["fonk"].values() if f["thunk"] or f["dis"])


def g1_kapisi(d: dict[str, Any]) -> bool:
    """Kapı adayı: ikilide KS-1 çapası ≥ 1 ya da ``__assert_fail`` / ``__assert_rtn`` içe aktarımı."""
    n = ks1_capa_sayisi(d)
    return (n is not None and n >= 1) or assert_ice_aktarimi(d)


# --------------------------------------------------------------------------------------------
# K1 karakter düzeyinde ek (ÖK-7 A): K1'in kararı (hangi fonksiyona ad) AYNI; yalnız yazım çapadan


def _parcalar(s: str) -> list[str]:
    return [p for p in re.split(r"[^A-Za-z0-9]+", s) if p]


def _deve(s: str) -> str:
    b = kurallar()["V"].belirtecler(s)
    return (b[0] + "".join(x.capitalize() for x in b[1:])) if b else ""


def _pascal(s: str) -> str:
    return "".join(x.capitalize() for x in kurallar()["V"].belirtecler(s))


# Aday dönüşümler, öncelik sırasıyla (ayar okumasından ÖNCE yazıldı; ayar tarafında dondurulur).
DONUSUM_ADAYLARI: dict[str, Callable[[str], str]] = {
    "aynen": lambda s: s,
    "alt_cizgi": lambda s: "_".join(_parcalar(s)),
    "bitisik": lambda s: "".join(_parcalar(s)),
    "kucuk_alt_cizgi": lambda s: "_".join(_parcalar(s)).lower(),
    "kucuk_bitisik": lambda s: "".join(_parcalar(s)).lower(),
    "deve": _deve,
    "pascal": _pascal,
    "buyuk_alt_cizgi": lambda s: "_".join(_parcalar(s)).upper(),
}
DONUSUM_ESIGI_N = 5          # ayar kuralı: kullanıldığı ad ≥ 5 ve karakter doğruluğu < %50 ise çıkar
DONUSUM_ESIGI_ORAN = 0.5


def karakter_ayristir(dizgi: str, capa_ad: str, ek: tuple[str, str],
                      donusumler: Iterable[str]) -> list[tuple[str, str, str]]:
    """Çapa adında dizginin bir dönüşümünün TEK geçtiği yer → (önek, dönüşüm, sonek) adayları.

    Yalnız norm ekiyle (``kayit_cifti.ek_cikar``) tutarlı ayrışımlar: norm(önek) = ek[0], norm(sonek) = ek[1].
    """
    V = kurallar()["V"]
    out = []
    for ad in donusumler:
        alt = DONUSUM_ADAYLARI[ad](dizgi)
        if not alt or capa_ad.count(alt) != 1:
            continue
        i = capa_ad.find(alt)
        on, son = capa_ad[:i], capa_ad[i + len(alt):]
        if V.norm(on) == ek[0] and V.norm(son) == ek[1]:
            out.append((on, ad, son))
    return out


def karakter_adi(fa: int, fa_adaylari: list[tuple[tuple, str]], gruplar: dict[tuple, list[tuple[int, str]]],
                 ad_kaynagi: dict[int, list[str]], donusumler: tuple[str, ...]
                 ) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """(norm adı, karakter adı ya da None, kullanılan dönüşüm). Norm kararı ``ek_kurali.tahmin``."""
    m = kurallar()
    E, K = m["E"], m["K"]
    norm_ad, _durum = E.tahmin(fa, fa_adaylari, gruplar, ad_kaynagi, E.MIN_DESTEK)
    if norm_ad is None:
        return None, None, None
    adlar: dict[str, str] = {}
    for grup, s in fa_adaylari:
        ek = E._ek_oyu(gruplar[grup], fa, ad_kaynagi, E.MIN_DESTEK)
        if ek is None:
            continue
        oy: Counter = Counter()
        hangi: dict[str, int] = {}          # aday ad → onu veren en öncelikli dönüşümün sırası
        sira = {ad: i for i, ad in enumerate(donusumler)}
        for a, s_a in gruplar[grup]:
            if a == fa or a not in ad_kaynagi:
                continue
            # ``ek_kurali._ek_oyu`` ile aynı: çapanın eki, ek veren ilk adından
            capa = next((g for g in ad_kaynagi[a] if K.ek_cikar(s_a, g) is not None), None)
            if capa is None or K.ek_cikar(s_a, capa) != ek:
                continue
            bu_capa: dict[str, int] = {}
            for on, don, son in karakter_ayristir(s_a, capa, ek, donusumler):
                aday = on + DONUSUM_ADAYLARI[don](s) + son
                bu_capa[aday] = min(bu_capa.get(aday, sira[don]), sira[don])
            for aday, i in bu_capa.items():     # bir çapa bir aday ada en çok bir oy
                oy[aday] += 1
                hangi[aday] = min(hangi.get(aday, i), i)
        if not oy:
            continue
        (ad1, n1), *kalan = oy.most_common(2)
        if n1 < E.MIN_DESTEK or (kalan and kalan[0][1] == n1):
            continue
        adlar[ad1] = donusumler[hangi[ad1]]
    if len(adlar) == 1:
        ad1, don = next(iter(adlar.items()))
        return norm_ad, ad1, don
    return norm_ad, None, None


# --------------------------------------------------------------------------------------------
# Ölçüler (her biri yalnız görünür tarafta döner)


def say_cift(taraf: str) -> dict[str, Any]:
    K = kurallar()["K"]
    return temizle(K.say(taraf))


def say_k1(taraf: str) -> dict[str, Any]:
    E = kurallar()["E"]
    return temizle(E.olc(taraf))


def say_belirtec(taraf: str) -> dict[str, dict[str, int]]:
    """``ek_kurali_belirtec.py``'nin ölçüm döngüsü (kâhin çapa; karakter / norm / ayraçsız; belirteç)."""
    m = kurallar()
    V, K, E, B = m["V"], m["K"], m["E"], m["B"]
    birim: dict[str, Counter] = defaultdict(Counter)
    for d in V.hepsi(taraf_=taraf):
        c = birim[d["birim"]]
        ad = E.adaylar(d)
        gruplar = defaultdict(list)
        for fa, liste in ad.items():
            for grup, s in liste:
                gruplar[grup].append((fa, s))
        kaynak = {x: list(v) for x, v in d["gt_adlar"].items()}
        for fa in sorted(d["nufus"]):
            if fa not in ad:
                continue
            t, _durum = E.tahmin(fa, ad[fa], gruplar, kaynak, E.MIN_DESTEK)
            if t is None:
                continue
            gt = d["gt_adlar"][fa]
            c["ad"] += 1
            c["karakter"] += t in gt
            c["norm"] += K.gt_esit(t, gt)
            c["ayracsiz"] += any(B.ayracsiz(t) == B.ayracsiz(g) for g in gt)
            tb = set(V.ad_belirtecleri(t))
            en_iyi = max(((len(tb & set(V.ad_belirtecleri(g))), len(set(V.ad_belirtecleri(g))))
                          for g in gt), key=lambda x: (x[0] / x[1] if x[1] else 0))
            c["ortak"] += en_iyi[0]
            c["aday_belirtec"] += len(tb)
            c["gt_belirtec"] += en_iyi[1]
    return {b: dict(c) for b, c in birim.items()}


def say_k1_tekil(taraf: str) -> dict[str, Any]:
    """A-14 tekil düzey: kâhin K1 adları (kaynak grubu, GT adı) başına bir kez; ayrıca program
    düzeyi (kaynak grubu) kesinlikleri (İ-7; yalnız rapor)."""
    m = kurallar()
    V, K, E = m["V"], m["K"], m["E"]
    tekil: dict[tuple[str, str], bool] = {}
    program: dict[str, Counter] = defaultdict(Counter)
    for d in V.hepsi(taraf_=taraf):
        ad = E.adaylar(d)
        gruplar = defaultdict(list)
        for fa, liste in ad.items():
            for grup, s in liste:
                gruplar[grup].append((fa, s))
        kaynak = {x: list(v) for x, v in d["gt_adlar"].items()}
        pg = kaynak_grubu(d["birim"])
        for fa in sorted(d["nufus"]):
            if fa not in ad:
                continue
            t, _ = E.tahmin(fa, ad[fa], gruplar, kaynak, E.MIN_DESTEK)
            if t is None:
                continue
            gt = d["gt_adlar"][fa]
            dogru = K.gt_esit(t, gt)
            program[pg]["ad"] += 1
            program[pg]["dogru"] += dogru
            anahtar = (pg, gt[0])
            tekil[anahtar] = tekil.get(anahtar, True) and dogru   # tekil öğe: bütün örnekleri doğruysa doğru
    return {"tekil_ad": len(tekil), "tekil_dogru": sum(tekil.values()),
            "program": {p: dict(c) for p, c in sorted(program.items())}}


def _capa_kaynaklari(d: dict[str, Any], kapi_acik: Optional[bool] = None) -> dict[str, dict[int, list[str]]]:
    """``ek_kurali_capa.py``'nin kipleri. A: ürünün ön ad kanalları (``on_ad:*``, ``ks1:*``) + Ghidra'nın
    jenerik olmayan adı; C: A + G1 (düz); C_kapili: A + G1 yalnız kapıdan geçen ikilide; D: bütün ürün adları."""
    m = kurallar()
    V, G = m["V"], m["G"]
    f1 = V.ks1()._f1()
    ghidra = {a: [f["ad"]] for a, f in d["fonk"].items()
              if not f["thunk"] and not f["dis"] and not f1.is_generic_name(f["ad"], [a])}
    kaynak = {k_: dict(ghidra) for k_ in ("A", "C", "C_kapili", "D")}
    for a, r in d["urun"].items():
        kaynak["D"][a] = [r["ad"]]
        if r["kanal"].startswith(("on_ad:", "ks1:")):
            for k_ in ("A", "C", "C_kapili"):
                kaynak[k_][a] = [r["ad"]]
    g1 = G.g1(d)
    for a, s in g1.items():
        kaynak["C"].setdefault(a, [s])
    if kapi_acik if kapi_acik is not None else g1_kapisi(d):
        for a, s in g1.items():
            kaynak["C_kapili"].setdefault(a, [s])
    return kaynak


def say_k1_capa(taraf: str) -> dict[str, dict[str, dict[str, int]]]:
    """Kip A / C / C_kapılı / D: hedef = nüfusta, o kipte çapa adı OLMAYAN fonksiyonlar."""
    m = kurallar()
    V, K, E = m["V"], m["K"], m["E"]
    say: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for d in V.hepsi(taraf_=taraf):
        ad = E.adaylar(d)
        gruplar = defaultdict(list)
        for fa, liste in ad.items():
            for grup, s in liste:
                gruplar[grup].append((fa, s))
        kaynak = _capa_kaynaklari(d)
        for k_, kay in kaynak.items():
            c = say[k_][d["birim"]]
            c["nufus"] += len(d["nufus"])
            c["capa_adli_fn"] += sum(1 for a in kay if a in ad)
            for fa in sorted(d["nufus"]):
                if fa not in ad or fa in kay:
                    continue
                t, _durum = E.tahmin(fa, ad[fa], gruplar, kay, E.MIN_DESTEK)
                if t is None:
                    continue
                gt = d["gt_adlar"][fa]
                bugun = d["urun"].get(fa)
                c["ad"] += 1
                c["dogru"] += K.gt_esit(t, gt)
                c["karakter"] += K.karakter_esit(t, gt)
                c["bugun_adsiz_dogru"] += K.gt_esit(t, gt) and bugun is None
    return {k_: {b: dict(c) for b, c in bb.items()} for k_, bb in say.items()}


def say_g1(taraf: str) -> dict[str, dict[str, int]]:
    """G1 düz ve kapılı (kapı ikili düzeyinde). Hüküm ``ks1_olc.capa_degerlendir`` (tam eşitlik)."""
    m = kurallar()
    V, G = m["V"], m["G"]
    k = V.ks1()
    birim: dict[str, Counter] = defaultdict(Counter)
    for d in V.hepsi(taraf_=taraf):
        c = birim[d["birim"]]
        kapi = g1_kapisi(d)
        n_ks1 = ks1_capa_sayisi(d)
        c["ikili"] += 1
        c["kapidan_gecen_ikili"] += kapi
        c["ks1_capali_ikili"] += bool(n_ks1)
        c["ks1_capa_dosyasi_yok"] += n_ks1 is None
        c["assert_ikili"] += assert_ice_aktarimi(d)
        c["nufus"] += len(d["nufus"])
        for fa, s in G.g1(d).items():
            if fa not in d["nufus"]:
                c["nufus_disi_ad"] += 1
                continue
            gt = d["gt_adlar"][fa]
            dogru = k.capa_degerlendir(s, gt, k.PLATFORM_DEBIAN)["durum"] == "dogru"
            bugun = d["urun"].get(fa)
            durum = "adsiz" if bugun is None else ("dogru" if bugun["durum"] == "dogru" else "yanlis")
            for on in ("duz",) + (("kapili",) if kapi else ()):
                c[f"{on}_ad"] += 1
                c[f"{on}_dogru"] += dogru
                c[f"{on}_bugun_{durum}"] += 1
                c[f"{on}_dogru_bugun_{durum}"] += dogru
    return {b: dict(c) for b, c in birim.items()}


def say_ozad(taraf: str) -> dict[str, dict[str, int]]:
    """``oz_ad`` adları: bugünkü hüküm, R1 (``oz_ad_ayrim.kural_tut``), kanıt harfleriyle hüküm
    (``oz_ad_harf.py``'nin tanımı: kanıt tek tanımlayıcıysa ``capa_degerlendir``)."""
    m = kurallar()
    V, O = m["V"], m["O"]
    k = V.ks1()
    tanim = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
    birim: dict[str, Counter] = defaultdict(Counter)
    ozellik = {(o["birim"], o["ikili"], o["adres"]): o for o in O.ozellikler(taraf)}
    for d in V.hepsi(taraf_=taraf):
        c = birim[d["birim"]]
        for fa, r in d["urun"].items():
            if r["kanal"] != O.KANAL:
                continue
            o = ozellik[(d["birim"], d["ad"], fa)]
            gt = d["gt_adlar"].get(fa)
            h = bool(gt and tanim.match(o["kanit"])) and \
                k.capa_degerlendir(o["kanit"], gt, k.PLATFORM_DEBIAN)["durum"] == "dogru"
            r1 = O.kural_tut(o)
            c["ad"] += 1
            c["bugun_dogru"] += o["dogru"]
            c["harf_dogru"] += h
            c["r1_tut"] += r1
            c["r1_bugun_dogru"] += r1 and o["dogru"]
            c["r1_harf_dogru"] += r1 and h
    return {b: dict(c) for b, c in birim.items()}


def say_tavan(taraf: str) -> dict[str, Any]:
    """``tavan.main`` olduğu gibi (yalnız görünür taraf); ekran çıktısı dosyaya, tavan.json'dan önek."""
    m = kurallar()
    V, T = m["V"], m["T"]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        T.main()
    (V.ARGE_KOKU / f"tavan_{taraf}.txt").write_text(buf.getvalue(), encoding="utf-8")
    t = json.loads((V.ARGE_KOKU / "tavan.json").read_text(encoding="utf-8"))
    onek = {k_: v for k_, v in t["onek"].items() if k_.split("|")[0] in (taraf, "hepsi")
            or k_.split("|")[0] in V.BIRIMLER}
    return {"onek": onek}


# --------------------------------------------------------------------------------------------
# K1 karakter eki: ölçüm (kâhin çapa)


def say_k1_karakter(taraf: str, donusumler: tuple[str, ...]) -> dict[str, Any]:
    m = kurallar()
    V, K, E = m["V"], m["K"], m["E"]
    birim: dict[str, Counter] = defaultdict(Counter)
    don: dict[str, Counter] = defaultdict(Counter)
    for d in V.hepsi(taraf_=taraf):
        c = birim[d["birim"]]
        ad = E.adaylar(d)
        gruplar = defaultdict(list)
        for fa, liste in ad.items():
            for grup, s in liste:
                gruplar[grup].append((fa, s))
        kaynak = {x: list(v) for x, v in d["gt_adlar"].items()}
        for fa in sorted(d["nufus"]):
            if fa not in ad:
                continue
            norm_ad, kar_ad, dn = karakter_adi(fa, ad[fa], gruplar, kaynak, donusumler)
            if norm_ad is None:
                continue
            gt = d["gt_adlar"][fa]
            yazilan = kar_ad if kar_ad is not None else norm_ad
            c["ad"] += 1
            c["norm_dogru"] += K.gt_esit(norm_ad, gt)
            c["norm_karakter"] += K.karakter_esit(norm_ad, gt)
            c["karakter_ogrenildi"] += kar_ad is not None
            c["karakter"] += K.karakter_esit(yazilan, gt)
            if dn is not None:
                don[dn]["ad"] += 1
                don[dn]["karakter"] += K.karakter_esit(kar_ad, gt)
    return {"birim": {b: dict(c) for b, c in birim.items()}, "donusum": {k_: dict(v) for k_, v in don.items()}}


def donusum_dondur(donusum_sayaci: dict[str, dict[str, int]], adaylar: Iterable[str] = DONUSUM_ADAYLARI
                   ) -> tuple[str, ...]:
    """Ayar kuralı (ön kayıtlı): kullanıldığı ad ≥ DONUSUM_ESIGI_N ve karakter doğruluğu < %50 olan
    dönüşüm çıkarılır; kalanlar aday sırasıyla dondurulur."""
    out = []
    for ad in adaylar:
        c = donusum_sayaci.get(ad, {})
        n = c.get("ad", 0)
        if n >= DONUSUM_ESIGI_N and c.get("karakter", 0) < DONUSUM_ESIGI_ORAN * n:
            continue
        out.append(ad)
    return tuple(out)


# --------------------------------------------------------------------------------------------
# Ön kayıtlı hükümler (on_kayit_OK5.md; eşikler ölçümden sonra değişmez)

ESIKLER = {
    "K1-a": {"kesinlik": 0.85, "wilson_alt": 0.80, "ad": 200, "paket": 5, "paket_ad": 10,
             "acik_alt": 0.70},
    "K1-b": {"pay": 0.05, "paket_payi": 0.5},
    "K1-c": {"kesinlik": 0.90, "n": 30, "nufus_payi": 0.02},
    "G1-a": {"kesinlik": 0.85},
    "G1-b": {"kesinlik": 0.90, "wilson_alt": 0.85, "ad": 50},
    "Ö-a": {"kesinlik": 0.85},
}


def _kes(k_: int, n_: int) -> Optional[float]:
    return k_ / n_ if n_ else None


def hukum_k1a(birim: dict[str, dict[str, int]], e: dict[str, Any] = ESIKLER["K1-a"]) -> dict[str, Any]:
    t = topla(birim)
    o = oran(t["kahin_dogru"], t["kahin_ad"])
    paket10 = sum(1 for c in birim.values() if c.get("kahin_ad", 0) >= e["paket_ad"])
    kes = _kes(t["kahin_dogru"], t["kahin_ad"])
    tuttu = (kes is not None and kes >= e["kesinlik"] and o["alt"] >= e["wilson_alt"]
             and t["kahin_ad"] >= e["ad"] and paket10 >= e["paket"])
    if tuttu:
        karar = "ÖK-4b açılır"
    elif o["alt"] is None:
        karar = "veri yok"
    elif o["alt"] >= e["wilson_alt"]:
        # kesinlik şartları tuttu, hacim şartı (ad sayısı / paket) tutmadı: planın üç kolunda yok
        karar = "hacim şartı tutmadı: ÖK-4b kapalı kalır (yeniden ön kayıt ana oturumun kararı)"
    elif o["alt"] >= e["acik_alt"]:
        karar = "K1 yalnız 'ek yüzey biçimi + tablo türü' kısıtlarıyla yeniden ön kayıt"
    else:
        karar = "K1 ad kanalı olarak bırakılır (kanıt satırı kalır)"
    return {"oran": o, "paket_10_ad": paket10, "tuttu": tuttu, "karar": karar}


def hukum_k1b(cift_birim: dict[str, dict[str, int]], e: dict[str, Any] = ESIKLER["K1-b"]) -> dict[str, Any]:
    paylar = {b: _kes(c.get("VC_var", 0), c.get("nufus", 0)) for b, c in cift_birim.items()}
    tanimli = {b: p for b, p in paylar.items() if p is not None}
    gecen = sum(1 for p in tanimli.values() if p >= e["pay"])
    tuttu = bool(tanimli) and gecen >= e["paket_payi"] * len(tanimli)
    return {"paket": len(tanimli), "esigi_gecen": gecen, "tuttu": tuttu,
            "paylar": {b: round(p, 6) for b, p in tanimli.items()}}


def hukum_k1c(capa_a: dict[str, dict[str, int]], e: dict[str, Any] = ESIKLER["K1-c"]) -> dict[str, Any]:
    t = topla(capa_a)
    o = oran(t["dogru"], t["ad"])
    pay = _kes(t["ad"], t["nufus"])
    kucuk = pay is not None and pay < e["nufus_payi"]
    hukme = t["ad"] >= e["n"]
    kes = _kes(t["dogru"], t["ad"])
    if hukme:
        tuttu: Optional[bool] = kucuk and kes is not None and kes >= e["kesinlik"]
    else:
        tuttu = None         # n < 30: kesinlik hükme girmez; yalnız "küçük" beklentisi raporlanır
    return {"oran": o, "nufus_payi": pay, "kucuk": kucuk, "hukme_girer": hukme, "tuttu": tuttu}


def hukum_g1(g1_birim: dict[str, dict[str, int]]) -> dict[str, Any]:
    t = topla(g1_birim)
    a = oran(t["duz_dogru"], t["duz_ad"])
    b = oran(t["kapili_dogru"], t["kapili_ad"])
    ea, eb = ESIKLER["G1-a"], ESIKLER["G1-b"]
    ka, kb = _kes(t["duz_dogru"], t["duz_ad"]), _kes(t["kapili_dogru"], t["kapili_ad"])
    g1a = ka is not None and ka >= ea["kesinlik"]
    g1b = (kb is not None and kb >= eb["kesinlik"] and b["alt"] >= eb["wilson_alt"]
           and t["kapili_ad"] >= eb["ad"])
    return {"G1-a": {"oran": a, "tuttu": g1a}, "G1-b": {"oran": b, "tuttu": g1b,
            "karar": "ÖK-3 açılır" if g1b else "ÖK-3 açılmaz"}}


def hukum_oa(onek: dict[str, dict[str, int]], taraf: str, e: dict[str, Any] = ESIKLER["Ö-a"]) -> dict[str, Any]:
    c = onek.get(f"{taraf}|hepsi", {})
    o32 = oran(c.get("sandvic_32_dogru", 0), c.get("sandvic_32_karar", 0))
    o0 = oran(c.get("sandvic_0_dogru", 0), c.get("sandvic_0_karar", 0))
    k32 = _kes(o32["k"], o32["n"])
    tuttu = k32 is not None and k32 >= e["kesinlik"]
    return {"aralik_32": o32, "sinirsiz": o0, "tuttu": tuttu,
            "karar": "ÖK-6 açılır" if tuttu else "ÖK-6 açılmaz"}


# --------------------------------------------------------------------------------------------
# ÖK-V adım 6: GT bağ dizini + olgu önbelleği


def gt_bag_kur(v: Veri, nufus_kok: Path = NUFUS_KOK) -> dict[str, Any]:
    """``ks1_olc.gt_elf``'in değişmeden çalışması için bağ dizini (yalnız sembolik bağ; veri kopyası yok).

    ``gt_elf`` hata ayıklama dosyasını ``<indir>/x_*-dbgsym_*/usr/lib/debug/.build-id/xx/yy.debug`` diye
    arar ve anahtarı ``function_f1.read_elf_info`` verir. ÖK-V'de dosyalar ``x_<hata paketi>/`` altında.
    İki ELF'te (NUFUS.md §8 not 3) ``read_elf_info`` SystemTap notunu BuildID sanıyor; ölçüm bu yüzden
    ``_gnu_buildid_baglami`` içinde koşar ve bağ GNU BuildID'siyle kurulur. Her ölçülecek ELF için:
    GNU BuildID'ler (``tabaka_indir.elf_bilgisi``: ikili ve .debug) birbirine ve ``nufus.json``'a eşit
    olmalı. Döndürür: ELF sayısı, eşleşen, stapsdt sapması, hatalar (yalnız sayı ve iş anahtarı)."""
    f1 = kurallar()["V"].ks1()._f1()
    nk = _modul("ozkod_nufus_kur", OLCUM / "ozkod_nufus_kur.py")
    nufus = json.loads((nufus_kok / "nufus.json").read_text(encoding="utf-8"))
    taban = v.debian_indir / "x_ok5-dbgsym_bag" / "usr" / "lib" / "debug" / ".build-id"
    say: Counter = Counter()
    hatalar = []
    for is_ in nk.olculecek_isler(nufus_kok, nufus):
        say["elf"] += 1
        gercek_i = gnu_buildid(is_["girdi"])
        gercek_d = gnu_buildid(is_["debug"])
        if not (gercek_i and gercek_i == gercek_d == is_["build_id"]):
            hatalar.append({"anahtar": is_["anahtar"], "neden": "GNU BuildID eşleşmedi"})
            continue
        say["buildid_eslesti"] += 1
        if f1.read_elf_info(is_["girdi"])["build_id"] != gercek_i:
            say["stapsdt_sapmasi"] += 1
        anahtar = gercek_i
        bag = taban / anahtar[:2] / f"{anahtar[2:]}.debug"
        bag.parent.mkdir(parents=True, exist_ok=True)
        if bag.is_symlink() or bag.exists():
            if bag.resolve() != Path(is_["debug"]).resolve():
                hatalar.append({"anahtar": is_["anahtar"], "neden": "bağ anahtarı çakışıyor"})
                continue
        else:
            bag.symlink_to(Path(is_["debug"]).resolve())
        say["bag"] += 1
    v.mac_veri.mkdir(parents=True, exist_ok=True)
    (v.kosu_kok / "mac").mkdir(parents=True, exist_ok=True)   # ozkod_veri.elfler iki kökü de okur
    return {"sayac": dict(say), "hatalar": hatalar}


def _modul(ad: str, yol: Path):
    import importlib.util
    if ad in sys.modules:
        return sys.modules[ad]
    if str(yol.parent) not in sys.path:
        sys.path.insert(0, str(yol.parent))
    spec = importlib.util.spec_from_file_location(ad, yol)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[ad] = mod
    spec.loader.exec_module(mod)
    return mod


def onbellek_kur(v: Veri, gorunur: Iterable[str]) -> dict[str, Any]:
    """Görünür taraf(lar)ın her ikilisi için olgu önbelleği; hata olan ikili atlanır ve sayılır.
    Tutarlılık: ikili başına nüfus, GT fonksiyonu; havuzda nüfus > 0."""
    gorunur = tuple(gorunur)
    birim: dict[str, Counter] = defaultdict(Counter)
    atla: list[tuple[str, str]] = []
    hatalar = []
    with etkin(v, gorunur) as m:
        V = m["V"]
        k = V.ks1()
        hepsi = k.elfleri_topla(V.KOSU_KOKU / "mac", V.KOSU_KOKU / "debian")
        bitmis = V.urun().haritasizlari_isaretle(hepsi)
        sec = set(V.BIRIMLER)
        for e, e0 in zip(bitmis, hepsi):
            b = k.birim_anahtari(e)
            if b not in sec:
                continue
            c = birim[b]
            c["ikili"] += 1
            if e0.static is None:
                c["bitmemis"] += 1
                continue
            if e.static is None:
                c["harita_yok"] += 1
                continue
            if (b, e.ad) in V.AYNI_DOSYA_ATLA:
                c["atlandi"] += 1
                continue
            try:
                d = V.yukle(e)
            except Exception as ex:        # GT / ofset kanıtı kurulamadı: sayılır, ölçüme girmez
                c["hata"] += 1
                atla.append((b, e.ad))
                hatalar.append({"birim": b, "ikili": e.ad, "hata": type(ex).__name__})
                continue
            if d.get("cpp"):
                c["cpp"] += 1
                continue
            c["kuruldu"] += 1
            c["fonk"] += len(d["fonk"])
            c["gt_fonksiyon"] += len(d["gt_adlar"])
            c["nufus"] += len(d["nufus"])
            c["urun_ad"] += len(d["urun"])
            c["yuva"] += len(d["yuvalar"])
            c["nufus_sifir_ikili"] += not d["nufus"]
    return {"birim": {b: dict(c) for b, c in sorted(birim.items())}, "atla": atla, "hatalar": hatalar}


# --------------------------------------------------------------------------------------------
# Bütün sayım (bir taraf)


def tam_sayim(v: Veri, taraf: str, donusumler: tuple[str, ...]) -> dict[str, Any]:
    """``taraf`` = "kesif" | "sinama" (bağımsız nüfusta ayar | kör). Yalnız o taraf görünür."""
    t0 = time.time()
    out: dict[str, Any] = {"veri": v.ad, "taraf": v.taraf_adi[taraf], "betikler": betik_kunyesi(),
                           "donusumler": list(donusumler), "baslangic": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    with etkin(v, (taraf,)):
        out["cift"] = say_cift(taraf)
        out["k1"] = say_k1(taraf)
        out["k1_tekil"] = say_k1_tekil(taraf)
        out["belirtec"] = say_belirtec(taraf)
        out["k1_karakter"] = say_k1_karakter(taraf, donusumler)
        out["k1_capa"] = say_k1_capa(taraf)
        out["g1"] = say_g1(taraf)
        out["ozad"] = say_ozad(taraf)
        out["tavan"] = say_tavan(taraf)
    out["sure_sn"] = round(time.time() - t0, 1)
    return out


def hukumler(s: dict[str, Any], taraf: str) -> dict[str, Any]:
    return {"K1-a": hukum_k1a(s["k1"]["birim"]), "K1-b": hukum_k1b(s["cift"]["birim"]),
            "K1-c": hukum_k1c(s["k1_capa"]["A"]), **hukum_g1(s["g1"]), "Ö-a": hukum_oa(s["tavan"]["onek"], taraf)}


# --------------------------------------------------------------------------------------------
# Rapor (yalnız sayı ve paket adı)


def rapor(s: dict[str, Any], h: dict[str, Any], taraf: str) -> str:
    sat = [f"# ÖK-5 sayımı — veri: {s['veri']}, taraf: {s['taraf']} ({s['sure_sn']} sn)", ""]
    sat.append("## Hükümler")
    for ad, x in h.items():
        o = x.get("oran") or x.get("aralik_32")
        sat.append(f"- {ad}: {yuzde(o) if o else ''} → tuttu: {x.get('tuttu')} {x.get('karar', '')}")
    sat.append(f"- K1-a ≥ 10 adlı paket: {h['K1-a']['paket_10_ad']}; K1-b eşiği geçen paket: "
               f"{h['K1-b']['esigi_gecen']} / {h['K1-b']['paket']}; K1-c nüfus payı: {h['K1-c']['nufus_payi']}")
    sat.append("")
    sat.append("## Paket başına (K1 kâhin norm / karakter; V ∪ C erişimi; G1 düz / kapılı; kip A; sandviç ≤ 32)")
    sat.append("| paket | nüfus | V ∪ C | K1 ad | K1 doğru (norm) | K1 karakter | G1 düz ad / doğru | G1 kapılı ad / doğru | kip A ad / doğru | sandviç ≤ 32 doğru / karar |")
    sat.append("|---|---:|---:|---:|---:|---:|---|---|---|---|")
    birimler = sorted(set(s["cift"]["birim"]) | set(s["k1"]["birim"]))
    for b in birimler:
        c = s["cift"]["birim"].get(b, {})
        k1 = s["k1"]["birim"].get(b, {})
        g = s["g1"].get(b, {})
        ka = s["k1_capa"].get("A", {}).get(b, {})
        on = s["tavan"]["onek"].get(f"{b}|hepsi", {})
        sat.append(f"| {b} | {c.get('nufus', 0)} | {c.get('VC_var', 0)} | {k1.get('kahin_ad', 0)} | "
                   f"{k1.get('kahin_dogru', 0)} | {k1.get('kahin_karakter_dogru', 0)} | "
                   f"{g.get('duz_ad', 0)} / {g.get('duz_dogru', 0)} | {g.get('kapili_ad', 0)} / {g.get('kapili_dogru', 0)} | "
                   f"{ka.get('ad', 0)} / {ka.get('dogru', 0)} | {on.get('sandvic_32_dogru', 0)} / {on.get('sandvic_32_karar', 0)} |")
    return "\n".join(sat)


# --------------------------------------------------------------------------------------------
# Alt komutlar


def _veri(ad: str) -> Veri:
    if ad == "gelistirme":
        return gelistirme_verisi()
    atla_yolu = NUFUS_CIKTI / "atla.json"
    atla = [tuple(x) for x in json.loads(atla_yolu.read_text(encoding="utf-8"))] if atla_yolu.is_file() else []
    return nufus_verisi(atla=atla)


def _yaz(yol: Path, belge: Any) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(json.dumps(belge, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8")


def komut_esdeger(onbellek: str) -> int:
    """Geliştirme setinde araştırma betiklerinin sayılarını yeniden üret (ÖK-5 adım 2)."""
    cikti = D0_CIKTI / ("gelistirme_kopya" if onbellek == "kopya" else "gelistirme")
    v = gelistirme_verisi(cikti)
    if onbellek == "kopya":       # araştırma turunun önbelleğini (salt okur) kendi dizinimize kopyala
        import shutil
        for alt in ("onbellek", "onbellek_cagri", "onbellek_c_dizini"):
            hedef = cikti / alt
            if not hedef.exists():
                shutil.copytree(ARGE_ESKI / alt, hedef)
    sonuc: dict[str, Any] = {"onbellek": onbellek, "betikler": betik_kunyesi()}
    with etkin(v, ("kesif", "sinama")):
        for tr in ("kesif", "sinama"):
            t = topla(say_k1(tr)["birim"])
            sonuc[f"k1_{tr}"] = (t["kahin_ad"], t["kahin_dogru"])
            g = topla(say_g1(tr))
            sonuc[f"g1_{tr}"] = (g["duz_ad"], g["duz_dogru"])
        c = topla(say_cift("kesif")["birim"]) + topla(say_cift("sinama")["birim"])
        sonuc["vc_toplam"] = (c["nufus"], c["VC_var"])
        ka: Counter = Counter()
        kc: Counter = Counter()
        oz: Counter = Counter()
        for tr in ("kesif", "sinama"):
            cp = say_k1_capa(tr)
            ka.update(topla(cp["A"]))
            kc.update(topla(cp["C"]))
            oz.update(topla(say_ozad(tr)))
        sonuc["kip_a"] = (ka["ad"], ka["dogru"])
        sonuc["kip_c"] = (kc["ad"], kc["dogru"])
        sonuc["r1_harf"] = (oz["r1_tut"], oz["r1_harf_dogru"])
        on = say_tavan("hepsi")["onek"].get("hepsi|hepsi", {})
        sonuc["sandvic_32"] = (on.get("sandvic_32_karar"), on.get("sandvic_32_dogru"))
        sonuc["sandvic_0"] = (on.get("sandvic_0_karar"), on.get("sandvic_0_dogru"))
    sonuc["karsilastirma"] = {k_: {"beklenen": list(b), "bulunan": list(sonuc.get(k_, ())),
                                   "ayni": tuple(sonuc.get(k_, ())) == b} for k_, b in GELISTIRME_BEKLENEN.items()}
    _yaz(cikti / "esdeger.json", sonuc)
    for k_, x in sonuc["karsilastirma"].items():
        print(f"{k_:12s} beklenen {x['beklenen']} bulunan {x['bulunan']} {'AYNI' if x['ayni'] else 'FARKLI'}")
    return 0 if all(x["ayni"] for k_, x in sonuc["karsilastirma"].items() if k_.startswith("k1_")) else 1


def komut_kur(taraf: str) -> int:
    v = _veri("nufus")
    bag = gt_bag_kur(v)
    gorunur = ("kesif", "sinama") if taraf == "hepsi" else (TARAF_ESLEME[taraf],)
    kur_ = onbellek_kur(v, gorunur)
    atla_yolu = NUFUS_CIKTI / "atla.json"
    eski = [tuple(x) for x in json.loads(atla_yolu.read_text(encoding="utf-8"))] if atla_yolu.is_file() else []
    _yaz(atla_yolu, sorted(set(eski) | set(map(tuple, kur_["atla"]))))
    belge = {"taraf": taraf, "gt_bag": bag, "onbellek": kur_, "betikler": betik_kunyesi(),
             "zaman": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    _yaz(NUFUS_CIKTI / f"kur_{'ayar' if taraf == AYAR else 'kor' if taraf == KOR else 'hepsi'}.json", belge)
    print(f"GT bağı: {bag['sayac']}; bağ hatası {len(bag['hatalar'])}")
    print("| birim | ikili | kuruldu | hata | bitmemiş | harita yok | nüfus | GT fonksiyonu | nüfusu 0 ikili |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for b, c in kur_["birim"].items():
        print(f"| {b} | {c.get('ikili', 0)} | {c.get('kuruldu', 0)} | {c.get('hata', 0)} | {c.get('bitmemis', 0)} | "
              f"{c.get('harita_yok', 0)} | {c.get('nufus', 0)} | {c.get('gt_fonksiyon', 0)} | {c.get('nufus_sifir_ikili', 0)} |")
    print(f"hata türleri: {Counter(h['hata'] for h in kur_['hatalar'])}")
    return 0


def komut_ayar() -> int:
    """ÖK-5 adım 4: ayar tarafında yalnız G1 kapısı ve K1 karakter eki okunur."""
    v = _veri("nufus")
    with etkin(v, ("kesif",)):
        g = say_g1("kesif")
        kar = say_k1_karakter("kesif", tuple(DONUSUM_ADAYLARI))
    dondurulan = donusum_dondur(kar["donusum"])
    belge = {"taraf": AYAR, "g1": g, "k1_karakter": kar, "dondurulan_donusumler": list(dondurulan),
             "kapi": "KS-1 çapası ≥ 1 ya da __assert_fail / __assert_rtn içe aktarımı",
             "betikler": betik_kunyesi(), "zaman": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    _yaz(NUFUS_CIKTI / "ayar.json", belge)
    tg = topla(g)
    print(f"G1 düz: {yuzde(oran(tg['duz_dogru'], tg['duz_ad']))}; kapılı: {yuzde(oran(tg['kapili_dogru'], tg['kapili_ad']))}; "
          f"kapıdan geçen ikili {tg['kapidan_gecen_ikili']} / {tg['ikili']}")
    print("| paket | ikili | kapıdan geçen | KS-1 çapalı | assert | G1 düz ad / doğru | G1 kapılı ad / doğru |")
    print("|---|---:|---:|---:|---:|---|---|")
    for b, c in sorted(g.items()):
        print(f"| {b} | {c.get('ikili', 0)} | {c.get('kapidan_gecen_ikili', 0)} | {c.get('ks1_capali_ikili', 0)} | "
              f"{c.get('assert_ikili', 0)} | {c.get('duz_ad', 0)} / {c.get('duz_dogru', 0)} | "
              f"{c.get('kapili_ad', 0)} / {c.get('kapili_dogru', 0)} |")
    tk = topla(kar["birim"])
    print(f"K1 karakter (kâhin): ad {tk['ad']}, norm doğru {tk['norm_dogru']}, norm adın karakter eşitliği "
          f"{tk['norm_karakter']}, yüzey öğrenildi {tk['karakter_ogrenildi']}, karakter eşit {tk['karakter']}")
    for ad in DONUSUM_ADAYLARI:
        c = kar["donusum"].get(ad, {})
        print(f"  dönüşüm {ad:16s} ad {c.get('ad', 0):4d} karakter {c.get('karakter', 0):4d}")
    print(f"dondurulan dönüşümler: {list(dondurulan)}")
    return 0


def komut_kor() -> int:
    v = _veri("nufus")
    ayar = json.loads((NUFUS_CIKTI / "ayar.json").read_text(encoding="utf-8"))
    don = tuple(ayar["dondurulan_donusumler"])
    s = tam_sayim(v, "sinama", don)
    h = hukumler(s, "sinama")
    s["hukumler"] = h
    _yaz(NUFUS_CIKTI / "kor_sayim.json", s)
    r = rapor(s, h, "sinama")
    (NUFUS_CIKTI / "kor_sayim.md").write_text(r + "\n", encoding="utf-8")
    print(r)
    return 0


def komut_tek(olcu: str, veri: str, taraf: str) -> int:
    v = _veri(veri)
    tr = TARAF_ESLEME.get(taraf, taraf) if veri == "nufus" else taraf
    if veri == "nufus" and tr == "kesif" and olcu not in ("g1",):
        raise SystemExit("ayar tarafında yalnız G1 kapısı ve K1 karakter eki okunur (komut: ayar)")
    fn = {"cift": lambda: say_cift(tr), "k1": lambda: say_k1(tr), "k1-capa": lambda: say_k1_capa(tr),
          "ozad": lambda: say_ozad(tr), "g1": lambda: say_g1(tr), "tavan": lambda: say_tavan(tr)}[olcu]
    with etkin(v, (tr,)):
        s = fn()
    _yaz(v.cikti / f"{olcu.replace('-', '_')}_{tr}.json", s)
    print(json.dumps({"yazildi": str(v.cikti / f"{olcu.replace('-', '_')}_{tr}.json")}, ensure_ascii=False))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    alt = ap.add_subparsers(dest="komut", required=True)
    a = alt.add_parser("esdeger")
    a.add_argument("--onbellek", choices=("yeniden", "kopya"), default="yeniden")
    a = alt.add_parser("kur")
    a.add_argument("--taraf", choices=(AYAR, KOR, "hepsi"), required=True)
    alt.add_parser("ayar")
    alt.add_parser("kor")
    for ad in ("cift", "k1", "k1-capa", "ozad", "g1", "tavan"):
        a = alt.add_parser(ad)
        a.add_argument("--veri", choices=("gelistirme", "nufus"), default="gelistirme")
        a.add_argument("--taraf", required=True)
    a = alt.add_parser("hedef")
    a = alt.add_parser("dokum")
    ns = ap.parse_args(argv)
    if ns.komut == "esdeger":
        return komut_esdeger(ns.onbellek)
    if ns.komut == "kur":
        return komut_kur(ns.taraf)
    if ns.komut == "ayar":
        return komut_ayar()
    if ns.komut == "kor":
        return komut_kor()
    if ns.komut in ("cift", "k1", "k1-capa", "ozad", "g1", "tavan"):
        return komut_tek(ns.komut, ns.veri, ns.taraf)
    if ns.komut == "hedef":
        return komut_hedef()
    if ns.komut == "dokum":
        return komut_dokum()
    return 1


# --------------------------------------------------------------------------------------------
# İ-1/3: hedef setinde erişim (gösteri koşusu, Ollama arm64; salt okur, GT yok)

GOSTERI_CALISMA = GOSTERI / "ws" / "workspaces" / "Ollama" / "20261119_081103"
USTVERI = REPO / "scripts" / "arge" / "ustveri"
HEDEF_CIKTI = D0_CIKTI / "hedef"


@contextlib.contextmanager
def _gtsiz_erisim() -> Iterator[None]:
    """Erişim sayımı GT gerektirmez ve C++ kodu da sayar. Yalnız iki şey değişir, bağlamın içinde:
    ``ks1_olc.gt_mac`` boş GT döndürür (ad hükmü yok, nüfus boş) ve ``ks1_olc.cpp_ikili_mi`` (ölçüm
    nüfusunun C++ süzgeci) hayır der. Veri katmanının geri kalanı (``ozkod_veri.ikili_kur``) aynen."""
    k = kurallar()["V"].ks1()
    eski = (k.gt_mac, k.cpp_ikili_mi)
    k.gt_mac = lambda e, mac_veri: k.GtBirimi({}, set(), set(), {"gt": "yok (hedef erişimi)"})
    k.cpp_ikili_mi = lambda fonksiyonlar, platform_=None: False
    try:
        yield
    finally:
        k.gt_mac, k.cpp_ikili_mi = eski


def hedef_kok_kur(cikti: Path = HEDEF_CIKTI, calisma: Path = GOSTERI_CALISMA) -> tuple[Path, Path]:
    """``ks1_olc.mac_elfleri`` yerleşimi: ``<kök>/mac/Ollama/ws/workspaces/Ollama/<zaman>/`` altında
    ``static`` ve ``reconstructed`` gösteri koşusuna sembolik bağ; ``raw/target_info.json`` analiz edilen
    arm64 dilimini (``raw/Ollama_arm64``, Karadul'un çıkardığı) gösterir (N4 okuyucusu tek mimari ister)."""
    kok = cikti / "kok"
    z = kok / "mac" / "Ollama" / "ws" / "workspaces" / "Ollama" / calisma.name
    (z / "raw").mkdir(parents=True, exist_ok=True)
    (kok / "debian").mkdir(parents=True, exist_ok=True)
    for alt in ("static", "reconstructed"):
        if not (z / alt).is_symlink():
            (z / alt).symlink_to(calisma / alt)
    dilim = calisma / "raw" / "Ollama_arm64"
    asil = json.loads((calisma / "raw" / "target_info.json").read_text(encoding="utf-8"))
    (z / "raw" / "target_info.json").write_text(json.dumps({
        "path": str(dilim), "name": "Ollama", "file_hash": sha256_dosya(dilim),
        "kaynak_target_info": str(calisma / "raw" / "target_info.json"),
        "kaynak_file_hash": asil.get("file_hash"),
        "not": "OK5 hedef erişimi: analiz edilen arm64 dilimi (universal_slice.json 'selected')"},
        ensure_ascii=False, indent=1), encoding="utf-8")
    return kok, dilim


def go_kumeleri(fat: Path, dilim: str = "arm64") -> dict[str, set[int]]:
    """ÜST VERİ ``butce.py``'nin tanımları: nüfus = LC_FUNCTION_STARTS, Go = pclntab girişleri,
    ObjC = yöntem IMP'leri, sembol = metin bölümündeki tanımlı simgeler."""
    for p in (str(USTVERI),):
        if p not in sys.path:
            sys.path.insert(0, p)
    import macho as MO
    import go_pclntab as GP
    import objc_meta as OM
    m = MO.load(fat, dilim)
    go = {f.entry for f in GP.PclnTab(m).funcs() if f.name} if m.secs_named("__gopclntab") else set()
    fs = set(m.function_starts() or ())
    objc = set()
    if m.secs_named("__objc_classlist") or m.secs_named("__objc_catlist"):
        *_x, satirlar = OM.yontemler(m)
        objc = {s["imp"] for s in satirlar if s["imp"] and s["sinif"] and s["secici"]}
    tsec = {t.index for t in m.text_sections()}
    sembol = {s.value for s in m.defined_symbols() if s.n_sect in tsec}
    go_disi = fs - go
    return {"nufus": fs, "go": go & fs, "go_disi": go_disi, "kalan": go_disi - objc - sembol}


def komut_hedef() -> int:
    kok, dilim = hedef_kok_kur()
    v = Veri("hedef", kok, HEDEF_CIKTI / "indir_yok", HEDEF_CIKTI / "mac_yok", HEDEF_CIKTI,
             kesif=(), sinama=("mac/Ollama",), olgu=HEDEF_CIKTI / "olgu_bos.jsonl.gz")
    kume = go_kumeleri(GOSTERI / "girdi" / "Ollama")
    sonuc: dict[str, Any] = {"girdi_sha256": sha256_dosya(GOSTERI / "girdi" / "Ollama"),
                             "dilim_sha256": sha256_dosya(dilim), "betikler": betik_kunyesi(),
                             "kume": {k_: len(s) for k_, s in kume.items()}}
    with etkin(v, ("sinama",)) as m, _gtsiz_erisim():
        V, E, G, O, K = m["V"], m["E"], m["G"], m["O"], m["K"]
        d = next(V.hepsi(taraf_="sinama"))
        fonk = {a for a, f in d["fonk"].items() if not f["thunk"] and not f["dis"]}
        ad = E.adaylar(d)
        # K1-b'nin tanımı (``kayit_cifti.say``: V kaydı ya da C çağrı çifti; dizginin ad biçimi aranmaz)
        vc = {fa for fa, k_ in K.ikili_ciftleri(d).items() if k_["V"] or k_["C"]}
        g1 = G.g1(d)
        kapi = g1_kapisi(d)
        oz = [o for o in O.ozellikler("sinama")]
        oz_adres = {o["adres"] for o in oz}
        r1_adres = {o["adres"] for o in oz if O.kural_tut(o)}
        sonuc["ghidra_ic_fonksiyon"] = len(fonk)
        sonuc["g1_kapisi"] = kapi
        sonuc["ks1_capa"] = ks1_capa_sayisi(d)
        for kume_adi in ("nufus", "go_disi", "kalan", "go"):
            s = kume[kume_adi]
            ghidrada = s & set(d["fonk"])
            tur = Counter()
            for fa in ghidrada:
                for g_ in {g[0] for g, _s in ad.get(fa, ())}:
                    tur[g_] += 1
            sonuc[kume_adi] = {
                "fonksiyon": len(s), "ghidrada": len(ghidrada), "vc": len(ghidrada & vc),
                "kayit_cifti": len(ghidrada & set(ad)), "kayit_cifti_tur": dict(tur),
                "g1_duz": len(ghidrada & set(g1)), "g1_kapili": len(ghidrada & set(g1)) if kapi else 0,
                "oz_ad": len(ghidrada & oz_adres), "r1": len(ghidrada & r1_adres)}
    _yaz(HEDEF_CIKTI / "hedef.json", sonuc)
    print(f"Ollama arm64: nüfus {sonuc['kume']['nufus']}, Go {sonuc['kume']['go']}, Go dışı "
          f"{sonuc['kume']['go_disi']}, kalan {sonuc['kume']['kalan']}; Ghidra iç fonksiyon "
          f"{sonuc['ghidra_ic_fonksiyon']}; G1 kapısı {sonuc['g1_kapisi']} (KS-1 çapa {sonuc['ks1_capa']})")
    print("| küme | fonksiyon | Ghidra'da | V ∪ C (K1-b tanımı) | K1 aday grubu | tür | G1 düz | G1 kapılı | oz_ad | R1 |")
    print("|---|---:|---:|---:|---:|---|---:|---:|---:|---:|")
    for k_ in ("go_disi", "kalan", "go", "nufus"):
        x = sonuc[k_]
        print(f"| {k_} | {x['fonksiyon']} | {x['ghidrada']} | {x['vc']} | {x['kayit_cifti']} | {x['kayit_cifti_tur']} | "
              f"{x['g1_duz']} | {x['g1_kapili']} | {x['oz_ad']} | {x['r1']} |")
    return 0


# --------------------------------------------------------------------------------------------
# PLAN ÖK-5 adım 7: yanlışların dökümü (ölçümden ve OK5.md commit'inden SONRA; depoya girmez)

DOKUM_YOLU = NUFUS_KOK / "runs" / "ok5_dokum" / "yanlislar.json"


def komut_dokum() -> int:
    """Kör tarafta K1 (kâhin, norm), G1 (düz / kapılı) ve K1 kip A'nın yanlış adları: (paket, ikili,
    adres, GT adları, hesaplanan ad, kanal). Yalnız ``~/karadul_olcum/ozkod_nufus/runs/ok5_dokum/``
    altına yazılır; ekrana yalnız satır sayısı basılır. Ad düzensizliği / gerçek yanlış ayrımı yapılmaz."""
    v = _veri("nufus")
    satirlar = []
    with etkin(v, ("sinama",)) as m:
        V, K, E, G = m["V"], m["K"], m["E"], m["G"]
        k = V.ks1()
        for d in V.hepsi(taraf_="sinama"):
            ad = E.adaylar(d)
            gruplar = defaultdict(list)
            for fa, liste in ad.items():
                for grup, s in liste:
                    gruplar[grup].append((fa, s))
            kahin = {x: list(y) for x, y in d["gt_adlar"].items()}
            kaynak = _capa_kaynaklari(d)
            kapi = g1_kapisi(d)
            for fa in sorted(d["nufus"]):
                gt = d["gt_adlar"][fa]
                if fa in ad:
                    t, _ = E.tahmin(fa, ad[fa], gruplar, kahin, E.MIN_DESTEK)
                    if t is not None and not K.gt_esit(t, gt):
                        satirlar.append({"olcu": "K1_kahin", "birim": d["birim"], "ikili": d["ad"], "adres": fa,
                                         "gt": gt, "ad": t})
                    if fa not in kaynak["A"]:
                        t, _ = E.tahmin(fa, ad[fa], gruplar, kaynak["A"], E.MIN_DESTEK)
                        if t is not None and not K.gt_esit(t, gt):
                            satirlar.append({"olcu": "K1_kip_A", "birim": d["birim"], "ikili": d["ad"],
                                             "adres": fa, "gt": gt, "ad": t})
            for fa, s in G.g1(d).items():
                if fa in d["nufus"] and k.capa_degerlendir(s, d["gt_adlar"][fa], k.PLATFORM_DEBIAN)["durum"] != "dogru":
                    satirlar.append({"olcu": "G1_kapili" if kapi else "G1_duz", "birim": d["birim"], "ikili": d["ad"],
                                     "adres": fa, "gt": d["gt_adlar"][fa], "ad": s})
    DOKUM_YOLU.parent.mkdir(parents=True, exist_ok=True)
    _yaz(DOKUM_YOLU, {"zaman": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "satirlar": satirlar})
    print(f"yanlış dökümü: {len(satirlar)} satır ({Counter(s['olcu'] for s in satirlar)}) → {DOKUM_YOLU}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
