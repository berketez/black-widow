"""Büyük ikili kipi (ÖL-10): decompile edilecek fonksiyonların seçim kuralı (kural sürümü 1).

Kaynak: ``docs/arge/2026-11-19_mythos/olcek/OL10_TASARIM.md`` §2 (bağlayıcı). Modül saftır:
dosya okumaz, Ghidra'ya ve ``karadul.pipeline``'a bağlı değildir. Girdi ``SecimGirdisi``
(K1 çıktılarından ``karadul.core.tembel_girdi`` kurar), çıktı ``SecimSonucu``: sıralı
(adres, basamak, sınıf, anahtar) listesi, sayımlar ve sıranın sha256'sı.

Kural özeti (§2.2–§2.4):

- Sınıf (her fonksiyona tek değer): ``TASLAK`` (Ghidra ``is_thunk`` / ``is_external``),
  ``KENDI`` (Go ``kendi``; ObjC yöntemi), ``BAGIMLILIK`` (Go ``ucuncu_taraf``), ``STANDART``
  (Go ``standart`` / ``calisma_zamani`` / ``derleyici``), ``BILINMIYOR`` (geri kalan).
- Basamaklar sözlük sırasıyla: B0 istek → B1 giriş (E ve E'den en çok 2 adımda ulaşılanlar;
  genişleme ``STANDART`` / ``TASLAK`` fonksiyona girmez, onlardan geçmez; en çok 256) → B2
  kendi → B3 bilinmiyor + kanıt → B4a bilinmiyor, seçilenin çağırdığı → B4b bilinmiyor, kalan →
  B5 bağımlılık → B6 taslak. ``STANDART`` yalnız istekle (B0) ya da E üyesi olarak (B1) seçilir.
- kanıt(f) = f'nin başvurduğu farklı dizgi adresi sayısı + f'nin çağırdığı farklı ``TASLAK``
  fonksiyon sayısı (ikisi de küme boyutu).
- Adres karşılaştırması tam sayıyla; sıra yalnız anahtardan çıkar (girdinin sırası etkisizdir).

Kural metninin belirsiz noktalarında uygulanan okuma ön kayıtta yazılıdır
(``olcek/on_kayit_OL10A.md`` "Belirsiz kural noktalarında uygulanan okuma").
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from karadul.analyzers.ustveri import go_pclntab

# Kural sabitleri (§2.3). Başka dosya bu sayıları yazmaz, buradan içe aktarır.
KURAL_SURUMU = 1
GIRIS_DERINLIGI = 2
GIRIS_UST_SINIR = 256

# Sınıflar (§2.2).
SECIM_TASLAK = "TASLAK"
SECIM_KENDI = "KENDI"
SECIM_BAGIMLILIK = "BAGIMLILIK"
SECIM_STANDART = "STANDART"
SECIM_BILINMIYOR = "BILINMIYOR"
SECIM_SINIFLARI = (SECIM_TASLAK, SECIM_KENDI, SECIM_BAGIMLILIK, SECIM_STANDART, SECIM_BILINMIYOR)

# Go paket sınıfı → seçim sınıfı. ``paketsiz`` / ``adsiz`` eşlemede yok: ``BILINMIYOR``.
GO_SINIF_ESLEME: Mapping[str, str] = {
    go_pclntab.SINIF_KENDI: SECIM_KENDI,
    go_pclntab.SINIF_UCUNCU_TARAF: SECIM_BAGIMLILIK,
    go_pclntab.SINIF_STANDART: SECIM_STANDART,
    go_pclntab.SINIF_CALISMA_ZAMANI: SECIM_STANDART,
    go_pclntab.SINIF_DERLEYICI: SECIM_STANDART,
}
# IMP'si bu ikilide olan ObjC yöntemi.
OBJC_SINIFI = SECIM_KENDI

# Basamaklar (§2.3), sıra sözlük sırasıdır.
BASAMAK_ISTEK = "B0"
BASAMAK_GIRIS = "B1"
BASAMAK_KENDI = "B2"
BASAMAK_BILINMIYOR_KANITLI = "B3"
BASAMAK_BILINMIYOR_KOMSU = "B4a"
BASAMAK_BILINMIYOR_KALAN = "B4b"
BASAMAK_BAGIMLILIK = "B5"
BASAMAK_TASLAK = "B6"
BASAMAKLAR = (BASAMAK_ISTEK, BASAMAK_GIRIS, BASAMAK_KENDI, BASAMAK_BILINMIYOR_KANITLI,
              BASAMAK_BILINMIYOR_KOMSU, BASAMAK_BILINMIYOR_KALAN, BASAMAK_BAGIMLILIK,
              BASAMAK_TASLAK)
BASAMAK_ADLARI: Mapping[str, str] = {
    BASAMAK_ISTEK: "istek",
    BASAMAK_GIRIS: "giris",
    BASAMAK_KENDI: "kendi",
    BASAMAK_BILINMIYOR_KANITLI: "bilinmiyor_kanitli",
    BASAMAK_BILINMIYOR_KOMSU: "bilinmiyor_komsu",
    BASAMAK_BILINMIYOR_KALAN: "bilinmiyor_kalan",
    BASAMAK_BAGIMLILIK: "bagimlilik",
    BASAMAK_TASLAK: "taslak",
}

# Künyedeki ana modül durumu.
ANA_MODUL_BILINMIYOR = "bilinmiyor"
ANA_MODUL_BULUNDU = "bulundu"
ANA_MODUL_GO_YOK = "go_ust_verisi_yok"


def go_sinifi(go_sinif: str) -> str:
    """Go okuyucusunun paket sınıfı → seçim sınıfı (``paketsiz`` / ``adsiz`` → ``BILINMIYOR``)."""
    return GO_SINIF_ESLEME.get(go_sinif, SECIM_BILINMIYOR)


@dataclass(frozen=True)
class SecimGirdisi:
    """Seçim kuralının girdisi; bütün adresler tam sayıdır (Ghidra adres uzayında).

    - ``boyut``: fonksiyon adresi → gövde baytı; anahtar kümesi fonksiyon nüfusudur.
    - ``taslak``: ``is_thunk`` ya da ``is_external`` fonksiyonlar.
    - ``dizgiler``: fonksiyon → başvurduğu dizgi adresi kümesi.
    - ``cagrilan``: fonksiyon → çağırdığı fonksiyon kümesi.
    - ``giris``: giriş kümesi E (§2.3).
    - ``sinif``: taslak olmayan fonksiyonun üst veri sınıfı (``KENDI`` / ``BAGIMLILIK`` /
      ``STANDART`` / ``BILINMIYOR``); haritada olmayan ``BILINMIYOR`` sayılır.
    - ``ana_modul_bilinmiyor``: Go üst verisi var ama ana modül bulunamadı → ``BAGIMLILIK`` B2'de.
    - ``kunye``: girdiyi kuranın notları (karşılaştırmaya girmez).
    """

    boyut: Mapping[int, int]
    taslak: frozenset[int] = frozenset()
    dizgiler: Mapping[int, frozenset[int]] = field(default_factory=dict)
    cagrilan: Mapping[int, frozenset[int]] = field(default_factory=dict)
    giris: frozenset[int] = frozenset()
    sinif: Mapping[int, str] = field(default_factory=dict)
    ana_modul_bilinmiyor: bool = False
    kunye: Mapping[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class SecimOgesi:
    adres: int
    basamak: str
    sinif: str
    anahtar: tuple


@dataclass(frozen=True)
class SecimSonucu:
    """Sıralı seçim listesi ve künyesi (§2.6).

    ``sira`` kesimden sonraki listedir; ``tam_sha256`` kesimden önceki tam listenin, ``sha256``
    ``sira``'nın özetidir. ``secilmeyen`` kendiliğinden hiçbir basamağa girmeyen fonksiyonlardır
    (``STANDART``, istenmemiş ve E üyesi olmayan).
    """

    sira: tuple[SecimOgesi, ...]
    sinif_sayimi: Mapping[str, int]
    basamak_sayimi: Mapping[str, int]
    sha256: str
    tam_sha256: str
    tam_uzunluk: int
    secilmeyen: tuple[int, ...]
    istek_bulunamayan: tuple[int, ...]
    ana_modul: str
    ust_sinir: int = 0
    kural_surumu: int = KURAL_SURUMU

    def adresler(self) -> list[int]:
        return [o.adres for o in self.sira]

    def kunye(self) -> dict[str, Any]:
        """Koşu künyesine yazılan özet (JSON'a uygun)."""
        return {
            "kural_surumu": self.kural_surumu,
            "sinif_sayimi": dict(self.sinif_sayimi),
            "basamak_sayimi": dict(self.basamak_sayimi),
            "secili": len(self.sira),
            "tam_uzunluk": self.tam_uzunluk,
            "secilmeyen": len(self.secilmeyen),
            "istek_bulunamayan": [f"{a:x}" for a in self.istek_bulunamayan],
            "ust_sinir": self.ust_sinir,
            "ana_modul": self.ana_modul,
            "sha256": self.sha256,
            "tam_sha256": self.tam_sha256,
        }


def sira_ozeti(sira: Iterable[SecimOgesi]) -> str:
    """Sıranın sha256'sı: ``"<adres onaltılık> <basamak> <sınıf>"`` satırları ``\\n`` ile."""
    metin = "\n".join(f"{o.adres:x} {o.basamak} {o.sinif}" for o in sira)
    return hashlib.sha256(metin.encode("utf-8")).hexdigest()


def _basamak_sayimi(sira: Iterable[SecimOgesi]) -> dict[str, int]:
    sayim = {b: 0 for b in BASAMAKLAR}
    for o in sira:
        sayim[o.basamak] += 1
    return sayim


def siniflandir(girdi: SecimGirdisi) -> dict[int, str]:
    """Her fonksiyona tek sınıf: taslak önce, sonra üst veri haritası, yoksa ``BILINMIYOR``."""
    sonuc: dict[int, str] = {}
    for a in girdi.boyut:
        if a in girdi.taslak:
            sonuc[a] = SECIM_TASLAK
            continue
        s = girdi.sinif.get(a, SECIM_BILINMIYOR)
        if s not in SECIM_SINIFLARI or s == SECIM_TASLAK:
            raise ValueError(f"geçersiz sınıf {s!r} (adres {a:#x})")
        sonuc[a] = s
    return sonuc


def kanit_hesapla(girdi: SecimGirdisi) -> dict[int, int]:
    """kanıt(f) = |başvurulan dizgi adresleri| + |çağrılan ∩ TASLAK| (küme boyutları)."""
    taslak = girdi.taslak
    return {a: len(girdi.dizgiler.get(a, ())) + len(set(girdi.cagrilan.get(a, ())) & taslak)
            for a in girdi.boyut}


def _gecilebilir(sinif: str) -> bool:
    return sinif not in (SECIM_STANDART, SECIM_TASLAK)


def sec(girdi: SecimGirdisi, istek: Iterable[int] = ()) -> SecimSonucu:
    """Kural sürümü 1 ile tam sıralı listeyi kur (kesim yok; bkz. ``kes``)."""
    fonks = girdi.boyut
    sinif = siniflandir(girdi)
    kanit = kanit_hesapla(girdi)
    sira: list[SecimOgesi] = []
    gor: set[int] = set()

    def ekle(adres: int, basamak: str, anahtar: tuple) -> None:
        sira.append(SecimOgesi(adres, basamak, sinif[adres], anahtar))
        gor.add(adres)

    # B0: istek (verildiği sıra; yinelenen ilk konumunda; fonksiyon olmayan seçilmez).
    bulunamayan: list[int] = []
    for i, a in enumerate(istek):
        a = int(a)
        if a not in fonks:
            if a not in bulunamayan:
                bulunamayan.append(a)
            continue
        if a not in gor:
            ekle(a, BASAMAK_ISTEK, (i,))

    # B1: E + E'den çağrı grafiğinde en çok GIRIS_DERINLIGI adım; STANDART / TASLAK'a girmez,
    # onlardan geçmez. E üyesi sınıfına bakılmadan seçilir.
    derinlik: dict[int, int] = {a: 0 for a in girdi.giris if a in fonks}
    sinir = {a for a in derinlik if _gecilebilir(sinif[a])}
    for d in range(1, GIRIS_DERINLIGI + 1):
        yeni: set[int] = set()
        for a in sinir:
            for c in girdi.cagrilan.get(a, ()):
                if c in fonks and c not in derinlik and _gecilebilir(sinif[c]):
                    yeni.add(c)
        for c in yeni:
            derinlik[c] = d
        sinir = yeni
    b1 = sorted((a for a in derinlik if a not in gor), key=lambda a: (derinlik[a], a))
    for a in b1[:GIRIS_UST_SINIR]:
        ekle(a, BASAMAK_GIRIS, (derinlik[a], a))

    ana_bilinmiyor = bool(girdi.ana_modul_bilinmiyor)
    kendi_siniflari = {SECIM_KENDI, SECIM_BAGIMLILIK} if ana_bilinmiyor else {SECIM_KENDI}

    def kanitli_ekle(uyeler: Iterable[int], basamak: str) -> None:
        for a in sorted((a for a in uyeler if a not in gor), key=lambda a: (-kanit[a], a)):
            ekle(a, basamak, (-kanit[a], a))

    def adresli_ekle(uyeler: Iterable[int], basamak: str) -> None:
        for a in sorted(a for a in uyeler if a not in gor):
            ekle(a, basamak, (a,))

    kanitli_ekle((a for a in fonks if sinif[a] in kendi_siniflari), BASAMAK_KENDI)
    kanitli_ekle((a for a in fonks if sinif[a] == SECIM_BILINMIYOR and kanit[a] > 0),
                 BASAMAK_BILINMIYOR_KANITLI)
    # B4a: B0–B3'teki en az bir fonksiyonun çağırdığı.
    cagrilan_secili: set[int] = set()
    for a in gor:
        cagrilan_secili.update(girdi.cagrilan.get(a, ()))
    adresli_ekle((a for a in fonks if sinif[a] == SECIM_BILINMIYOR and kanit[a] == 0
                  and a in cagrilan_secili), BASAMAK_BILINMIYOR_KOMSU)
    adresli_ekle((a for a in fonks if sinif[a] == SECIM_BILINMIYOR and kanit[a] == 0),
                 BASAMAK_BILINMIYOR_KALAN)
    if not ana_bilinmiyor:
        kanitli_ekle((a for a in fonks if sinif[a] == SECIM_BAGIMLILIK), BASAMAK_BAGIMLILIK)
    adresli_ekle((a for a in fonks if sinif[a] == SECIM_TASLAK), BASAMAK_TASLAK)

    sinif_sayimi = {s: 0 for s in SECIM_SINIFLARI}
    for s in sinif.values():
        sinif_sayimi[s] += 1
    ozet = sira_ozeti(sira)
    if not girdi.kunye.get("go_eslenen"):
        ana_modul = ANA_MODUL_GO_YOK if not ana_bilinmiyor else ANA_MODUL_BILINMIYOR
    else:
        ana_modul = ANA_MODUL_BILINMIYOR if ana_bilinmiyor else ANA_MODUL_BULUNDU
    return SecimSonucu(
        sira=tuple(sira),
        sinif_sayimi=sinif_sayimi,
        basamak_sayimi=_basamak_sayimi(sira),
        sha256=ozet,
        tam_sha256=ozet,
        tam_uzunluk=len(sira),
        secilmeyen=tuple(sorted(a for a in fonks if a not in gor)),
        istek_bulunamayan=tuple(bulunamayan),
        ana_modul=ana_modul,
    )


def kes(sonuc: SecimSonucu, ust_sinir: int) -> SecimSonucu:
    """Sıralı listenin ilk ``ust_sinir`` öğesi (0 = sınır yok; §2.4 sınır 1)."""
    n = int(ust_sinir)
    if n < 0:
        raise ValueError("ust_sinir negatif olamaz")
    sira = sonuc.sira if n == 0 else sonuc.sira[:n]
    return SecimSonucu(
        sira=tuple(sira),
        sinif_sayimi=dict(sonuc.sinif_sayimi),
        basamak_sayimi=_basamak_sayimi(sira),
        sha256=sira_ozeti(sira),
        tam_sha256=sonuc.tam_sha256,
        tam_uzunluk=sonuc.tam_uzunluk,
        secilmeyen=sonuc.secilmeyen,
        istek_bulunamayan=sonuc.istek_bulunamayan,
        ana_modul=sonuc.ana_modul,
        ust_sinir=n,
        kural_surumu=sonuc.kural_surumu,
    )
