#!/usr/bin/env python3
"""N4 v2: "davranış satırı" ailelerinin GT'siz ateşleme sayımı.

Soru: adı verilemeyen fonksiyonların kaçında, fonksiyon kartına yazılabilecek ve koddan mekanik
olarak türeyen bir davranış satırı çıkıyor? Altı aile sayılır (tanımlar ``AILE_TANIMLARI``):

    A1 erişimci   (dar ``get`` / ``set`` / yüklem; yalnız çağrısız fonksiyon)
    A2 yaşam      (parametreyi bırakır; taze nesne döndürür; yeniden ayırır; alanı bırakıp sıfırlar)
    A3 alan       (bir parametre üstünden sabit ofsetli alan okuma / yazma)
    A4 global     (yazılabilir veri bölümünde bir adrese başvuru)
    A5 sözleşme   (evrensel iddia: yan etkisiz; yalnız parametre üstünden yazar; hiç dönmez)
    A6 sarma      (tek kütüphane hedefini saran ya da tek iç hedefe ileten fonksiyon)

ve dünkü tablo yuvası kanıtıyla (``tablo_yuvasi_sayim.py``) örtüşmeleri.

Ayrıca A5'in evrensel iddiaları, Ghidra decompiler'ının yüksek p-code'undan bağımsız türetimle
çapraz denetlenir (``pcode_capraz``; GT'siz). Bu denetim dünkü ``on_sayim.Fonksiyon``'da iki hata
buldu (giriş bloğu ve gövde dışına düşme); ``_KayitliFonksiyon`` ikisini düzeltir. Düzeltmeler
``--giris-duzeltmesi-kapali`` ile kapatılırsa dünkü ``on_sayim.json`` sayaçları aynen çıkar.

Bu betik KESİNLİK ÖLÇMEZ. GT, dbgsym, ``macho_score.json`` ve kilitli dizinler okunmaz. Okunanlar:

- saklı taban koşularının ``static/`` çıktıları (dünkü ``on_sayim.py`` ile; veri akışı oradadır;
  p-code çapraz denetimi için ``ghidra_output/pcode.jsonl``);
- aynı koşuların ``raw/<ikili>`` kopyası (yalnız tablo yuvası için, ``tablo_yuvasi_sayim.py`` ile);
- yeni ürün koşusunun (``--yeni-kosu``) ``reconstructed/src/naming_map.json`` → ``global``
  girişleri: bir ``FUN_`` anahtarının ürün adı alıp almadığı (ad dışarı yazılmaz).

Nüfuslar (ikili başına):

- ``jenerik``: dünkü ``isim_bekleyen`` (thunk ve dış olmayan, adı ``FUN_<onaltılık>`` olan
  fonksiyon);
- ``adsiz``: yeni ürün koşusu o ikilide bittiyse (``BITTI`` dosyası) ``jenerik`` eksi ürünün ad
  verdikleri; bitmediyse ``jenerik``'in tamamı (``kunye.yeni_kosu`` hangisinin kullanıldığını yazar).

Çıktıda fonksiyon adı, adres ve dizgi yoktur; yalnız sayılar vardır.

Kullanım (depo kökünden):
    python3 -I -B docs/arge/2026-11-11_n4_v2/on_sayim_v2.py --oz-sinama
    python3 -I -B docs/arge/2026-11-11_n4_v2/on_sayim_v2.py \
        --mac-kosu workspaces/olcum_mac/runs/ol7-c-b7faeac --debian-kosu ~/karadul_olcum/n1_debian13 \
        --yeni-kosu ~/karadul_olcum/runs/urun-yeni-93a2956 \
        --cikti docs/arge/2026-11-11_n4_v2/on_sayim_v2.json --md docs/arge/2026-11-11_n4_v2/on_sayim_v2.md
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import math
import multiprocessing
import platform
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

BURASI = Path(__file__).resolve().parent
DUNKU = BURASI.parent / "2026-11-10_n4"
sys.path.insert(0, str(DUNKU))

import on_sayim as OS  # noqa: E402  (dünkü ön sayım: veri akışı, nüfus, sayaçlar)
import tablo_yuvasi_sayim as TY  # noqa: E402  (dünkü tablo yuvası sayımı)

SAYIM_V2_SURUMU = 1    # bu betiğin kendi sürümü (on_sayim.py ve tablo_yuvasi_sayim.py sürümlerinden bağımsız)
PARALEL_AZAMI = 2          # görev kuralı: sayımda en çok 2 süreç
ORNEK_SAYISI = OS.ORNEK_SAYISI   # elle okuma için satır başına örnek (dünkü değer)

# ---------------------------------------------------------------------------------------------
# Tanımlar (bu sayıma özgü; ürün kuralı değildir)

AILELER = ("a1", "a2", "a3", "a4", "a5", "a6")
AILE_ADI = {"a1": "erişimci", "a2": "yaşam", "a3": "alan", "a4": "global", "a5": "sözleşme",
            "a6": "sarma", "ty": "tablo yuvası (dünkü kanıt)"}
# Alt satırlar; aile bayrağı (a1 … a6) aşağıdaki "ates" kümesindeki alt satırların birleşimidir.
ALT_SATIRLAR = {
    "a1": ("a1_al", "a1_yaz_tek", "a1_yaz_cok", "a1_yuklem"),
    "a2": ("a2_birakir", "a2_taze", "a2_buyutur", "a2_sokum"),
    "a3": ("a3_sifir_disi",),
    "a4": ("a4_degisken",),
    "a5": ("a5_ye_yerel", "a5_ye_gecisli", "a5_param_yazar", "a5_donmez"),
    "a6": ("a6_lib", "a6_ic"),
}
# Aile bayrağına girmeyen, yalnız raporlanan ek sayaçlar
EK_SAYACLAR = (
    "disasm_yok", "a1_al_saf", "a1g_yuklem_okur_cagrili",
    "a2_birakir_her_yolda", "a2g_alan_birak_genis", "a6g_ic_genis",
    "a3_var", "a3_iki_ofset", "a3_yazar",
    "a4_yazar", "a4_paylasimli", "a4_sabit_veri", "a4_sabit_veri_ddalsiz",
    "a5_sabit_bos", "a6_lib_ayirici", "a6_lib_birakici", "a6_sarma_kullanan",
    "ty_kayit", "ty_dizgili",
    # dünkü kuralların aynı nüfustaki ateşlemesi (karşılaştırma için; on_sayim._n4_fonksiyon)
    "v1_is", "v1_kalip1_is", "v1_init", "v1_kalip2_init", "v1_destroy", "v1_create_genis",
    "v1_kalip3_arg",
)
KESISIM_KUMELERI = AILELER + ("ty",)        # ty = ty_dizgili (kayıt dizgisi ad biçimli tablo kaydı)
PCODE_ANAHTARLARI = (
    "ye_yerel:n", "ye_yerel:uyusmaz", "ye_yerel:store", "ye_yerel:cagri",
    "ye_gecisli:n", "ye_gecisli:uyusmaz", "ye_gecisli:store", "ye_gecisli:callind",
    "param_yazar:n", "param_yazar:uyusmaz", "donmez:n", "donmez:uyusmaz",
    "pcode_kaydi_yok", "pcode_dosyasi_yok", "bozuk_satir")

# Yazılabilir veri (program değişkeni) ve salt okunur veri blokları: Ghidra bellek bloğu adıyla.
# GOT, PLT, metin, dizgi ve dış (EXTERNAL) bloklar hiçbir sınıfa girmez.
DEGISKEN_BLOKLARI = frozenset({".data", ".bss", ".tdata", ".tbss",
                               "__data", "__bss", "__common", "__DATA"})
SABIT_VERI_BLOKLARI = frozenset({".rodata", ".data.rel.ro", "__const", "__DATA_CONST"})

AILE_TANIMLARI = {
    "ortak": (
        "Zemin dünkü on_sayim.py: gömülü AArch64 disassembly üstünde fonksiyon içi ileri veri "
        "akışı (değerler p_i, k_c, b, r_pc, f_i,o, s, ?). 'Çağrı' = derleyici eki ve CRT dışındaki "
        "çağrı yeri (bl, blr, kuyruk çağrısı). 'Dış saklama' = tabanı sp/x29 olmayan ve taban "
        "değeri yığın adresi olmayan saklama. 'Dış yükleme' = aynı koşulla yükleme (blok giriş "
        "durumundan komut komut yeniden oynatılır). 'Yalın' = çağrı yok, dolaylı dallanma (br) "
        "yok, en az bir dönen çıkış var. U = dönen çıkışlardaki x0 değerlerinin birleşimi."),
    "a1_al": "Yalın; dış saklama yok; dönüş türü void değil; U'da tam bir f_i,o var, geri kalanı sabit",
    "a1_al_saf": "a1_al ve U = {f_i,o}",
    "a1_yaz_tek": (
        "Yalın; dış saklama var ve hepsinin taban değeri aynı tek {p_i}, ofseti sabit, saklanan "
        "değerler ⊆ {sabit, parametre}; dönüş void ya da U ⊆ parametreler; yazılan ofset sayısı 1"),
    "a1_yaz_cok": "a1_yaz_tek ile aynı, yazılan ayrı ofset sayısı ≥ 2",
    "a1_yuklem": (
        "Yalın; dış saklama yok; dönüş void değil; U ⊆ {0, 1, b} ve U sabit değil (b içeriyor "
        "ya da en az iki değer)"),
    "a1g_yuklem_okur_cagrili": (
        "Aileye girmez (gevşetme sayacı): a1_yuklem'in çağrı koşulu 'bütün çağrılar SALT_OKUR "
        "kütüphane listesine' biçiminde gevşetilmiş hâli; en az bir çağrı var"),
    "a2_birakir": "dünkü fire_destroy (ana yolda bir bırakıcı çağrısının x0'ı tam {p_i})",
    "a2_taze": "dünkü fire_create_genis ve create_buyutme değil",
    "a2_buyutur": "dünkü create_buyutme (döndürülen ayırıcı realloc/reallocarray)",
    "a2g_alan_birak_genis": (
        "Aileye girmez: dünkü kalip2 (bir bırakıcı çağrısının x0'ı {f_i,o}; p_i'nin en az iki "
        "ofsetine sabit/parametre yazılıyor; p_i'nin kendisi bırakılmıyor)"),
    "a2_sokum": (
        "a2g_alan_birak_genis ve fonksiyonun bütün çağrı yerleri bırakıcı (alanları bırakıp "
        "sıfırlamaktan başka çağrısı yok)"),
    "a2_birakir_her_yolda": "Aileye girmez: dünkü destroy_her_yolda (bırakmasız dönen yol yok)",
    "a3_var": "Taban değeri tam {p_i} ve ofseti sabit olan en az bir dış yükleme ya da dış saklama",
    "a3_sifir_disi": "a3_var ve ofsetlerden en az biri 0 değil (aile bayrağı)",
    "a3_iki_ofset": "Aynı p_i üstünden en az iki ayrı ofset (okunan ∪ yazılan)",
    "a3_yazar": "a3_var ve en az bir dış saklama",
    "a4_degisken": (
        "adrp(+add) / adr ile kurulan ya da adrp + bellek işleneniyle erişilen mutlak adreslerden "
        "en az biri DEGISKEN_BLOKLARI içinde (aile bayrağı). İzleme doğrusal: yazmaç yeniden "
        "yazılınca ya da çağrıda (x0-x18, x30) bilgi silinir; kontrol akışına bakılmaz"),
    "a4_yazar": "a4_degisken ve o adreslerden birine doğrudan saklama",
    "a4_paylasimli": (
        "a4_degisken ve adreslerden en az birine aynı ikilide başka bir iç fonksiyon da "
        "başvuruyor (tam adres eşitliği; aynı değişkenin başka alanına başvuru sayılmaz)"),
    "a4_sabit_veri": (
        "Adreslerden en az biri SABIT_VERI_BLOKLARI içinde ve bir Ghidra dizgisinin içinde değil"),
    "a4_sabit_veri_ddalsiz": "a4_sabit_veri ve fonksiyonda dolaylı dallanma (atlama tablosu) yok",
    "a5_ye_yerel": "Yan etkisiz, yerel kanıt: yalın ve dış saklama yok",
    "a5_ye_gecisli": (
        "Yan etkisiz, geçişli kanıt: en az bir çağrı var; dış saklama, dolaylı çağrı ve dolaylı "
        "dallanma yok; dönen çıkış var; her çağrı hedefi çözülüyor, kütüphane hedefleri ⊆ "
        "SALT_OKUR, iç hedeflerin hepsi yan etkisiz (çağrı grafında en büyük sabit nokta)"),
    "a5_param_yazar": (
        "Dönen çıkış var; dolaylı çağrı ve dolaylı dallanma yok; dış saklama var ve hepsinin "
        "taban değeri tam {p_i}, ofseti sabit; çağrı yok ya da bütün çağrı hedefleri yan etkisiz"),
    "a5_donmez": "Girişten dönen bir çıkışa ulaşılamıyor (dünkü tum_yollar_donmez)",
    "a5_sabit_bos": "a5_ye_yerel ve (U tek bir sabit ya da dönüş void ve dış yükleme yok)",
    "a6_lib": (
        "Dış saklama, dolaylı çağrı ve dolaylı dallanma yok; hata ailesi (dönmez, ileti, errno, "
        "dönmeyen iç fonksiyon) dışındaki çağrı yerlerinin hepsi aynı tek kütüphane adına "
        "iniyor; o çağrıların her birinde x0-x7'den en az biri bir parametre içeriyor; dönüş "
        "void ya da U ⊆ o çağrıların dönüşü ∪ sabitler"),
    "a6g_ic_genis": (
        "Aileye girmez: a6_lib ile aynı koşullar, hedef tek bir iç fonksiyon (kendisi ve dönmeyen "
        "iç fonksiyon değil)"),
    "a6_ic": (
        "a6g_ic_genis ve hata ailesi dışında tam bir çağrı yeri var, kontrol akışında döngü yok, "
        "dönüş void ya da çıkışlardan en az biri o çağrının dönüşünü taşıyor (ince iletici)"),
    "a6_sarma_kullanan": (
        "Aileye girmez: çağrı hedeflerinden biri a6_lib ateşleyen bir iç fonksiyon"),
    "ty_kayit": "dünkü 'tablo kaydında' (tablo_yuvasi_sayim.py)",
    "ty_dizgili": (
        "dünkü gevşek ad kanıtı: tablo kaydında ve kayıt dizgilerinden biri tanımlayıcı ya da "
        "kısa ad biçiminde ('bugün ad almıyor' koşulu burada nüfus tanımıyla uygulanır)"),
    "demet": (
        "A5'in bilgi ölçüsü için (dönüş türü, yazma türü, çağrı türü) üçlüsü; ikili içinde "
        "dağılımın entropisi ve en sık üçlünün payı raporlanır"),
}

_ASIL_FONKSIYON = OS.Fonksiyon
_ASIL_N4_ELF = OS.n4_elf
_ASIL_N4_FONKSIYON = OS._n4_fonksiyon


class _Yakala:
    """on_sayim.elf_say'in ara verisi: Fonksiyon nesneleri, n4_elf argümanları, kapanışlar."""

    def __init__(self):
        self.sifirla()

    def sifirla(self):
        self.fonk: dict[int, OS.Fonksiyon] = {}
        self.n4: dict | None = None
        self.kapanis: dict | None = None
        self.olcu: dict[int, set[str]] = {}
        self.duzeltme: Counter = Counter()
        self._listelenen: set[int] | None = None

    def listelenen(self) -> set[int]:
        """İkilide herhangi bir fonksiyonun gömülü disassembly'sinde geçen komut adresleri."""
        if self._listelenen is None:
            self._listelenen = {pc for k in self.n4["kod"].values() for pc, _, _ in k}
        return self._listelenen


YAKALA = _Yakala()


GIRIS_DUZELTMESI = True    # --giris-duzeltmesi-kapali ile kapanır (dünkü sayıları yeniden üretmek için)


def yastiklari_ayikla(adres: int, komutlar: list[tuple[int, str, str]], f: dict) -> tuple[list, int]:
    """BTI'li PLT girişlerinin iniş yastıklarını gövdeden çıkarır.

    Debian arm64 ELF'lerinde PLT girişi ``bti c`` ile başlar; Ghidra thunk fonksiyonunu yastıktan
    SONRAKİ adreste kuruyor ve yastığı, o girişe kuyruk çağrısı yapan fonksiyonun gövdesine
    katıyor. Gömülü disassembly adrese göre sıralı olduğu için yastık listenin başına düşer.
    Dünkü ``on_sayim.Fonksiyon`` listedeki ilk komutu giriş sayar; böyle fonksiyonlarda akış
    yastıktan başlar, gövde sonundan düşer ve fonksiyon "hiç dönmez" görünür, kuyruk çağrısı da
    çağrı sayılmaz (bu sayımın p-code çapraz denetimi buldu).

    Düzeltme: girişi içermeyen, yalnız ``bti`` komutlarından oluşan ve bitişi bilinen bir fonksiyon
    girişi olan bitişik parçalar listeden atılır; o parçaya giden dallanmaların hedefi parçanın
    bitişine (thunk girişine) çevrilir. Dönüş: (yeni liste, atılan yastık sayısı).
    """
    parcalar: list[list[tuple[int, str, str]]] = []
    for kmt in komutlar:
        if parcalar and kmt[0] == parcalar[-1][-1][0] + 4:
            parcalar[-1].append(kmt)
        else:
            parcalar.append([kmt])
    yastik = {p[0][0]: p[-1][0] + 4 for p in parcalar
              if all(pc != adres for pc, _, _ in p) and all(mn == "bti" for _, mn, _ in p)
              and (p[-1][0] + 4) in f}
    if not yastik:
        return komutlar, 0
    out = []
    for p in parcalar:
        if p[0][0] in yastik:
            continue
        for pc, mn, isl in p:
            m = OS._HEDEF.search(isl)
            if m and int(m.group(1), 16) in yastik and (mn in ("b", "bl") or OS._KOSULLU.match(mn)):
                isl = isl[:m.start()] + f"0x{yastik[int(m.group(1), 16)]:x}"
            out.append((pc, mn, isl))
    return out, len(yastik)


class _KayitliFonksiyon(_ASIL_FONKSIYON):
    """on_sayim.Fonksiyon + iki düzeltme (``GIRIS_DUZELTMESI`` açıkken):

    1. Giriş: iniş yastıkları atılır (``yastiklari_ayikla``); giriş yine de listenin ilk komutu
       değilse akış ``self.adres`` bloğundan başlatılır.
    2. Gövde dışına düşme: bir komuttan sonraki adres (pc + 4) bu fonksiyonun listesinde yoksa ama
       başka bir fonksiyonun girişi ya da başka bir fonksiyonun listesindeyse, akış o koda düşer
       (paylaşılan kuyruk). Dünkü ``on_sayim`` bu yolu yok sayıyordu: fonksiyon olduğundan kısa
       ve çağrısız görünüyordu. Burada düşme, hedefi pc + 4 olan bir kuyruk çağrısı gibi kaydedilir
       (çağrı olayı ve dönen çıkış; hedef dönmeyen bir fonksiyonsa dönmeyen son).
    """

    def __init__(self, adres, komutlar):
        if GIRIS_DUZELTMESI:
            if komutlar and komutlar[0][0] != adres:
                YAKALA.duzeltme["giris_ilk_komut_degil"] += 1
            komutlar, n = yastiklari_ayikla(adres, komutlar, YAKALA.n4["f"] if YAKALA.n4 else {})
            YAKALA.duzeltme["yastigi_atilan_fonksiyon"] += int(n > 0)
        super().__init__(adres, komutlar)
        YAKALA.fonk[adres] = self
        self.dusen: dict[int, int] = {}          # blok başı → düşülen adres (cfg'de kurulur)
        self.dusen_aday: dict[int, int] = {}     # komut adresi → pc + 4
        if GIRIS_DUZELTMESI and YAKALA.n4:
            f, listelenen = YAKALA.n4["f"], YAKALA.listelenen()
            for pc, mn, ops in self.k:
                t = pc + 4
                if t in self.govde or OS.dal_turu(mn, ops)[0] in ("atla", "don", "ddal", "tuzak"):
                    continue
                if t in f or t in listelenen:
                    self.dusen_aday[pc] = t
            YAKALA.duzeltme["dusme_adayi_fonksiyon"] += int(bool(self.dusen_aday))

    def hedefler(self) -> set[int]:
        return super().hedefler() | set(self.dusen_aday.values())

    def cfg(self, donmez_mi) -> None:
        super().cfg(donmez_mi)
        self.dusen = {}
        if not GIRIS_DUZELTMESI:
            return
        for b, (_i0, i1) in self.blok.items():
            pc, mn, ops = self.k[i1 - 1]
            hedef = self.dusen_aday.get(pc)
            if hedef is None:
                continue
            tur, t = OS.dal_turu(mn, ops)
            if tur == "cagri" and donmez_mi(t) is not None:
                continue                          # çağrı dönmüyor: düşme yok
            self.dusen[b] = hedef
            dm = donmez_mi(hedef)
            if not dm:
                self.donen.add(b)
                self.son_tur.pop(b, None)
                self.donmez_hedef.pop(b, None)
            elif not self.ardil[b]:
                self.son_tur[b] = f"donmez_{dm}"
                self.donmez_hedef[b] = hedef
        if self.dusen:
            self.ana = self.geri_erisilen(set(self.donen)) if self.donen else set()
        # giriş, listedeki en küçük adres değilse (gövdenin girişten önce duran parçası varsa)
        # akış yine de girişten başlamalı: on_sayim girişi baslar[0] olarak okur
        if self.baslar[0] != self.adres and self.adres in self.blok:
            self.baslar = [self.adres] + [b for b in self.baslar if b != self.adres]

    def _blok_isle(self, b, d, donmez_mi, kayit, bas=0, son=None, cikis_listesi=None):
        d = super()._blok_isle(b, d, donmez_mi, kayit, bas=bas, son=son, cikis_listesi=cikis_listesi)
        hedef = self.dusen.get(b)
        if hedef is not None:
            i0, i1 = self.blok[b]
            if son is None or i0 + son >= i1:
                if kayit is not None:
                    self.cagrilar.append((hedef, "kuyruk", hedef,
                                          tuple(d.oku(f"x{n}") for n in range(8)), kayit))
                cikis = self.cikislar if kayit is not None else cikis_listesi
                if cikis is not None and not donmez_mi(hedef):
                    cikis.append((hedef, "kuyruk", OS.kume(("r", hedef)), b))
        return d


def _n4_elf(f, kod, meta, coz, aile, uyeler, sinif, cagiran_sayisi, n_komut, yazar):
    YAKALA.n4 = {"f": f, "kod": kod, "meta": meta, "coz": coz, "aile": aile, "uyeler": uyeler,
                 "sinif": sinif, "cagiran_sayisi": cagiran_sayisi, "n_komut": n_komut}
    return _ASIL_N4_ELF(f, kod, meta, coz, aile, uyeler, sinif=sinif,
                        cagiran_sayisi=cagiran_sayisi, n_komut=n_komut, yazar=yazar)


def _n4_fonksiyon(fn, meta, yazar, anlamli_cagrilar, ayirici_mi, ayirici_adlari, birakici_mi,
                  bilgi, fk1_free, fk1_dar, fk1_genis, donmez_ic, donmez_mi):
    out = _ASIL_N4_FONKSIYON(fn, meta, yazar, anlamli_cagrilar, ayirici_mi, ayirici_adlari,
                             birakici_mi, bilgi, fk1_free, fk1_dar, fk1_genis, donmez_ic, donmez_mi)
    YAKALA.olcu[fn.adres] = out
    if YAKALA.kapanis is None:
        YAKALA.kapanis = {"anlamli_cagrilar": anlamli_cagrilar, "bilgi": bilgi,
                          "birakici_mi": birakici_mi, "donmez_ic": donmez_ic,
                          "donmez_mi": donmez_mi}
    return out


def kancalari_kur() -> None:
    """on_sayim'in üç adını sarar; elf_say bunları modül sözlüğünden çağırdığı için yeterlidir."""
    OS.Fonksiyon = _KayitliFonksiyon
    OS.n4_elf = _n4_elf
    OS._n4_fonksiyon = _n4_fonksiyon


# ---------------------------------------------------------------------------------------------
# Fonksiyon başına olgular


def yigin_mi(taban: str | None, taban_degeri: frozenset) -> bool:
    return taban in OS._YIGIN_TABANI or taban_degeri == OS.YIGIN


def dis_yuklemeler(fn, donmez_mi) -> list[tuple]:
    """(pc, taban, taban değeri, ofset) — yığın dışı yüklemeler; blok giriş durumundan komut komut."""
    out = []
    for b in fn.baslar:
        if b not in fn.ic_durum:
            continue
        i0, i1 = fn.blok[b]
        d = fn.ic_durum[b].kopya()
        for j in range(i1 - i0):
            pc, mn, ops = fn.k[i0 + j]
            if mn.startswith("ld") and not mn.startswith(OS._RMW):
                bl = OS.bellek(ops)
                if bl is not None:
                    _i, taban, ofs, _geri = bl
                    tv = d.oku(taban)
                    if not yigin_mi(taban, tv):
                        out.append((pc, taban, tv, ofs))
            d = fn._blok_isle(b, d, donmez_mi, None, bas=j, son=j + 1)
    return out


def temel_olgu(fn, kap: dict) -> dict:
    """Çağrı, saklama ve dönüş olguları (yükleme yok; bütün iç fonksiyonlar için hesaplanır)."""
    cs = kap["anlamli_cagrilar"](fn)
    donusler = [c[2] for c in fn.cikislar]
    return {
        "cs": cs,
        "dolayli": any(c[1] == "blr" for c in cs),
        "ddal": any(OS.dal_turu(mn, ops)[0] == "ddal" for _, mn, ops in fn.k),
        "doner": fn.donen_cikis_erisilir(),
        "donusler": donusler,
        "U": frozenset().union(*donusler) if donusler else frozenset(),
        "dis_sak": [s for s in fn.saklamalar if not yigin_mi(s[1], s[2])],
    }


def hedef_bilgileri(o: dict, bilgi) -> list | None:
    """Her çağrı yeri için (kütüphane adları, iç hedefler); biri çözülemiyorsa None."""
    out = []
    for c in o["cs"]:
        h = bilgi(c[2])
        if h is None or h[2] or not (h[0] or h[1]):
            return None
        out.append(h)
    return out


def yan_etkisiz_kumesi(olgular: dict[int, dict], bilgi) -> set[int]:
    """Çağrı grafında en büyük sabit nokta: dış saklama yok, dolaylı çağrı/dallanma yok, dönüyor,
    kütüphane hedefleri ⊆ SALT_OKUR, iç hedefler de kümede."""
    bagim: dict[int, set[int]] = {}
    for a, o in olgular.items():
        if o["dis_sak"] or o["dolayli"] or o["ddal"] or not o["doner"]:
            continue
        hs = hedef_bilgileri(o, bilgi)
        if hs is None or any(not (h[0] <= OS.SALT_OKUR) for h in hs):
            continue
        bagim[a] = set().union(*(h[1] for h in hs)) if hs else set()
    degisti = True
    while degisti:
        degisti = False
        for a in sorted(bagim):
            if not bagim[a] <= bagim.keys():
                del bagim[a]
                degisti = True
    return set(bagim)


_GLOBAL_YUKLEME = ("ld",)


def global_basvurulari(komutlar: list[tuple[int, str, str]]) -> dict[int, set[str]]:
    """Mutlak adres → {'al', 'oku', 'yaz'}. Doğrusal izleme (bkz. AILE_TANIMLARI['a4_degisken'])."""
    yz: dict[str, int] = {}
    out: dict[int, set[str]] = {}
    for _pc, mn, isl in komutlar:
        ops = OS.isleneler(isl)
        tur, _t = OS.dal_turu(mn, ops)
        if tur in ("cagri", "dcagri"):
            for n in list(range(19)) + [30]:
                yz.pop(f"x{n}", None)
            continue
        if tur != "yok":
            continue
        hedef = OS.yazmac(ops[0]) if ops else None
        if mn in ("adrp", "adr") and len(ops) == 2:
            v = OS.sayi(ops[1])
            yz.pop(hedef, None)
            if hedef and v is not None:
                yz[hedef] = v
                if mn == "adr":
                    out.setdefault(v, set()).add("al")
            continue
        if mn == "add" and len(ops) == 3 and ops[2].strip().startswith("#"):
            kaynak, c = OS.yazmac(ops[1]), OS.sayi(ops[2])
            v = yz[kaynak] + c if kaynak in yz and c is not None else None
            yz.pop(hedef, None)
            if hedef and v is not None:
                yz[hedef] = v
                out.setdefault(v, set()).add("al")
            continue
        if mn == "mov" and len(ops) == 2:
            v = yz.get(OS.yazmac(ops[1]))
            yz.pop(hedef, None)
            if hedef and v is not None:
                yz[hedef] = v
            continue
        saklama = mn.startswith(OS._YAZMA)
        if saklama or (mn.startswith(_GLOBAL_YUKLEME) and not mn.startswith(OS._RMW)):
            bl = OS.bellek(ops)
            if bl is None:
                if not saklama:
                    yz.pop(hedef, None)
                continue
            i, taban, ofs, geri = bl
            if taban in yz and ofs is not None:
                out.setdefault(yz[taban] + ofs, set()).add("yaz" if saklama else "oku")
            if not saklama:
                for h in ops[:i]:
                    yz.pop(OS.yazmac(h), None)
            elif mn.startswith(OS._DURUMLU_SAKLAMA) and ops:
                yz.pop(OS.yazmac(ops[0]), None)
            if geri:
                yz.pop(taban, None)
            continue
        if mn in OS._YAZMAYAN:
            continue
        yz.pop(hedef, None)
    return out


class Bloklar:
    """Ghidra bellek blokları ve dizgi aralıkları: bir adresin sınıfı."""

    def __init__(self, static_dir: Path):
        bilgi = json.loads((static_dir / "ghidra_combined_results.json").read_text(encoding="utf-8"))
        self.araliklar = []
        for b in bilgi["program_info"].get("memory_blocks") or []:
            bas, son = OS.onaltilik(b.get("start", "")), OS.onaltilik(b.get("end", ""))
            if bas is not None and son is not None:
                self.araliklar.append((bas, son, str(b.get("name") or "")))
        self.araliklar.sort()
        self.baslar = [a[0] for a in self.araliklar]
        dizgiler = json.loads((static_dir / "ghidra_strings.json").read_text(encoding="utf-8"))
        self.dizgi = sorted((a, a + int(d.get("length") or 0)) for d in dizgiler.get("strings", [])
                            for a in [OS.onaltilik(d.get("address", ""))] if a is not None)
        self.dizgi_baslari = [d[0] for d in self.dizgi]

    def sinif(self, adres: int) -> str | None:
        k = bisect.bisect_right(self.baslar, adres) - 1
        if k < 0 or adres > self.araliklar[k][1]:
            return None
        ad = self.araliklar[k][2]
        if ad in DEGISKEN_BLOKLARI:
            return "degisken"
        if ad in SABIT_VERI_BLOKLARI:
            j = bisect.bisect_right(self.dizgi_baslari, adres) - 1
            if j >= 0 and adres < self.dizgi[j][1]:
                return None
            return "sabit"
        return None


def dongu_var(fn) -> bool:
    """Girişten ulaşılan bloklarda çevrim var mı (derinlik öncelikli arama, geri kenar)."""
    kok = fn.baslar[0]
    renk = {kok: 1}
    yigin = [(kok, iter(fn.ardil[kok]))]
    while yigin:
        b, it = yigin[-1]
        for t in it:
            if renk.get(t) == 1:
                return True
            if t not in renk:
                renk[t] = 1
                yigin.append((t, iter(fn.ardil[t])))
                break
        else:
            renk[b] = 2
            yigin.pop()
    return False


def donus_turu(o: dict, void: bool) -> str:
    if not o["doner"]:
        return "donmez"
    if void:
        return "yok"
    U = o["U"]
    turler = {d[0] for d in U}
    if not U or "?" in turler or o["ddal"]:
        return "bilinmez"
    if turler == {"k"} and len(U) == 1:
        return "sabit"
    if U <= OS.MANTIKSAL:
        return "mantiksal"
    if turler == {"k"}:
        return "sabit_kumesi"
    if turler == {"p"}:
        return "param"
    if "f" in turler and turler <= {"f", "k"}:
        return "alan"
    if "r" in turler and turler <= {"r", "k"}:
        return "cagri_sonucu"
    return "karisik"


def satirlar(a: int, fn, meta: dict, o: dict, kap: dict, v1: set[str], ye: set[int],
             sarmalar: set[int], aile: str) -> tuple[set[str], str]:
    """Bir fonksiyonun ateşleyen satırları (a4 ve ty hariç) ve A5 üçlüsü."""
    out: set[str] = set()
    bilgi = kap["bilgi"]
    cs, U, dis_sak = o["cs"], o["U"], o["dis_sak"]
    void = meta.get("donus") == "void"
    yuk = dis_yuklemeler(fn, kap["donmez_mi"])
    yalin = not cs and not o["ddal"] and o["doner"] and bool(o["donusler"])

    # yazılan ve okunan parametre alanları
    okunan: dict[int, set[int]] = defaultdict(set)
    yazilan: dict[int, set[int]] = defaultdict(set)
    for _pc, _t, tv, ofs in yuk:
        p = OS.tek_param(tv)
        if p is not None and ofs is not None:
            okunan[p].add(ofs)
    for _pc, _t, tv, ofs, gen, degerler, _b in dis_sak:
        p = OS.tek_param(tv)
        if p is not None and ofs is not None:
            for k in range(max(1, len(degerler))):
                yazilan[p].add(ofs + k * gen)
    param_saklama = bool(dis_sak) and all(
        OS.tek_param(s[2]) is not None and s[3] is not None for s in dis_sak)

    # A1 erişimci
    if yalin and not dis_sak and not void:
        alanlar = {d for d in U if d[0] == "f"}
        if len(alanlar) == 1 and all(d[0] in ("f", "k") for d in U):
            out.add("a1_al")
            if len(U) == 1:
                out.add("a1_al_saf")
        elif U <= OS.MANTIKSAL and (("b",) in U or len(U) >= 2):
            out.add("a1_yuklem")
    if yalin and param_saklama and len({OS.tek_param(s[2]) for s in dis_sak}) == 1:
        degerler_tamam = all(s[5] and all(v and all(d[0] in ("k", "p") for d in v) for v in s[5])
                             for s in dis_sak)
        donus_tamam = void or (bool(U) and all(d[0] == "p" for d in U))
        if degerler_tamam and donus_tamam:
            i = OS.tek_param(dis_sak[0][2])
            out.add("a1_yaz_tek" if len(yazilan.get(i, ())) == 1 else "a1_yaz_cok")
    # gevşetme sayacı: yalnız salt okur kütüphane çağrılı yüklem
    if (cs and not o["dolayli"] and not o["ddal"] and o["doner"] and not dis_sak and not void
            and U and U <= OS.MANTIKSAL and (("b",) in U or len(U) >= 2)):
        hs = hedef_bilgileri(o, bilgi)
        if hs is not None and all(not h[1] and h[0] <= OS.SALT_OKUR for h in hs):
            out.add("a1g_yuklem_okur_cagrili")

    # A2 yaşam (dünkü kurallar)
    if "fire_destroy" in v1:
        out.add("a2_birakir")
    if "create_buyutme" in v1:
        out.add("a2_buyutur")
    elif "fire_create_genis" in v1:
        out.add("a2_taze")
    if "destroy_her_yolda" in v1:
        out.add("a2_birakir_her_yolda")
    if "kalip2" in v1:
        out.add("a2g_alan_birak_genis")
        if cs and all(c[1] != "blr" and kap["birakici_mi"](c[2]) for c in cs):
            out.add("a2_sokum")

    # A3 alan
    ofsetler = {p: okunan.get(p, set()) | yazilan.get(p, set())
                for p in sorted(set(okunan) | set(yazilan))}
    if ofsetler:
        out.add("a3_var")
        if any(x != 0 for s in ofsetler.values() for x in s):
            out.add("a3_sifir_disi")
        if any(len(s) >= 2 for s in ofsetler.values()):
            out.add("a3_iki_ofset")
        if any(yazilan.get(p) for p in ofsetler):
            out.add("a3_yazar")

    # A5 sözleşme
    if not o["doner"]:
        out.add("a5_donmez")
    if yalin and not dis_sak:
        out.add("a5_ye_yerel")
        if (not void and len(U) == 1 and next(iter(U))[0] == "k") or (void and not yuk):
            out.add("a5_sabit_bos")
    elif cs and a in ye:
        out.add("a5_ye_gecisli")
    if param_saklama and o["doner"] and not o["dolayli"] and not o["ddal"]:
        hs = hedef_bilgileri(o, bilgi)
        if hs is not None and all(h[0] <= OS.SALT_OKUR and h[1] <= ye for h in hs):
            out.add("a5_param_yazar")

    # A6 sarma
    if cs and not dis_sak and not o["dolayli"] and not o["ddal"]:
        hs = hedef_bilgileri(o, bilgi)
        if hs is not None:
            ileti = OS.ILETI | (OS.ILETI_YALNIZ_ELF if aile == "elf" else frozenset())
            hata = OS.DONMEZ | ileti | {OS.import_adi(n) for n in OS.ERRNO_HAM[aile]}
            cekirdek = [(c, h) for c, h in zip(cs, hs)
                        if not (h[0] <= hata and h[1] <= kap["donmez_ic"])]
            r_cekirdek = {("r", c[0]) for c, _h in cekirdek}
            param_gidiyor = all(any(d[0] == "p" for n in range(8) for d in c[3][n])
                                for c, _h in cekirdek)
            donus_tamam = void or (bool(U) and all(d in r_cekirdek or d[0] == "k" for d in U))
            if cekirdek and param_gidiyor and donus_tamam:
                libs = {h[0] for _c, h in cekirdek}
                ics = {h[1] for _c, h in cekirdek}
                if len(libs) == 1 and ics == {frozenset()} and len(next(iter(libs))) == 1:
                    out.add("a6_lib")
                    ad = next(iter(next(iter(libs))))
                    if ad in OS.AYIRICI:
                        out.add("a6_lib_ayirici")
                    if ad in OS.BIRAKICI:
                        out.add("a6_lib_birakici")
                elif (len(ics) == 1 and libs == {frozenset()} and len(next(iter(ics))) == 1
                      and a not in next(iter(ics))
                      and not next(iter(ics)) <= kap["donmez_ic"]):
                    out.add("a6g_ic_genis")
                    if (len(cekirdek) == 1 and not dongu_var(fn)
                            and (void or any(v & r_cekirdek for v in o["donusler"]))):
                        out.add("a6_ic")
    if cs and sarmalar:
        for c in cs:
            h = bilgi(c[2])
            if h is not None and h[1] & sarmalar:
                out.add("a6_sarma_kullanan")
                break

    # dünkü kurallar (karşılaştırma sayaçları)
    for eski, yeni in (("fire_is", "v1_is"), ("kalip1_is", "v1_kalip1_is"), ("fire_init", "v1_init"),
                       ("kalip2_init", "v1_kalip2_init"), ("fire_destroy", "v1_destroy"),
                       ("fire_create_genis", "v1_create_genis"), ("kalip3_arg", "v1_kalip3_arg")):
        if eski in v1:
            out.add(yeni)

    if dis_sak:
        yazma = "param_alani" if param_saklama else "diger"
    else:
        yazma = "yok"
    if not cs:
        cagri = "yok"
    elif o["dolayli"]:
        cagri = "dolayli"
    else:
        hs = hedef_bilgileri(o, bilgi)
        if hs is None:
            cagri = "cozulemeyen"
        else:
            lib, ic = any(h[0] for h in hs), any(h[1] for h in hs)
            cagri = "ikisi" if lib and ic else ("lib" if lib else "ic")
    return out, f"{donus_turu(o, void)}|{yazma}|{cagri}"


def aile_bayraklari(alt: set[str]) -> set[str]:
    out = set(alt)
    for aile, altlar in ALT_SATIRLAR.items():
        if out & set(altlar):
            out.add(aile)
    if "ty_dizgili" in out:
        out.add("ty")
    return out


# ---------------------------------------------------------------------------------------------
# Tablo yuvası (dünkü betiğin yerel değişkenleri) ve yeni ürün koşusu


def tablo_yuvasi(static_dir: Path) -> tuple[set[int], set[int]]:
    """(tablo kaydındaki fonksiyonlar, kayıt dizgisi ad biçimli olanlar) — dünkü tanımlarla."""
    yakalanan: dict = {}
    hedef = TY.ikili_say.__code__

    def izle(frame, olay, _arg):
        if olay == "return" and frame.f_code is hedef:
            yakalanan.update(frame.f_locals)

    eski = sys.getprofile()
    sys.setprofile(izle)
    try:
        TY.ikili_say(static_dir)
    finally:
        sys.setprofile(eski)
    eksik = {"tablo_kaydi", "gevsek_dizgi"} - set(yakalanan)
    if eksik:
        raise RuntimeError(f"tablo_yuvasi_sayim.ikili_say değişmiş: {sorted(eksik)}")
    kayit = set(yakalanan["tablo_kaydi"])
    dizgili = {a for a in kayit
               if yakalanan["gevsek_dizgi"].get(a, {}).get("sinif", set()) & TY.AD_KANITI_SINIFLARI}
    return kayit, dizgili


def yeni_adlilar(yeni_kok: Path | None, platform_adi: str, program: str, ikili: str) -> dict:
    """Yeni ürün koşusunda ad alan ``FUN_`` anahtarları. Koşu bitmediyse ``bitti`` False."""
    if yeni_kok is None:
        return {"bitti": False, "neden": "yeni koşu verilmedi", "adli": set()}
    d = yeni_kok / "mac" / ikili if platform_adi == "mac" else yeni_kok / "debian" / program / ikili
    if not (d / "BITTI").is_file():
        return {"bitti": False, "neden": "BITTI yok", "adli": set()}
    yollar = sorted(d.glob("ws/workspaces/*/*/reconstructed/src/naming_map.json"))
    if len(yollar) != 1:
        return {"bitti": False, "neden": f"{len(yollar)} naming_map.json", "adli": set()}
    veri = json.loads(yollar[0].read_text(encoding="utf-8"))
    g = veri.get("global") if isinstance(veri, dict) else None
    if not isinstance(g, dict):
        return {"bitti": False, "neden": "global sözlüğü yok", "adli": set()}
    adli = {k for k, v in g.items()
            if OS.BEKLEYEN_RE.match(k) and str(v) != k and not OS.JENERIK_RE.match(str(v))}
    return {"bitti": True, "neden": "", "adli": adli}


def pcode_capraz(static_dir: Path, nufus: list[int], bayrak: dict[int, set[str]], bilgi,
                 uyusmayan: dict[str, list[int]] | None = None) -> Counter:
    """A5 iddialarının ikinci, bağımsız türetimle çapraz denetimi (GT'siz; kesinlik değildir).

    İkinci türetim Ghidra decompiler'ının yüksek p-code'udur (``ghidra_output/pcode.jsonl``;
    seçici listede STORE, CALL, CALLIND ve RETURN var). Uyuşmazlık tanımları:

    - ``ye_yerel``: p-code'da STORE, CALLIND ya da derleyici eki/CRT dışı bir hedefe CALL var;
    - ``ye_gecisli``: p-code'da STORE ya da CALLIND var (CALL beklenir);
    - ``param_yazar``: p-code'da hiç STORE yok;
    - ``donmez``: p-code'da gerçek bir RETURN var. Ghidra dönmeyen bitişi ilk girdisi sabit 1
      olan RETURN ile işaretler; ilk girdisi başka olan RETURN gerçek dönüştür.
    """
    say: Counter = Counter()
    yol = static_dir / "ghidra_output" / "pcode.jsonl"
    iddialar = ("a5_ye_yerel", "a5_ye_gecisli", "a5_param_yazar", "a5_donmez")
    ilgi = {a for a in nufus if bayrak[a] & set(iddialar)}
    if not yol.is_file():
        say["pcode_dosyasi_yok"] = 1
        return say

    def derleyici(t: int) -> bool:
        h = bilgi(t)
        return bool(h is not None and not h[1] and not h[2] and h[0]
                    and h[0] <= (OS.DERLEYICI | OS.CRT))

    gorulen: set[int] = set()
    with yol.open(encoding="utf-8") as fh:
        for satir in fh:
            try:
                r = json.loads(satir)
            except ValueError:
                say["bozuk_satir"] += 1
                continue
            a = OS.onaltilik(r.get("a", ""))
            if a not in ilgi or a in gorulen:
                continue
            gorulen.add(a)
            ops = r.get("ops") or []
            tur = Counter(op[0] for op in ops)
            cagri = any(not derleyici(op[2][0][1]) for op in ops if op[0] == "CALL" and op[2])
            b = bayrak[a]
            if "a5_ye_yerel" in b:
                say["ye_yerel:n"] += 1
                say["ye_yerel:store"] += int(tur["STORE"] > 0)
                say["ye_yerel:cagri"] += int(cagri or tur["CALLIND"] > 0)
                say["ye_yerel:uyusmaz"] += int(tur["STORE"] > 0 or cagri or tur["CALLIND"] > 0)
                if (tur["STORE"] > 0 or cagri or tur["CALLIND"] > 0) and uyusmayan is not None:
                    uyusmayan.setdefault("pcode_uyusmaz_ye_yerel", []).append(a)
            if "a5_ye_gecisli" in b:
                say["ye_gecisli:n"] += 1
                say["ye_gecisli:store"] += int(tur["STORE"] > 0)
                say["ye_gecisli:callind"] += int(tur["CALLIND"] > 0)
                say["ye_gecisli:uyusmaz"] += int(tur["STORE"] > 0 or tur["CALLIND"] > 0)
            if "a5_param_yazar" in b:
                say["param_yazar:n"] += 1
                say["param_yazar:uyusmaz"] += int(tur["STORE"] == 0)
            if "a5_donmez" in b:
                say["donmez:n"] += 1
                gercek_donus = any(
                    op[0] == "RETURN" and not (op[2] and op[2][0][0] == 2 and op[2][0][1] == 1)
                    for op in ops)
                say["donmez:uyusmaz"] += int(gercek_donus)
                if gercek_donus and uyusmayan is not None:
                    uyusmayan.setdefault("pcode_uyusmaz_donmez", []).append(a)
    say["pcode_kaydi_yok"] = len(ilgi - gorulen)
    return say


# ---------------------------------------------------------------------------------------------
# Bir ikilinin sayımı


def ikili_say(gorev: tuple) -> dict:
    global GIRIS_DUZELTMESI
    platform_adi, program, ikili, static_metni, yeni_metni, tablo, ornek_iste, duzeltme = gorev
    GIRIS_DUZELTMESI = duzeltme
    static_dir = Path(static_metni)
    kancalari_kur()
    YAKALA.sifirla()
    r = OS.elf_say(static_dir)
    n4, kap = YAKALA.n4, YAKALA.kapanis
    f, sinif, aile = n4["f"], n4["sinif"], n4["aile"]
    nufus = sorted(n4["uyeler"]["bekleyen"])
    fonk = dict(YAKALA.fonk)
    meta = n4["meta"]

    yeni = yeni_adlilar(Path(yeni_metni) if yeni_metni else None, platform_adi, program, ikili)
    adlar = {f[a]["ad"] for a in nufus}
    adsiz = [a for a in nufus if f[a]["ad"] not in yeni["adli"]] if yeni["bitti"] else list(nufus)
    eslesmeyen_anahtar = len(yeni["adli"] - adlar) if yeni["bitti"] else 0

    bayrak: dict[int, set[str]] = {a: set() for a in nufus}
    demet: dict[int, str] = {}
    if kap is not None:
        olgular = {a: temel_olgu(fn, kap) for a, fn in sorted(fonk.items())}
        ye = yan_etkisiz_kumesi(olgular, kap["bilgi"])
        # A6 sarmalayıcıları bütün iç fonksiyonlarda (çağıranlara 'sarma kullanan' satırı için)
        sarmalar: set[int] = set()
        for a, fn in sorted(fonk.items()):
            s, _d = satirlar(a, fn, meta.get(a, {}), olgular[a], kap, set(), ye, set(), aile) \
                if a not in bayrak else (set(), "")
            if "a6_lib" in s:
                sarmalar.add(a)
        for a in nufus:
            if a not in fonk:
                bayrak[a].add("disasm_yok")
                continue
            s, d = satirlar(a, fonk[a], meta.get(a, {}), olgular[a], kap, YAKALA.olcu.get(a, set()),
                            ye, set(), aile)
            bayrak[a] |= s
            demet[a] = d
            if "a6_lib" in s:
                sarmalar.add(a)
        for a in nufus:
            if a in fonk and sarmalar:
                for c in olgular[a]["cs"]:
                    h = kap["bilgi"](c[2])
                    if h is not None and h[1] & sarmalar:
                        bayrak[a].add("a6_sarma_kullanan")
                        break
    else:
        for a in nufus:
            bayrak[a].add("disasm_yok")

    # A4 global: bütün iç fonksiyonların başvuruları (paylaşım için)
    bloklar = Bloklar(static_dir)
    sahip: dict[int, set[int]] = defaultdict(set)
    basvuru: dict[int, dict[int, set[str]]] = {}
    for a in sorted(n4["kod"]):
        if a in f and f[a]["tur"] == "ic":
            g = {adr: bay for adr, bay in global_basvurulari(n4["kod"][a]).items()
                 if bloklar.sinif(adr) is not None}
            basvuru[a] = g
            for adr in g:
                sahip[adr].add(a)
    for a in nufus:
        g = basvuru.get(a, {})
        degisken = {adr: bay for adr, bay in g.items() if bloklar.sinif(adr) == "degisken"}
        if degisken:
            bayrak[a].add("a4_degisken")
            if any("yaz" in bay for bay in degisken.values()):
                bayrak[a].add("a4_yazar")
            if any(len(sahip[adr]) >= 2 for adr in degisken):
                bayrak[a].add("a4_paylasimli")
        if any(bloklar.sinif(adr) == "sabit" for adr in g):
            bayrak[a].add("a4_sabit_veri")
            if a in fonk and not any(OS.dal_turu(mn, ops)[0] == "ddal" for _, mn, ops in fonk[a].k):
                bayrak[a].add("a4_sabit_veri_ddalsiz")

    # tablo yuvası
    ty_durum = "atlandi"
    if tablo:
        kayit, dizgili = tablo_yuvasi(static_dir)
        ty_durum = "tamam"
        for a in nufus:
            if a in kayit:
                bayrak[a].add("ty_kayit")
            if a in dizgili:
                bayrak[a].add("ty_dizgili")

    uyusmayan: dict[str, list[int]] = {}
    pcode = pcode_capraz(static_dir, nufus, bayrak, kap["bilgi"], uyusmayan) \
        if kap is not None else Counter()

    # sayım
    giris_sonra = sum(1 for a in nufus if a in fonk and fonk[a].k and fonk[a].k[0][0] != a)
    cikti = {"birim": f"{platform_adi}/{program}", "ikili": ikili, "bicim": aile, "pcode": pcode,
             "duzeltme": {**{k: YAKALA.duzeltme.get(k, 0)
                             for k in ("giris_ilk_komut_degil", "yastigi_atilan_fonksiyon",
                                       "dusme_adayi_fonksiyon")},
                          "nufusta_giris_hala_ilk_degil": giris_sonra,
                          "nufusta_govde_disina_dusen": sum(
                              1 for a in nufus if a in fonk and getattr(fonk[a], "dusen", None))},
             "yeni_bitti": yeni["bitti"], "yeni_neden": yeni["neden"],
             "yeni_adli": len(yeni["adli"]) if yeni["bitti"] else None,
             "yeni_eslesmeyen_anahtar": eslesmeyen_anahtar, "ty": ty_durum,
             "on_sayim": {k: r["sayim"][k] for k in ("isim_bekleyen", "sinif_K", "sinif_I", "sinif_Y")},
             "v1_n4": {k: r["n4"]["sayac"].get(f"bekleyen:{k}", 0)
                       for k in ("fire_is", "fire_init", "fire_destroy", "fire_create_genis", "kalip2")},
             "nufus": {}}
    for ad, uyeler in (("jenerik", nufus), ("adsiz", adsiz)):
        say: Counter = Counter()
        kes: Counter = Counter()
        kat: Counter = Counter()
        dm: Counter = Counter()
        for a in uyeler:
            b = aile_bayraklari(bayrak[a])
            ks = sinif[a]
            say["n"] += 1
            say[f"n:{ks}"] += 1
            for x in b:
                say[x] += 1
                say[f"{x}:{ks}"] += 1
            var = [k for k in KESISIM_KUMELERI if k in b]
            alti = [k for k in var if k != "ty"]
            kat[f"aile_{len(alti)}"] += 1
            if alti:
                say["en_az_bir"] += 1
                say[f"en_az_bir:{ks}"] += 1
            if var:
                say["en_az_bir_ty_dahil"] += 1
            if set(alti) - {"a5"}:
                say["en_az_bir_a5siz"] += 1
            if set(alti) - {"a3", "a5"}:
                say["en_az_bir_a3_a5siz"] += 1
            if set(alti) & {"a1", "a2", "a6"}:
                say["en_az_bir_a1_a2_a6"] += 1
            if len(alti) == 1:
                say[f"yalniz:{alti[0]}"] += 1
            if var == ["ty"]:
                say["yalniz:ty"] += 1
            for i, x in enumerate(var):
                for y in var[i + 1:]:
                    kes[f"{x}&{y}"] += 1
            if a in demet:
                dm[demet[a]] += 1
        cikti["nufus"][ad] = {"sayac": say, "kesisim": kes, "kat": kat, "demet": dm}
    if ornek_iste:
        ornek: dict[str, list[int]] = defaultdict(list)
        for a in adsiz:
            b = aile_bayraklari(bayrak[a])
            for x in sorted(b):
                ornek[x].append(a)
            if not (b & set(AILELER)) and "disasm_yok" not in b:
                ornek["satirsiz"].append(a)
        ornek.update(uyusmayan)
        cikti["ornek"] = {"static": static_metni, "adres": dict(ornek)}
    return cikti


# ---------------------------------------------------------------------------------------------
# Toplama ve çıktı


def entropi(dm: Counter) -> float | None:
    n = sum(dm.values())
    if n == 0:
        return None
    return round(-sum(c / n * math.log2(c / n) for c in dm.values()), 4)


def ozet(say: Counter, kes: Counter, kat: Counter, demetler: list[Counter]) -> dict:
    n = say.get("n", 0)

    def oran(k):
        return round(k / n, 4) if n else None

    satir_adlari = list(AILELER) + [s for a in AILELER for s in ALT_SATIRLAR[a]] + list(EK_SAYACLAR) \
        + ["ty", "en_az_bir", "en_az_bir_ty_dahil", "en_az_bir_a5siz", "en_az_bir_a3_a5siz",
           "en_az_bir_a1_a2_a6"] + [f"yalniz:{k}" for k in KESISIM_KUMELERI]
    # demet: ikili başına hesaplanır; birimde en sık üçlülerin sayıları toplanır
    modal = sum(max(d.values()) for d in demetler if d)
    demetli = sum(sum(d.values()) for d in demetler)
    birlesik: Counter = Counter()
    for d in demetler:
        birlesik.update(d)
    return {
        "n": n,
        "sinif": {k: say.get(f"n:{k}", 0) for k in "KIY"},
        "sayi": {k: say.get(k, 0) for k in satir_adlari},
        "oran": {k: oran(say.get(k, 0)) for k in satir_adlari},
        "sinif_kirilimi": {k: {s: say.get(f"{k}:{s}", 0) for s in "KIY"}
                           for k in list(AILELER) + ["ty", "en_az_bir"]},
        "satirsiz": {"n": n - say.get("en_az_bir", 0),
                     **{s: say.get(f"n:{s}", 0) - say.get(f"en_az_bir:{s}", 0) for s in "KIY"}},
        "kesisim": {f"{x}&{y}": kes.get(f"{x}&{y}", 0)
                    for i, x in enumerate(KESISIM_KUMELERI) for y in KESISIM_KUMELERI[i + 1:]},
        "aile_sayisina_gore": {f"aile_{i}": kat.get(f"aile_{i}", 0) for i in range(len(AILELER) + 1)},
        "demet": {
            "fonksiyon": demetli,
            "ikili_ici_en_sik_uclu_payi": round(modal / demetli, 4) if demetli else None,
            "farkli_uclu": len(birlesik),
            "entropi_bit_birlesik": entropi(birlesik),
            "en_sik_5": [[k, v] for k, v in sorted(birlesik.items(), key=lambda kv: (-kv[1], kv[0]))[:5]],
        },
    }


BIRIM_PROGRAMI = {"mac/tmux": "tmux", "debian/tmux": "tmux", "mac/htop": "htop", "debian/htop": "htop"}


def makro(birim_ozetleri: dict[str, dict], anahtarlar: list[str]) -> dict:
    """Program düzeyi makro: aynı programın platform birimleri önce ortalanır (fiil_tavani T3)."""
    prog: dict[str, list[dict]] = defaultdict(list)
    for b, o in birim_ozetleri.items():
        prog[BIRIM_PROGRAMI.get(b, b.split("/", 1)[1])].append(o["oran"])
    out = {}
    for k in anahtarlar:
        degerler = []
        for _p, liste in sorted(prog.items()):
            vs = [o[k] for o in liste if o.get(k) is not None]
            if vs:
                degerler.append(sum(vs) / len(vs))
        out[k] = round(sum(degerler) / len(degerler), 4) if degerler else None
    return {"program_sayisi": len(prog), "oran": out}


def _s(n) -> str:
    return f"{n:,}".replace(",", " ") if isinstance(n, int) else str(n)


def _y(k: int, n: int) -> str:
    return f"{_s(k)} (%{100 * k / n:.1f})".replace(".", ",") if n else f"{_s(k)} (—)"


def markdown(belge: dict) -> str:
    L: list[str] = []
    k = belge["kunye"]
    L += ["# N4 v2 ateşleme sayımı: tablolar (betik çıktısı)", "",
          "`on_sayim_v2.py --md` üretir; elle değiştirilmez. Bütün sayılar `on_sayim_v2.json`'da.",
          "Kesinlik ölçülmedi; sayılar tanımların ateşleme sayısıdır. Fonksiyon adı ve adres yoktur.", "",
          f"- betik sha256 (ilk 16): `{k['betik_sha256'][:16]}`; `on_sayim.py`: "
          f"`{k['on_sayim_sha256'][:16]}`; `tablo_yuvasi_sayim.py`: `{k['tablo_yuvasi_sha256'][:16]}`",
          f"- koşular: Mac `{k['mac_kosu']}`, Debian `{k['debian_kosu']}`, yeni ürün `{k['yeni_kosu']['kok']}`",
          f"- yeni ürün koşusu biten ikili: {k['yeni_kosu']['biten_ikili']} / {k['yeni_kosu']['ikili']} "
          f"(bitmeyen ikilide `adsiz` = `jenerik`)", ""]
    sira = [b for b in sorted(belge["birimler"])]
    gruplar = [(b, belge["birimler"][b]) for b in sira] + [
        ("**Mac ikilisi**", belge["havuz"]["mac"]), ("**havuz Debian**", belge["havuz"]["debian"]),
        ("**havuz**", belge["havuz"]["tum"])]

    def tablo(baslik, satir_ureten, nufus):
        L.append("| " + " | ".join(baslik) + " |")
        L.append("|" + "|".join(["---"] + ["---:"] * (len(baslik) - 1)) + "|")
        for ad, v in gruplar:
            L.append("| " + " | ".join([ad if ad.startswith("**") else f"`{ad}`"]
                                       + satir_ureten(v[nufus])) + " |")
        L.append("")

    for nufus, baslik in (("adsiz", "Nüfus `adsiz`"), ("jenerik", "Nüfus `jenerik` (bütün `FUN_`)")):
        L += [f"## {baslik}", "", "### Aile ateşlemesi", ""]
        tablo(["birim", "n", "A1 erişimci", "A2 yaşam", "A3 alan", "A4 global", "A5 sözleşme",
               "A6 sarma", "tablo yuvası (dizgili)", "en az bir (6 aile)", "… tablo yuvası dahil"],
              lambda o: [_s(o["n"])] + [_y(o["sayi"][a], o["n"]) for a in AILELER]
              + [_y(o["sayi"]["ty"], o["n"]), _y(o["sayi"]["en_az_bir"], o["n"]),
                 _y(o["sayi"]["en_az_bir_ty_dahil"], o["n"])], nufus)
        L += ["### Birleşim duyarlılığı (en az bir satır alan fonksiyon)", ""]
        tablo(["birim", "n", "6 aile", "A5 hariç (5 aile)", "A3 ve A5 hariç (4 aile)",
               "A1 ∪ A2 ∪ A6", "hiç satır yok", "… K / I / Y"],
              lambda o: [_s(o["n"]), _y(o["sayi"]["en_az_bir"], o["n"]),
                         _y(o["sayi"]["en_az_bir_a5siz"], o["n"]),
                         _y(o["sayi"]["en_az_bir_a3_a5siz"], o["n"]),
                         _y(o["sayi"]["en_az_bir_a1_a2_a6"], o["n"]),
                         _y(o["satirsiz"]["n"], o["n"]),
                         " / ".join(_s(o["satirsiz"][s]) for s in "KIY")], nufus)
        L += ["### A1 erişimci ve A2 yaşam: alt satırlar", ""]
        tablo(["birim", "n", "al", "… saf", "yaz (tek ofset)", "yaz (çok ofset)", "yüklem",
               "gevşetme: okur çağrılı yüklem", "bırakır", "… her yolda", "taze nesne",
               "yeniden ayırır", "söküm (dar)", "gevşetme: alanı bırakıp sıfırlar (geniş)"],
              lambda o: [_s(o["n"])] + [_y(o["sayi"][x], o["n"]) for x in (
                  "a1_al", "a1_al_saf", "a1_yaz_tek", "a1_yaz_cok", "a1_yuklem",
                  "a1g_yuklem_okur_cagrili", "a2_birakir", "a2_birakir_her_yolda", "a2_taze",
                  "a2_buyutur", "a2_sokum", "a2g_alan_birak_genis")], nufus)
        L += ["### A3 alan ve A4 global: düzeyler", ""]
        tablo(["birim", "n", "alan: herhangi", "alan: sıfır dışı ofset (aile)", "alan: ≥ 2 ofset",
               "alan: yazar", "global: değişken (aile)", "… doğrudan yazar", "… paylaşımlı adres",
               "sabit veri", "… dolaylı dallanmasız"],
              lambda o: [_s(o["n"])] + [_y(o["sayi"][x], o["n"]) for x in (
                  "a3_var", "a3_sifir_disi", "a3_iki_ofset", "a3_yazar", "a4_degisken", "a4_yazar",
                  "a4_paylasimli", "a4_sabit_veri", "a4_sabit_veri_ddalsiz")], nufus)
        L += ["### A5 sözleşme ve A6 sarma: alt satırlar", ""]
        tablo(["birim", "n", "yan etkisiz (yerel)", "… sabit/boş", "yan etkisiz (geçişli)",
               "yalnız parametreye yazar", "hiç dönmez", "kütüphane sarmalayıcısı", "… ayırıcı",
               "… bırakıcı", "ince iç iletici", "gevşetme: tek iç hedefli (geniş)",
               "sarmalayıcı kullanan (aile dışı)"],
              lambda o: [_s(o["n"])] + [_y(o["sayi"][x], o["n"]) for x in (
                  "a5_ye_yerel", "a5_sabit_bos", "a5_ye_gecisli", "a5_param_yazar", "a5_donmez",
                  "a6_lib", "a6_lib_ayirici", "a6_lib_birakici", "a6_ic", "a6g_ic_genis",
                  "a6_sarma_kullanan")],
              nufus)
        L += ["### K / I / Y kırılımı (aile ateşlemesi; payda sınıfın nüfusu)", ""]
        tablo(["birim", "K / I / Y"] + [f"{a.upper()}" for a in AILELER] + ["tablo yuvası", "en az bir"],
              lambda o: [" / ".join(_s(o["sinif"][s]) for s in "KIY")]
              + [" / ".join(_s(o["sinif_kirilimi"][a][s]) for s in "KIY")
                 for a in list(AILELER) + ["ty", "en_az_bir"]], nufus)
        L += ["### Kaç aile ateşliyor (6 aile; tablo yuvası hariç)", ""]
        tablo(["birim", "n"] + [str(i) for i in range(7)],
              lambda o: [_s(o["n"])] + [_y(o["aile_sayisina_gore"][f"aile_{i}"], o["n"])
                                        for i in range(7)], nufus)
        L += ["### Yalnız tek ailenin ateşlediği fonksiyonlar", ""]
        tablo(["birim", "n"] + [a.upper() for a in AILELER],
              lambda o: [_s(o["n"])] + [_y(o["sayi"][f"yalniz:{a}"], o["n"]) for a in AILELER], nufus)
        L += ["### İkili örtüşmeler (fonksiyon sayısı)", ""]
        ciftler = [f"{x}&{y}" for i, x in enumerate(KESISIM_KUMELERI) for y in KESISIM_KUMELERI[i + 1:]]
        for ad, v in (("`mac/tmux`", belge["birimler"].get("mac/tmux")),
                      ("`mac/htop`", belge["birimler"].get("mac/htop")),
                      ("**havuz**", belge["havuz"]["tum"])):
            if v is None:
                continue
            o = v[nufus]
            L.append(f"{ad} (n = {_s(o['n'])}):")
            L.append("")
            L.append("| | " + " | ".join(x.upper() for x in KESISIM_KUMELERI) + " |")
            L.append("|---|" + "|".join(["---:"] * len(KESISIM_KUMELERI)) + "|")
            for x in KESISIM_KUMELERI:
                hucreler = []
                for y in KESISIM_KUMELERI:
                    if x == y:
                        hucreler.append(_s(o["sayi"][x]))
                    else:
                        c = f"{x}&{y}" if f"{x}&{y}" in ciftler else f"{y}&{x}"
                        hucreler.append(_s(o["kesisim"][c]))
                L.append(f"| {x.upper()} | " + " | ".join(hucreler) + " |")
            L.append("")
        L += ["### A5 üçlüsünün (dönüş, yazma, çağrı) ayırt ediciliği", ""]
        tablo(["birim", "fonksiyon", "farklı üçlü", "entropi (bit)", "ikili içi en sık üçlünün payı"],
              lambda o: [_s(o["demet"]["fonksiyon"]), _s(o["demet"]["farkli_uclu"]),
                         str(o["demet"]["entropi_bit_birlesik"]).replace(".", ","),
                         ("%" + f"{100 * o['demet']['ikili_ici_en_sik_uclu_payi']:.1f}".replace(".", ","))
                         if o["demet"]["ikili_ici_en_sik_uclu_payi"] is not None else "—"], nufus)
        L += ["### Dünkü kuralların aynı nüfustaki ateşlemesi (karşılaştırma)", ""]
        tablo(["birim", "n", "v1 `is`", "… kalıp 1", "v1 `init`", "… kalıp 2", "v1 `destroy`",
               "v1 `create` geniş"],
              lambda o: [_s(o["n"])] + [_y(o["sayi"][x], o["n"]) for x in (
                  "v1_is", "v1_kalip1_is", "v1_init", "v1_kalip2_init", "v1_destroy",
                  "v1_create_genis")], nufus)
    L += ["## A5 iddialarının p-code ile çapraz denetimi (nüfus `jenerik`; GT'siz, kesinlik değildir)", "",
          "İkinci türetim Ghidra decompiler'ının yüksek p-code'udur. Uyuşmazlık: yan etkisiz (yerel) "
          "iddiasında STORE, CALLIND ya da derleyici dışı CALL; yan etkisiz (geçişli) iddiasında STORE "
          "ya da CALLIND; 'yalnız parametreye yazar' iddiasında hiç STORE olmaması; 'hiç dönmez' "
          "iddiasında gerçek RETURN (ilk girdisi sabit 1 olmayan).", "",
          "| birim | yan etkisiz (yerel): uyuşmaz / n | … STORE | … çağrı | yan etkisiz (geçişli): "
          "uyuşmaz / n | … STORE | … CALLIND | yalnız parametreye yazar: uyuşmaz / n | hiç dönmez: "
          "uyuşmaz / n | p-code kaydı yok |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    pc = belge["pcode_capraz"]["sayim"]
    for ad, anahtar in [(f"`{b}`", b) for b in sira] + [("**Mac ikilisi**", "mac"),
                                                        ("**havuz Debian**", "debian"),
                                                        ("**havuz**", "tum")]:
        v = pc[anahtar]
        L.append(f"| {ad} | {_s(v['ye_yerel:uyusmaz'])} / {_s(v['ye_yerel:n'])} | {_s(v['ye_yerel:store'])} "
                 f"| {_s(v['ye_yerel:cagri'])} | {_s(v['ye_gecisli:uyusmaz'])} / {_s(v['ye_gecisli:n'])} "
                 f"| {_s(v['ye_gecisli:store'])} | {_s(v['ye_gecisli:callind'])} "
                 f"| {_s(v['param_yazar:uyusmaz'])} / {_s(v['param_yazar:n'])} "
                 f"| {_s(v['donmez:uyusmaz'])} / {_s(v['donmez:n'])} | {_s(v['pcode_kaydi_yok'])} |")
    L += ["", "## Program düzeyi makro (nüfus `adsiz`)", "",
          "Aynı programın platform birimleri önce ortalanır, sonra programlar eşit ağırlıkla.", "",
          "| ölçü | makro |", "|---|---:|"]
    for a, v in belge["makro"]["adsiz"]["oran"].items():
        L.append(f"| `{a}` | " + ("—" if v is None else "%" + f"{100 * v:.1f}".replace(".", ",")) + " |")
    L += ["", "## Denetim", ""]
    d = belge["denetim"]
    L += [f"- `on_sayim.json` ile nüfus ve K/I/Y: {d['on_sayim_json']['eslesen_birim']} birim eşleşti; "
          f"eşleşmeyen: {d['on_sayim_json']['eslesmeyen'] or 'yok'}",
          f"- dünkü kural sayaçları (`fire_is`, `fire_init`, `fire_destroy`, `fire_create_genis`, "
          f"`kalip2`) `on_sayim.json` ile: {d['v1_n4']['eslesen_birim']} birim eşleşti; eşleşmeyen: "
          f"{d['v1_n4']['eslesmeyen'] or 'yok'}",
          f"- tablo yuvası (`tablo_kaydinda`, `gevsek_ad_kanitli`) `tablo_yuvasi_sayim.json` ile: "
          f"{d['tablo_yuvasi_json']['eslesen_birim']} birim eşleşti; eşleşmeyen: "
          f"{d['tablo_yuvasi_json']['eslesmeyen'] or 'yok'}",
          f"- yeni ürün ad haritasında tabanda karşılığı olmayan `FUN_` anahtarı: "
          f"{d['yeni_eslesmeyen_anahtar']}",
          f"- giriş/yastık düzeltmesi: {'açık' if d['giris_duzeltmesi']['acik'] else 'KAPALI'}. "
          "Açıkken dünkü kural sayaçlarının `on_sayim.json` ile eşleşmemesi beklenir (düzeltmenin "
          "etkisi); kapalıyken eşleşmelidir.", "",
          "| birim | iç fonksiyon: ilk komut giriş değil | yastığı atılan iç fonksiyon | nüfusta giriş "
          "hâlâ ilk komut değil | nüfusta gövde dışına düşen | dünkü sayaçlar [is, init, destroy, "
          "create geniş, kalıp 2]: biz → dünkü |",
          "|---|---:|---:|---:|---:|---|"]
    fark = {e["birim"]: e for e in d["v1_n4"]["eslesmeyen"]}
    for b in sira:
        g = d["giris_duzeltmesi"]["birim"][b]
        e = fark.get(b)
        L.append(f"| `{b}` | {_s(g['giris_ilk_komut_degil'])} | {_s(g['yastigi_atilan_fonksiyon'])} "
                 f"| {_s(g['nufusta_giris_hala_ilk_degil'])} | {_s(g['nufusta_govde_disina_dusen'])} | "
                 + (f"{e['biz']} → {e['dunku']}" if e else "aynı") + " |")
    L.append("")
    return "\n".join(L)


def oz_sinama() -> int:
    """Sentetik disassembly ile alt satır tanımlarının küçük denetimi (mutant kanıtı değildir)."""
    kancalari_kur()

    def kur(kod: dict[int, list[tuple[int, str, str]]], lib: dict[int, str] | None = None,
            donus: dict[int, str] | None = None):
        lib = lib or {}
        f = {a: {"ad": f"FUN_{a:08x}", "tur": "ic", "kaynak": "", "boyut": 4 * len(k)}
             for a, k in kod.items()}
        f.update({a: {"ad": ad, "tur": "lib", "kaynak": "", "boyut": 0} for a, ad in lib.items()})
        meta = {a: {"donus": (donus or {}).get(a, "undefined8"), "ghidra_donmez": False} for a in kod}
        YAKALA.sifirla()
        OS.n4_elf(f, kod, meta, lambda h: {h}, "elf", {"bekleyen": set(kod)},
                  sinif={a: "Y" for a in kod}, cagiran_sayisi={a: 0 for a in kod},
                  n_komut={a: len(k) for a, k in kod.items()}, yazar={a: False for a in kod})
        kap = YAKALA.kapanis
        olg = {a: temel_olgu(fn, kap) for a, fn in YAKALA.fonk.items()}
        ye = yan_etkisiz_kumesi(olg, kap["bilgi"])
        return {a: satirlar(a, YAKALA.fonk[a], meta[a], olg[a], kap, YAKALA.olcu.get(a, set()),
                            ye, set(), "elf")[0] for a in kod}

    def k(bas, *satir):
        return [(bas + 4 * i, s.split(None, 1)[0], (s.split(None, 1) + [""])[1]) for i, s in enumerate(satir)]

    hatalar = []

    def bekle(ad, bulunan, olmali=(), olmamali=()):
        for x in olmali:
            if x not in bulunan:
                hatalar.append(f"{ad}: {x} bekleniyordu; bulunan {sorted(bulunan)}")
        for x in olmamali:
            if x in bulunan:
                hatalar.append(f"{ad}: {x} olmamalıydı")

    r = kur({0x1000: k(0x1000, "ldr x0,[x0, #0x28]", "ret"),
             0x2000: k(0x2000, "str w1,[x0, #0x10]", "ret"),
             0x3000: k(0x3000, "str xzr,[x0, #0x8]", "str w1,[x0, #0x10]", "ret"),
             0x4000: k(0x4000, "ldr w8,[x0, #0x4]", "cmp w8,#0x0", "cset w0,ne", "ret"),
             0x5000: k(0x5000, "mov w0,#0x0", "ret"),
             0x6000: k(0x6000, "ldr x8,[x0]", "str x8,[x1]", "ret"),
             0x7000: k(0x7000, "adrp x8,0x30000", "str w0,[x8, #0x10]", "ret")},
            donus={0x2000: "void", 0x3000: "void", 0x6000: "void", 0x7000: "void"})
    bekle("al", r[0x1000], ("a1_al", "a1_al_saf", "a5_ye_yerel", "a3_sifir_disi"), ("a1_yuklem", "a5_sabit_bos"))
    bekle("yaz_tek", r[0x2000], ("a1_yaz_tek", "a5_param_yazar", "a3_yazar"), ("a1_yaz_cok", "a5_ye_yerel"))
    bekle("yaz_cok", r[0x3000], ("a1_yaz_cok", "a3_iki_ofset"), ("a1_yaz_tek",))
    bekle("yuklem", r[0x4000], ("a1_yuklem", "a5_ye_yerel"), ("a1_al", "a5_sabit_bos"))
    bekle("sabit", r[0x5000], ("a5_sabit_bos", "a5_ye_yerel"), ("a1_al", "a1_yuklem", "a3_var"))
    bekle("kopya", r[0x6000], ("a5_param_yazar", "a3_var"), ("a1_yaz_tek", "a1_yaz_cok", "a3_sifir_disi"))
    bekle("global", r[0x7000], (), ("a1_yaz_tek", "a5_param_yazar", "a5_ye_yerel"))
    g = global_basvurulari(k(0x7000, "adrp x8,0x30000", "str w0,[x8, #0x10]", "adrp x9,0x31000",
                             "add x9,x9,#0x20", "ldr x0,[x9, #0x8]", "bl 0x9000", "ldr x1,[x9]"))
    if g != {0x30010: {"yaz"}, 0x31020: {"al"}, 0x31028: {"oku"}}:
        hatalar.append(f"global_basvurulari: {g}")
    # çağrılı: kütüphane sarmalayıcısı, iç iletici, geçişli yan etkisiz, bırakır
    r = kur({0x1000: k(0x1000, "stp x29,x30,[sp, #-0x10]!", "bl 0x9000", "ldp x29,x30,[sp], #0x10", "ret"),
             0x2000: k(0x2000, "mov w1,#0x0", "b 0x1000"),
             0x3000: k(0x3000, "stp x29,x30,[sp, #-0x10]!", "bl 0x9100", "cmp w0,#0x0", "cset w0,eq",
                       "ldp x29,x30,[sp], #0x10", "ret"),
             0x4000: k(0x4000, "stp x29,x30,[sp, #-0x10]!", "bl 0x3000", "ldp x29,x30,[sp], #0x10", "ret"),
             0x5000: k(0x5000, "stp x29,x30,[sp, #-0x10]!", "bl 0x9200", "ldp x29,x30,[sp], #0x10", "ret"),
             # döngü içinde tek iç hedef: geniş tanım tutar, ince iletici tutmaz
             0x6000: k(0x6000, "stp x29,x30,[sp, #-0x10]!", "bl 0x3000", "cbnz w0,0x6004",
                       "ldp x29,x30,[sp], #0x10", "ret"),
             # alanları bırakıp sıfırlayan söküm: yalnız bırakıcı çağrısı
             0x7000: k(0x7000, "stp x29,x30,[sp, #-0x20]!", "str x19,[sp, #0x10]", "mov x19,x0",
                       "ldr x0,[x19, #0x8]", "bl 0x9200", "str xzr,[x19, #0x8]",
                       "str wzr,[x19, #0x10]", "ldr x19,[sp, #0x10]",
                       "ldp x29,x30,[sp], #0x20", "ret")},
            lib={0x9000: "malloc", 0x9100: "strcmp", 0x9200: "free"},
            donus={0x5000: "void", 0x7000: "void"})
    bekle("lib_sarma", r[0x1000], ("a6_lib", "a6_lib_ayirici"), ("a6_ic", "a5_ye_gecisli"))
    bekle("ic_iletici", r[0x2000], ("a6_ic", "a6g_ic_genis"), ("a6_lib", "a5_ye_gecisli"))
    bekle("okur_yuklem", r[0x3000], ("a1g_yuklem_okur_cagrili", "a5_ye_gecisli"), ("a1_yuklem", "a6_lib"))
    bekle("gecisli", r[0x4000], ("a5_ye_gecisli", "a6_ic"), ("a5_ye_yerel",))
    bekle("free_sarma", r[0x5000], ("a6_lib", "a6_lib_birakici"), ("a5_ye_gecisli",))
    bekle("dongulu_ic", r[0x6000], ("a6g_ic_genis",), ("a6_ic",))
    bekle("sokum", r[0x7000], ("a2_sokum", "a2g_alan_birak_genis", "a3_iki_ofset"), ("a2_birakir", "a6_lib"))
    # giriş/yastık ve gövde dışına düşme düzeltmeleri
    r = kur({0x1000: [(0x1000, "ldr", "x0,[x0, #0x28]"), (0x1004, "cbz", "x0,0x1010"),
                      (0x1010, "ret", "")],                       # 0x1008'e (başka fonksiyona) düşer
             0x1008: k(0x1008, "str w1,[x0, #0x10]", "ret"),
             0x2000: [(0x1ff0, "bti", "c"), (0x2000, "mov", "w1,#0x0"), (0x2004, "b", "0x1ff0")]},
            lib={0x1ff4: "free"}, donus={0x1008: "void", 0x2000: "void"})
    bekle("dusen", r[0x1000], ("a3_sifir_disi",), ("a5_ye_yerel", "a1_al", "a1_yuklem", "a5_donmez"))
    bekle("yastik", r[0x2000], ("a6_lib", "a6_lib_birakici"), ("a5_donmez", "a5_ye_yerel"))
    global GIRIS_DUZELTMESI
    GIRIS_DUZELTMESI = False
    try:
        r = kur({0x2000: [(0x1ff0, "bti", "c"), (0x2000, "mov", "w1,#0x0"), (0x2004, "b", "0x1ff0")]},
                lib={0x1ff4: "free"}, donus={0x2000: "void"})
        bekle("yastik_duzeltmesiz", r[0x2000], ("a5_donmez",), ("a6_lib",))   # dünkü davranış
    finally:
        GIRIS_DUZELTMESI = True
    for h in hatalar:
        print("HATA", h)
    print(f"öz sınama: {'başarısız' if hatalar else 'tamam'} ({len(hatalar)} hata)")
    return 1 if hatalar else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--mac-kosu", type=Path)
    ap.add_argument("--debian-kosu", type=Path)
    ap.add_argument("--yeni-kosu", type=Path, help="yeni ürün koşusu kökü (BITTI olan ikililer kullanılır)")
    ap.add_argument("--cikti", type=Path)
    ap.add_argument("--md", type=Path, help="tabloları bu dosyaya yaz")
    ap.add_argument("--surec", type=int, default=PARALEL_AZAMI)
    ap.add_argument("--yalniz", help="yalnız bu birim(ler), virgülle (deneme için; çıktı denetimi atlanır)")
    ap.add_argument("--tablosuz", action="store_true", help="tablo yuvası sayımını atla (deneme)")
    ap.add_argument("--oz-sinama", action="store_true")
    ap.add_argument("--giris-duzeltmesi-kapali", action="store_true",
                    help="yastık/giriş düzeltmesini kapat: dünkü on_sayim.json sayaçlarını yeniden üretir")
    ap.add_argument("--ornekler", type=Path,
                    help="elle okuma örnekleri (adresli; DEPO DIŞINA yazılmalı): satır başına 10")
    args = ap.parse_args()
    if args.oz_sinama:
        return oz_sinama()
    if not (args.mac_kosu and args.debian_kosu and args.cikti):
        ap.error("--mac-kosu, --debian-kosu ve --cikti gerekli")
    if not 1 <= args.surec <= PARALEL_AZAMI:
        ap.error(f"--surec 1..{PARALEL_AZAMI}")

    dizinler = OS.static_dizinleri(args.mac_kosu.expanduser(), args.debian_kosu.expanduser())
    bulunan = Counter(f"{p}/{program}" for p, program, _, _ in dizinler)
    for birim in sorted(set(OS.BEKLENEN_ELF) | set(bulunan)):
        if bulunan.get(birim, 0) != OS.BEKLENEN_ELF.get(birim, 0):
            raise SystemExit(f"{birim}: {bulunan.get(birim, 0)} ikili bulundu")
    secim = set(args.yalniz.split(",")) if args.yalniz else None
    yeni = args.yeni_kosu.expanduser() if args.yeni_kosu else None
    gorevler = [(p, program, ikili, str(sd), str(yeni) if yeni else "", not args.tablosuz,
                 args.ornekler is not None, not args.giris_duzeltmesi_kapali)
                for p, program, ikili, sd in dizinler
                if secim is None or f"{p}/{program}" in secim]
    if args.surec == 1:
        sonuclar = [ikili_say(g) for g in gorevler]
    else:
        with multiprocessing.get_context("spawn").Pool(args.surec) as havuz:
            sonuclar = havuz.map(ikili_say, gorevler, chunksize=1)
    sonuclar.sort(key=lambda r: (r["birim"], r["ikili"]))
    if args.ornekler is not None:
        havuz_ornek: dict[str, list[tuple[str, str, str, str, int]]] = defaultdict(list)
        for r in sonuclar:
            for x, adresler in r["ornek"]["adres"].items():
                for a in adresler:
                    ozet_ = hashlib.sha1(f"{x}/{r['birim']}/{r['ikili']}/{a:x}".encode()).hexdigest()
                    havuz_ornek[x].append((ozet_, r["birim"], r["ikili"], r["ornek"]["static"], a))
                    if r["birim"].startswith("mac/"):
                        havuz_ornek[x + "@mac"].append(
                            (ozet_, r["birim"], r["ikili"], r["ornek"]["static"], a))
        secilen = {x: [{"birim": b, "ikili": i, "static": sd, "adres": f"{a:x}"}
                       for _o, b, i, sd, a in sorted(v)[:ORNEK_SAYISI]]
                   for x, v in sorted(havuz_ornek.items())}
        args.ornekler.expanduser().write_text(json.dumps(secilen, ensure_ascii=False, indent=1) + "\n",
                                              encoding="utf-8")

    def topla(secici) -> dict:
        out = {}
        for nufus in ("jenerik", "adsiz"):
            say, kes, kat, dms = Counter(), Counter(), Counter(), []
            for r in sonuclar:
                if secici(r):
                    v = r["nufus"][nufus]
                    say.update(v["sayac"])
                    kes.update(v["kesisim"])
                    kat.update(v["kat"])
                    dms.append(v["demet"])
            out[nufus] = ozet(say, kes, kat, dms)
        return out

    def pcode_topla(secici) -> dict:
        c: Counter = Counter()
        for r in sonuclar:
            if secici(r):
                c.update(r["pcode"])
        return {k: c.get(k, 0) for k in PCODE_ANAHTARLARI}

    birimler = {b: topla(lambda r, b=b: r["birim"] == b) for b in sorted({r["birim"] for r in sonuclar})}
    pcode_ozet = {**{b: pcode_topla(lambda r, b=b: r["birim"] == b) for b in birimler},
                  "mac": pcode_topla(lambda r: r["birim"].startswith("mac/")),
                  "debian": pcode_topla(lambda r: r["birim"].startswith("debian/")),
                  "tum": pcode_topla(lambda r: True)}
    havuz_ = {"tum": topla(lambda r: True),
              "mac": topla(lambda r: r["birim"].startswith("mac/")),
              "debian": topla(lambda r: r["birim"].startswith("debian/"))}
    makro_anahtarlari = list(AILELER) + ["ty", "en_az_bir", "en_az_bir_ty_dahil", "en_az_bir_a5siz",
                                         "en_az_bir_a3_a5siz", "en_az_bir_a1_a2_a6"]
    makrolar = {n: makro({b: v[n] for b, v in birimler.items()}, makro_anahtarlari)
                for n in ("jenerik", "adsiz")}

    # denetim: dünkü çıktılarla
    def karsilastir(dosya: Path, biz_fn, onlar_fn) -> dict:
        if not dosya.is_file():
            return {"dosya": "yok", "eslesen_birim": 0, "eslesmeyen": []}
        veri = json.loads(dosya.read_text(encoding="utf-8"))
        eslesen, eslesmeyen = 0, []
        for b in sorted(birimler):
            biz = biz_fn(b)
            onlar = onlar_fn(veri, b)
            if biz == onlar:
                eslesen += 1
            else:
                eslesmeyen.append({"birim": b, "biz": biz, "dunku": onlar})
        return {"dosya_sha256": hashlib.sha256(dosya.read_bytes()).hexdigest(),
                "eslesen_birim": eslesen, "eslesmeyen": eslesmeyen}

    def birim_toplami(b, alan, anahtarlar):
        c = Counter()
        for r in sonuclar:
            if r["birim"] == b:
                c.update({k: r[alan][k] for k in anahtarlar})
        return [c[k] for k in anahtarlar]

    nk = ("isim_bekleyen", "sinif_K", "sinif_I", "sinif_Y")
    vk = ("fire_is", "fire_init", "fire_destroy", "fire_create_genis", "kalip2")
    tablo_var = not args.tablosuz
    denetim = {
        "on_sayim_json": karsilastir(
            DUNKU / "on_sayim.json", lambda b: birim_toplami(b, "on_sayim", nk),
            lambda v, b: [v["birimler"].get(b, {}).get("sayim", {}).get(k, 0) for k in nk]),
        "v1_n4": karsilastir(
            DUNKU / "on_sayim.json", lambda b: birim_toplami(b, "v1_n4", vk),
            lambda v, b: [v["birimler"].get(b, {}).get("n4", {}).get(f"bekleyen:{k}", 0) for k in vk]),
        "tablo_yuvasi_json": karsilastir(
            DUNKU / "tablo_yuvasi_sayim.json",
            lambda b: [birimler[b]["jenerik"]["sayi"]["ty_kayit"], birimler[b]["jenerik"]["sayi"]["ty_dizgili"]],
            lambda v, b: [v["birimler"].get(b, {}).get("nufus", {}).get("tablo_kaydinda", 0),
                          v["birimler"].get(b, {}).get("nufus", {}).get("gevsek_ad_kanitli", 0)])
        if tablo_var else {"dosya": "atlandi", "eslesen_birim": 0, "eslesmeyen": []},
        "yeni_eslesmeyen_anahtar": sum(r["yeni_eslesmeyen_anahtar"] for r in sonuclar),
        "giris_duzeltmesi": {
            "acik": not args.giris_duzeltmesi_kapali,
            "tanim": yastiklari_ayikla.__doc__ + "\n" + _KayitliFonksiyon.__doc__,
            "birim": {b: {k: sum(r["duzeltme"][k] for r in sonuclar if r["birim"] == b)
                          for k in ("giris_ilk_komut_degil", "yastigi_atilan_fonksiyon",
                                    "nufusta_giris_hala_ilk_degil", "dusme_adayi_fonksiyon",
                                    "nufusta_govde_disina_dusen")} for b in sorted(birimler)},
        },
        "not": ("Dünkü çıktılar Mac'te ol7-a-9a36142 koşusundandır; bu sayım başka bir Mac "
                "koşusuyla yapıldıysa Mac birimlerinde fark beklenebilir."),
    }

    belge = {
        "kunye": {
            "betik": "docs/arge/2026-11-11_n4_v2/on_sayim_v2.py", "surum": SAYIM_V2_SURUMU,
            "betik_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "on_sayim_sha256": hashlib.sha256(Path(OS.__file__).read_bytes()).hexdigest(),
            "tablo_yuvasi_sha256": hashlib.sha256(Path(TY.__file__).read_bytes()).hexdigest(),
            "python": platform.python_version(),
            "mac_kosu": OS.ev_kisalt(args.mac_kosu), "debian_kosu": OS.ev_kisalt(args.debian_kosu),
            "yeni_kosu": {
                "kok": OS.ev_kisalt(yeni) if yeni else None,
                "ikili": len(sonuclar),
                "biten_ikili": sum(1 for r in sonuclar if r["yeni_bitti"]),
                "biten": sorted(f"{r['birim']}/{r['ikili']}" for r in sonuclar if r["yeni_bitti"]),
                "biten_ikililerde_ad_alan_FUN": sum(r["yeni_adli"] or 0 for r in sonuclar),
            },
            "ikili_sayisi": dict(sorted(bulunan.items())),
            "secim": sorted(secim) if secim else None,
            "nufuslar": {
                "jenerik": "thunk ve dış olmayan, adı ^FUN_<onaltılık>$ olan Ghidra fonksiyonu "
                           "(dünkü isim_bekleyen)",
                "adsiz": "yeni ürün koşusu ikilide bittiyse jenerik eksi naming_map global'de ürün "
                         "adı alanlar; bitmediyse jenerik'in tamamı",
            },
            "aileler": {a: {"ad": AILE_ADI[a], "ates": list(ALT_SATIRLAR[a])} for a in AILELER},
            "ek_sayaclar": list(EK_SAYACLAR),
            "tanimlar": AILE_TANIMLARI,
            "degisken_bloklari": sorted(DEGISKEN_BLOKLARI),
            "sabit_veri_bloklari": sorted(SABIT_VERI_BLOKLARI),
            "salt_okur": sorted(OS.SALT_OKUR),
            "birlesimler": {
                "en_az_bir": "altı aileden en az biri",
                "en_az_bir_ty_dahil": "altı aile ya da ty_dizgili",
                "en_az_bir_a5siz": "A5 dışındaki beş aileden en az biri",
                "en_az_bir_a3_a5siz": "A3 ve A5 dışındaki dört aileden en az biri",
                "en_az_bir_a1_a2_a6": "A1, A2 ya da A6",
            },
        },
        "birimler": birimler, "havuz": havuz_, "makro": makrolar, "denetim": denetim,
        "pcode_capraz": {"nufus": "jenerik", "tanim": pcode_capraz.__doc__, "sayim": pcode_ozet},
        "ikililer": [{"birim": r["birim"], "ikili": r["ikili"], "yeni_bitti": r["yeni_bitti"],
                      "yeni_adli": r["yeni_adli"], "jenerik": r["nufus"]["jenerik"]["sayac"].get("n", 0),
                      "adsiz": r["nufus"]["adsiz"]["sayac"].get("n", 0),
                      "en_az_bir_adsiz": r["nufus"]["adsiz"]["sayac"].get("en_az_bir", 0)}
                     for r in sonuclar],
    }
    args.cikti.write_text(json.dumps(belge, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
                          encoding="utf-8")
    if args.md:
        args.md.write_text(markdown(belge) + "\n", encoding="utf-8")
    h = havuz_["tum"]["adsiz"]
    print(f"adsiz {h['n']}; " + ", ".join(f"{a}={h['sayi'][a]}" for a in AILELER)
          + f"; ty={h['sayi']['ty']}; en az bir={h['sayi']['en_az_bir']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
