#!/usr/bin/env python3
"""Kalan ad kanallarının dökümü: yanlış sınıfları, tür ve özellik başına kesinlik, kural adayları.

Bu bir KEŞİF çözümlemesidir. Sayılar geliştirme setindendir (taban ölçümün okuduğu saklı koşular:
Debian 117 + Mac 2 ikili, C++ dışı 118). Buradan çıkan her kural adayı geliştirme setinde
bulunmuştur; taze veride (doğrulama seti) sınanmadan iddia sayılmaz. Çok sayıda özellik aynı veride
denendiği için tek tek aralıklar çoklu karşılaştırmaya göre düzeltilmemiştir.

Soru: üründe KALACAK kanalların (ön adlar, ``string_context/oz_ad``, ``string_context/kebap_ad``,
``api_param_reverse``) verdiği yanlış adlar hangi sınıftan, ve GT'siz hesaplanabilen hangi alt
koşulda tam ad kesinliği ≥ %95?

Girdi ve hüküm ``scripts/measurement/urun_olc.py``'den içe aktarılır (o da GT, adres eşlemesi ve
hükmü ``ks1_olc.py``'den alır); bu betik onları yeniden yazmaz. Toplamlar taban ölçümle
(``urun_olcumu_taban.json``) karşılaştırılır; tutmazsa betik durur.

Çıktıda fonksiyon adı, ürün adı, GT adı, ``FUN_`` anahtarı ve dizgi YOKTUR: yalnız sayılar, sınıf
adları, program ve ikili adları. Katalog girdileri (gnulib parmak izi, çağrı biçimi, ELF önyükü)
adla değil ürün kodundaki sıra numarasıyla gösterilir. ``ornek`` alt komutu örnekleri yalnız
uçbirime yazar (elle denetim için); dosyaya yazmaz.

Ön ad türü
----------
Saklı koşuların köken kaydında ön adın türü yazılı değildir (``pre_name_kind`` sonradan eklendi;
bütün ön adlar ``binary_extract`` görünür). Tür, ürünün kendi tohum fonksiyonları
(``ReconstructionStage._recover_main_from_entry`` / ``_recover_gnulib_from_fingerprints`` /
``_recover_elf_boilerplate``) saklı ``static/`` çıktısı üzerinde yeniden çağrılarak bulunur
(Karadul hattı ya da Ghidra koşmaz). Yeniden üretim, koşunun kendi sayaçlarıyla
(``reports/pipeline_result.json``) ve köken kaydındaki adla karşılaştırılır; uyuşmayan ad
``belirlenemedi`` türüne düşer ve sayılır.

Kullanım
--------
    python docs/arge/2026-11-10_n1_adim3/kalan_kanal_dokumu.py dok \\
        --kok-debian ~/karadul_olcum/n1_debian13 \\
        --kok-mac workspaces/olcum_mac/runs/ol7-a-9a36142 --mac-veri workspaces/olcum_mac \\
        --json docs/arge/2026-11-10_n1_adim3/kalan_kanal_dokumu.json \\
        --md docs/arge/2026-11-10_n1_adim3/kalan_kanal_dokumu.md
    python docs/arge/2026-11-10_n1_adim3/kalan_kanal_dokumu.py ornek --sinif ilgisiz --grup oz_ad ...
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import importlib.util
import json
import pickle
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

SEMA = "karadul-kalan-kanal-dokumu/1"
REPO = Path(__file__).resolve().parents[3]
BURASI = Path(__file__).resolve().parent
BETIK = Path(__file__).resolve()
URUN_OLC_YOLU = REPO / "scripts" / "measurement" / "urun_olc.py"
TABAN_YOLU = BURASI / "urun_olcumu_taban.json"


def _yukle(ad: str, yol: Path) -> Any:
    spec = importlib.util.spec_from_file_location(ad, yol)
    modul = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modul
    spec.loader.exec_module(modul)
    return modul


uo = _yukle("urun_olc", URUN_OLC_YOLU)     # ks1_olc'yi ve ürün modüllerini kendisi yükler
ks1 = uo.ks1

from karadul.analyzers import elf_boilerplate, gnulib_fingerprints  # noqa: E402
from karadul.core import naming_labels  # noqa: E402
from karadul.reconstruction.tarif import alt_kanal, baglama  # noqa: E402

DOGRU = uo.DOGRU

# ============================================================================================
# TANIMLAR. Bu bölüm sayımdan ÖNCE, ürün kodu okunarak yazıldı (c_namer.py: ön ad temizleme ve
# çakışma eki; stages.py: tohumlar; alt_kanal.py: alt kanal yüklemleri; api_param_db.py: ters
# yayılım; ks1_olc.py: hüküm). Veri görüldükten sonra yapılan değişiklikler belgenin
# "Tanımda sonradan yapılan değişiklikler" bölümünde yazılıdır.
# ============================================================================================

# ---- Kanal grupları (kalan kanallar) ----
GRUP_ON_AD = "on_ad"
GRUP_OZ_AD = "oz_ad"
GRUP_KEBAP = "kebap_ad"
GRUP_API = "api_param_reverse"
GRUP_DIGER = "diger_kalan"            # beklenmeyen: taban ölçümde yok; varsa sayılır
GRUPLAR = (GRUP_ON_AD, GRUP_OZ_AD, GRUP_KEBAP, GRUP_API, GRUP_DIGER)
KANAL_ON_AD = "binary_extract"        # saklı koşularda bütün ön adların stratejisi
KANAL_OZ_AD = f"{naming_labels.STRATEGY_STRING_CONTEXT}/{alt_kanal.SUB_OWN_NAME}"
KANAL_KEBAP = f"{naming_labels.STRATEGY_STRING_CONTEXT}/{alt_kanal.SUB_KEBAB_NAME}"
KANAL_API = "api_param_reverse"

# ---- Ön ad türleri (baglama.py KIND_* ile aynı yazım; alt tür tohumun katmanı) ----
TUR_MAIN = "main_giris"
TUR_GNULIB_DIZGI = "gnulib/dizgi_parmak_izi"
TUR_GNULIB_CAGRI = "gnulib/cagri_bicimi"
TUR_GNULIB_AYRISTIRMA = "gnulib/ayristirma"
TUR_ELF_ONYUK = "elf_onyuk"
TUR_FAZ1 = "faz1"                     # BinaryNameExtractor (alt kaynağı ``faz1/<source>``)
TUR_ELLE = "elle"
TUR_BELIRSIZ = "belirlenemedi"        # yeniden üretim köken kaydındaki adı vermedi

# ---- Yanlış sınıfları. İlk tutan kazanır (sıra tanımın parçası). ----
# N: ürünün yazdığı ad; R: ham ad (ön adda temizlenmeden, adayda çakışma eki eklenmeden önceki ad;
# köken kaydında ``proposed_name``); G: o adresteki GT adları (Mach-O'da baştaki ``_`` soyulmuş).
S_GT_YOK = "gt_yok"
S_TEMIZLEYICI = "temizleyici_farki"
S_CARPISMA = "carpisma_eki"
S_SONEK = "sonek_farki"
S_HARF = "harf_altcizgi_farki"
S_BASKA = "baska_fonksiyonun_adi"
S_ICE = "ice_aktarilan_adi"
S_KATALOG = "katalog_adi"
S_ONEK = "onek_sonek_farki"
S_ILGISIZ = "ilgisiz"
SINIFLAR: tuple[tuple[str, str], ...] = (
    (S_GT_YOK, "GT'de o adreste fonksiyon yok (eşlenemeyen adres); ürün yine de ad yazdı"),
    (S_TEMIZLEYICI, "R ≠ N ve R tek başına doğru hüküm alırdı: ad temizleyici (`_sanitize_c_name`: "
                    "baştaki/sondaki alt çizgiyi atar, küçük harfe çevirir) doğru adı bozdu"),
    (S_CARPISMA, "R ≠ N, N = R + `_<sayı>` ve R tek başına doğru hüküm alırdı: çakışma eki doğru adı bozdu "
                 "(aynı ad ikilide daha önce başka bir anahtara verilmişti)"),
    (S_SONEK, "N ya da R, bir GT adının ilk `.` ya da `@`'den sonrası atılmış hâline eşit (hükmün tanımadığı "
              "derleyici / sürüm soneki)"),
    (S_HARF, "N ya da R ile bir GT adı yalnız büyük/küçük harf ve alfasayısal olmayan karakterlerde ayrışıyor"),
    (S_BASKA, "N ya da R, aynı ikilide BAŞKA bir adresteki GT fonksiyonunun adı (klon tabanı dahil); alt sınıf "
              "o fonksiyonla ilişki: `cagrilan`, `cagiran`, `komsu` (adres sırasında bitişik), `uzak`"),
    (S_ICE, "N ya da R, ikilinin içe aktardığı (thunk / dış) bir fonksiyonun adı; alt sınıf: bu fonksiyon onu "
            "çağırıyor mu"),
    (S_KATALOG, "N ya da R, tohum kataloglarındaki (gnulib parmak izi, çağrı biçimi, ayrıştırma, ELF önyükü) bir "
                "ad, ama ikilinin GT'sinde hiçbir adreste yok (yanlış parmak izi)"),
    (S_ONEK, "N'nin belirteç dizisi bir GT adınınkinin başı ya da sonu (ya da tersi): yalnız önek / sonek farkı"),
    (S_ILGISIZ, "yukarıdakilerin hiçbiri"),
)
SINIF_ADLARI = tuple(s for s, _ in SINIFLAR)
# GT'de karşılığı olmayan adın alt sınıfı
GT_YOK_ONCEKI = "onceki_gt_fonksiyonunun_adi"   # adres, o adı taşıyan GT fonksiyonundan sonraki ilk boşlukta
GT_YOK_BASKA = "ad_ikilide_baska_adreste"
GT_YOK_CRT = "crt_adi"                          # ad bir CRT adı (function_f1.is_crt_name)
GT_YOK_DIGER = "diger"
# GT fonksiyonunun türü (yanlış ve doğru adlar için ortak öznitelik)
GT_TURLERI = ("gt_yok", "export", "klon", "crt", "parca", "program")

# ---- Yakınlık ölçüleri (kebap_ad ve api_param_reverse için; GT'li, yalnız çözümleme) ----
YAKINLIK = (
    ("norm_esit", "küçük harf + alfasayısal olmayanlar atılınca eşit"),
    ("belirtec_kumesi_esit", "belirteç kümeleri eşit (sıra farklı olabilir)"),
    ("urun_belirtecleri_gt_icinde", "ürün adının bütün belirteçleri GT adında var (GT'de fazlası var)"),
    ("gt_belirtecleri_urun_icinde", "GT adının bütün belirteçleri ürün adında var"),
    ("alt_dizi", "normalleştirilmiş adlardan biri öbürünün alt dizgisi (kısa olan ≥ 4 karakter)"),
    ("belirtec_kesisimi_var", "en az bir ortak belirteç (≥ 3 karakter)"),
    ("ortak_belirtec_yok", "ortak belirteç yok"),
)
JACCARD_KOVALARI = ("0", "(0;0,5)", "[0,5;1)", "1")

# ---- oz_ad özellikleri. Hepsi GT'siz: köken kaydı, Ghidra çıktısı ve KS-1 çıkarıcısından. ----
OZ_AD_OZELLIKLERI: tuple[tuple[str, str], ...] = (
    ("kanit_kaynagi", "kanıt dizgisi nereden okundu: `string_ref` (dizgi tablosu) | `body_literal`"),
    ("carpisma_eki", "ada çakışma eki eklendi mi (aynı ad ikilide daha önce verilmişti)"),
    ("dizgiyi_kullanan_fonksiyon", "kanıt dizgisini (aynı değer) kullanan fonksiyon sayısı (`ghidra_xrefs`): "
                                   "0 | 1 | 2 | 3+"),
    ("ayni_adi_oneren_fonksiyon", "ikilide aynı ham adı kazanan aday olarak alan fonksiyon sayısı: 1 | 2+"),
    ("govdede_gecis", "kanıt dizgisinin fonksiyonun ham decompile gövdesinde literal olarak geçiş sayısı: "
                      "0 | 1 | 2+"),
    ("cagri_argumani", "ilk geçişin yeri: `arg<k>/<ic|dis>` (çağrının k. argümanı; çağrılan `FUN_` ise ic) | "
                       "`cagri_disi` | `govdede_yok`"),
    ("oz_ad_bicimli_dizgi", "fonksiyonun kullandığı, oz_ad biçimli (alt çizgili, küçük harfli tanımlayıcı) farklı "
                            "dizgi sayısı: 1 | 2 | 3+"),
    ("fonksiyonun_dizgi_sayisi", "fonksiyonun kullandığı dizgi sayısı (`strings_used`): 0 | 1 | 2-3 | 4+"),
    ("ad_ghidra_adli", "ham ad, ikilide Ghidra'nın zaten adlandırdığı bir fonksiyonun (içe/dışa aktarım) adı mı"),
    ("dizgide_buyuk_harf", "kanıt dizgisinde büyük harf var mı (ad küçük harfe çevrildi)"),
    ("ikili_adi_onekli", "ham adın ilk belirteci ikili ya da program adının ilk belirtecine eşit mi"),
    ("ks1_capasi", "aynı adreste KS-1 çapası: `yok` | `ayni_ad` | `farkli_ad` (dizgi türü çapalar; parça dahil)"),
    ("aday_sayisi", "anahtarın aday sayısı (`n_candidates`): 1 | 2 | 3+"),
)
# Önceden yazılmış bileşik koşullar (tek özelliklerden sonra bakılacak; hepsi raporlanır)
OZ_AD_BILESIKLER: tuple[tuple[str, tuple[tuple[str, tuple[str, ...]], ...]], ...] = (
    ("tek_fonksiyon_ve_eksiz", (("dizgiyi_kullanan_fonksiyon", ("1",)), ("carpisma_eki", ("hayir",)))),
    ("tek_fonksiyon_ve_tek_oz_ad_dizgisi", (("dizgiyi_kullanan_fonksiyon", ("1",)),
                                             ("oz_ad_bicimli_dizgi", ("1",)), ("carpisma_eki", ("hayir",)))),
    ("ks1_ayni_ad", (("ks1_capasi", ("ayni_ad",)),)),
    ("ks1_yok_ve_tek_fonksiyon", (("ks1_capasi", ("yok",)), ("dizgiyi_kullanan_fonksiyon", ("1",)),
                                  ("carpisma_eki", ("hayir",)))),
    ("ks1_yok", (("ks1_capasi", ("yok",)),)),
)
# SONRADAN eklenen bileşikler: tek özellik tabloları görüldükten sonra yazıldı (aynı veride seçildikleri
# için aşırı uyuma en açık satırlar). Kararları aynı kuralla verilir, çıktıda ayrı işaretlenir.
_OZ_TEMIZ = (("dizgiyi_kullanan_fonksiyon", ("1",)), ("oz_ad_bicimli_dizgi", ("1",)), ("carpisma_eki", ("hayir",)))
_OZ_SONRAKI_ARG = ("cagri_argumani", ("arg1/ic", "arg2+/dis", "arg2+/ic"))   # çağrının ilk argümanı değil
_OZ_KS1_YOK = ("ks1_capasi", ("yok",))
OZ_AD_SONRADAN: tuple[tuple[str, tuple[tuple[str, tuple[str, ...]], ...]], ...] = (
    ("tek_tek_eksiz_ve_ks1_yok", _OZ_TEMIZ + (_OZ_KS1_YOK,)),
    ("tek_tek_eksiz_ve_az_dizgi", _OZ_TEMIZ + (("fonksiyonun_dizgi_sayisi", ("1", "2-3")),)),
    ("sonraki_arguman", (_OZ_SONRAKI_ARG,)),
    ("sonraki_arguman_ve_ks1_yok", (_OZ_SONRAKI_ARG, _OZ_KS1_YOK)),
    ("tek_tek_eksiz_ve_sonraki_arguman", _OZ_TEMIZ + (_OZ_SONRAKI_ARG,)),
    ("tek_tek_eksiz_ve_sonraki_arguman_ve_ks1_yok", _OZ_TEMIZ + (_OZ_SONRAKI_ARG, _OZ_KS1_YOK)),
)

# ---- Ön ad özellikleri (GT'siz) ----
ON_AD_OZELLIKLERI: tuple[tuple[str, str], ...] = (
    ("tur", "ön adın türü (tohum katmanı)"),
    ("katalog_girdisi", "adı veren katalog girdisinin ürün kodundaki sıra numarası "
                        "(`GNULIB_FINGERPRINTS[i]`, `GNULIB_CALL_SHAPES[i]`, `GNULIB_DISAMBIGUATORS[i]`, "
                        "`ELF_BOILERPLATE_SHAPES[i]`)"),
    ("temizleyici_degistirdi", "ham ad temizlenince değişti mi (R ≠ N)"),
    ("ikilide_gnulib_dizgi_isabeti", "ikilide dizgi parmak iziyle kurtarılan gnulib adı sayısı: 0 | 1 | 2 | 3+"),
    ("ad_ghidra_adli", "ham ad, ikilide Ghidra'nın zaten adlandırdığı bir fonksiyonun adı mı"),
    ("ks1_capasi", "aynı adreste KS-1 çapası: `yok` | `ayni_ad` | `farkli_ad`"),
)
# SONRADAN eklenen ön ad koşulları (tür tablosu görüldükten sonra):
#   gnulib_ikilisi: gnulib adı ve ikilide ≥ 3 dizgi parmak izi isabeti (ikili gnulib kullanıyor görünüyor);
#   sifir_dogrulu_girdiler_haric: gnulib adı ve katalog girdisi, bu veride n ≥ N_MIN iken hiç doğru vermeyen
#   girdilerden değil (girdi seçimi AYNI veride yapıldı: en iyimser satır).
ON_AD_GNULIB_ISABET_ESIGI = "3+"

# ---- Kural adayı kararı [seçim; sayımdan önce yazıldı] ----
KESINLIK_ESIGI = ks1.KESINLIK_ESIGI   # 0,95
N_MIN = ks1.N_MIN                     # bir programın "giren" sayılması için en az ad
EN_AZ_PROGRAM = ks1.EN_AZ_PROGRAM     # en az bu kadar FARKLI program N_MIN'i geçmeli
KARAR_ONERI = "oneri"                 # kesinlik ≥ eşik VE Wilson %95 alt sınırı ≥ eşik VE program çeşitliliği
KARAR_YETERSIZ = "yetersiz"           # kesinlik ≥ eşik ama alt sınır ya da program çeşitliliği tutmuyor
KARAR_TUTMUYOR = "tutmuyor"           # kesinlik < eşik
NEDEN_WILSON = "wilson_alt_siniri_esigin_altinda"
NEDEN_PROGRAM = "program_cesitliligi_yok"
# Susturma: ürünün kendi kuralı ("yalnız zayıflar"; N0b ve ``baglama.WRONG_RATE_TARGET``): yanlış oranının
# Wilson %95 alt sınırı bu hedefin üstündeyse kanal / koşul susar.
SUSTURMA_HEDEFI = baglama.WRONG_RATE_TARGET

# ---- Sayım görüldükten SONRA yapılan değişiklikler (belgeye aynen yazılır) ----
SONRADAN_DEGISIKLIKLER: tuple[str, ...] = (
    "Sınıflama: `oz_ad`'da `baska_fonksiyonun_adi`, `ice_aktarilan_adi`, `katalog_adi` ve `gt_yok` alt sınıfı "
    "sınamalarına kanıt dizgisinin kendisi (özgün harfleriyle) de aday olarak eklendi. İlk tanım yalnız ürün "
    "adına (küçük harf) bakıyordu; elle denetimde `oz_ad` / `ilgisiz` sınıfındaki 53 adın 4'ünün, harf farkıyla, "
    "ikilideki başka bir fonksiyonun (3) ya da içe aktarılan bir fonksiyonun (1) adı olduğu, `oz_ad` / "
    "`onek_sonek_farki` sınıfındaki 6 adın 1'inin de yine harf farkıyla başka bir fonksiyonun adı olduğu görüldü. "
    "Öbür sınıfların tanımı ve sırası değişmedi.",
    "`oz_ad` tablolarına ikinci hüküm sütunu eklendi (kanıt dizgisi olduğu gibi yazılsa): yanlışların en büyük "
    "sınıfının yalnız harf farkı olduğu görüldükten sonra.",
    "`oz_ad` için altı bileşik koşul (`OZ_AD_SONRADAN`) ve \"KS-1 çapası yok\" katmanlaması, ön adlar için gnulib "
    "koşulları (`on_ad.sonradan`) tek özellik tabloları görüldükten sonra yazıldı. Bu satırlar çıktıda "
    "`sonradan` diye işaretlidir; aynı veride seçildikleri için en iyimser satırlardır.",
    "Sınıf tablosuna `Tekil ad` sütunu eklendi (örnek düzeyi sayımın coreutils'te aynı hatayı yüzü aşkın kez "
    "saydığı görüldükten sonra).",
)

# ---- Sınırlar ve doğrulanamayanlar (belgeye aynen yazılır) ----
SINIRLAR: tuple[str, ...] = (
    "Ön ad türü köken kaydından okunmadı (saklı koşularda yazılı değil); tohum fonksiyonları BUGÜNKÜ kodla "
    "(HEAD) saklı `static/` çıktısında yeniden çağrıldı. Yeniden üretimin koşudakiyle aynı olduğu iki yoldan "
    "denetlendi (koşunun sayaçları, köken kaydındaki ham ad); anahtar düzeyinde başka kanıt yok.",
    "`ks1_capasi` özelliği KS-1 çıkarıcısının (`kesin.py`) bugünkü çıktısıdır: çapanın VARLIĞI. Üründe hangi "
    "karar satırlarının ad vereceği (`baglama.ROW_STATUS`) bu çözümlemenin dışında; bugün dört satır da susuyor.",
    "\"Kanıt dizgisi olduğu gibi yazılsa\" ve \"çakışma eki eklenmese\" karşı olguları ad tekliğini yok sayar: aynı "
    "ad ikilide iki fonksiyona yazılamaz. Çakışma ekli adlarda bu hüküm ulaşılabilir olanın üst sınırıdır; "
    "`carpisma_eki = hayir` koşulunu taşıyan satırlarda bu sorun yoktur.",
    "`cagri_argumani` ve `govdede_gecis` ham decompile metninde basit bir ayrıştırmayla bulunur (literali saran "
    "ilk açık parantez). Belirlenimci seçilen 24 `oz_ad` örneğinde elle bakıldı: 24 örnekte de doğru; 6 örnek "
    "`govdede_yok` idi ve hepsi Mach-O. Mach-O'da dizgi gövdede çoğu kez literal değil simge olarak geçiyor "
    "(`govdede_yok`: mac/tmux {mac_yok}, debian birimleri toplamı {debian_yok}); bu iki özellik Mac'te zayıf.",
    "Kanal başına veri dengesiz (§1): ön adlarda coreutils'in payı {on_ad_pay} (106 ikili, ortak kitaplık); "
    "tmux'un payı `oz_ad`'da {oz_ad_pay}, `kebap_ad`'da {kebap_pay} (aynı programın iki platform birimi). "
    "\"Tek program\" notu bu yüzden sık; program düzeyi genelleme bu veriyle yapılamaz.",
    "Elle denetimi tek kişi (bu çözümlemeyi yapan) yaptı; ikinci değerlendirici yok.",
    "Doğrulama ve test setleri açılmadı; hiçbir koşul taze veride sınanmadı.",
)

# ---- Elle denetim. Sayılar elle girildi (uçbirimde ``ornek`` çıktısı okunarak); ad yazılmadı. ----
# sınıf → (incelenen örnek, sınıflayıcının yanlış koyduğu). İlk tanımla (değişiklik 1'den önce) yapıldı.
ELLE_DENETIM: dict[str, tuple[int, int]] = {
    S_GT_YOK: (1, 0),
    S_TEMIZLEYICI: (10, 0),
    S_CARPISMA: (8, 0),
    S_HARF: (45, 0),
    S_BASKA: (27, 0),
    S_KATALOG: (15, 0),
    S_ONEK: (16, 1),
    S_ILGISIZ: (144, 4),
}
ELLE_DENETIM_NOTLARI: tuple[str, ...] = (
    "Kapsam: `on_ad` `temizleyici_farki` 10, `baska_fonksiyonun_adi` 14, `katalog_adi` 15 (hepsi); `oz_ad` "
    "yanlışlarının tamamı (125); `kebap_ad` 40 örnek + `onek_sonek_farki` 8 (hepsi) + `gt_yok` 1 (hepsi); "
    "`api_param_reverse` yanlışlarının tamamı (55). `sonek_farki` ve `ice_aktarilan_adi` ilk tanımda boştu.",
    "Yanlış konan 5 adın hepsi `oz_ad`'daydı (`ilgisiz` 4, `onek_sonek_farki` 1): tanım değişikliği 1 ile "
    "`baska_fonksiyonun_adi` (4) ve `ice_aktarilan_adi` (1) sınıflarına geçtiler; değişiklikten sonra bu 5 ad "
    "yeniden okundu, yeni sınıfları doğru. Tablodaki sayılar ilk tanımla yapılan denetimindir.",
    "`ilgisiz` mekanik bir artık sınıftır, anlam sınıfı değildir. Okunan örneklerde üç ayrı şey var: (a) `oz_ad`'da "
    "GT'de simgesi olmayan (satır içine alınmış) bir fonksiyonun adı ya da bir değişken / biçim anahtarı adı; "
    "(b) `kebap_ad`'da seçenek ve kanca adları; (c) `api_param_reverse`'te geri çağrı rolü adları (karşılaştırıcı, "
    "sinyal işleyici, olay geri çağrısı). (a)'nın iki alt durumu GT simgesinden ayırt edilemez; sayılmadı.",
    "`baska_fonksiyonun_adi` alt sınıfı (`cagrilan` / `cagiran` / `komsu` / `uzak`) yalnız doğrudan çağrı "
    "kenarına bakar; iki adım uzaktaki çağıran `uzak` görünür (ön adlarda 104 örnek böyle).",
)
ORNEK_SAYISI = 10

ONDALIK = ks1.ONDALIK


# --------------------------------------------------------------------------------------------
# Küçük yardımcılar


def oran(k: int, n: int) -> dict[str, Any]:
    return ks1.oran(k, n)


def norm(ad: str) -> str:
    """Küçük harf, alfasayısal olmayanlar atılmış."""
    return re.sub(r"[^a-z0-9]", "", ad.lower())


_DEVE_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def belirtecler(ad: str) -> list[str]:
    """Belirteç dizisi: deveHörgücü sınırı ve alfasayısal olmayan karakterlerde bölünür, küçük harf."""
    return [p.lower() for p in re.split(r"[^A-Za-z0-9]+", _DEVE_RE.sub("_", ad)) if p]


def sonek_soy(ad: str) -> str:
    """İlk ``.`` ya da ``@``'den sonrası atılır (boş kalırsa adın kendisi)."""
    return re.sub(r"[.@].*$", "", ad) or ad


def kova(n: int, sinirlar: tuple[int, ...]) -> str:
    """``n`` için kova adı: sınırların altındaysa sayının kendisi, son sınırdan itibaren ``<s>+``."""
    return str(n) if n < sinirlar[-1] else f"{sinirlar[-1]}+"


def evet_hayir(b: bool) -> str:
    return "evet" if b else "hayir"


def _sirali_ornek(ogeler: list[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    """Belirlenimci örnek: (birim, ikili, adres) özetine göre sıralanıp ilk ``n``."""
    def anahtar(k: dict[str, Any]) -> str:
        return hashlib.sha256(f"{k['birim']}/{k['ikili']}/{k['adres']:x}".encode()).hexdigest()
    return sorted(ogeler, key=anahtar)[:n]


# --------------------------------------------------------------------------------------------
# Ön ad türü: tohumların saklı static/ üzerinde yeniden üretimi


class _Iz(dict):
    """Yazılanları sırasıyla kaydeden sözlük (tohum fonksiyonları ``d[k] = v`` ile yazar)."""

    def __init__(self, *a: Any) -> None:
        super().__init__(*a)
        self.yazilan: list[tuple[str, str]] = []

    def __setitem__(self, k: str, v: str) -> None:
        self.yazilan.append((k, v))
        super().__setitem__(k, v)


def _katalog_dizini() -> dict[str, dict[str, str]]:
    """Tür → {ad → katalog sıra numarası}. Aynı ad birden çok girdideyse numaralar ``+`` ile."""
    def dizin(girdiler: Iterable[Any]) -> dict[str, str]:
        out: dict[str, list[str]] = {}
        for i, g in enumerate(girdiler):
            out.setdefault(g.name, []).append(str(i))
        return {ad: "+".join(ns) for ad, ns in out.items()}
    return {TUR_GNULIB_DIZGI: dizin(gnulib_fingerprints.GNULIB_FINGERPRINTS),
            TUR_GNULIB_CAGRI: dizin(gnulib_fingerprints.GNULIB_CALL_SHAPES),
            TUR_GNULIB_AYRISTIRMA: dizin(gnulib_fingerprints.GNULIB_DISAMBIGUATORS),
            TUR_ELF_ONYUK: dizin(elf_boilerplate.ELF_BOILERPLATE_SHAPES)}


KATALOG = _katalog_dizini()
KATALOG_ADLARI = frozenset(ad for d in KATALOG.values() for ad in d)
YINELEME_SAYACLARI = ("gnulib_recovered", "gnulib_callshape_recovered", "gnulib_disambiguated",
                      "elf_boilerplate_recovered")


def tohumlari_yinele(static: Path, faz1: dict[str, str]) -> tuple[dict[str, tuple[str, str]], dict[str, Any]]:
    """Tohumları ürünün sırasıyla (giriş fonksiyonu → gnulib → ELF önyükü) yeniden çağır.

    Döner: anahtar → (tür, ad) ve tohumların yazdığı sayaçlar. Faz 1 adları (varsa) önceden
    sözlüktedir; tohumlar dolu yuvaya yazmaz (giriş fonksiyonu tohumu hariç), ürünle aynı.
    """
    from karadul.stages import ReconstructionStage
    asama = ReconstructionStage.__new__(ReconstructionStage)   # tohumlar örnek durumunu okumaz
    iz = _Iz(faz1)
    sayac: dict[str, Any] = {}
    turler: dict[str, tuple[str, str]] = {}
    asama._recover_main_from_entry(iz, static, sayac)
    for k, v in iz.yazilan:
        turler[k] = (TUR_MAIN, v)
    bas = len(iz.yazilan)
    asama._recover_gnulib_from_fingerprints(iz, static, sayac)
    gnulib = iz.yazilan[bas:]
    n_dizgi = int(sayac.get("gnulib_recovered", 0))
    n_cagri = int(sayac.get("gnulib_callshape_recovered", 0))
    n_ayr = int(sayac.get("gnulib_disambiguated", 0))
    if len(gnulib) != n_dizgi + n_cagri + n_ayr:
        raise ks1.OnkosulHatasi(f"{static}: gnulib tohumunun yazdığı ad sayısı sayaçlarıyla tutmuyor")
    for i, (k, v) in enumerate(gnulib):
        tur = TUR_GNULIB_DIZGI if i < n_dizgi else (TUR_GNULIB_CAGRI if i < n_dizgi + n_cagri
                                                     else TUR_GNULIB_AYRISTIRMA)
        turler[k] = (tur, v)
    bas = len(iz.yazilan)
    asama._recover_elf_boilerplate(iz, static, sayac)
    for k, v in iz.yazilan[bas:]:
        turler[k] = (TUR_ELF_ONYUK, v)
    return turler, sayac


def faz1_adlari(kosu: Path) -> dict[str, dict[str, Any]]:
    """``reconstructed/binary_names.json``: anahtar → {recovered, source}; dosya yoksa boş."""
    yol = Path(kosu) / "reconstructed" / "binary_names.json"
    if not yol.is_file():
        return {}
    adlar = uo._json(yol).get("names") or {}
    return {k: v for k, v in adlar.items() if isinstance(v, dict) and v.get("recovered")}


def kosu_sayaclari(kosu: Path) -> dict[str, Any]:
    try:
        return uo._json(Path(kosu) / "reports" / "pipeline_result.json")["stages"]["reconstruct"]["stats"]
    except (OSError, ValueError, KeyError):
        return {}


# --------------------------------------------------------------------------------------------
# İkili bağlamı (GT'li ve GT'siz dizinler)


class Ikili:
    """Bir ikilinin çözümleme bağlamı. Adlar yalnız bellekte tutulur."""

    def __init__(self, e: Any, gt: Any, fonk_ham: list[dict[str, Any]]) -> None:
        f1 = ks1._f1()
        self.birim = ks1.birim_anahtari(e)
        self.program = e.program
        self.ad = e.ad
        self.platform = e.platform
        self.static = Path(e.static)
        self.kosu = Path(e.kosu)
        self.gt_ham: dict[int, list[str]] = gt.adlar
        self.gt_adlar = {a: [ks1.platform_adi(n, e.platform) for n in ns] for a, ns in gt.adlar.items()}
        self.gt_export = gt.export_gt
        self.gt_sirali = sorted(self.gt_adlar)
        dizin: dict[str, set[int]] = {}
        for a, ns in self.gt_adlar.items():
            for n in ns:
                dizin.setdefault(n, set()).add(a)
                taban = ks1.klon_tabani(n)
                if taban:
                    dizin.setdefault(taban, set()).add(a)
        self.ad_dizini = dizin
        self.ice_aktarilan = {ks1.platform_adi(str(f.get("name") or ""), e.platform) for f in fonk_ham
                              if f.get("is_thunk") or f.get("is_external")}
        self.ghidra_adli: set[str] = set()
        for f in fonk_ham:
            ad, adres = str(f.get("name") or ""), f.get("address")
            if ad and adres not in (None, "") and not f1.is_generic_name(ad, [int(str(adres), 16)]):
                self.ghidra_adli.add(ks1.platform_adi(ad, e.platform))
        self.cagrilan: dict[int, set[int]] = {}
        self.cagiran: dict[int, set[int]] = {}
        self.cagrilan_ad: dict[int, set[str]] = {}
        dugumler = uo._json(self.static / "ghidra_call_graph.json").get("nodes") or {}
        for adres, d in dugumler.items():
            a = int(str(adres), 16)
            self.cagrilan[a] = {int(str(c["address"]), 16) for c in d.get("callees") or []
                                if _onaltilik_mi(c.get("address"))}
            self.cagiran[a] = {int(str(c["address"]), 16) for c in d.get("callers") or []
                               if _onaltilik_mi(c.get("address"))}
            self.cagrilan_ad[a] = {ks1.platform_adi(str(c.get("name") or ""), e.platform)
                                   for c in d.get("callees") or []}
        self.on_ad_turu: dict[str, tuple[str, str]] = {}
        self.yineleme: dict[str, Any] = {}
        self._dizgiler: Optional[tuple[dict[int, list[str]], Counter]] = None
        self._capalar: Optional[dict[int, Any]] = None
        self.ham_ad_sayaci: Counter = Counter()      # string_context kazananlarının ham adı → fonksiyon sayısı

    def dizgiler(self) -> tuple[dict[int, list[str]], Counter]:
        """(fonksiyon adresi → kullandığı dizgi değerleri, dizgi değeri → kullanan fonksiyon sayısı)."""
        if self._dizgiler is None:
            fx = uo._json(self.static / "ghidra_xrefs.json").get("function_xrefs") or {}
            kullanim: dict[int, list[str]] = {}
            sayac: Counter = Counter()
            for adres, d in fx.items():
                degerler = [str(s.get("value")) for s in d.get("strings_used") or [] if s.get("value") is not None]
                kullanim[int(str(adres), 16)] = degerler
                sayac.update(set(degerler))
            self._dizgiler = (kullanim, sayac)
        return self._dizgiler

    def govde(self, anahtar: str) -> str:
        yol = self.static / "ghidra_output" / "decompiled" / f"{anahtar}.c"
        try:
            return yol.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def capalar(self) -> dict[int, Any]:
        """KS-1 çapaları (GT'siz), adres → çapa; yalnız dizgi türleri (export tek başına çapa sayılmaz)."""
        if self._capalar is None:
            kesin = _kesin()
            r = kesin.extract_anchors(self.static)
            self._capalar = {int(a, 16): c for a, c in r.anchors.items()
                             if set(c.types) & set(kesin.STRING_TYPES)}
        return self._capalar


_KESIN: Any = None


def _kesin() -> Any:
    global _KESIN
    if _KESIN is None:
        _KESIN = ks1.kesin_modulu()
    return _KESIN


def _onaltilik_mi(deger: Any) -> bool:
    try:
        int(str(deger), 16)
        return True
    except (TypeError, ValueError):
        return False


def grup_bul(kanal: str) -> str:
    if kanal == KANAL_ON_AD or kanal.startswith("on_ad:"):
        return GRUP_ON_AD
    return {KANAL_OZ_AD: GRUP_OZ_AD, KANAL_KEBAP: GRUP_KEBAP, KANAL_API: GRUP_API}.get(kanal, GRUP_DIGER)


def yukle(kok_debian: Optional[Path], kok_mac: Optional[Path], mac_veri: Path,
          indir: Path) -> tuple[list[Ikili], list[dict[str, Any]], dict[str, Any]]:
    """Bütün ikilileri ``urun_olc`` yoluyla oku; (ikililer, kalan kanalların kayıtları, künye)."""
    elfler = uo.haritasizlari_isaretle(ks1.elfleri_topla(kok_mac, kok_debian))
    ks1.nufus_denetle(elfler, ks1.BEKLENEN_ELF, False)
    f1 = ks1._f1()
    ikililer: list[Ikili] = []
    kayitlar: list[dict[str, Any]] = []
    butun = Counter()
    cpp: list[str] = []
    for e in elfler:
        fonk_ham = uo._json(Path(e.static) / "ghidra_functions.json").get("functions", [])
        if ks1.cpp_ikili_mi(fonk_ham, e.platform):
            cpp.append(f"{ks1.birim_anahtari(e)}/{e.ad}")
            continue
        genel, koken, _ = uo.haritayi_oku(e.kosu)
        gt = ks1.gt_mac(e, mac_veri) if e.platform == ks1.PLATFORM_MAC else ks1.gt_elf(e, indir)
        gfonk = f1.load_ghidra_functions(Path(e.static) / "ghidra_functions.json")
        olculen, _ = uo.degerlendir_elf(genel, koken, gfonk, gt, e.platform)
        b = Ikili(e, gt, fonk_ham)
        anahtarlar = {}
        for anahtar in genel:
            sinif_, adres = uo.anahtar_sinifi(anahtar)
            if sinif_ == uo.SINIF_FONKSIYON:
                anahtarlar[adres] = anahtar
        for anahtar, kayit in koken.items():
            if (isinstance(kayit, dict) and kayit.get("source") == "candidate"
                    and kayit.get("strategy") == naming_labels.STRATEGY_STRING_CONTEXT
                    and uo.anahtar_sinifi(anahtar)[0] == uo.SINIF_FONKSIYON):
                b.ham_ad_sayaci[str(kayit.get("proposed_name") or kayit.get("new_name") or "")] += 1
        var_kalan = False
        for k in olculen:
            butun["ad_verilen"] += 1
            butun["dogru"] += int(k["durum"] == DOGRU)
            if uo.kanal_grubu(k["kanal"]) != uo.GRUP_KALAN:
                continue
            anahtar = anahtarlar[k["adres"]]
            kayit = koken.get(anahtar) or {}
            kayitlar.append({**k, "birim": b.birim, "program": b.program, "ikili": b.ad, "anahtar": anahtar,
                             "kayit": kayit, "ham": str(kayit.get("proposed_name") or k["ad"]),
                             "grup": grup_bul(k["kanal"]), "b": len(ikililer)})
            var_kalan = True
        if var_kalan and any(k["grup"] == GRUP_ON_AD for k in kayitlar if k["b"] == len(ikililer)):
            faz1 = faz1_adlari(b.kosu)
            turler, sayac = tohumlari_yinele(b.static, {k: str(v["recovered"]) for k, v in faz1.items()})
            for anahtar, v in faz1.items():
                turler.setdefault(anahtar, (f"{TUR_FAZ1}/{v.get('source') or 'bilinmiyor'}", str(v["recovered"])))
            b.on_ad_turu = turler
            saklanan = kosu_sayaclari(b.kosu)
            b.yineleme = {
                "sayac_tutuyor": all(int(sayac.get(a, 0)) == int(saklanan.get(a, 0)) for a in YINELEME_SAYACLARI),
                "main_tutuyor": sayac.get("main_recovered") == saklanan.get("main_recovered")}
        ikililer.append(b)
    return ikililer, kayitlar, {"butun": dict(butun), "cpp_disarida": sorted(cpp),
                                "ikili": len(ikililer)}


# --------------------------------------------------------------------------------------------
# Sınıflama (GT'li)


def dogru_mu(ad: str, b: Ikili, adres: int) -> bool:
    return ks1.capa_degerlendir(ad, b.gt_ham[adres], b.platform)["durum"] == DOGRU


def gt_turu(k: dict[str, Any], b: Ikili) -> str:
    adres = k["adres"]
    if adres not in b.gt_adlar:
        return "gt_yok"
    if adres in b.gt_export:
        return "export"
    if k["satir"] == ks1.SATIR_KLON:
        return "klon"
    adlar = b.gt_adlar[adres]
    if b.platform == ks1.PLATFORM_MAC:
        mf = ks1._mf()
        return "program" if mf.fragment_class(b.gt_ham[adres]) == mf.CLASS_PROGRAM else "parca"
    return "crt" if all(ks1._f1().is_crt_name(n) for n in adlar) else "program"


def _iliski(b: Ikili, adres: int, sahipler: set[int]) -> str:
    if sahipler & b.cagrilan.get(adres, set()):
        return "cagrilan"
    if sahipler & b.cagiran.get(adres, set()):
        return "cagiran"
    i = bisect.bisect_left(b.gt_sirali, adres)
    komsular = set()
    if i < len(b.gt_sirali) and b.gt_sirali[i] == adres:
        komsular.update(b.gt_sirali[max(0, i - 1):i] + b.gt_sirali[i + 1:i + 2])
    else:
        komsular.update(b.gt_sirali[max(0, i - 1):i + 1])
    return "komsu" if sahipler & komsular else "uzak"


def _onek_sonek(urun: str, gt_adlari: Iterable[str]) -> Optional[str]:
    """Belirteç dizisi (ya da normalleştirilmiş dizgi, kısa olan ≥ 4) başta ya da sonda örtüşüyor mu."""
    tu, nu = belirtecler(urun), norm(urun)
    for g in gt_adlari:
        tg, ng = belirtecler(sonek_soy(g)), norm(sonek_soy(g))
        if not tu or not tg or tu == tg:
            continue
        if len(tu) < len(tg):
            if tg[-len(tu):] == tu:
                return "urunde_onek_eksik"
            if tg[:len(tu)] == tu:
                return "urunde_sonek_eksik"
        elif len(tu) > len(tg):
            if tu[-len(tg):] == tg:
                return "urunde_onek_fazla"
            if tu[:len(tg)] == tg:
                return "urunde_sonek_fazla"
        if nu != ng and min(len(nu), len(ng)) >= 4:
            if ng.endswith(nu):
                return "urunde_onek_eksik"
            if ng.startswith(nu):
                return "urunde_sonek_eksik"
            if nu.endswith(ng):
                return "urunde_onek_fazla"
            if nu.startswith(ng):
                return "urunde_sonek_fazla"
    return None


def sinifla(k: dict[str, Any], b: Ikili) -> tuple[str, str]:
    """Yanlış bir adın (sınıf, alt sınıf)'ı. İlk tutan kazanır (``SINIFLAR`` sırası)."""
    n, r, adres = k["ad"], k["ham"], k["adres"]
    adaylar = (r, n) if r != n else (n,)
    # Sonradan değişiklik 1: oz_ad'da ad, kanıt dizgisinin küçük harfli hâlidir; "başka fonksiyonun adı",
    # "içe aktarılan adı" ve "katalog adı" sınamalarına kanıt dizgisi (özgün harfleriyle) de girer.
    kanit = str(k["kayit"].get("evidence") or "").strip() if k["grup"] == GRUP_OZ_AD else ""
    genis = adaylar + ((kanit,) if kanit and kanit not in adaylar else ())
    g = b.gt_adlar.get(adres)
    if g is None:
        i = bisect.bisect_left(b.gt_sirali, adres)
        onceki = b.gt_sirali[i - 1] if i > 0 else None
        onceki_adlar: set[str] = set()
        if onceki is not None:
            for ad in b.gt_adlar[onceki]:
                onceki_adlar.add(ad)
                onceki_adlar.add(ks1.klon_tabani(ad) or ad)
        if any(a in onceki_adlar for a in genis):
            return S_GT_YOK, GT_YOK_ONCEKI
        if any(a in b.ad_dizini for a in genis):
            return S_GT_YOK, GT_YOK_BASKA
        if any(ks1._f1().is_crt_name(a) for a in genis):
            return S_GT_YOK, GT_YOK_CRT
        return S_GT_YOK, GT_YOK_DIGER
    if r != n and dogru_mu(r, b, adres):
        if re.fullmatch(re.escape(r) + r"_\d+", n):
            return S_CARPISMA, "ek"
        if r.strip("_") == n:
            return S_TEMIZLEYICI, "bas_son_alt_cizgi"
        if r.lower() == n:
            return S_TEMIZLEYICI, "kucuk_harf"
        if r.strip("_").lower() == n:
            return S_TEMIZLEYICI, "alt_cizgi_ve_kucuk_harf"
        return S_TEMIZLEYICI, "diger"
    soyulmus = [sonek_soy(x) for x in g]
    if any(a in soyulmus for a in adaylar):
        return S_SONEK, "klon_satiri" if k["satir"] == ks1.SATIR_KLON else "ana_satir"
    if any(norm(a) == norm(x) for a in adaylar for x in soyulmus):
        yalniz_harf = any(a.lower() == x.lower() for a in adaylar for x in soyulmus)
        return S_HARF, "yalniz_harf" if yalniz_harf else "alt_cizgi_ya_da_ayrac"
    sahipler: set[int] = set()
    for a in genis:
        sahipler |= b.ad_dizini.get(a, set())
    sahipler.discard(adres)
    if sahipler:
        return S_BASKA, _iliski(b, adres, sahipler)
    if any(a in b.ice_aktarilan for a in genis):
        cagiriyor = any(a in b.cagrilan_ad.get(adres, set()) for a in genis)
        return S_ICE, "cagiriyor" if cagiriyor else "cagirmiyor"
    if any(a in KATALOG_ADLARI for a in genis):
        return S_KATALOG, "katalog"
    for a in adaylar:
        alt = _onek_sonek(a, g)
        if alt:
            return S_ONEK, alt
    return S_ILGISIZ, "ilgisiz"


def yakinlik(k: dict[str, Any], b: Ikili) -> dict[str, Any]:
    """Yanlış adın GT adına mekanik yakınlığı (en yakın GT adına göre). GT yoksa ``None``."""
    g = b.gt_adlar.get(k["adres"])
    if g is None:
        return {"olcu": "gt_yok", "jaccard": None}
    adaylar = {k["ad"], k["ham"]}
    en_iyi, en_iyi_j = len(YAKINLIK) - 1, 0.0
    sira = [ad for ad, _ in YAKINLIK]
    for a in sorted(adaylar):
        ta, na = set(t for t in belirtecler(a) if len(t) >= 3), norm(a)
        for x in g:
            x = sonek_soy(x)
            tx, nx = set(t for t in belirtecler(x) if len(t) >= 3), norm(x)
            j = len(ta & tx) / len(ta | tx) if ta | tx else 0.0
            en_iyi_j = max(en_iyi_j, j)
            if na == nx:
                olcu = "norm_esit"
            elif ta and ta == tx:
                olcu = "belirtec_kumesi_esit"
            elif ta and ta < tx:
                olcu = "urun_belirtecleri_gt_icinde"
            elif tx and tx < ta:
                olcu = "gt_belirtecleri_urun_icinde"
            elif min(len(na), len(nx)) >= 4 and (na in nx or nx in na):
                olcu = "alt_dizi"
            elif ta & tx:
                olcu = "belirtec_kesisimi_var"
            else:
                olcu = "ortak_belirtec_yok"
            en_iyi = min(en_iyi, sira.index(olcu))
    j_kova = ("0" if en_iyi_j == 0 else "1" if en_iyi_j == 1 else "(0;0,5)" if en_iyi_j < 0.5 else "[0,5;1)")
    return {"olcu": sira[en_iyi], "jaccard": j_kova}


def ikilide_ad_var_mi(k: dict[str, Any], b: Ikili) -> dict[str, bool]:
    """Ürün adı ikilinin GT'sinde herhangi bir adreste var mı (tam / normalleştirilmiş / sonek olarak)."""
    adaylar = {k["ad"], k["ham"]}
    tam = any(a in b.ad_dizini for a in adaylar)
    normlar = {norm(a) for a in adaylar}
    norm_esit = sonek = False
    for ad in b.ad_dizini:
        na = norm(sonek_soy(ad))
        if na in normlar:
            norm_esit = True
        elif any(len(x) >= 4 and na.endswith(x) for x in normlar):
            sonek = True
    return {"tam": tam, "norm_esit": norm_esit, "sonek_olarak": sonek}


# --------------------------------------------------------------------------------------------
# GT'siz özellikler


_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_CAGRILAN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*$")
_CAGRI_OLMAYAN = frozenset({"if", "while", "for", "switch", "return", "sizeof"})


def cagri_argumani(govde: str, dizgi: str) -> tuple[int, str]:
    """(literalin gövdedeki geçiş sayısı, ilk geçişin yeri). Öbür literallerin içi maskelenir."""
    yerler = [m for m in _LITERAL_RE.finditer(govde) if m.group(1) == dizgi]
    if not yerler:
        return 0, "govdede_yok"
    maske = list(govde)
    for m in _LITERAL_RE.finditer(govde):
        for i in range(m.start(1), m.end(1)):
            maske[i] = " "
    metin = "".join(maske)
    i, derinlik, virgul = yerler[0].start() - 1, 0, 0
    while i >= 0:
        c = metin[i]
        if c in ")]":
            derinlik += 1
        elif c in "([":
            if derinlik == 0:
                break
            derinlik -= 1
        elif c == "," and derinlik == 0:
            virgul += 1
        elif c in ";{}" and derinlik == 0:
            return len(yerler), "cagri_disi"
        i -= 1
    if i < 0 or metin[i] != "(":
        return len(yerler), "cagri_disi"
    m = _CAGRILAN_RE.search(metin[:i])
    if not m or m.group(1) in _CAGRI_OLMAYAN:
        return len(yerler), "cagri_disi"
    tur = "ic" if m.group(1).startswith(("FUN_", "thunk_FUN_")) else "dis"
    return len(yerler), f"arg{kova(virgul, (0, 1, 2))}/{tur}"


def ks1_ozelligi(k: dict[str, Any], b: Ikili) -> str:
    capa = b.capalar().get(k["adres"])
    if capa is None:
        return "yok"
    return "ayni_ad" if capa.name in (k["ham"], k["ad"]) else "farkli_ad"


def oz_ad_ozellikleri(k: dict[str, Any], b: Ikili) -> dict[str, str]:
    kayit, r = k["kayit"], k["ham"]
    kanit = str(kayit.get("evidence") or "")
    kullanim, sayac = b.dizgiler()
    kullanan = sayac.get(kanit, 0)
    gecis, yer = cagri_argumani(b.govde(k["anahtar"]), kanit)
    fonk_dizgileri = kullanim.get(k["adres"], [])
    oz_bicimli = {d.strip() for d in fonk_dizgileri + [kanit]
                  if alt_kanal._is_underscored_identifier(d.strip()) and any(c.islower() for c in d.strip())}
    ilk = (belirtecler(r) or [""])[0]
    ikili_ilk = {(belirtecler(b.ad) or [""])[0], (belirtecler(b.program) or [""])[0]}
    return {
        "kanit_kaynagi": str(kayit.get("evidence_origin") or "bilinmiyor"),
        "carpisma_eki": evet_hayir("proposed_name" in kayit),
        "dizgiyi_kullanan_fonksiyon": kova(kullanan, (0, 1, 2, 3)),
        "ayni_adi_oneren_fonksiyon": kova(b.ham_ad_sayaci.get(r, 0), (1, 2)),
        "govdede_gecis": kova(gecis, (0, 1, 2)),
        "cagri_argumani": yer,
        "oz_ad_bicimli_dizgi": kova(len(oz_bicimli), (1, 2, 3)),
        "fonksiyonun_dizgi_sayisi": ("0" if not fonk_dizgileri else "1" if len(fonk_dizgileri) == 1
                                     else "2-3" if len(fonk_dizgileri) <= 3 else "4+"),
        "ad_ghidra_adli": evet_hayir(r in b.ghidra_adli),
        "dizgide_buyuk_harf": evet_hayir(any(c.isupper() for c in kanit)),
        "ikili_adi_onekli": evet_hayir(bool(ilk) and ilk in ikili_ilk),
        "ks1_capasi": ks1_ozelligi(k, b),
        "aday_sayisi": kova(int(kayit.get("n_candidates") or 0), (1, 2, 3)),
    }


def on_ad_turu(k: dict[str, Any], b: Ikili) -> str:
    kayit = k["kayit"]
    tur_kayitta = kayit.get("pre_name_kind")
    if tur_kayitta:                      # yeni koşu: tür köken kaydında
        return str(tur_kayitta)
    tur, ad = b.on_ad_turu.get(k["anahtar"], (TUR_BELIRSIZ, ""))
    return tur if ad == k["ham"] else TUR_BELIRSIZ


def on_ad_ozellikleri(k: dict[str, Any], b: Ikili) -> dict[str, str]:
    tur = on_ad_turu(k, b)
    girdi = KATALOG.get(tur, {}).get(k["ham"])
    isabet = sum(1 for t, _ in b.on_ad_turu.values() if t == TUR_GNULIB_DIZGI)
    return {
        "tur": tur,
        "katalog_girdisi": f"{tur}#{girdi}" if girdi is not None else f"{tur}#-",
        "temizleyici_degistirdi": evet_hayir(k["ham"] != k["ad"]),
        "ikilide_gnulib_dizgi_isabeti": kova(isabet, (0, 1, 2, 3)),
        "ad_ghidra_adli": evet_hayir(k["ham"] in b.ghidra_adli),
        "ks1_capasi": ks1_ozelligi(k, b),
    }


# --------------------------------------------------------------------------------------------
# Tablolar


def dy(kayitlar: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Doğru / yanlış özeti: sayılar, kesinlik ve Wilson %95."""
    ks = list(kayitlar)
    d = sum(1 for k in ks if k["durum"] == DOGRU)
    return {"n": len(ks), "dogru": d, "yanlis": len(ks) - d, "kesinlik": oran(d, len(ks))}


def dy_alan(kayitlar: Iterable[dict[str, Any]], alan: str) -> dict[str, Any]:
    """``dy`` gibi, ama doğruluk kayıttaki bir mantıksal alandan okunur."""
    ks = list(kayitlar)
    d = sum(1 for k in ks if k[alan])
    return {"n": len(ks), "dogru": d, "yanlis": len(ks) - d, "kesinlik": oran(d, len(ks))}


def program_kirilimi(kayitlar: Iterable[dict[str, Any]], alan: str = "program") -> dict[str, Any]:
    ks = list(kayitlar)
    return {p: dy([k for k in ks if k[alan] == p]) for p in sorted({k[alan] for k in ks})}


def karar_ver(ks: list[dict[str, Any]], dogru_say: Optional[Callable[[dict[str, Any]], bool]] = None
              ) -> dict[str, Any]:
    """Kural adayı kararı (``KARAR_*``). ``dogru_say`` verilirse hüküm yerine o kullanılır (karşı olgu)."""
    say = dogru_say or (lambda k: k["durum"] == DOGRU)
    n = len(ks)
    d = sum(1 for k in ks if say(k))
    o = oran(d, n)
    programlar = Counter(k["program"] for k in ks)
    giren = sorted(p for p, c in programlar.items() if c >= N_MIN)
    prog = {p: {"n": c, "dogru": sum(1 for k in ks if k["program"] == p and say(k))}
            for p, c in sorted(programlar.items())}
    buyuk = max(sorted(programlar), key=lambda p: programlar[p]) if programlar else None
    disi = [k for k in ks if k["program"] != buyuk]
    nedenler: list[str] = []
    if n == 0 or d / n < KESINLIK_ESIGI:
        karar = KARAR_TUTMUYOR
    else:
        if o["aralik"][0] < KESINLIK_ESIGI:
            nedenler.append(NEDEN_WILSON)
        if len(giren) < EN_AZ_PROGRAM:
            nedenler.append(NEDEN_PROGRAM)
        karar = KARAR_YETERSIZ if nedenler else KARAR_ONERI
    return {"n": n, "dogru": d, "yanlis": n - d, "kesinlik": o, "program": prog,
            "giren_programlar": giren, "en_buyuk_program": buyuk,
            "en_buyuk_program_disi": {"n": len(disi), "dogru": sum(1 for k in disi if say(k))},
            "karar": karar, "nedenler": nedenler}


def kosul_ozeti(secilen: list[dict[str, Any]], kanal_n: int, kanal_dogru: int,
                donusum: Optional[tuple[str, str]] = None) -> dict[str, Any]:
    """Bir koşulu tutan adların karar özeti + kapsam (kanalın adlarının ve doğru adlarının payı).

    ``donusum`` = (çıktı alanı, kayıt alanı): aynı adlar için ikinci hüküm (dönüşüm uygulansaydı).
    """
    ozet = karar_ver(secilen)
    ozet["kapsam"] = oran(ozet["n"], kanal_n)
    ozet["dogru_payi"] = oran(ozet["dogru"], kanal_dogru)
    if donusum:
        ozet[donusum[0]] = karar_ver(secilen, lambda k: bool(k[donusum[1]]))
        ozet[donusum[0]]["kapsam"] = ozet["kapsam"]
    return ozet


def ozellik_tablosu(ks: list[dict[str, Any]], ozellikler: Iterable[str], kanal_n: int, kanal_dogru: int,
                    donusum: Optional[tuple[str, str]] = None) -> dict[str, Any]:
    """Özellik → değer → ``kosul_ozeti``."""
    return {oz: {deger: kosul_ozeti([k for k in ks if k["oz"][oz] == deger], kanal_n, kanal_dogru, donusum)
                 for deger in sorted({k["oz"][oz] for k in ks})}
            for oz in ozellikler}


def bilesik_tablosu(ks: list[dict[str, Any]], bilesikler: Iterable[tuple[str, Any]], kanal_n: int,
                    kanal_dogru: int, donusum: Optional[tuple[str, str]] = None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for ad, kosullar in bilesikler:
        secilen = [k for k in ks if all(k["oz"][o] in degerler for o, degerler in kosullar)]
        out[ad] = {**kosul_ozeti(secilen, kanal_n, kanal_dogru, donusum),
                   "kosul": [{"ozellik": o, "degerler": list(d)} for o, d in kosullar]}
    return out


def sinif_tablosu(yanlislar: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for s in SINIF_ADLARI:
        ks = [k for k in yanlislar if k["sinif"] == s]
        out[s] = {"n": len(ks), "tekil_ad": len({(k["program"], k["ham"]) for k in ks}),
                  "alt": dict(sorted(Counter(k["alt_sinif"] for k in ks).items())),
                  "program": dict(sorted(Counter(k["program"] for k in ks).items())),
                  "gt_turu": dict(sorted(Counter(k["gt_turu"] for k in ks).items())),
                  "proje_normallestirmesiyle_dogru": sum(1 for k in ks if k["proje"])}
    return out


def taban_denetimi(kayitlar: list[dict[str, Any]], kunye: dict[str, Any], taban_yolu: Path) -> dict[str, Any]:
    """Toplamlar taban ölçümle aynı mı (kalan grup ve kanal başına). Tutmazsa durur."""
    taban = uo._json(taban_yolu)
    t = taban["toplam"]
    beklenen = {"kalan": (t["kanal_grubu"]["kalan"]["havuz"]["ad_verilen"],
                          t["kanal_grubu"]["kalan"]["havuz"]["dogru"]),
                "butun": (t["fonksiyon"]["havuz"]["ad_verilen"], t["fonksiyon"]["havuz"]["dogru"])}
    bulunan = {"kalan": (len(kayitlar), sum(1 for k in kayitlar if k["durum"] == DOGRU)),
               "butun": (kunye["butun"]["ad_verilen"], kunye["butun"]["dogru"])}
    kanal_farki = []
    for kanal in sorted({k["kanal"] for k in kayitlar}):
        ks = [k for k in kayitlar if k["kanal"] == kanal]
        h = (t["kanal"].get(kanal) or {}).get("havuz") or {}
        b = (len(ks), sum(1 for k in ks if k["durum"] == DOGRU))
        if (h.get("ad_verilen"), h.get("dogru")) != b:
            kanal_farki.append(kanal)
        beklenen[kanal] = (h.get("ad_verilen"), h.get("dogru"))
        bulunan[kanal] = b
    tutuyor = beklenen == bulunan and not kanal_farki
    if not tutuyor:
        raise ks1.OnkosulHatasi(f"toplamlar taban ölçümle tutmuyor: beklenen {beklenen}, bulunan {bulunan}")
    return {"taban": str(taban_yolu.relative_to(REPO)), "taban_sha256": ks1.sha256_dosya(taban_yolu),
            "tutuyor": tutuyor,
            "satirlar": {a: {"ad_verilen": b[0], "dogru": b[1]} for a, b in sorted(bulunan.items())}}


def dok(kok_debian: Optional[Path], kok_mac: Optional[Path], mac_veri: Path, indir: Path,
        taban_yolu: Path = TABAN_YOLU, onbellek: Optional[Path] = None) -> tuple[dict[str, Any], Any]:
    if onbellek and onbellek.is_file():
        ikililer, kayitlar, kunye = pickle.loads(onbellek.read_bytes())
    else:
        ikililer, kayitlar, kunye = yukle(kok_debian, kok_mac, mac_veri, indir)
        if onbellek:
            onbellek.parent.mkdir(parents=True, exist_ok=True)
            onbellek.write_bytes(pickle.dumps((ikililer, kayitlar, kunye)))
    denetim = taban_denetimi(kayitlar, kunye, taban_yolu)

    # --- öznitelikler
    for k in kayitlar:
        b = ikililer[k["b"]]
        k["gt_turu"] = gt_turu(k, b)
        if k["durum"] != DOGRU:
            k["sinif"], k["alt_sinif"] = sinifla(k, b)
            k["yakinlik"] = yakinlik(k, b)
        if k["grup"] == GRUP_ON_AD:
            k["oz"] = on_ad_ozellikleri(k, b)
            k["ham_dogru"] = k["adres"] in b.gt_ham and dogru_mu(k["ham"], b, k["adres"])
        elif k["grup"] == GRUP_OZ_AD:
            k["oz"] = oz_ad_ozellikleri(k, b)
            kanit = str(k["kayit"].get("evidence") or "").strip()
            k["kanit_dogru"] = k["adres"] in b.gt_ham and dogru_mu(kanit, b, k["adres"])
            k["ham_dogru"] = k["adres"] in b.gt_ham and dogru_mu(k["ham"], b, k["adres"])
            capa = b.capalar().get(k["adres"])
            k["ks1_dogru"] = (capa is not None and k["adres"] in b.gt_ham
                              and dogru_mu(capa.name, b, k["adres"]))
        else:
            k["oz"] = {"ks1_capasi": ks1_ozelligi(k, b), "ad_ghidra_adli": evet_hayir(k["ham"] in b.ghidra_adli)}
            k["ikilide"] = ikilide_ad_var_mi(k, b)

    gruplar = {g: [k for k in kayitlar if k["grup"] == g] for g in GRUPLAR}
    sonuc: dict[str, Any] = {
        "sema": SEMA,
        "uyari": ("Keşif çözümlemesi: bütün sayılar geliştirme setindendir. Kural adayları taze veride "
                  "(doğrulama seti) sınanmadan iddia sayılmaz; aralıklar çoklu karşılaştırmaya göre "
                  "düzeltilmemiştir."),
        "arac": {"betik_sha256": ks1.sha256_dosya(BETIK), "urun_olc_sha256": ks1.sha256_dosya(URUN_OLC_YOLU),
                 "ks1_olc_sha256": ks1.sha256_dosya(uo.KS1_YOLU),
                 "git_head": ks1._git("rev-parse", "HEAD").stdout.strip()},
        "kokler": {"debian": kok_debian and str(kok_debian), "mac": kok_mac and str(kok_mac)},
        "nufus": {"ikili": kunye["ikili"], "cpp_disarida": kunye["cpp_disarida"]},
        "taban_denetimi": denetim,
        "tanimlar": {"siniflar": [{"ad": s, "tanim": t} for s, t in SINIFLAR],
                     "yakinlik": [{"ad": s, "tanim": t} for s, t in YAKINLIK],
                     "oz_ad_ozellikleri": [{"ad": s, "tanim": t} for s, t in OZ_AD_OZELLIKLERI],
                     "on_ad_ozellikleri": [{"ad": s, "tanim": t} for s, t in ON_AD_OZELLIKLERI],
                     "karar": {"kesinlik_esigi": KESINLIK_ESIGI, "n_min": N_MIN, "en_az_program": EN_AZ_PROGRAM}},
        "grup": {g: {**dy(ks), "program": program_kirilimi(ks), "birim": program_kirilimi(ks, "birim"),
                     "gt_turu": program_kirilimi(ks, "gt_turu")}
                 for g, ks in gruplar.items()},
        "yanlis_siniflari": {g: sinif_tablosu([k for k in ks if k["durum"] != DOGRU])
                             for g, ks in gruplar.items()},
    }
    sonuc["yanlis_siniflari"]["hepsi"] = sinif_tablosu([k for k in kayitlar if k["durum"] != DOGRU])

    # --- ön adlar
    on = gruplar[GRUP_ON_AD]
    on_dogru = sum(1 for k in on if k["durum"] == DOGRU)
    turler = sorted({k["oz"]["tur"] for k in on})
    ana_tur = lambda t: t.split("/", 1)[0]   # noqa: E731
    yinelenen = [b for b in ikililer if b.yineleme]
    sonuc["on_ad"] = {
        "yineleme": {"ikili": len(yinelenen),
                     "sayaci_tutan_ikili": sum(1 for b in yinelenen if b.yineleme["sayac_tutuyor"]),
                     "main_tutan_ikili": sum(1 for b in yinelenen if b.yineleme["main_tutuyor"]),
                     "turu_belirlenemeyen_ad": sum(1 for k in on if k["oz"]["tur"] == TUR_BELIRSIZ)},
        "tur": {t: {**karar_ver([k for k in on if k["oz"]["tur"] == t]),
                    "sinif": dict(sorted(Counter(k["sinif"] for k in on
                                                 if k["oz"]["tur"] == t and k["durum"] != DOGRU).items())),
                    "ham_adla": karar_ver([k for k in on if k["oz"]["tur"] == t], lambda k: k["ham_dogru"])}
                for t in turler},
        "ana_tur": {t: {**karar_ver([k for k in on if ana_tur(k["oz"]["tur"]) == t]),
                        "ham_adla": karar_ver([k for k in on if ana_tur(k["oz"]["tur"]) == t],
                                              lambda k: k["ham_dogru"])}
                    for t in sorted({ana_tur(t) for t in turler})},
        "ozellikler": ozellik_tablosu(on, [o for o, _ in ON_AD_OZELLIKLERI], len(on), on_dogru),
        "ham_adla": {**karar_ver(on, lambda k: k["ham_dogru"]),
                     "aciklama": "karşı olgu: ön ad temizlenmeden (ham) yazılsaydı doğru sayılacak adlar"},
        "tur_x_gt_turu": {t: dict(sorted(Counter(k["gt_turu"] for k in on if k["oz"]["tur"] == t).items()))
                          for t in turler},
        "katalog_girdisi_ham_adla": {
            g: karar_ver([k for k in on if k["oz"]["katalog_girdisi"] == g], lambda k: k["ham_dogru"])
            for g in sorted({k["oz"]["katalog_girdisi"] for k in on})},
    }
    # sonradan eklenen ön ad koşulları (gnulib)
    gnulib = [k for k in on if ana_tur(k["oz"]["tur"]) == "gnulib"]
    girdi = sonuc["on_ad"]["ozellikler"]["katalog_girdisi"]
    sifir = sorted(g for g, v in girdi.items() if g.startswith("gnulib/") and v["n"] >= N_MIN and v["dogru"] == 0)
    sonuc["on_ad"]["sonradan"] = {
        "gnulib_ikilisi": {
            **kosul_ozeti([k for k in gnulib if k["oz"]["ikilide_gnulib_dizgi_isabeti"] == ON_AD_GNULIB_ISABET_ESIGI],
                          len(on), on_dogru),
            "aciklama": f"gnulib adı ve ikilide dizgi parmak izi isabeti {ON_AD_GNULIB_ISABET_ESIGI}"},
        "gnulib_ikilisi_degil": {
            **kosul_ozeti([k for k in gnulib if k["oz"]["ikilide_gnulib_dizgi_isabeti"] != ON_AD_GNULIB_ISABET_ESIGI],
                          len(on), on_dogru),
            "aciklama": f"gnulib adı ve ikilide dizgi parmak izi isabeti {ON_AD_GNULIB_ISABET_ESIGI} değil"},
        "sifir_dogrulu_girdiler_haric": {
            **kosul_ozeti([k for k in gnulib if k["oz"]["katalog_girdisi"] not in sifir], len(on), on_dogru),
            "aciklama": "gnulib adı; bu veride n ≥ %d iken hiç doğru vermeyen katalog girdileri hariç "
                        "(girdi seçimi aynı veride)" % N_MIN,
            "haric_tutulan_girdiler": sifir},
        "sifir_dogrulu_girdiler_haric_ve_gnulib_ikilisi": {
            **kosul_ozeti([k for k in gnulib if k["oz"]["katalog_girdisi"] not in sifir
                           and k["oz"]["ikilide_gnulib_dizgi_isabeti"] == ON_AD_GNULIB_ISABET_ESIGI],
                          len(on), on_dogru),
            "aciklama": "gnulib adı; hiç doğru vermeyen katalog girdileri hariç ve ikilide dizgi parmak izi "
                        f"isabeti {ON_AD_GNULIB_ISABET_ESIGI} (girdi seçimi aynı veride)",
            "haric_tutulan_girdiler": sifir},
    }

    # --- oz_ad
    oz = gruplar[GRUP_OZ_AD]
    oz_dogru = sum(1 for k in oz if k["durum"] == DOGRU)
    oz_adlari = [o for o, _ in OZ_AD_OZELLIKLERI]
    donusum = ("kanit_dizgisiyle", "kanit_dogru")
    kalan = [k for k in oz if k["oz"]["ks1_capasi"] == "yok"]      # KS-1'in ad vermeyeceği oz_ad adları
    kalan_dogru = sum(1 for k in kalan if k["durum"] == DOGRU)
    sonuc["oz_ad"] = {
        "ozellikler": ozellik_tablosu(oz, oz_adlari, len(oz), oz_dogru, donusum),
        "bilesik": bilesik_tablosu(oz, OZ_AD_BILESIKLER, len(oz), oz_dogru, donusum),
        "sonradan": bilesik_tablosu(oz, OZ_AD_SONRADAN, len(oz), oz_dogru, donusum),
        "ks1_yok_icinde": {
            "aciklama": "sonradan eklenen katmanlama: yalnız aynı adreste KS-1 çapası OLMAYAN oz_ad adları "
                        "(KS-1 açıldığında oz_ad'a kalan kısım); kapsam bu alt kümeye göre",
            **kosul_ozeti(kalan, len(oz), oz_dogru, donusum),
            "ozellikler": ozellik_tablosu(kalan, [o for o in oz_adlari if o != "ks1_capasi"], len(kalan),
                                          kalan_dogru, donusum)},
        "kanit_dizgisi_oldugu_gibi": {**karar_ver(oz, lambda k: k["kanit_dogru"]),
                                      "aciklama": "karşı olgu: ad küçük harfe çevrilmeden ve çakışma eki "
                                                  "eklenmeden, kanıt dizgisi olduğu gibi yazılsaydı"},
        "eksiz_ham_adla": {**karar_ver(oz, lambda k: k["ham_dogru"]),
                           "aciklama": "karşı olgu: yalnız çakışma eki eklenmeseydi (küçük harf kalır)"},
        "ks1_capasi_dogrulugu": {
            "aciklama": "aynı adreste KS-1 çapası olan oz_ad adlarında KS-1 adının hükmü (oz_ad'ın halefi)",
            "ayni_ad": dy_alan([k for k in oz if k["oz"]["ks1_capasi"] == "ayni_ad"], "ks1_dogru"),
            "farkli_ad": dy_alan([k for k in oz if k["oz"]["ks1_capasi"] == "farkli_ad"], "ks1_dogru")},
    }

    # --- kebap_ad ve api_param_reverse
    for g in (GRUP_KEBAP, GRUP_API):
        ks = gruplar[g]
        yanlis = [k for k in ks if k["durum"] != DOGRU]
        sonuc[g] = {
            "yakinlik": dict(sorted(Counter(k["yakinlik"]["olcu"] for k in yanlis).items())),
            "jaccard": dict(sorted(Counter(str(k["yakinlik"]["jaccard"]) for k in yanlis).items())),
            "yakinlik_program": {p: dict(sorted(Counter(k["yakinlik"]["olcu"] for k in yanlis
                                                         if k["program"] == p).items()))
                                 for p in sorted({k["program"] for k in yanlis})},
            "urun_adi_ikilinin_gt_sinde": {
                "tam": sum(1 for k in ks if k["ikilide"]["tam"]),
                "norm_esit": sum(1 for k in ks if k["ikilide"]["norm_esit"]),
                "yalniz_sonek_olarak": sum(1 for k in ks if k["ikilide"]["sonek_olarak"]
                                            and not k["ikilide"]["norm_esit"])},
            "carpisma_ekli": sum(1 for k in ks if "proposed_name" in k["kayit"]),
            "ozellikler": ozellik_tablosu(ks, ["ks1_capasi", "ad_ghidra_adli"], len(ks),
                                          sum(1 for k in ks if k["durum"] == DOGRU)),
        }

    sonuc["kural_adaylari"] = kural_adaylari(sonuc)

    def pay(grup: str, program: str) -> str:
        n = sonuc["grup"][grup]["n"]
        return yuzde((sonuc["grup"][grup]["program"].get(program) or {"n": 0})["n"] / n) if n else "—"

    yok = [k for k in oz if k["oz"]["cagri_argumani"] == "govdede_yok"]
    mac_oz = [k for k in oz if k["birim"].startswith(ks1.PLATFORM_MAC + "/")]
    mac_yok = sum(1 for k in yok if k["birim"].startswith(ks1.PLATFORM_MAC + "/"))
    paylar = {"on_ad_pay": pay(GRUP_ON_AD, "coreutils"), "oz_ad_pay": pay(GRUP_OZ_AD, "tmux"),
              "kebap_pay": pay(GRUP_KEBAP, "tmux"), "mac_yok": f"{mac_yok}/{len(mac_oz)}",
              "debian_yok": f"{len(yok) - mac_yok}/{len(oz) - len(mac_oz)}"}
    sonuc["sinirlar"] = [m.format(**paylar) if "{" in m else m for m in SINIRLAR]
    sonuc["susturma"] = susturma_tablosu(sonuc)
    sonuc["sonradan_degisiklikler"] = list(SONRADAN_DEGISIKLIKLER)
    sonuc["elle_denetim"] = {
        "ornek_sayisi": ORNEK_SAYISI,
        "sinif": {s: {"incelenen": v[0], "yanlis_konan": v[1]} for s, v in sorted(ELLE_DENETIM.items())},
        "toplam": {"incelenen": sum(v[0] for v in ELLE_DENETIM.values()),
                   "yanlis_konan": sum(v[1] for v in ELLE_DENETIM.values())},
        "notlar": list(ELLE_DENETIM_NOTLARI)}
    return sonuc, (ikililer, kayitlar)


def susturma_tablosu(s: dict[str, Any]) -> list[dict[str, Any]]:
    """Ürünün kendi susturma kuralı ("yalnız zayıflar", N0b; ``baglama.row_status_from_measurement`` ile aynı
    eşik): yanlış oranının Wilson %95 alt sınırı ``SUSTURMA_HEDEFI``'nin üstündeyse `sus`, değilse `kalir`.
    Satırlar: kanal grupları, ön ad türleri (olduğu gibi ve temizlenmeden), katalog girdileri (temizlenmeden)
    ve `oz_ad`'ın KS-1 katmanları."""
    out: list[dict[str, Any]] = []

    def ekle(kapsam: str, ozet: dict[str, Any]) -> None:
        yo = oran(ozet["n"] - ozet["dogru"], ozet["n"])
        karar = "bos" if not ozet["n"] else ("sus" if yo["aralik"][0] > SUSTURMA_HEDEFI else "kalir")
        out.append({"kapsam": kapsam, "n": ozet["n"], "yanlis": ozet["n"] - ozet["dogru"], "yanlis_orani": yo,
                    "karar": karar})

    for g in (GRUP_ON_AD, GRUP_OZ_AD, GRUP_KEBAP, GRUP_API):
        ekle(f"kanal: {g}", s["grup"][g])
    for t, v in s["on_ad"]["tur"].items():
        ekle(f"ön ad türü: {t}", v)
        if v["ham_adla"]["dogru"] != v["dogru"]:
            ekle(f"ön ad türü: {t}; ad temizlenmeden yazılır", v["ham_adla"])
    for gi, v in s["on_ad"]["katalog_girdisi_ham_adla"].items():
        if not gi.endswith("#-"):
            ekle(f"katalog girdisi: {gi}; ad temizlenmeden yazılır", v)
    for deger, v in s["oz_ad"]["ozellikler"]["ks1_capasi"].items():
        ekle(f"oz_ad; ks1_capasi = {deger}", v)
        ekle(f"oz_ad; ks1_capasi = {deger}; kanıt dizgisi olduğu gibi yazılır", v["kanit_dizgisiyle"])
    for alan, ek in (("bilesik", ""), ("sonradan", " (sonradan)")):
        for ad, v in s["oz_ad"][alan].items():
            if len(v["kosul"]) > 1:
                ekle(f"oz_ad; bileşik `{ad}`{ek}", v)
                ekle(f"oz_ad; bileşik `{ad}`{ek}; kanıt dizgisi olduğu gibi yazılır", v["kanit_dizgisiyle"])
    return out


def kural_adaylari(s: dict[str, Any]) -> list[dict[str, Any]]:
    """Bütün tek özellik değerleri, bileşikler ve karşı olgular; karar ``karar_ver``'den."""
    out: list[dict[str, Any]] = []
    KANIT = "; kanıt dizgisi olduğu gibi yazılır"
    HAM = "; ad temizlenmeden yazılır"

    def ekle(kanal: str, kosul: str, ozet: dict[str, Any], tur: str = "sus_kalan",
             sonradan: bool = False) -> None:
        out.append({"kanal": kanal, "kosul": kosul, "tur": tur, "sonradan": sonradan,
                    "n": ozet["n"], "dogru": ozet["dogru"], "yanlis": ozet["yanlis"],
                    "kesinlik": ozet["kesinlik"], "kapsam": oran(ozet["n"], s["grup"][kanal]["n"]),
                    "giren_programlar": ozet["giren_programlar"],
                    "en_buyuk_program": ozet["en_buyuk_program"],
                    "en_buyuk_program_disi": ozet["en_buyuk_program_disi"],
                    "karar": ozet["karar"], "nedenler": ozet["nedenler"]})

    def kosul_yaz(ozet: dict[str, Any]) -> str:
        return " ve ".join(f"{k['ozellik']} ∈ {{{', '.join(k['degerler'])}}}" for k in ozet["kosul"])

    def cift(kanal: str, kosul: str, ozet: dict[str, Any], donusumlu: dict[str, Any], ek: str,
             sonradan: bool = False, yalin: bool = True) -> None:
        """Koşulun yalın hâli ve (dönüşüm bir adın hükmünü değiştiriyorsa) dönüşümlü hâli."""
        if yalin:
            ekle(kanal, kosul, ozet, sonradan=sonradan)
        if donusumlu["dogru"] != ozet["dogru"]:
            ekle(kanal, kosul + ek, donusumlu, "donusum", sonradan)

    # Aynı ad kümesini seçen koşullar bir kez yazılır: katmansız türde "tur" ile "ana tür" aynıdır,
    # tek koşullu bileşik özellik satırının aynısıdır, `#-` katalog girdisi türün kendisidir.
    on = s["on_ad"]
    for oz, degerler in on["ozellikler"].items():
        for deger, ozet in degerler.items():
            if oz == "tur":
                cift(GRUP_ON_AD, f"tur = {deger}", ozet, on["tur"][deger]["ham_adla"], HAM)
            elif oz == "katalog_girdisi":
                if not deger.endswith("#-"):
                    cift(GRUP_ON_AD, f"katalog_girdisi = {deger}", ozet, on["katalog_girdisi_ham_adla"][deger], HAM)
            else:
                ekle(GRUP_ON_AD, f"{oz} = {deger}", ozet)
    for t, ozet in on["ana_tur"].items():
        if t not in on["tur"]:
            cift(GRUP_ON_AD, f"ana tür = {t}", ozet, ozet["ham_adla"], HAM)
    ekle(GRUP_ON_AD, f"bütün ön adlar{HAM}", on["ham_adla"], "donusum")
    for ozet in on["sonradan"].values():
        ekle(GRUP_ON_AD, ozet["aciklama"], ozet, sonradan=True)
    # oz_ad
    for oz, degerler in s["oz_ad"]["ozellikler"].items():
        for deger, ozet in degerler.items():
            cift(GRUP_OZ_AD, f"{oz} = {deger}", ozet, ozet["kanit_dizgisiyle"], KANIT)
    for alan, sonradan in (("bilesik", False), ("sonradan", True)):
        for ozet in s["oz_ad"][alan].values():
            if len(ozet["kosul"]) > 1:
                cift(GRUP_OZ_AD, "bileşik: " + kosul_yaz(ozet), ozet, ozet["kanit_dizgisiyle"], KANIT, sonradan)
    for oz, degerler in s["oz_ad"]["ks1_yok_icinde"]["ozellikler"].items():
        for deger, ozet in degerler.items():
            cift(GRUP_OZ_AD, f"ks1_capasi = yok ve {oz} = {deger}", ozet, ozet["kanit_dizgisiyle"], KANIT, True)
    ekle(GRUP_OZ_AD, f"bütün oz_ad{KANIT}", s["oz_ad"]["kanit_dizgisi_oldugu_gibi"], "donusum")
    ekle(GRUP_OZ_AD, "bütün oz_ad; çakışma eki eklenmez", s["oz_ad"]["eksiz_ham_adla"], "donusum")
    # kebap_ad, api_param_reverse
    for g in (GRUP_KEBAP, GRUP_API):
        for oz, degerler in s[g]["ozellikler"].items():
            for deger, ozet in degerler.items():
                ekle(g, f"{oz} = {deger}", ozet)
    sira = {KARAR_ONERI: 0, KARAR_YETERSIZ: 1, KARAR_TUTMUYOR: 2}
    return sorted(out, key=lambda a: (sira[a["karar"]], a["kanal"], -a["n"], a["kosul"]))


# --------------------------------------------------------------------------------------------
# Markdown


yuzde = ks1.yuzde


def _o(o: Optional[dict[str, Any]]) -> str:
    if not o or not o["n"]:
        return "—"
    return f"{o['k']}/{o['n']} ({yuzde(o['oran'])}; {yuzde(o['aralik'][0])}-{yuzde(o['aralik'][1])})"


def _alt(o: Optional[dict[str, Any]]) -> str:
    return "—" if not o or not o["n"] else yuzde(o["aralik"][0])


def _sayilar(d: dict[str, int]) -> str:
    return ", ".join(f"{k} {v}" for k, v in d.items()) or "—"


def _prog(ozet: dict[str, Any]) -> str:
    return ", ".join(f"{p} {v['dogru']}/{v['n']}" for p, v in ozet["program"].items()) or "—"


def _karar(ozet: dict[str, Any]) -> str:
    neden = {NEDEN_WILSON: "Wilson alt sınırı < %95", NEDEN_PROGRAM: "tek program"}
    ek = f" ({'; '.join(neden[n] for n in ozet['nedenler'])})" if ozet["nedenler"] else ""
    return f"`{ozet['karar']}`{ek}"


def _kn(v: dict[str, Any]) -> str:
    """``doğru/n (%x)``."""
    return f"{v['dogru']}/{v['n']} ({yuzde(v['kesinlik']['oran'])})" if v["n"] else "0/0"


def ozet_md(s: dict[str, Any]) -> list[str]:
    """Belgenin başındaki özet; bütün sayılar sonuç sözlüğünden okunur."""
    g, on, oz, ys = s["grup"], s["on_ad"], s["oz_ad"], s["yanlis_siniflari"]
    tur = on["tur"]
    sn = on["sonradan"]
    sifir = sn["sifir_dogrulu_girdiler_haric"]["haric_tutulan_girdiler"]
    sifir_n = sum(on["ozellikler"]["katalog_girdisi"][h]["n"] for h in sifir)
    oneri = [a for a in s["kural_adaylari"] if a["karar"] == KARAR_ONERI]
    yetersiz = [a for a in s["kural_adaylari"] if a["karar"] == KARAR_YETERSIZ]
    ky, kc = oz["ks1_yok_icinde"], oz["ks1_capasi_dogrulugu"]
    yo, yk, ya = ys[GRUP_OZ_AD], ys[GRUP_KEBAP], ys[GRUP_API]
    elf, main = tur.get(TUR_ELF_ONYUK), tur.get(TUR_MAIN)
    gn = on["ana_tur"].get("gnulib")
    sat = ["## 0. Özet", "",
           f"- **Kalan kanallar:** {g[GRUP_ON_AD]['n'] + g[GRUP_OZ_AD]['n'] + g[GRUP_KEBAP]['n'] + g[GRUP_API]['n']} "
           f"ad; ön adlar {_kn(g[GRUP_ON_AD])}, `oz_ad` {_kn(g[GRUP_OZ_AD])}, `kebap_ad` {_kn(g[GRUP_KEBAP])}, "
           f"`api_param_reverse` {_kn(g[GRUP_API])}."]
    if elf and main and gn:
        sat += [
            f"- **Ön adlar, tür başına:** `main_giris` {_kn(main)}; `elf_onyuk` {_kn(elf)}; gnulib (üç katman) "
            f"{_kn(gn)}. Olduğu hâliyle karar: "
            + ", ".join(f"`{t}` {_karar(v)}" for t, v in tur.items()) + ".",
            f"- **ELF önyükü:** yanlışların tamamı ({ys[GRUP_ON_AD][S_TEMIZLEYICI]['n']}) ad temizleyicinin baştaki "
            f"alt çizgiyi atmasından. Ad temizlenmeden yazılsa {_kn(elf['ham_adla'])}, Wilson alt sınırı "
            f"{_alt(elf['ham_adla']['kesinlik'])} → {_karar(elf['ham_adla'])}. Bu adların hepsi CRT fonksiyonudur "
            "(ad bekleyen nüfusa girmez; kesinliği yükseltir, kapsamı değiştirmez).",
            f"- **gnulib:** {gn['yanlis']} yanlışın sınıfı: ad ikilide BAŞKA bir fonksiyona ait "
            f"(`baska_fonksiyonun_adi`) {ys[GRUP_ON_AD][S_BASKA]['n']}, ad ikilinin GT'sinde hiç yok (`katalog_adi`) "
            f"{ys[GRUP_ON_AD][S_KATALOG]['n']}. Yanlışlar katalog girdisine bağlı: {len(sifir)} girdi "
            f"({', '.join(f'`{h}`' for h in sifir)}) toplam {sifir_n} adın hiçbirinde doğru değil. Bu girdiler "
            f"çıkarılırsa {_kn(sn['sifir_dogrulu_girdiler_haric'])} ({_karar(sn['sifir_dogrulu_girdiler_haric'])}; "
            f"girdi seçimi aynı veride). {gn['en_buyuk_program']} dışındaki programlarda gnulib adları "
            f"{gn['en_buyuk_program_disi']['dogru']}/{gn['en_buyuk_program_disi']['n']}; ikilide dizgi parmak izi "
            f"isabeti 3'ten az olan ikililerde {_kn(sn['gnulib_ikilisi_degil'])}.",
        ]
    sat += [
        f"- **`oz_ad` yanlışları ({g[GRUP_OZ_AD]['yanlis']}):** yalnız harf farkı {yo[S_HARF]['n']}, çakışma eki "
        f"{yo[S_CARPISMA]['n']}, ikilideki başka bir fonksiyonun adı {yo[S_BASKA]['n']}, içe aktarılan adı "
        f"{yo[S_ICE]['n']}, önek/sonek farkı {yo[S_ONEK]['n']}, ilgisiz {yo[S_ILGISIZ]['n']}. Kanıt dizgisi olduğu "
        f"gibi (küçük harfe çevrilmeden, eksiz) yazılsa {_kn(oz['kanit_dizgisi_oldugu_gibi'])}: eşiğin altında.",
        f"- **`oz_ad` ve KS-1:** {kc['ayni_ad']['n'] + kc['farkli_ad']['n']} adda aynı adreste KS-1 çapası var; "
        f"çapa aynı adı veriyorsa KS-1 adı {_o(kc['ayni_ad']['kesinlik'])}, farklı ad veriyorsa KS-1 adı "
        f"{_o(kc['farkli_ad']['kesinlik'])} doğru. Çapası olmayan {ky['n']} adda `oz_ad` {_kn(ky)}; kanıt dizgisi "
        f"olduğu gibi yazılsa {_kn(ky['kanit_dizgisiyle'])}. KS-1 açıldığında `oz_ad`'a kalan kısım budur.",
        f"- **`kebap_ad`:** {g[GRUP_KEBAP]['n']} adın hiçbiri doğru değil ve hiçbiri normalleştirilince de eşit "
        f"değil; ürün adı ikilinin GT'sinde hiçbir adreste yok (tam eşit "
        f"{s[GRUP_KEBAP]['urun_adi_ikilinin_gt_sinde']['tam']}). Yalnız {yk[S_ONEK]['n']} adda GT adı \"önek + ürün "
        f"adı\" biçiminde; çakışma ekli ad {s[GRUP_KEBAP]['carpisma_ekli']} (aynı dizgi birçok fonksiyonda). "
        "Mekanik bir dönüşümle kurtarılamaz; ürünün kendi kuralıyla `sus`.",
        f"- **`api_param_reverse`:** {g[GRUP_API]['n']} adın hiçbiri doğru değil; adlar geri çağrı ROLÜ adı "
        f"(`ilgisiz` {ya[S_ILGISIZ]['n']}, önek/sonek {ya[S_ONEK]['n']}), çakışma ekli ad "
        f"{s[GRUP_API]['carpisma_ekli']}. Fonksiyon adı olarak kurtarılamaz; ürünün kendi kuralıyla `sus`.",
        f"- **Kural adayları:** {len(s['kural_adaylari'])} koşul denendi; `oneri` {len(oneri)}, `yetersiz` "
        f"{len(yetersiz)} (§6). `oneri` çıkan her koşul da geliştirme setinde bulunmuştur.", ""]
    return sat


def markdown(s: dict[str, Any]) -> str:
    g = s["grup"]
    sat = ["# Kalan ad kanallarının dökümü: yanlış sınıfları ve kesinliği ayıran koşullar", "",
           f"> **Uyarı.** {s['uyari']}", "",
           f"- Kökler: Debian `{s['kokler']['debian']}`, Mac `{s['kokler']['mac']}`; {s['nufus']['ikili']} ikili "
           f"(C++ dışarıda: {', '.join(s['nufus']['cpp_disarida']) or 'yok'}).",
           f"- Betik sha256 `{s['arac']['betik_sha256'][:16]}…`; `urun_olc.py` `{s['arac']['urun_olc_sha256'][:16]}…`; "
           f"`ks1_olc.py` `{s['arac']['ks1_olc_sha256'][:16]}…`; HEAD `{s['arac']['git_head'][:7]}`.",
           "- Hüküm taban ölçümünkiyle aynıdır (tam eşitlik; `urun_olc.degerlendir_elf`). Bu belgede fonksiyon "
           "adı, ürün adı, GT adı, anahtar ve dizgi geçmez; katalog girdileri ürün kodundaki sıra numarasıyla "
           "gösterilir.",
           f"- Taban denetimi (`{s['taban_denetimi']['taban']}`): "
           + "; ".join(f"`{a}` {v['dogru']}/{v['ad_verilen']}" for a, v in s["taban_denetimi"]["satirlar"].items())
           + f" → {'tutuyor' if s['taban_denetimi']['tutuyor'] else 'TUTMUYOR'}.",
           f"- Kural adayı kararı [seçim, sayımdan önce]: `oneri` = kesinlik ≥ {yuzde(KESINLIK_ESIGI)} ve Wilson "
           f"%95 alt sınırı ≥ {yuzde(KESINLIK_ESIGI)} ve en az {EN_AZ_PROGRAM} farklı programda n ≥ {N_MIN}; "
           "`yetersiz` = kesinlik eşiği tutuyor ama öbür iki koşuldan biri tutmuyor; `tutmuyor` = kesinlik eşiğin "
           "altında.", ""]
    sat += ozet_md(s)
    sat += ["## 1. Kanal grubu başına", "",
           "| Grup | Ad | Doğru | Yanlış | Kesinlik (%95) | Program başına (doğru/n) |", "|---|---|---|---|---|---|"]
    for ad in GRUPLAR:
        v = g[ad]
        if v["n"]:
            sat.append(f"| `{ad}` | {v['n']} | {v['dogru']} | {v['yanlis']} | {_o(v['kesinlik'])} | "
                       + ", ".join(f"{p} {x['dogru']}/{x['n']}" for p, x in v["program"].items()) + " |")
    sat += ["", "Birim (platform/program) başına:", "", "| Grup | Birim | Ad | Doğru | Kesinlik (%95) |",
            "|---|---|---|---|---|"]
    for ad in GRUPLAR:
        for b, x in g[ad]["birim"].items():
            sat.append(f"| `{ad}` | {b} | {x['n']} | {x['dogru']} | {_o(x['kesinlik'])} |")
    sat += ["", "GT fonksiyonunun türü başına (`gt_yok`: o adreste GT fonksiyonu yok; `crt`: bütün adları CRT adı; "
            "`klon`: bütün adları derleyici ekli; `export`: dışa aktarılan; `parca`: Mach-O soğuk / dışlanmış parça):",
            "", "| Grup | GT türü | Ad | Doğru |", "|---|---|---|---|"]
    for ad in GRUPLAR:
        for t, x in g[ad]["gt_turu"].items():
            sat.append(f"| `{ad}` | `{t}` | {x['n']} | {x['dogru']} |")

    sat += ["", "## 2. Yanlış sınıfları", "",
            "Sınıflar sayımdan önce ürün kodu okunarak yazıldı; ilk tutan kazanır. N: ürünün yazdığı ad; R: ham ad "
            "(temizlenmeden / çakışma eki eklenmeden önce).", "", "| Sınıf | Tanım |", "|---|---|"]
    sat += [f"| `{t['ad']}` | {t['tanim']} |" for t in s["tanimlar"]["siniflar"]]
    sat += ["", "| Sınıf | " + " | ".join(f"`{a}`" for a in GRUPLAR if g[a]["n"]) + " | Toplam |",
            "|---|" + "---|" * (sum(1 for a in GRUPLAR if g[a]["n"]) + 1)]
    for sn in SINIF_ADLARI:
        sat.append(f"| `{sn}` | " + " | ".join(str(s["yanlis_siniflari"][a][sn]["n"]) for a in GRUPLAR if g[a]["n"])
                   + f" | {s['yanlis_siniflari']['hepsi'][sn]['n']} |")
    sat.append("| **Toplam** | " + " | ".join(str(g[a]["yanlis"]) for a in GRUPLAR if g[a]["n"])
               + f" | {sum(g[a]['yanlis'] for a in GRUPLAR)} |")
    sat += ["", "Alt sınıflar, program ve GT türü (grup başına; yalnız dolu sınıflar). Sayım örnek düzeyindedir "
            "(ikili başına ad): coreutils'in 106 ikilisi aynı kitaplık fonksiyonlarını taşıdığı için tek bir "
            "katalog hatası yüzü aşkın kez sayılır; `Tekil ad` sütunu program başına farklı ham ad sayısıdır.", "",
            "| Grup | Sınıf | n | Tekil ad | Alt sınıf | Program | GT türü | Proje norm. ile doğru |",
            "|---|---|---|---|---|---|---|---|"]
    for a in GRUPLAR:
        for sn in SINIF_ADLARI:
            v = s["yanlis_siniflari"][a][sn]
            if v["n"]:
                sat.append(f"| `{a}` | `{sn}` | {v['n']} | {v['tekil_ad']} | {_sayilar(v['alt'])} | "
                           f"{_sayilar(v['program'])} | {_sayilar(v['gt_turu'])} | "
                           f"{v['proje_normallestirmesiyle_dogru']} |")

    on = s["on_ad"]
    y = on["yineleme"]
    sat += ["", "## 3. Ön adlar: tür başına", "",
            "Saklı koşuların köken kaydında tür yazılı değil; tür, ürünün tohum fonksiyonları saklı `static/` "
            f"çıktısında yeniden çağrılarak bulundu. Yeniden üretim {y['ikili']} ikilide yapıldı: koşunun kendi "
            f"sayaçlarıyla {y['sayaci_tutan_ikili']} ikilide, giriş fonksiyonunun anahtarıyla {y['main_tutan_ikili']} ikilide "
            f"tutuyor; türü belirlenemeyen ad {y['turu_belirlenemeyen_ad']}. Tabloda olmayan türler bu veride ad "
            "vermedi: Faz 1 (BinaryNameExtractor, byte pattern, CAPA) ölçüye giren hiçbir `FUN_` anahtarına ad "
            "yazmadı, elle verilmiş ad yok.", "",
            "| Tür | Ad | Doğru | Kesinlik (%95) | Karar | Temizlenmeden yazılsa (%95) | Karar | Program başına (doğru/n) | "
            "Yanlış sınıfları |", "|---|---|---|---|---|---|---|---|---|"]
    for t, v in on["tur"].items():
        sat.append(f"| `{t}` | {v['n']} | {v['dogru']} | {_o(v['kesinlik'])} | {_karar(v)} | "
                   f"{_o(v['ham_adla']['kesinlik'])} | {_karar(v['ham_adla'])} | {_prog(v)} | {_sayilar(v['sinif'])} |")
    sat += ["", "Ana tür (gnulib katmanları birleşik):", "",
            "| Ana tür | Ad | Doğru | Kesinlik (%95) | Karar | Temizlenmeden yazılsa (%95) | Karar |",
            "|---|---|---|---|---|---|---|"]
    for t, v in on["ana_tur"].items():
        sat.append(f"| `{t}` | {v['n']} | {v['dogru']} | {_o(v['kesinlik'])} | {_karar(v)} | "
                   f"{_o(v['ham_adla']['kesinlik'])} | {_karar(v['ham_adla'])} |")
    h = on["ham_adla"]
    sat += ["", f"Bütün ön adlar temizlenmeden yazılsaydı: {_o(h['kesinlik'])} ({_karar(h)}).", "",
            "Tür × GT türü (ad sayısı):", "", "| Tür | GT türü dağılımı |", "|---|---|"]
    sat += [f"| `{t}` | {_sayilar(v)} |" for t, v in on["tur_x_gt_turu"].items()]
    sat += ["", "### Ön ad özellikleri (GT'siz)", "", "| Özellik | Tanım |", "|---|---|"]
    sat += [f"| `{t['ad']}` | {t['tanim']} |" for t in s["tanimlar"]["on_ad_ozellikleri"]]
    sat += ["", "| Özellik | Değer | Ad | Doğru | Kesinlik (%95) | Kapsam | Doğru adların payı | Program başına | Karar |",
            "|---|---|---|---|---|---|---|---|---|"]
    for oz, degerler in on["ozellikler"].items():
        for deger, v in degerler.items():
            sat.append(f"| `{oz}` | `{deger}` | {v['n']} | {v['dogru']} | {_o(v['kesinlik'])} | "
                       f"{_y(v['kapsam'])} | {_y(v['dogru_payi'])} | {_prog(v)} | {_karar(v)} |")
    sat += ["", "Katalog girdisi başına, ad temizlenmeden yazılsaydı:", "",
            "| Katalog girdisi | Ad | Doğru (ham adla) | Kesinlik (%95) | Program başına | Karar |", "|---|---|---|---|---|---|"]
    for gi, v in on["katalog_girdisi_ham_adla"].items():
        sat.append(f"| `{gi}` | {v['n']} | {v['dogru']} | {_o(v['kesinlik'])} | {_prog(v)} | {_karar(v)} |")
    sat += ["", "Sonradan eklenen koşullar (tür tablosu görüldükten sonra; gnulib adları):", "",
            "| Koşul | Ad | Doğru | Kesinlik (%95) | Kapsam | Program başına | Karar |", "|---|---|---|---|---|---|---|"]
    for v in on["sonradan"].values():
        haric = v.get("haric_tutulan_girdiler")
        ek = f" Hariç tutulan: {', '.join(f'`{h}`' for h in haric)}." if haric else ""
        sat.append(f"| {v['aciklama']}.{ek} | {v['n']} | {v['dogru']} | {_o(v['kesinlik'])} | {_y(v['kapsam'])} | "
                   f"{_prog(v)} | {_karar(v)} |")

    oz = s["oz_ad"]
    baslik = ("Ad | Doğru | Kesinlik (%95) | Kanıt dizgisi olduğu gibi yazılsa (%95) | Kapsam | Doğru adların payı | "
              "Program başına (doğru / dönüşümle doğru / n) | Karar | Karar (dönüşümle)")
    cizgi = "---|---|---|---|---|---|---|---|---"

    def oz_satiri(v: dict[str, Any]) -> str:
        kd = v["kanit_dizgisiyle"]
        prog = ", ".join(f"{p} {x['dogru']}/{kd['program'][p]['dogru']}/{x['n']}" for p, x in v["program"].items())
        return (f"{v['n']} | {v['dogru']} | {_o(v['kesinlik'])} | {_o(kd['kesinlik'])} | {_y(v['kapsam'])} | "
                f"{_y(v['dogru_payi'])} | {prog or '—'} | {_karar(v)} | {_karar(kd)}")

    def kosul_md(v: dict[str, Any]) -> str:
        return " ve ".join(f"`{k['ozellik']}` ∈ {{{', '.join(k['degerler'])}}}" for k in v["kosul"])

    sat += ["", "## 4. `oz_ad`: kesinliği ayıran GT'siz özellikler", "", "| Özellik | Tanım |", "|---|---|"]
    sat += [f"| `{t['ad']}` | {t['tanim']} |" for t in s["tanimlar"]["oz_ad_ozellikleri"]]
    sat += ["", "`oz_ad` adı, kanıt dizgisinin küçük harfe çevrilmiş hâlidir (gerekirse çakışma ekiyle). \"Kanıt "
            "dizgisi olduğu gibi yazılsa\" sütunu, aynı adlar için dizginin kendisi (özgün harfler, eksiz) yazılsaydı "
            "alınacak hükümdür (dönüşüm; GT'siz uygulanabilir).", "",
            f"| Özellik | Değer | {baslik} |", f"|---|---|{cizgi}|"]
    for o_, degerler in oz["ozellikler"].items():
        for deger, v in degerler.items():
            sat.append(f"| `{o_}` | `{deger}` | {oz_satiri(v)} |")
    sat += ["", "Bileşik koşullar (önceden yazılmış):", "", f"| Bileşik | Koşul | {baslik} |", f"|---|---|{cizgi}|"]
    for ad, v in oz["bilesik"].items():
        sat.append(f"| `{ad}` | {kosul_md(v)} | {oz_satiri(v)} |")
    sat += ["", "Bileşik koşullar (SONRADAN: tek özellik tabloları görüldükten sonra yazıldı; aynı veride seçildi):",
            "", f"| Bileşik | Koşul | {baslik} |", f"|---|---|{cizgi}|"]
    for ad, v in oz["sonradan"].items():
        sat.append(f"| `{ad}` | {kosul_md(v)} | {oz_satiri(v)} |")
    sat += ["", "Bütün kanal için dönüşümler (karşı olgu):", "",
            "| Dönüşüm | Doğru olurdu (%95) | Program başına | Karar |", "|---|---|---|---|"]
    for a in ("kanit_dizgisi_oldugu_gibi", "eksiz_ham_adla"):
        v = oz[a]
        sat.append(f"| {v['aciklama']} | {_o(v['kesinlik'])} | {_prog(v)} | {_karar(v)} |")
    kc = oz["ks1_capasi_dogrulugu"]
    ky = oz["ks1_yok_icinde"]
    sat += ["", "### KS-1'den sonra `oz_ad`'a kalan kısım (SONRADAN eklenen katmanlama)", "",
            "KS-1 ön adı `oz_ad` adayının önüne geçer. Aynı adreste KS-1 çapası olan `oz_ad` adlarında KS-1 adının "
            f"hükmü: çapa aynı adı veriyorsa {_o(kc['ayni_ad']['kesinlik'])}, farklı ad veriyorsa "
            f"{_o(kc['farkli_ad']['kesinlik'])} (KS-1'in hangi satırlarının üründe ad vereceği ayrı bir karardır; "
            "burada yalnız çapanın varlığına bakıldı). Çapası OLMAYAN adlar: "
            f"{_o(ky['kesinlik'])}; kanıt dizgisi olduğu gibi yazılsa {_o(ky['kanit_dizgisiyle']['kesinlik'])}. "
            "Aşağıdaki tablo yalnız bu alt kümedir (kapsam ve pay alt kümeye göre).", "",
            f"| Özellik | Değer | {baslik} |", f"|---|---|{cizgi}|"]
    for o_, degerler in ky["ozellikler"].items():
        for deger, v in degerler.items():
            sat.append(f"| `{o_}` | `{deger}` | {oz_satiri(v)} |")

    sat += ["", "## 5. `kebap_ad` ve `api_param_reverse`: yakın mı, ilgisiz mi", "",
            "Yakınlık, yanlış adın o adresteki GT adına en yakın ölçüsüdür (sırayla ilk tutan):", "",
            "| Ölçü | Tanım |", "|---|---|"]
    sat += [f"| `{t['ad']}` | {t['tanim']} |" for t in s["tanimlar"]["yakinlik"]]
    sat += ["| `gt_yok` | o adreste GT fonksiyonu yok |", "",
            "| Kanal | Yanlış | " + " | ".join(f"`{a}`" for a, _ in YAKINLIK) + " | `gt_yok` |",
            "|---|---|" + "---|" * (len(YAKINLIK) + 1)]
    for a in (GRUP_KEBAP, GRUP_API):
        v = s[a]
        sat.append(f"| `{a}` | {g[a]['yanlis']} | " + " | ".join(str(v["yakinlik"].get(o_, 0)) for o_, _ in YAKINLIK)
                   + f" | {v['yakinlik'].get('gt_yok', 0)} |")
    sat += ["", "Belirteç kümesi Jaccard benzerliği (belirteç ≥ 3 karakter; GT'si olan yanlışlar):", "",
            "| Kanal | " + " | ".join(f"`{k}`" for k in JACCARD_KOVALARI) + " | GT yok |",
            "|---|" + "---|" * (len(JACCARD_KOVALARI) + 1)]
    for a in (GRUP_KEBAP, GRUP_API):
        v = s[a]["jaccard"]
        sat.append(f"| `{a}` | " + " | ".join(str(v.get(k, 0)) for k in JACCARD_KOVALARI) + f" | {v.get('None', 0)} |")
    sat += ["", "Ürün adı ikilinin GT'sinde HERHANGİ bir adreste var mı (dönüştürerek kurtarma için üst sınır):", "",
            "| Kanal | Ad | Tam eşit | Normalleştirilince eşit | Yalnız sonek olarak | Çakışma ekli |",
            "|---|---|---|---|---|---|"]
    for a in (GRUP_KEBAP, GRUP_API):
        v = s[a]["urun_adi_ikilinin_gt_sinde"]
        sat.append(f"| `{a}` | {g[a]['n']} | {v['tam']} | {v['norm_esit']} | {v['yalniz_sonek_olarak']} | "
                   f"{s[a]['carpisma_ekli']} |")
    sat += ["", "Program başına yakınlık:", "", "| Kanal | Program | Dağılım |", "|---|---|---|"]
    for a in (GRUP_KEBAP, GRUP_API):
        for p, v in s[a]["yakinlik_program"].items():
            sat.append(f"| `{a}` | {p} | {_sayilar(v)} |")

    sat += ["", "## 6. Kural adayları", "",
            "Bütün tek özellik değerleri, önceden yazılmış bileşikler ve dönüşümler (karşı olgu) aynı kuralla "
            "karara bağlandı. `donusum`: adın yazılış biçimini değiştiren kural (kesinlik, dönüşüm uygulansaydı "
            "doğru sayılacak adlardan); `sus_kalan`: koşulu tutan adlar kalır, tutmayanlar susar.", ""]
    for karar, baslik in ((KARAR_ONERI, "### Öneri (üç koşul da tutuyor)"),
                          (KARAR_YETERSIZ, "### Yetersiz (kesinlik ≥ %95 ama n ya da program çeşitliliği yetmiyor)")):
        secilen = [a for a in s["kural_adaylari"] if a["karar"] == karar]
        sat += [baslik, ""]
        if not secilen:
            sat += ["Yok.", ""]
            continue
        sat += ["| Kanal | Koşul | Tür | Sonradan | Doğru/n | Kesinlik | Wilson alt sınırı | Kapsam (kanalın adları) | "
                "n ≥ 10 olan programlar | En büyük program dışı (doğru/n) | Neden |",
                "|---|---|---|---|---|---|---|---|---|---|---|"]
        neden = {NEDEN_WILSON: "Wilson alt sınırı < %95", NEDEN_PROGRAM: "tek program"}
        for a in secilen:
            d = a["en_buyuk_program_disi"]
            sat.append(f"| `{a['kanal']}` | {a['kosul']} | `{a['tur']}` | {'evet' if a['sonradan'] else '—'} | "
                       f"{a['dogru']}/{a['n']} | {yuzde(a['kesinlik']['oran'])} | {_alt(a['kesinlik'])} | "
                       f"{_y(a['kapsam'])} | {', '.join(a['giren_programlar']) or '—'} | {d['dogru']}/{d['n']} | "
                       f"{'; '.join(neden[n] for n in a['nedenler']) or '—'} |")
        sat.append("")
    tutmayan = [a for a in s["kural_adaylari"] if a["karar"] == KARAR_TUTMUYOR]
    sat += [f"Kesinlik eşiğini tutmayan koşul: {len(tutmayan)} (hepsi §3-§5 tablolarında ve JSON'da). Denenen "
            f"koşul sayısı: {len(s['kural_adaylari'])}; bu kadar koşul aynı veride denendiği için tek tek "
            "aralıklar iyimserdir.", "",
            "### Susturma (ürünün kendi kuralıyla)", "",
            "Ürünün alt kanal kararı \"yalnız zayıflar\" kuralıdır (N0b; `baglama.row_status_from_measurement` aynı "
            f"eşiği kullanır): yanlış oranının Wilson %95 alt sınırı hedefin ({yuzde(SUSTURMA_HEDEFI)}) üstündeyse `sus`. "
            "Aynı kural kalan kanallara, ön ad türlerine, katalog girdilerine ve `oz_ad`'ın KS-1 katmanlarına "
            "uygulandı:", "",
            "| Kapsam | Ad | Yanlış | Yanlış oranı (%95) | Karar |", "|---|---|---|---|---|"]
    sat += [f"| {r['kapsam']} | {r['n']} | {r['yanlis']} | {_o(r['yanlis_orani'])} | `{r['karar']}` |"
            for r in s["susturma"]]
    sat += ["", "## 7. Tanımda sonradan yapılan değişiklikler", ""]
    sat += [f"{i}. {m}" for i, m in enumerate(SONRADAN_DEGISIKLIKLER, 1)]
    sat += ["", "## 8. Elle denetim", ""]
    e = s["elle_denetim"]
    if e["sinif"]:
        sat += [f"Her sınıftan en az {e['ornek_sayisi']} örnek (sınıf küçükse hepsi; belirlenimci seçim: `ornek` alt "
                "komutu) uçbirimde okundu; adlar dosyaya yazılmadı. Sayılar betiğe elle girildi "
                "(`ELLE_DENETIM`).", "", "| Sınıf | İncelenen | Sınıflayıcının yanlış koyduğu |",
                "|---|---|---|"]
        sat += [f"| `{sn}` | {v['incelenen']} | {v['yanlis_konan']} |" for sn, v in e["sinif"].items()]
        sat += [f"| **Toplam** | {e['toplam']['incelenen']} | {e['toplam']['yanlis_konan']} |", ""]
        sat += [f"- {n}" for n in e["notlar"]]
    else:
        sat.append("Henüz yapılmadı.")
    sat += ["", "## 9. Sınırlar ve doğrulanamayanlar", ""]
    sat += [f"- {m}" for m in s["sinirlar"]]
    return "\n".join(sat) + "\n"


def _y(o: Optional[dict[str, Any]]) -> str:
    return "—" if not o or not o["n"] else yuzde(o["oran"])


# --------------------------------------------------------------------------------------------
# Uçbirim: örnekler (dosyaya yazılmaz)


def ornek_yaz(veri: Any, sinif: Optional[str], grup: Optional[str], n: int, durum: Optional[str],
              ozellik: Optional[str]) -> None:
    ikililer, kayitlar = veri
    secilen = [k for k in kayitlar
               if (grup is None or k["grup"] == grup)
               and (sinif is None or k.get("sinif") == sinif)
               and (durum is None or (k["durum"] == DOGRU) == (durum == "dogru"))
               and (ozellik is None or k.get("oz", {}).get(ozellik.split("=")[0]) == ozellik.split("=")[1])]
    print(f"# {len(secilen)} kayıt; ilk {min(n, len(secilen))} (belirlenimci sıra)")
    for k in _sirali_ornek(secilen, n):
        b = ikililer[k["b"]]
        print(json.dumps({
            "yer": f"{k['birim']}/{k['ikili']}", "anahtar": k["anahtar"], "kanal": k["kanal"], "durum": k["durum"],
            "urun": k["ad"], "ham": k["ham"], "gt": b.gt_adlar.get(k["adres"]), "gt_turu": k["gt_turu"],
            "sinif": k.get("sinif"), "alt": k.get("alt_sinif"), "yakinlik": k.get("yakinlik"),
            "kanit": k["kayit"].get("evidence"), "oz": k.get("oz")}, ensure_ascii=False))


# --------------------------------------------------------------------------------------------
# CLI


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="komut", required=True)
    d = sub.add_parser("dok", help="dökümü üret (JSON ve Markdown)")
    o = sub.add_parser("ornek", help="örnekleri uçbirime yaz (elle denetim; dosyaya yazmaz)")
    for p in (d, o):
        p.add_argument("--kok-debian", type=Path, default=Path.home() / "karadul_olcum" / "n1_debian13")
        p.add_argument("--kok-mac", type=Path, default=None)
        p.add_argument("--mac-veri", type=Path, default=REPO / "workspaces" / "olcum_mac")
        p.add_argument("--debian-indir", type=Path,
                       default=Path.home() / "karadul_olcum" / "downloads" / "debian13")
        p.add_argument("--taban", type=Path, default=TABAN_YOLU)
        p.add_argument("--onbellek", type=Path, default=None,
                       help="okunan kayıtların pickle'ı (geliştirme kolaylığı; ad içerir, depoya konmaz)")
    d.add_argument("--json", type=Path, required=True)
    d.add_argument("--md", type=Path, default=None)
    o.add_argument("--sinif", default=None, choices=SINIF_ADLARI)
    o.add_argument("--grup", default=None, choices=GRUPLAR)
    o.add_argument("--durum", default=None, choices=("dogru", "yanlis"))
    o.add_argument("--ozellik", default=None, help="özellik=değer")
    o.add_argument("--n", type=int, default=ORNEK_SAYISI)
    a = ap.parse_args(argv)
    try:
        sonuc, veri = dok(a.kok_debian, a.kok_mac, a.mac_veri, a.debian_indir, a.taban, a.onbellek)
    except (ks1.OnkosulHatasi, ValueError) as hata:
        print(f"DURDU: {hata}", file=sys.stderr)
        return 2
    if a.komut == "ornek":
        ornek_yaz(veri, a.sinif, a.grup, a.n, a.durum, a.ozellik)
        return 0
    a.json.parent.mkdir(parents=True, exist_ok=True)
    a.json.write_text(json.dumps(sonuc, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    if a.md:
        a.md.write_text(markdown(sonuc), encoding="utf-8")
    t = sonuc["taban_denetimi"]["satirlar"]["kalan"]
    print(f"dok: {sonuc['nufus']['ikili']} ikili; kalan kanallar {t['dogru']}/{t['ad_verilen']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
