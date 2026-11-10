"""karadul/reconstruction/tarif/kesin.py — KS-1 kesin çapalarının testleri (plan v2.2 N1).

Bütün testler sentetik ``static/`` dizinleriyle koşar (fonksiyon listesi, dizgiler, xref'ler,
gömülü disassembly); gerçek ad, GT ya da koşu verisi kullanılmaz.
Kilitlenen davranışlar:
  (a) türler: Darwin ``__assert_rtn`` 1. argüman, glibc ``__assert_fail`` 4. argüman; ``func_kalibi``
      biçim ayracı ve çağrı kuralı (Darwin: [sp, #0], AAPCS64: x(biçim+1)); aktarma ve sabit noktası;
      export (Ghidra'nın simge tablosundan adlandırdığı, thunk ve oto ad olmayan),
  (b) ad yuvası dizgisi: tanımlayıcı biçimi, ikilinin kendi adı değil,
  (c) veri akışı: birleşmede yalnız uyuşan değerler, çağrıda çağıranın sakladığı yazmaçların ölmesi,
      bayat yığın yuvası, yığından geri yükleme, bölüm çapası + ofset, kuyruk çağrısı,
  (d) assert parçasının üst fonksiyona kaldırılması, yükleyici özeti, parça çapası,
  (e) inline koruması K0-K5 ve huni sayaçları,
  (f) belirlenimcilik (girdi sırası ve karma tohumu).

Mutasyon koruması: ``scripts/measurement/mutation_specs_ks1.json``
(``PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <o dosya>``).
"""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from karadul.reconstruction.tarif import kesin as K

KOK = Path(__file__).resolve().parents[1]
MACHO = "Mac OS X Mach-O"
ELF = "Executable and Linking Format (ELF)"


# --------------------------------------------------------------------------------------------
# Sentetik static/ kurucusu


def adr(n: int, adres: int) -> list[str]:
    """``adrp xN`` + ``add xN`` ile adres yükleme (Ghidra disassembly biçimi)."""
    sayfa = adres & ~0xFFF
    return [f"adrp x{n},0x{sayfa:x}", f"add x{n},x{n},#0x{adres - sayfa:x}"]


def bl(hedef: int) -> str:
    return f"bl 0x{hedef:x}"


class Ikili:
    """Sahte bir ikilinin Ghidra çıktısı. Fonksiyon gövdeleri komut metni listesidir; adresler
    sırayla 4'er artar. Dizgi başvuruları (xrefs ``strings_used``) gövdedeki adrp/add
    çiftlerinden çıkarılır; ``ek_basvuru`` ile ayrıca eklenebilir."""

    def __init__(self, bicim: str = MACHO, program: str = "prog", islemci: str = "AARCH64"):
        self.bicim, self.program, self.islemci = bicim, program, islemci
        self.fonksiyonlar: dict[int, dict] = {}
        self.govdeler: dict[int, list[str]] = {}
        self.dizgiler: dict[int, str] = {}
        self.ek_basvurular: dict[int, set[int]] = {}
        self.ek_cagiranlar: dict[int, set[int]] = {}

    def fonksiyon(self, adres: int, govde: list[str] | None = None, ad: str | None = None,
                  thunk: bool = False, kaynak: str = "DEFAULT") -> int:
        self.fonksiyonlar[adres] = {"name": ad or f"FUN_{adres:x}", "address": f"{adres:x}",
                                    "size": 4 * len(govde or [None]), "is_thunk": thunk,
                                    "is_external": False, "source": kaynak}
        if govde is not None:
            self.govdeler[adres] = govde
        return adres

    def dizgi(self, adres: int, deger: str) -> int:
        self.dizgiler[adres] = deger
        return adres

    def ek_basvuru(self, fonksiyon: int, dizgi: int) -> None:
        self.ek_basvurular.setdefault(fonksiyon, set()).add(dizgi)

    def _basvurular(self, adres: int) -> set[int]:
        out = set(self.ek_basvurular.get(adres, set()))
        sayfa: dict[str, int] = {}
        for satir in self.govdeler.get(adres, []):
            parca = satir.replace(",", " ").split()
            if parca[0] == "adrp":
                sayfa[parca[1]] = int(parca[2], 16)
            elif parca[0] == "add" and len(parca) == 4 and parca[2] in sayfa and parca[3].startswith("#"):
                a = sayfa[parca[2]] + int(parca[3][1:], 16)
                if a in self.dizgiler:
                    out.add(a)
        return out

    def _cagiranlar(self) -> dict[int, set[int]]:
        out: dict[int, set[int]] = {a: set(v) for a, v in self.ek_cagiranlar.items()}
        for a, govde in self.govdeler.items():
            for satir in govde:
                if satir.startswith("bl "):
                    h = int(satir.split()[1], 16)
                    if h != a:
                        out.setdefault(h, set()).add(a)
        return out

    def yaz(self, kok: Path, karistir: int | None = None) -> Path:
        st = kok / "static"
        dec = st / "ghidra_output" / "decompiled"
        dec.mkdir(parents=True, exist_ok=True)
        rnd = random.Random(karistir)
        fonk = list(self.fonksiyonlar.values())
        dizgi = [{"address": f"{a:x}", "value": v, "length": len(v) + 1, "type": "string",
                  "function": None} for a, v in self.dizgiler.items()]
        cag = self._cagiranlar()
        xref = {}
        for a, f in self.fonksiyonlar.items():
            xref[f"{a:x}"] = {
                "name": f["name"], "address": f"{a:x}",
                "strings_used": [{"address": f"{s:x}", "value": self.dizgiler.get(s, "")}
                                 for s in sorted(self._basvurular(a))],
                "functions_called": [], "called_by": [
                    {"name": self.fonksiyonlar.get(c, {}).get("name", ""), "address": f"{c:x}"}
                    for c in sorted(cag.get(a, set()))]}
        sirali = list(xref.items())
        if karistir is not None:
            rnd.shuffle(fonk)
            rnd.shuffle(dizgi)
            rnd.shuffle(sirali)
        (st / "ghidra_functions.json").write_text(json.dumps(
            {"total": len(fonk), "program": self.program, "functions": fonk}))
        (st / "ghidra_strings.json").write_text(json.dumps(
            {"total": len(dizgi), "program": self.program, "strings": dizgi}))
        (st / "ghidra_xrefs.json").write_text(json.dumps(
            {"program": self.program, "function_xrefs": dict(sirali)}))
        (st / "ghidra_combined_results.json").write_text(json.dumps(
            {"program_info": {"name": self.program, "processor": self.islemci,
                              "executable_format": self.bicim}}))
        adresler = list(self.govdeler)
        if karistir is not None:
            rnd.shuffle(adresler)
        for a in adresler:
            govde = self.govdeler[a]
            ad = self.fonksiyonlar[a]["name"]
            satirlar = [f"// Function: {ad}", f"// Address:  {a:x}", f"// Size:     {4 * len(govde)} bytes",
                        "", f"void {ad}(void) {{ }}", "", "",
                        f"// --- DISASSEMBLY ({len(govde)} instructions) ---"]
            satirlar += [f"// {a + 4 * i:x}  {komut}" for i, komut in enumerate(govde)]
            (dec / f"{ad}.c").write_text("\n".join(satirlar) + "\n")
        return st


# Sabit adresler
ASSERT_RTN = 0x100090000      # Darwin thunk
ASSERT_FAIL = 0x100090010     # glibc thunk
LOG = 0x100050000             # iç günlük fonksiyonu (gövdesi ret)
DIGER = 0x100060000           # sıradan iç fonksiyon
DZ = 0x1000A0000              # dizgi bölgesi


def temel(bicim: str = MACHO, program: str = "prog") -> Ikili:
    ik = Ikili(bicim, program)
    ik.fonksiyon(ASSERT_RTN, ["b 0x200000000"], ad="___assert_rtn", thunk=True, kaynak="IMPORTED")
    ik.fonksiyon(ASSERT_FAIL, ["b 0x200000010"], ad="__assert_fail", thunk=True, kaynak="IMPORTED")
    ik.fonksiyon(LOG, ["ret"])
    ik.fonksiyon(DIGER, ["ret"])
    return ik


def cikar(ik: Ikili, tmp_path: Path, **kw) -> K.Ks1Result:
    return K.extract_anchors(ik.yaz(tmp_path), **kw)


def darwin_log(fmt: int, ad: int, cagri: int = LOG) -> list[str]:
    """Darwin: ``log(fmt, ad)``; ad ilk değişken argüman olarak [sp]'de."""
    return adr(9, ad) + ["str x9,[sp]"] + adr(0, fmt) + [bl(cagri)]


def aapcs_log(fmt: int, ad: int, cagri: int = LOG) -> list[str]:
    """AAPCS64: ``log(fmt, ad)``; ad x1'de."""
    return adr(0, fmt) + adr(1, ad) + [bl(cagri)]


def capa_adlari(r: K.Ks1Result) -> dict[str, tuple[str, tuple[str, ...], str]]:
    return {a: (c.name, c.types, c.role) for a, c in r.anchors.items()}


# --------------------------------------------------------------------------------------------
# (a) türler


def test_assert_darwin_birinci_arguman(tmp_path):
    ik = temel()
    fa, fd, ex = ik.dizgi(DZ, "izgara_kur"), ik.dizgi(DZ + 0x20, "izgara.c"), ik.dizgi(DZ + 0x40, "gd_ok")
    f = ik.fonksiyon(0x100001000, adr(0, fa) + adr(1, fd) + ["mov w2,#0x10"] + adr(3, ex)
                     + [bl(ASSERT_RTN), "ret"])
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{f:x}": ("izgara_kur", ("assert",), "kendi")}


def test_assert_glibc_dorduncu_arguman(tmp_path):
    ik = temel(ELF)
    ex, fd, fa = ik.dizgi(DZ, "ifade_var"), ik.dizgi(DZ + 0x20, "a.c"), ik.dizgi(DZ + 0x40, "kume_sil")
    f = ik.fonksiyon(0x100001000, adr(0, ex) + adr(1, fd) + ["mov w2,#0x10"] + adr(3, fa)
                     + [bl(ASSERT_FAIL), "ret"])
    r = cikar(ik, tmp_path)
    # x0'daki tanımlayıcı biçimli ifade çapa vermez; çapa 4. argümandan
    assert capa_adlari(r) == {f"{f:x}": ("kume_sil", ("assert",), "kendi")}


@pytest.mark.parametrize("bicim, yerlesim, beklenen", [
    (MACHO, "yigin", True), (MACHO, "yazmac", False), (ELF, "yazmac", True), (ELF, "yigin", False),
])
def test_func_kalibi_cagri_kurali(tmp_path, bicim, yerlesim, beklenen):
    ik = temel(bicim)
    fmt, ad = ik.dizgi(DZ, "%s: pencere yok"), ik.dizgi(DZ + 0x40, "pencere_bul")
    govde = (darwin_log(fmt, ad) if yerlesim == "yigin" else aapcs_log(fmt, ad)) + ["ret"]
    f = ik.fonksiyon(0x100001000, govde)
    r = cikar(ik, tmp_path)
    beklenen_capa = {f"{f:x}": ("pencere_bul", ("func_kalibi",), "kendi")} if beklenen else {}
    assert capa_adlari(r) == beklenen_capa


@pytest.mark.parametrize("bicim, gecer", [
    ("%s: x=%d", True), ("%s:", True), ("%s(): bitti", False), ("%s() basladi", False),
    ("%s %s", False), ("%s - hata", False), ("x%s: y", False), ("%sx: y", False), ("%d: %s", False),
])
def test_bicim_ayraci(tmp_path, bicim, gecer):
    ik = temel(ELF)
    fmt, ad = ik.dizgi(DZ, bicim), ik.dizgi(DZ + 0x40, "oturum_ac")
    f = ik.fonksiyon(0x100001000, aapcs_log(fmt, ad) + ["ret"])
    r = cikar(ik, tmp_path)
    assert (f"{f:x}" in r.anchors) is gecer


def test_bicim_birden_cok_yazmacta_ise_yuva_yok(tmp_path):
    ik = temel(ELF)
    fmt, fmt2, ad = ik.dizgi(DZ, "%s: a"), ik.dizgi(DZ + 0x20, "%s: b"), ik.dizgi(DZ + 0x40, "oturum_ac")
    f = ik.fonksiyon(0x100001000, adr(0, fmt) + adr(1, ad) + adr(2, fmt2) + [bl(LOG), "ret"])
    assert f"{f:x}" not in cikar(ik, tmp_path).anchors


@pytest.mark.parametrize("deger, gecer", [
    ("oturum_ac", True), ("main", False), ("_iç", False), ("oturum ac", False), ("oturum-ac", False),
    ("a", False), ("9abc", False), ("prog", False), ("Oturum_Ac2", True), ("oturumAc", True),
    ("OTURUM_AC", False), ("oturum_ac\n", False), ("prog_ac", True), ("_oturum", False),
    # çok parçalı ve küçük harfli ama tanımlayıcı değil: günlük süzgeci tanımlayıcı şartını örtmemeli
    ("oturum_ac-x", False), ("9oturum_ac", False), ("oturum_ac.c", False), ("ic_adı", False),
])
def test_ad_yuvasi_dizgisi(tmp_path, deger, gecer):
    ik = temel(ELF, program="prog")
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, deger)
    f = ik.fonksiyon(0x100001000, aapcs_log(fmt, ad) + ["ret"])
    r = cikar(ik, tmp_path)
    assert (f"{f:x}" in r.anchors) is gecer


def test_aktarma_ve_sabit_noktasi(tmp_path):
    ik = temel(MACHO)
    fmt = ik.dizgi(DZ, "%s: s=%u")
    ad1, ad2 = ik.dizgi(DZ + 0x40, "bul_oturum"), ik.dizgi(DZ + 0x60, "bul_pencere")
    # H(prefix): parametre 0 → x19 → [sp] (Darwin değişken argümanı) → "%s: ..." biçimi
    h = ik.fonksiyon(0x100002000, ["mov x19,x0"] + ["str x19,[sp]"] + adr(0, fmt) + [bl(LOG), "ret"])
    # H2(p): parametre 0'ı H'ye x0'da geçirir (aktarıcının aktarıcısı)
    h2 = ik.fonksiyon(0x100002100, ["mov x20,x0", "mov x0,x20", bl(h), "ret"])
    c1 = ik.fonksiyon(0x100003000, adr(0, ad1) + [bl(h), "ret"])
    c2 = ik.fonksiyon(0x100003100, adr(0, ad2) + [bl(h2), "ret"])
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{c1:x}": ("bul_oturum", ("func_aktarma",), "kendi"),
                              f"{c2:x}": ("bul_pencere", ("func_aktarma",), "kendi")}
    assert r.counts["aktarici_fonksiyon"] == 2
    assert f"{h:x}" not in r.anchors and f"{h2:x}" not in r.anchors
    # tür kapalıysa aktarma yuvası çıkmaz
    r2 = cikar(ik, tmp_path / "b", types=("assert", "func_kalibi"))
    assert r2.anchors == {}


def test_export_ve_oto_adlar(tmp_path):
    ik = temel(ELF)
    e = ik.fonksiyon(0x100004000, ["ret"], ad="Meter_init", kaynak="IMPORTED")
    ik.fonksiyon(0x100004100, ["ret"], ad="entry", kaynak="IMPORTED")
    ik.fonksiyon(0x100004200, ["ret"], ad="_DT_INIT", kaynak="IMPORTED")
    ik.fonksiyon(0x100004300, ["ret"], ad="_FINI_0", kaynak="IMPORTED")
    ik.fonksiyon(0x100004400, ["b 0x100004000"], ad="Meter_init", thunk=True, kaynak="IMPORTED")
    ik.fonksiyon(0x100004500, ["ret"], ad="ilginc", kaynak="ANALYSIS")
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{e:x}": ("Meter_init", ("export",), "kendi")}
    assert r.counts["9_capa:export"] == 1
    assert cikar(ik, tmp_path / "b", types=K.STRING_TYPES).anchors == {}


# --------------------------------------------------------------------------------------------
# (c) veri akışı


def test_birlesmede_yalniz_uyusan_deger_kalir(tmp_path):
    ik = temel(ELF)
    fmt, ad, ad2 = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "yol_bir"), ik.dizgi(DZ + 0x60, "yol_iki")
    # f1: iki yol x1'i farklı dizgiyle yükler → birleşmede x1 bilinmez
    a1 = 0x100001000
    govde1 = adr(0, fmt) + ["cbz w3,0x%x" % (a1 + 4 * 6)] + adr(1, ad) + ["b 0x%x" % (a1 + 4 * 8)] \
        + adr(1, ad2) + [bl(LOG), "ret"]
    ik.fonksiyon(a1, govde1)
    # f2: iki yol x1'i aynı dizgiyle yükler → birleşmede bilinir
    a2 = 0x100001100
    ad3 = ik.dizgi(DZ + 0x80, "yol_ayni")
    govde2 = adr(0, fmt) + ["cbz w3,0x%x" % (a2 + 4 * 6)] + adr(1, ad3) + ["b 0x%x" % (a2 + 4 * 8)] \
        + adr(1, ad3) + [bl(LOG), "ret"]
    ik.fonksiyon(a2, govde2)
    r = cikar(ik, tmp_path)
    assert f"{a1:x}" not in r.anchors
    assert capa_adlari(r)[f"{a2:x}"] == ("yol_ayni", ("func_kalibi",), "kendi")


def test_cagri_cagiranin_sakladigi_yazmaclari_oldurur(tmp_path):
    ik = temel(ELF)
    fmt, ad, ad2 = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "once_yuklu"), ik.dizgi(DZ + 0x60, "korunan_ad")
    # x1 çağrıdan önce yüklenir, araya bir çağrı girer: x1 ölür
    f1 = ik.fonksiyon(0x100001000, adr(1, ad) + [bl(DIGER)] + adr(0, fmt) + [bl(LOG), "ret"])
    # x19 çağrıda korunur
    f2 = ik.fonksiyon(0x100001100, adr(19, ad2) + [bl(DIGER), "mov x1,x19"] + adr(0, fmt)
                      + [bl(LOG), "ret"])
    r = cikar(ik, tmp_path)
    assert f"{f1:x}" not in r.anchors
    assert f"{f2:x}" in r.anchors


def test_bayat_yigin_yuvasi_degisken_arguman_sayilmaz(tmp_path):
    ik = temel(MACHO)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "bayat_ad")
    f = ik.fonksiyon(0x100001000, adr(9, ad) + ["str x9,[sp]", bl(DIGER)] + adr(0, fmt)
                     + [bl(LOG), "ret"])
    assert f"{f:x}" not in cikar(ik, tmp_path).anchors


def test_yigindan_geri_yukleme_ve_bolum_capasi(tmp_path):
    ik = temel(ELF)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x88, "capali_ad")
    # x20 = DZ (çapa), x1 = x20 + 0x88; [sp, #0x68]'e sakla, çağrı, geri yükle
    govde = adr(20, DZ) + ["add x1,x20,#0x88", "str x1,[sp, #0x68]", bl(DIGER), "ldr x1,[sp, #0x68]"]
    f = ik.fonksiyon(0x100001000, govde + adr(0, fmt) + [bl(LOG), "ret"])
    ik.ek_basvuru(f, ad)
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{f:x}": ("capali_ad", ("func_kalibi",), "kendi")}


def test_sp_degisince_yigin_haritasi_silinir(tmp_path):
    ik = temel(MACHO)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "kayan_ad")
    f = ik.fonksiyon(0x100001000, adr(9, ad) + ["str x9,[sp]", "sub sp,sp,#0x10"] + adr(0, fmt)
                     + [bl(LOG), "ret"])
    assert f"{f:x}" not in cikar(ik, tmp_path).anchors


def test_guvenlik_siniri_tutucu(tmp_path, monkeypatch):
    """Sabit nokta sınırı aşılan blok hiçbir değeri bilmeyen duruma iner (çapa üretmez)."""
    ik = temel(ELF)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "sinir_ad")
    a = 0x100001000
    # değerler ilk blokta yüklenir; çağrı, dallanmayla girilen ikinci blokta
    f = ik.fonksiyon(a, adr(0, fmt) + adr(1, ad) + [f"b 0x{a + 20:x}", bl(LOG), "ret"])
    assert f"{f:x}" in cikar(ik, tmp_path / "a").anchors
    monkeypatch.setattr(K, "_MAX_ROUNDS", 0)
    assert cikar(ik, tmp_path / "b").anchors == {}


def test_kuyruk_cagrisi_yuvasi(tmp_path):
    ik = temel(ELF)
    fmt, ad = ik.dizgi(DZ, "%s: bitti"), ik.dizgi(DZ + 0x40, "son_is")
    f = ik.fonksiyon(0x100001000, adr(0, fmt) + adr(1, ad) + [f"b 0x{LOG:x}"])
    assert capa_adlari(cikar(ik, tmp_path)) == {f"{f:x}": ("son_is", ("func_kalibi",), "kendi")}


# --------------------------------------------------------------------------------------------
# (d) assert parçaları, yükleyici


def test_assert_parcasi_ust_fonksiyona_kalkar(tmp_path):
    ik = temel(MACHO)
    fa, fd, ex = ik.dizgi(DZ, "satir_sil"), ik.dizgi(DZ + 0x20, "izgara.c"), ik.dizgi(DZ + 0x40, "gl")
    p = 0x100001000
    s1, s2 = 0x100008000, 0x100008100
    ik.fonksiyon(s1, adr(0, fa) + adr(1, fd) + adr(3, ex) + [bl(ASSERT_RTN)])   # dönmez
    ik.fonksiyon(s2, adr(0, fa) + adr(1, fd) + adr(3, ex) + [bl(ASSERT_RTN)])
    ik.fonksiyon(p, ["cbz x0,0x%x" % (p + 12), bl(s1), bl(s2), "ret"])
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{p:x}": ("satir_sil", ("assert",), "ust"),
                              f"{s1:x}": ("satir_sil", ("assert",), "parca"),
                              f"{s2:x}": ("satir_sil", ("assert",), "parca")}
    assert r.counts["assert_parcasi"] == 2 and r.counts["capa_parca"] == 2
    assert K.kesin_mapping(r) == {f"{p:x}": "satir_sil"}


def test_assert_parcasi_iki_ustlu_ise_sahipsiz(tmp_path):
    ik = temel(MACHO)
    fa, fd = ik.dizgi(DZ, "satir_sil"), ik.dizgi(DZ + 0x20, "izgara.c")
    s = ik.fonksiyon(0x100008000, adr(0, fa) + adr(1, fd) + [bl(ASSERT_RTN)])
    ik.fonksiyon(0x100001000, [bl(s), "ret"])
    ik.fonksiyon(0x100001100, [bl(s), "ret"])
    r = cikar(ik, tmp_path)
    assert r.anchors == {}
    assert r.counts["eleme:K2_sahipsiz:assert"] == 1


def test_donen_fonksiyon_parca_degildir(tmp_path):
    ik = temel(MACHO)
    fa, fd = ik.dizgi(DZ, "denetle"), ik.dizgi(DZ + 0x20, "a.c")
    f = ik.fonksiyon(0x100008000, adr(0, fa) + adr(1, fd) + [bl(ASSERT_RTN), "ret"])
    ik.fonksiyon(0x100001000, [bl(f), "ret"])
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{f:x}": ("denetle", ("assert",), "kendi")}


@pytest.mark.parametrize("ek", ["dolayli", "kosullu_dis"])
def test_dolayli_cagrili_ya_da_disa_kosullu_dallanan_parca_degildir(tmp_path, ek):
    ik = temel(MACHO)
    fa, fd = ik.dizgi(DZ, "dogrula_bunu"), ik.dizgi(DZ + 0x20, "a.c")
    bas = ["blr x8"] if ek == "dolayli" else [f"cbz x0,0x{DIGER:x}"]
    s = ik.fonksiyon(0x100008000, bas + adr(0, fa) + adr(1, fd) + [bl(ASSERT_RTN)])
    ik.fonksiyon(0x100001000, [bl(s), "ret"])
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{s:x}": ("dogrula_bunu", ("assert",), "kendi")}
    assert r.counts["assert_parcasi"] == 0


def test_parca_zinciri_sabit_nokta(tmp_path):
    ik = temel(MACHO)
    fa, fd = ik.dizgi(DZ, "zincir_bas"), ik.dizgi(DZ + 0x20, "a.c")
    sb = ik.fonksiyon(0x100008100, adr(0, fa) + adr(1, fd) + [bl(ASSERT_RTN)])   # assert parçası
    sa = ik.fonksiyon(0x100008000, ["mov w2,#0x1", f"b 0x{sb:x}"])                # parçaya kuyruk çağrısı
    p = ik.fonksiyon(0x100001000, ["cbz x0,0x100001008", bl(sa), "ret"])
    r = cikar(ik, tmp_path)
    assert r.counts["assert_parcasi"] == 2
    assert capa_adlari(r) == {f"{p:x}": ("zincir_bas", ("assert",), "ust"),
                              f"{sb:x}": ("zincir_bas", ("assert",), "parca")}


def test_yukleyici_ozeti_assert_yuvasinda(tmp_path):
    ik = temel(MACHO)
    fa, fd = ik.dizgi(DZ, "temizlik_denetle"), ik.dizgi(DZ + 0x20, "izgara.c")
    ld = ik.fonksiyon(0x100007000, adr(0, fa) + adr(1, fd) + ["ret"])   # makine dışlayıcısı
    s1 = ik.fonksiyon(0x100008000, [bl(ld), "mov w2,#0x54", bl(ASSERT_RTN)])
    s2 = ik.fonksiyon(0x100008100, [bl(ld), "mov w2,#0x55", bl(ASSERT_RTN)])
    p = ik.fonksiyon(0x100001000, ["cbz x0,0x100001008", bl(s1), bl(s2), "ret"])
    r = cikar(ik, tmp_path)
    assert capa_adlari(r)[f"{p:x}"] == ("temizlik_denetle", ("assert",), "ust")
    # yükleyici başka bir yerden de çağrılıyorsa (yuvada tüketilmiyor) K1 dizgiyi düşürür
    ik.fonksiyon(0x100001100, [bl(ld), "ret"])
    r2 = cikar(ik, tmp_path / "b")
    assert r2.anchors == {}
    assert r2.counts["eleme:K1_yuva_disi_basvuru:assert"] == 1


def test_yukleyici_degeri_func_kalibinde_sayilmaz(tmp_path):
    ik = temel(ELF)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "ad_veren")
    ld = ik.fonksiyon(0x100007000, adr(0, ad) + ["ret"])
    f = ik.fonksiyon(0x100001000, [bl(ld), "mov x1,x0"] + adr(0, fmt) + [bl(LOG), "ret"])
    assert f"{f:x}" not in cikar(ik, tmp_path).anchors


# --------------------------------------------------------------------------------------------
# (e) inline koruması


@pytest.mark.parametrize("dosya, capa", [
    ("./lib/common/bits.h", False), ("mem.H", False), ("x.hpp", False), ("tablo.inc", False),
    ("izgara.c", True), ("bits.hash", True), ("h", True),
])
def test_K0_baslik_dosyasi(tmp_path, dosya, capa):
    ik = temel(ELF)
    ex, fd, fa = ik.dizgi(DZ, "x_y"), ik.dizgi(DZ + 0x20, dosya), ik.dizgi(DZ + 0x40, "yardimci_fonk")
    f = ik.fonksiyon(0x100001000, adr(0, ex) + adr(1, fd) + adr(3, fa) + [bl(ASSERT_FAIL), "ret"])
    r = cikar(ik, tmp_path)
    assert (f"{f:x}" in r.anchors) is capa
    assert r.counts.get("eleme:K0_baslik_dosyasi:assert", 0) == (0 if capa else 1)


def test_K0_basliktaki_ad_K3_celiskisi_sayilmaz(tmp_path):
    ik = temel(ELF)
    ex, h, c = ik.dizgi(DZ, "x_y"), ik.dizgi(DZ + 0x20, "bits.h"), ik.dizgi(DZ + 0x30, "zstd.c")
    satir_ici, kendi = ik.dizgi(DZ + 0x40, "highbit"), ik.dizgi(DZ + 0x60, "sikistir")
    f = ik.fonksiyon(0x100001000, adr(0, ex) + adr(1, h) + adr(3, satir_ici) + [bl(ASSERT_FAIL)]
                     + adr(0, ex) + adr(1, c) + adr(3, kendi) + [bl(ASSERT_FAIL), "ret"])
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{f:x}": ("sikistir", ("assert",), "kendi")}


def test_K1_yuva_disi_basvuru(tmp_path):
    ik = temel(ELF)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "tablo_adi")
    f = ik.fonksiyon(0x100001000, aapcs_log(fmt, ad) + ["ret"])
    g = ik.fonksiyon(0x100001100, adr(2, ad) + [bl(DIGER), "ret"])   # yuva değil
    r = cikar(ik, tmp_path)
    assert r.anchors == {}
    assert r.counts["eleme:K1_yuva_disi_basvuru:func_kalibi"] == 1
    assert {d["neden"] for d in r.dropped} == {"K1_yuva_disi_basvuru"}
    del f, g


def test_K2_cok_sahip(tmp_path):
    ik = temel(ELF)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "satir_ici")
    ik.fonksiyon(0x100001000, aapcs_log(fmt, ad) + ["ret"])
    ik.fonksiyon(0x100001100, aapcs_log(fmt, ad) + ["ret"])
    r = cikar(ik, tmp_path)
    assert r.anchors == {}
    assert r.counts["eleme:K2_cok_sahip:func_kalibi"] == 1
    assert r.counts["4_K1_sonrasi:func_kalibi"] == 1 and r.counts["5_K2_sonrasi:func_kalibi"] == 0


def test_K3_govdede_cok_ad_elenmis_dizgi_dahil(tmp_path):
    ik = temel(ELF)
    fmt = ik.dizgi(DZ, "%s: x")
    ad1, ad2 = ik.dizgi(DZ + 0x40, "dis_fonk"), ik.dizgi(DZ + 0x60, "ic_fonk")
    f = ik.fonksiyon(0x100001000, aapcs_log(fmt, ad1) + aapcs_log(fmt, ad2) + ["ret"])
    # ad2 başka bir fonksiyonda da yuvada: K2 onu düşürür; f'nin gövdesinde yine iki ad var
    ik.fonksiyon(0x100001100, aapcs_log(fmt, ad2) + ["ret"])
    r = cikar(ik, tmp_path)
    assert r.anchors == {}
    assert r.counts["eleme:K3_govdede_cok_ad:func_kalibi"] == 1
    del f


def test_K3_turler_arasi_celiski(tmp_path):
    ik = temel(ELF)
    fmt, ad1, ad2 = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "bir_ad"), ik.dizgi(DZ + 0x60, "iki_ad")
    f = ik.fonksiyon(0x100001000, aapcs_log(fmt, ad1) + adr(3, ad2) + [bl(ASSERT_FAIL), "ret"])
    r = cikar(ik, tmp_path)
    assert r.anchors == {}
    # aynı ad iki türden gelirse çapa iki türü de taşır
    ik2 = temel(ELF)
    fmt, ad, fd = ik2.dizgi(DZ, "%s: x"), ik2.dizgi(DZ + 0x40, "bir_ad"), ik2.dizgi(DZ + 0x20, "a.c")
    g = ik2.fonksiyon(0x100001000, aapcs_log(fmt, ad) + adr(1, fd) + adr(3, ad)
                      + [bl(ASSERT_FAIL), "ret"])
    r2 = cikar(ik2, tmp_path / "b")
    assert capa_adlari(r2) == {f"{g:x}": ("bir_ad", ("assert", "func_kalibi"), "kendi")}
    del f


def test_K4_ad_tekligi(tmp_path):
    ik = temel(ELF)
    fmt = ik.dizgi(DZ, "%s: x")
    a1, a2 = ik.dizgi(DZ + 0x40, "kullan_bunu"), ik.dizgi(DZ + 0x60, "kullan_bunu")   # iki nesne, aynı ad
    ik.fonksiyon(0x100001000, aapcs_log(fmt, a1) + ["ret"])
    ik.fonksiyon(0x100001100, aapcs_log(fmt, a2) + ["ret"])
    r = cikar(ik, tmp_path)
    assert r.anchors == {}
    assert r.counts["eleme:K4_ad_cok_fonksiyonda:func_kalibi"] == 2


@pytest.mark.parametrize("bicim, ghidra_adi, dolu", [
    (ELF, "oturum_kapat", True), (MACHO, "_oturum_kapat", True), (ELF, "_oturum_kapat", False),
    (MACHO, "FUN_100004400", False),
])
def test_K4_ghidra_adi_dolu(tmp_path, bicim, ghidra_adi, dolu):
    ik = temel(bicim)
    fmt, ad = ik.dizgi(DZ, "%s: %s"), ik.dizgi(DZ + 0x40, "oturum_kapat")
    ik.fonksiyon(0x100004400, ["b 0x200000100"], ad=ghidra_adi, thunk=True, kaynak="IMPORTED")
    govde = (darwin_log(fmt, ad) if bicim == MACHO else aapcs_log(fmt, ad)) + ["ret"]
    f = ik.fonksiyon(0x100001000, govde)
    r = cikar(ik, tmp_path)
    assert (f"{f:x}" in r.anchors) is not dolu
    assert r.counts.get("eleme:K4_ghidra_adi_dolu:func_kalibi", 0) == int(dolu)


def test_K0_dosya_bilinmiyor(tmp_path):
    ik = temel(ELF)
    ex, fd, fa = ik.dizgi(DZ, "x_y"), ik.dizgi(DZ + 0x20, "a.c"), ik.dizgi(DZ + 0x40, "yardimci_fonk")
    f = ik.fonksiyon(0x100001000, adr(0, ex) + ["mov x1,x20"] + adr(3, fa) + [bl(ASSERT_FAIL), "ret"])
    r = cikar(ik, tmp_path)
    assert f"{f:x}" not in r.anchors
    assert r.counts["eleme:K0_dosya_bilinmiyor:assert"] == 1
    # dosyası bilinmeyen ad, aynı gövdedeki başka bir ad için K3'te rakip sayılır
    ik2 = temel(ELF)
    ex, fd = ik2.dizgi(DZ, "x_y"), ik2.dizgi(DZ + 0x20, "a.c")
    yabanci, kendi = ik2.dizgi(DZ + 0x40, "yabanci_ad"), ik2.dizgi(DZ + 0x60, "kendi_ad")
    g = ik2.fonksiyon(0x100001000, adr(0, ex) + ["mov x1,x20"] + adr(3, yabanci) + [bl(ASSERT_FAIL)]
                      + adr(0, ex) + adr(1, fd) + adr(3, kendi) + [bl(ASSERT_FAIL), "ret"])
    r2 = cikar(ik2, tmp_path / "b")
    assert f"{g:x}" not in r2.anchors
    assert r2.counts["eleme:K3_govdede_cok_ad:assert"] == 1


def test_assert_yuvasinda_ad_bicimi_suzgeci_yok(tmp_path):
    ik = temel(ELF, program="tree")
    ex, fd = ik.dizgi(DZ, "x_y"), ik.dizgi(DZ + 0x20, "a.c")
    a1, a2 = ik.dizgi(DZ + 0x40, "main"), ik.dizgi(DZ + 0x60, "tree")
    f1 = ik.fonksiyon(0x100001000, adr(0, ex) + adr(1, fd) + adr(3, a1) + [bl(ASSERT_FAIL), "ret"])
    f2 = ik.fonksiyon(0x100001100, adr(0, ex) + adr(1, fd) + adr(3, a2) + [bl(ASSERT_FAIL), "ret"])
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{f1:x}": ("main", ("assert",), "kendi"),
                              f"{f2:x}": ("tree", ("assert",), "kendi")}


@pytest.mark.parametrize("program, deger, gecer", [
    ("redis-cli", "redis_cli", False), ("redis-cli", "Redis_Cli", False),
    ("redis-cli", "redis_cli_main", True), ("tmux", "tmux_kur", True),
])
def test_gunluk_turunde_program_adi_bicimleri(tmp_path, program, deger, gecer):
    ik = temel(ELF, program=program)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, deger)
    f = ik.fonksiyon(0x100001000, aapcs_log(fmt, ad) + ["ret"])
    assert (f"{f:x}" in cikar(ik, tmp_path).anchors) is gecer


def test_ad_bicimi_islevleri():
    assert K.program_name_forms("redis-cli") == frozenset({"redis-cli", "redis_cli", "redis", "cli"})
    assert K.log_name_candidate("pencereBul", "p") and not K.log_name_candidate("PENCERE_BUL", "p")
    assert not K.log_name_candidate("pencere", "p") and K.log_name_candidate("pencere_bul", "p")
    assert K.name_candidate("main") and not K.name_candidate("main\n") and not K.name_candidate(None)


def test_K5_zaten_adli(tmp_path):
    ik = temel(ELF)
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "baska_ad")
    f = ik.fonksiyon(0x100001000, aapcs_log(fmt, ad) + ["ret"], ad="gercek_ad", kaynak="IMPORTED")
    r = cikar(ik, tmp_path)
    assert capa_adlari(r) == {f"{f:x}": ("gercek_ad", ("export",), "kendi")}
    assert r.counts["eleme:K5_zaten_adli:func_kalibi"] == 1


def test_huni_sayaclari(tmp_path):
    ik = temel(ELF)
    fmt = ik.dizgi(DZ, "%s: x")
    a1, a2 = ik.dizgi(DZ + 0x40, "tek_ad"), ik.dizgi(DZ + 0x60, "ikinci_ad")
    ik.fonksiyon(0x100001000, aapcs_log(fmt, a1) + aapcs_log(fmt, a1) + ["ret"])
    ik.fonksiyon(0x100001100, aapcs_log(fmt, a2) + ["ret"])
    r = cikar(ik, tmp_path)
    c = r.counts
    assert [c[f"{a}:func_kalibi"] for a in K.FUNNEL] == [3, 2, 2, 2, 2, 2, 2, 2, 2]
    assert all(c[f"{a}:assert"] == 0 for a in K.FUNNEL)
    assert len(r.anchors) == 2


def test_desteklenmeyen_platform(tmp_path):
    ik = temel(ELF)
    ik.islemci = "x86"
    fmt, ad = ik.dizgi(DZ, "%s: x"), ik.dizgi(DZ + 0x40, "ad_bir")
    ik.fonksiyon(0x100001000, aapcs_log(fmt, ad) + ["ret"])
    r = cikar(ik, tmp_path)
    assert r.abi is None and r.anchors == {} and r.counts["desteklenmeyen_platform"] == 1


def test_yuklenmeyen_bolum_adresi_atlanir(tmp_path):
    ik = temel(ELF)
    st = ik.yaz(tmp_path)
    belge = json.loads((st / "ghidra_strings.json").read_text())
    belge["strings"].append({"address": ".shstrtab::00000001", "value": ".text", "type": "string"})
    (st / "ghidra_strings.json").write_text(json.dumps(belge))
    inp = K.load_static(st)
    assert ".text" not in inp.strings.values()


# --------------------------------------------------------------------------------------------
# (f) belirlenimcilik


def _zengin(bicim: str = MACHO) -> Ikili:
    ik = temel(bicim)
    fmt = ik.dizgi(DZ, "%s: x")
    for i in range(12):
        ad = ik.dizgi(DZ + 0x100 + 0x20 * i, f"fonk_{i}")
        log = darwin_log(fmt, ad) if bicim == MACHO else aapcs_log(fmt, ad)
        ik.fonksiyon(0x100001000 + 0x100 * i, log + ["ret"])
    fa = ik.dizgi(DZ + 0x800, "parcali")
    s = ik.fonksiyon(0x100008000, adr(0, fa) + [bl(ASSERT_RTN)])
    ik.fonksiyon(0x100002000, [bl(s), "ret"])
    return ik


def _ozet(r: K.Ks1Result) -> str:
    return json.dumps({"capa": [c.as_dict() for c in r.anchors.values()], "sayac": r.counts,
                       "elenen": r.dropped}, sort_keys=True)


def test_girdi_sirasindan_bagimsiz(tmp_path):
    ik = _zengin()
    ilk = _ozet(K.extract_anchors(ik.yaz(tmp_path / "a")))
    for tohum in (1, 2, 3):
        assert _ozet(K.extract_anchors(ik.yaz(tmp_path / f"k{tohum}", karistir=tohum))) == ilk
    assert list(K.extract_anchors(ik.yaz(tmp_path / "z")).anchors) == sorted(
        K.extract_anchors(ik.yaz(tmp_path / "y")).anchors, key=lambda a: int(a, 16))


def test_karma_tohumundan_bagimsiz(tmp_path):
    st = _zengin().yaz(tmp_path, karistir=5)
    kod = ("import json,sys; from pathlib import Path; from karadul.reconstruction.tarif import kesin as K;"
           "r=K.extract_anchors(Path(sys.argv[1]));"
           "print(json.dumps({'c':[c.as_dict() for c in r.anchors.values()],'s':r.counts,'d':r.dropped},"
           "sort_keys=True))")
    ciktilar = set()
    for tohum in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=tohum, PYTHONDONTWRITEBYTECODE="1")
        out = subprocess.run([sys.executable, "-c", kod, str(st)], cwd=KOK, env=env,
                             capture_output=True, text=True, check=True).stdout
        ciktilar.add(out)
    assert len(ciktilar) == 1
