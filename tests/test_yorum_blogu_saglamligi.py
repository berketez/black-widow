"""Yorum bloğu sağlamlığı: üretilen yorum geçerli C olsun ve kendi fonksiyonunu anlatsın.

İki kusuru kilitler (docs/arge/2026-11-10_cikti_saglamligi/rapor.md, bulgu 5 ve 11):

5.  Belge yorumu iç içe yorumla C'yi bozuyordu: imzadaki ``/* was: param_2 */``
    parametre metniyle birlikte ``/** ... */`` bloğuna kopyalanıyor, blok orada
    kapanıyor, kalan ``@calls``/``@algorithm`` satırları koda sızıyordu.
11. ``@address``/``@size``/``@called_by`` fonksiyon ADIYLA aranıyordu; aynı adlı
    iki fonksiyonda (ELF: thunk + dış sembol) öbür fonksiyonun kaydı geliyordu.

Son koşul yardımcısı ``yorum_ihlalleri`` küçük bir C sözcük tarayıcıdır (dizgi ve
karakter sabitlerini, ``//`` yorumlarını atlar). Hem buradaki birim testlerde hem
gerçek ikili kapısında kullanılır::

    python tests/test_yorum_blogu_saglamligi.py <çıktı dizini> [<çıktı dizini> ...]
"""

from __future__ import annotations

import bisect
import json
import random
import re
import sys
from pathlib import Path

import pytest

from karadul.reconstruction import c_comment_generator as ccg
from karadul.reconstruction.c_algorithm_id import AlgorithmMatch
from karadul.reconstruction.c_comment_generator import CCommentGenerator
from karadul.reconstruction.engineering.semantic_namer import (
    SemanticName,
    SemanticParameterNamer,
)

# ---------------------------------------------------------------------------
# Son koşul yardımcısı: C sözcük tarayıcı
# ---------------------------------------------------------------------------

KAPANIS_YORUM_DISINDA = "yorum dışında */"
ACILIS_BLOK_ICINDE = "blok yorumunun içinde /*"
KAPANMAMIS_BLOK = "kapanmamış blok yorumu"

_KOD, _BLOK, _SATIR, _DIZGI, _KARAKTER = range(5)


def yorum_ihlalleri(metin: str) -> list[tuple[int, str]]:
    """C metnindeki yorum dengesi ihlallerini ``(satır no, tür)`` olarak döndürür.

    Son koşul: yorum dışında ``*/`` yok; blok yorumunun içinde ``/*`` yok; dosya
    sonunda açık blok yorumu yok. Tarama C kurallarıyla yapılır:

    - dizgi (``"..."``) ve karakter (``'...'``) sabitlerinin içi atlanır, ``\\``
      kaçışı tanınır; kapanmamış sabit satır sonunda biter;
    - ``//`` yorumu satır sonuna kadar sürer; satır ``\\`` ile bitiyorsa sonraki
      satır da yorumdur (satır birleştirme);
    - blok yorumu İLK ``*/`` ile kapanır (yorumlar iç içe geçmez).
    """
    konumlar: list[tuple[int, str]] = []
    durum = _KOD
    blok_basi = 0
    i = 0
    n = len(metin)
    while i < n:
        c = metin[i]
        iki = metin[i:i + 2]
        if durum == _KOD:
            if iki == "/*":
                durum = _BLOK
                blok_basi = i
                i += 2
            elif iki == "//":
                durum = _SATIR
                i += 2
            elif iki == "*/":
                konumlar.append((i, KAPANIS_YORUM_DISINDA))
                i += 2
            else:
                if c == '"':
                    durum = _DIZGI
                elif c == "'":
                    durum = _KARAKTER
                i += 1
        elif durum == _BLOK:
            if iki == "*/":
                durum = _KOD
                i += 2
            elif iki == "/*":
                konumlar.append((i, ACILIS_BLOK_ICINDE))
                i += 1          # "/*/" dizisinde ardından gelen "*/" bloğu kapatır
            else:
                i += 1
        elif durum == _SATIR:
            if iki == "\\\n":
                i += 2          # satır birleştirme: yorum sonraki satırda sürer
            else:
                if c == "\n":
                    durum = _KOD
                i += 1
        else:                   # dizgi ya da karakter sabiti
            if c == "\\" and i + 1 < n:
                i += 2
            else:
                kapanis = '"' if durum == _DIZGI else "'"
                if c == kapanis or c == "\n":
                    durum = _KOD
                i += 1
    if durum == _BLOK:
        konumlar.append((blok_basi, KAPANMAMIS_BLOK))

    satir_baslari = [0] + [m.end() for m in re.finditer("\n", metin)]
    return [(bisect.bisect_right(satir_baslari, konum), tur) for konum, tur in konumlar]


# ---------------------------------------------------------------------------
# Gerçek ikili kapısı: bir çıktı ağacını say
# ---------------------------------------------------------------------------

_KAPI_BASLIK = re.compile(r"^// Function: .*$", re.M)
_KAPI_BASLIK_ADRES = re.compile(r"^// Address:\s+(\S+)\s*$", re.M)
_KAPI_BELGE_ADRES = re.compile(r"^[ \t]*\*[ \t]*@address[ \t]+(\S+)[ \t]*$", re.M)
_KAPI_BELGE_ACILIS = re.compile(r"^/\*\*[ \t]*$", re.M)
_KAPI_UZANTILAR = (".c", ".h", ".cpp", ".cc")


def _adres_yalin(adres: str) -> str:
    adres = adres.strip().lower()
    if adres.startswith("0x"):
        adres = adres[2:]
    return adres.lstrip("0") or "0"


def adres_uyusmazliklari(metin: str) -> list[tuple[str, str]]:
    """``// Address:`` başlığı ile aynı bloktaki ``@address`` farklıysa ``(başlık, belge)``.

    Dosya ``// Function:`` başlıklarından bloklara bölünür; her blokta başlık
    adresi, o bloktaki her ``@address`` satırıyla karşılaştırılır.
    """
    baslar = [m.start() for m in _KAPI_BASLIK.finditer(metin)]
    if not baslar:
        return []
    baslar.append(len(metin))
    sonuc: list[tuple[str, str]] = []
    for bas, son in zip(baslar, baslar[1:]):
        blok = metin[bas:son]
        baslik = _KAPI_BASLIK_ADRES.search(blok)
        if not baslik:
            continue
        for belge in _KAPI_BELGE_ADRES.finditer(blok):
            if _adres_yalin(belge.group(1)) != _adres_yalin(baslik.group(1)):
                sonuc.append((baslik.group(1), belge.group(1)))
    return sonuc


def agaci_say(kok: Path) -> dict:
    """Bir dizindeki C dosyalarında yorum dengesi ve adres uyuşmazlığı sayımı."""
    dosyalar = sorted(p for p in kok.rglob("*") if p.is_file() and p.suffix in _KAPI_UZANTILAR)
    sayim = {
        "kok": str(kok), "dosya": len(dosyalar), "belge_bloklu_dosya": 0,
        "yorum_dengesi_bozuk_dosya": 0, "ihlal": {}, "adres_farkli_dosya": 0,
        "ornek_denge": [], "ornek_adres": [],
    }
    for yol in dosyalar:
        metin = yol.read_text(encoding="utf-8", errors="replace")
        if _KAPI_BELGE_ACILIS.search(metin):
            sayim["belge_bloklu_dosya"] += 1
        ihlaller = yorum_ihlalleri(metin)
        if ihlaller:
            sayim["yorum_dengesi_bozuk_dosya"] += 1
            for _, tur in ihlaller:
                sayim["ihlal"][tur] = sayim["ihlal"].get(tur, 0) + 1
            if len(sayim["ornek_denge"]) < 10:
                sayim["ornek_denge"].append(f"{yol.relative_to(kok)}:{ihlaller[0][0]} {ihlaller[0][1]}")
        farklar = adres_uyusmazliklari(metin)
        if farklar:
            sayim["adres_farkli_dosya"] += 1
            if len(sayim["ornek_adres"]) < 10:
                sayim["ornek_adres"].append(
                    f"{yol.relative_to(kok)}: başlık {farklar[0][0]} / @address {farklar[0][1]}")
    return sayim


# ---------------------------------------------------------------------------
# Sabit girdiler
# ---------------------------------------------------------------------------

# Kusursuz blok: adlar tek, başlık adresi kayıtla aynı, yorum işareti yok.
# Beklenen çıktı (TEMIZ_BEKLENEN) düzeltmeden ÖNCEKİ kodla (586bb6a) üretildi.
TEMIZ_GIRDI = """#include "types.h"

// Function: FUN_00105fc0
// Address:  00105fc0
// Size:     128 bytes
// Callers:  1 (main)
// Callees:  2 (malloc, strcpy)
// Stack:    frame=32, locals=32, params=0


char * FUN_00105fc0(char *param_1,int param_2)

{
  char *pcVar1;

  pcVar1 = (char *)malloc(0x100);
  if (pcVar1 == NULL) {
    return NULL;
  }
  strcpy(pcVar1,param_1);
  while (1) {
    if (param_2 > 3) break;
    param_2 = param_2 + 1;
  }
  switch (param_2) {
  case 1:
    break;
  }
  goto LAB_00105ff0;
LAB_00105ff0:
  return pcVar1;
}


// --- DISASSEMBLY (2 instructions) ---
// 00105fc0  stp x29,x30,[sp, #-0x20]!
// 00105fc4  ret
"""
TEMIZ_FONKSIYONLAR = {"total": 2, "program": "ornek", "functions": [
    {"name": "FUN_00105fc0", "address": "00105fc0", "size": 128},
    {"name": "main", "address": "00104100", "size": 900},
]}
TEMIZ_GRAFIK = {"program": "ornek", "edges": [
    {"from": "00104100", "to": "00105fc0", "from_name": "main", "to_name": "FUN_00105fc0"},
    {"from": "00105fc0", "to": "00103d00", "from_name": "FUN_00105fc0", "to_name": "malloc"},
    {"from": "00105fc0", "to": "00103d10", "from_name": "FUN_00105fc0", "to_name": "strcpy"},
]}
TEMIZ_DIZGILER = {"total": 1, "strings": [
    {"address": "00100a00", "value": "hello %s", "function": "FUN_00105fc0"},
]}
TEMIZ_FORMULLER = [
    {"function_name": "FUN_00105fc0", "ascii": "y = a*x + b", "formula_type": "linear"},
]
TEMIZ_CFG = [
    {"function_name": "FUN_00105fc0", "matched_algorithm": "bubble_sort",
     "confidence": 0.99, "hash_matched": True},
]


def temiz_algoritmalar() -> list:
    return [AlgorithmMatch(
        name="CRC32", category="checksum", confidence=0.8, detection_method="constant",
        evidence=[], function_name="FUN_00105fc0", address="0x00105fc0",
    )]


TEMIZ_BEKLENEN = """#include "types.h"

// Function: FUN_00105fc0
// Address:  00105fc0
// Size:     128 bytes
// Callers:  1 (main)
// Callees:  2 (malloc, strcpy)
// Stack:    frame=32, locals=32, params=0


// [Computation] Formula: y = a*x + b [linear]
// [Computation] CFG exact match: bubble_sort (hash verified)
/**
 * @brief Function at address 0x00105fc0
 * @address 00105fc0
 * @size 128 bytes
 * @param char *param_1
 * @param int param_2
 * @called_by main (1 site)
 * @calls malloc, strcpy
 * @strings "hello %s"
 * @algorithm CRC32 (checksum, confidence: 80%)
 */
char * FUN_00105fc0(char *param_1,int param_2)
    /* ALGORITHM: CRC32 (confidence: 80%, via constant) */

{
  char *pcVar1;

  /* malloc: allocates 256 (0x100) bytes on heap */
  pcVar1 = (char *)malloc(0x100);
  /* null check: return on pcVar1 == NULL */
  if (pcVar1 == NULL) {
    return NULL;
  }
  /* [HIGH] VULN: Buffer overflow - use strncpy or strlcpy instead */
  strcpy(pcVar1,param_1);
  /* loop until param_2 > 3 */
  while (1) {
    /* bounds check: param_2 against 3 */
    if (param_2 > 3) break;
    param_2 = param_2 + 1;
  }
  /* dispatch on param_2 */
  switch (param_2) {
  case 1:
    break;
  }
  /* Uses goto - check for error cleanup pattern */
  goto LAB_00105ff0;
LAB_00105ff0:
  return pcVar1;
}


// --- DISASSEMBLY (2 instructions) ---
// 00105fc0  stp x29,x30,[sp, #-0x20]!
// 00105fc4  ret
"""

# Zincirsiz rename: çıktı düzeltmeden önceki kodla bayt bayt aynı kalmalı.
ZINCIRSIZ_GIRDI = """void solve(int param_1,double *param_2,double *param_3)

{
  param_2[0] = param_1 * 2.0;
  /* was: n_dof */
  param_3[0] = param_2[0] + 1.0;
}
"""
ZINCIRSIZ_ADLAR = [("param_1", "n_dof"), ("param_2", "K_global"), ("param_3", "F_vector")]
ZINCIRSIZ_BEKLENEN = """void solve(int n_dof /* was: param_1 */,double *K_global /* was: param_2 */,double *F_vector /* was: param_3 */)

{
  K_global[0] = n_dof * 2.0;
  /* was: param_1 */
  F_vector[0] = K_global[0] + 1.0;
}
"""


# ---------------------------------------------------------------------------
# Test yardımcıları
# ---------------------------------------------------------------------------

def _uret(tmp_path: Path, dosyalar: dict[str, str], fonksiyonlar=None, grafik=None,
          dizgiler=None, **ek) -> dict[str, str]:
    """Gerçek ``CCommentGenerator.generate`` yolunu koşturur; dosya adı -> çıktı metni."""
    girdi = tmp_path / "girdi"
    girdi.mkdir(parents=True)
    for ad, metin in dosyalar.items():
        (girdi / ad).write_text(metin, encoding="utf-8")
    yollar = {}
    for ad, veri in (("f", fonksiyonlar), ("cg", grafik), ("s", dizgiler)):
        if veri is not None:
            yollar[ad] = tmp_path / f"{ad}.json"
            yollar[ad].write_text(json.dumps(veri), encoding="utf-8")
    sonuc = CCommentGenerator().generate(
        decompiled_dir=girdi, output_dir=tmp_path / "cikti",
        functions_json=yollar.get("f"), strings_json=yollar.get("s"),
        call_graph_json=yollar.get("cg"), **ek,
    )
    assert sonuc.success, sonuc.errors
    return {ad: (tmp_path / "cikti" / ad).read_text(encoding="utf-8") for ad in dosyalar}


def _belge_blogu(metin: str) -> str:
    """Çıktıdaki ilk belge bloğu: ``/**`` satırından ilk `` */`` satırına kadar."""
    satirlar = metin.split("\n")
    bas = satirlar.index("/**")
    son = satirlar.index(" */", bas)
    return "\n".join(satirlar[bas:son + 1])


def _algo(ad: str, fonksiyon: str, kategori: str = "hash", yontem: str = "constant") -> AlgorithmMatch:
    return AlgorithmMatch(name=ad, category=kategori, confidence=0.7, detection_method=yontem,
                          evidence=[], function_name=fonksiyon, address="")


def _baslik(ad: str, adres: str, boyut: int) -> str:
    return (f"// Function: {ad}\n// Address:  {adres}\n// Size:     {boyut} bytes\n"
            "// Callers:  0\n// Callees:  0\n// Stack:    frame=0, locals=0, params=0\n\n\n")


# ---------------------------------------------------------------------------
# Son koşul yardımcısının kendi testleri
# ---------------------------------------------------------------------------

class TestSozcukTarayici:
    def test_temiz_kod_ihlalsiz(self):
        metin = "/* a */\nint f(void)\n{\n  // b\n  return 0; /* c */\n}\n"
        assert yorum_ihlalleri(metin) == []

    def test_yorum_disinda_kapanis(self):
        assert yorum_ihlalleri("int a;\nint b; */\n") == [(2, KAPANIS_YORUM_DISINDA)]

    def test_blok_icinde_acilis(self):
        assert yorum_ihlalleri("/* a\n /* b */\n") == [(2, ACILIS_BLOK_ICINDE)]

    def test_kapanmamis_blok_basladigi_satirla_bildirilir(self):
        assert yorum_ihlalleri("int a;\n/* b\nint c;\n") == [(2, KAPANMAMIS_BLOK)]

    def test_ic_ice_belge_blogu_iki_ihlal(self):
        """Kusur 5'in diskteki biçimi: blok 3. satırda kapanır, 5. satırdaki kapanış kodda kalır."""
        metin = ("/**\n * @brief x\n * @param int count /* was: param_2 */\n"
                 " * @calls f\n */\nint f(int count /* was: param_2 */)\n{\n}\n")
        assert yorum_ihlalleri(metin) == [(3, ACILIS_BLOK_ICINDE), (5, KAPANIS_YORUM_DISINDA)]

    @pytest.mark.parametrize("metin", [
        'char *s = "*/ /* */";\n',                 # dizgi içi
        'char *s = "a\\"*/";\n',                    # kaçışlı tırnaktan sonra hâlâ dizgi
        "char c = '\"'; /* tek tırnak içindeki çift tırnak dizgi açmaz */\n",
        "char c = '\\''; /* kaçışlı tek tırnak */\n",
        "// satır yorumunda /* ve */ serbest\nint a;\n",
        "/* blok içinde // satır yorumu sayılmaz */\nint a;\n",
        "/*/ bu tek bir yorum */\n",              # "/*/" kapanış değildir
        "/***/ int a; /**/\n",
    ])
    def test_ihlal_sayilmayanlar(self, metin):
        assert yorum_ihlalleri(metin) == []

    def test_dizgi_satir_sonunda_biter(self):
        """Kapanmamış dizgi satır sonunda biter; sonraki satırdaki ihlal görülür."""
        assert yorum_ihlalleri('char *s = "abc\nint b; */\n') == [(2, KAPANIS_YORUM_DISINDA)]

    def test_dizgiden_sonraki_ihlal_gorulur(self):
        assert yorum_ihlalleri('f("a"); */\n') == [(1, KAPANIS_YORUM_DISINDA)]

    def test_satir_yorumu_ters_boluyle_surer(self):
        """``//`` yorumu ``\\`` ile biterse sonraki satır da yorumdur."""
        assert yorum_ihlalleri("// a \\\n b */\nint c;\n") == []
        assert yorum_ihlalleri("// a\n b */\nint c;\n") == [(2, KAPANIS_YORUM_DISINDA)]

    def test_blok_ilk_kapanista_kapanir(self):
        assert yorum_ihlalleri("/* a */ b */\n") == [(1, KAPANIS_YORUM_DISINDA)]

    def test_egik_yildiz_egik_dizisi(self):
        """Blok içinde ``/*/``: açılış ihlali, ardından gelen ``*/`` bloğu kapatır."""
        assert yorum_ihlalleri("/* a /*/ int b;\n") == [(1, ACILIS_BLOK_ICINDE)]

    def test_adres_uyusmazligi_sayaci(self):
        ayni = _baslik("f", "00103ce0", 16) + "/**\n * @address 0x00103CE0\n */\nvoid f(void)\n{\n}\n"
        farkli = _baslik("f", "00103ce0", 16) + "/**\n * @address 00135000\n */\nvoid f(void)\n{\n}\n"
        assert adres_uyusmazliklari(ayni) == []
        assert adres_uyusmazliklari(farkli) == [("00103ce0", "00135000")]
        assert adres_uyusmazliklari(ayni + farkli) == [("00103ce0", "00135000")]

    def test_agaci_say(self, tmp_path):
        (tmp_path / "alt").mkdir()
        (tmp_path / "iyi.c").write_text("/**\n * @brief x\n */\nvoid f(void)\n{\n}\n")
        (tmp_path / "alt" / "bozuk.c").write_text(
            _baslik("g", "00001000", 4) + "/**\n * @address 00002000\n * @param int a /* was: p */\n */\n")
        (tmp_path / "not.txt").write_text("*/")
        s = agaci_say(tmp_path)
        assert (s["dosya"], s["belge_bloklu_dosya"]) == (2, 2)
        assert (s["yorum_dengesi_bozuk_dosya"], s["adres_farkli_dosya"]) == (1, 1)
        assert s["ihlal"] == {ACILIS_BLOK_ICINDE: 1, KAPANIS_YORUM_DISINDA: 1}


# ---------------------------------------------------------------------------
# Temizleme fonksiyonu
# ---------------------------------------------------------------------------

class TestYorumMetniTemizleme:
    def test_isaretsiz_metin_aynen_doner(self):
        metin = "@param char *param_1 * / (x) // y"
        assert ccg._comment_safe(metin) is metin

    def test_gomulu_yorum_paranteze_cevrilir(self):
        assert ccg._comment_safe("int count /* was: param_2 */") == "int count (was: param_2)"

    def test_birden_cok_gomulu_yorum(self):
        assert ccg._comment_safe("a /* x */ b /*y*/ c /**/") == "a (x) b (y) c ()"

    def test_tek_kalan_kapanis(self):
        assert ccg._comment_safe('"a*/b"') == '"a* /b"'

    def test_tek_kalan_acilis(self):
        assert ccg._comment_safe('"/*c"') == '"/ *c"'

    def test_gomulu_yorumun_icindeki_acilis(self):
        assert ccg._comment_safe("/* a /* b */") == "(a / * b)"

    def test_egik_yildiz_egik(self):
        assert ccg._comment_safe("x /*/ y") == "x / * / y"

    def test_rastgele_metin_hicbir_isaret_birakmaz(self):
        """Özellik: çıktı ``/*`` ve ``*/`` içermez; bloğa ve satır içi yoruma konunca ihlalsizdir."""
        rnd = random.Random(20261110)
        for _ in range(3000):
            metin = "".join(rnd.choice("/* a\n(") for _ in range(rnd.randint(0, 14)))
            temiz = ccg._comment_safe(metin)
            assert "/*" not in temiz and "*/" not in temiz, (metin, temiz)
            assert yorum_ihlalleri(ccg._doc_block([metin, metin])) == [], metin
            assert yorum_ihlalleri(ccg._inline_comment("  ", metin)) == [], metin

    def test_belge_blogu_bicimi(self):
        assert ccg._doc_block(["@brief x", "@param int a /* was: p */"]) == (
            "/**\n * @brief x\n * @param int a (was: p)\n */")

    def test_satir_ici_yorum_bicimi(self):
        assert ccg._inline_comment("  ", "a */ b") == "  /* a * / b */"

    def test_satir_yorumu_satir_sonunu_tasimaz(self):
        assert ccg._line_comment("a +\n b\r\nc") == "// a +  b c"

    def test_satir_yorumu_ters_boluyle_bitmez(self):
        assert ccg._line_comment("a \\") == "// a \\ ."
        assert ccg._line_comment("a \\  ") == "// a \\ ."
        assert ccg._line_comment("a \\ b") == "// a \\ b"


# ---------------------------------------------------------------------------
# Kusur 5: iç içe yorum
# ---------------------------------------------------------------------------

IC_ICE_GIRDI = '#include "types.h"\n\n' + _baslik("Process_rowChangePriorityBy", "001267c0", 164) + (
    "bool Process_rowChangePriorityBy(long buf_150,int count /* was: param_2 */)\n"
    "\n"
    "{\n"
    "  int getpriority_ret;\n"
    "  \n"
    "  count = (int)buf_150 + count;\n"
    "  getpriority_ret = getpriority(0,count);\n"
    "  return getpriority_ret != 0;\n"
    "}\n"
)
IC_ICE_FONKSIYONLAR = {"functions": [
    {"name": "Process_rowChangePriorityBy", "address": "001267c0", "size": 164},
]}
IC_ICE_GRAFIK = {"edges": [
    {"from": "001267c0", "to": "00112000", "from_name": "Process_rowChangePriorityBy",
     "to_name": "Settings_isReadonly"},
    {"from": "001267c0", "to": "00112010", "from_name": "Process_rowChangePriorityBy",
     "to_name": "getpriority"},
]}


class TestIcIceYorum:
    def _cikti(self, tmp_path):
        return _uret(tmp_path, {"Process_rowChangePriorityBy.c": IC_ICE_GIRDI},
                     IC_ICE_FONKSIYONLAR, IC_ICE_GRAFIK,
                     algorithm_results=[_algo("Keccak/SHA-3", "Process_rowChangePriorityBy")],
                     )["Process_rowChangePriorityBy.c"]

    def test_girdi_gecerli_c(self):
        assert yorum_ihlalleri(IC_ICE_GIRDI) == []

    def test_cikti_gecerli_c(self, tmp_path):
        assert yorum_ihlalleri(self._cikti(tmp_path)) == []

    def test_blok_tam_ve_was_bilgisi_korunur(self, tmp_path):
        assert _belge_blogu(self._cikti(tmp_path)) == (
            "/**\n"
            " * @brief Process rowchangepriorityby\n"
            " * @address 001267c0\n"
            " * @size 164 bytes\n"
            " * @param long buf_150\n"
            " * @param int count (was: param_2)\n"
            " * @calls Settings_isReadonly, getpriority\n"
            " * @algorithm Keccak/SHA-3 (hash, confidence: 70%)\n"
            " */")

    def test_imzadaki_yorum_kalir(self, tmp_path):
        assert ("bool Process_rowChangePriorityBy(long buf_150,int count /* was: param_2 */)\n"
                in self._cikti(tmp_path))

    def test_sistem_cagrisi_yorumunda_arguman_yorumu(self):
        """Satır içi yorum yolu: argümandaki ``/* was: */`` yorumu iç içe yazılmaz."""
        gen = CCommentGenerator()
        metin = "void f(int param_1)\n{\n  p = malloc(n /* was: param_1 */);\n}\n"
        cikti, _ = gen._annotate_file(metin, {}, {}, {}, {}, "f.c")
        assert "  /* malloc: allocates n (was: param_1) bytes on heap */\n" in cikti
        assert yorum_ihlalleri(cikti) == []

    def test_mantik_yorumunda_kosul_yorumu(self):
        gen = CCommentGenerator()
        metin = "void f(int a)\n{\n  while (1) {\n    if (a /* x */ > 3) break;\n  }\n}\n"
        cikti, _ = gen._annotate_file(metin, {}, {}, {}, {}, "f.c")
        assert "  /* loop until a (x) > 3 */\n" in cikti
        assert yorum_ihlalleri(cikti) == []

    @pytest.mark.parametrize("uretici", [
        "_check_vulnerability", "_check_syscall", "_check_logic_pattern", "_check_control_flow",
    ])
    def test_her_satir_ici_yol_temizlemeden_gecer(self, monkeypatch, uretici):
        """Dört satır içi yorum yolunun her biri, metni ne olursa olsun, geçerli C yazar."""
        for ad in ("_check_vulnerability", "_check_syscall", "_check_logic_pattern",
                   "_check_control_flow"):
            if ad == uretici:
                def sahte(line, *_):
                    return "kotu */ x /* y" if "HEDEF" in line else ""
            else:
                def sahte(line, *_):
                    return ""
            monkeypatch.setattr(CCommentGenerator, ad, staticmethod(sahte))
        metin = "void f(void)\n{\n  HEDEF();\n}\n"
        cikti, _ = CCommentGenerator()._annotate_file(metin, {}, {}, {}, {}, "f.c")
        assert "  /* kotu * / x / * y */\n  HEDEF();\n" in cikti
        assert yorum_ihlalleri(cikti) == []

    def test_her_alan_temizlenir(self, tmp_path):
        """Bloğa giren her alana ``*/`` ve ``/*`` sokulur; çıktı yine geçerli C'dir."""
        metin = "void f(int a /* was: p1 */)\n{\n  return;\n}\n"
        cikti = _uret(
            tmp_path, {"f.c": metin},
            fonksiyonlar={"functions": [{"name": "f", "address": "10*/00", "size": "8/*"}]},
            grafik={"edges": [{"from_name": "c1*/", "to_name": "f"},
                              {"from_name": "f", "to_name": "/*c2"}]},
            dizgiler={"strings": [{"value": "a*/b", "function": "f"},
                                  {"value": "/*c", "function": "f"}]},
            algorithm_results=[_algo("X*/Y", "f", kategori="k/*l", yontem="m*/n")],
        )["f.c"]
        assert yorum_ihlalleri(cikti) == []
        assert _belge_blogu(cikti) == (
            "/**\n"
            " * @brief F\n"
            " * @address 10* /00\n"
            " * @size 8/ * bytes\n"
            " * @param int a (was: p1)\n"
            " * @called_by c1* / (1 site)\n"
            " * @calls / *c2\n"
            ' * @strings "a* /b", "/ *c"\n'
            " * @algorithm X* /Y (k/ *l, confidence: 70%)\n"
            " */")
        assert "    /* ALGORITHM: X* /Y (confidence: 70%, via m* /n) */\n" in cikti

    def test_formul_yorumu_kodu_yutmaz(self, tmp_path):
        """``//`` yorumu: satır sonu ya da sondaki ters bölü imza satırını yoruma katmaz."""
        metin = "void f(void)\n{\n  return;\n}\n"
        cikti = _uret(tmp_path, {"f.c": metin}, formulas_extracted=[
            {"function_name": "f", "ascii": "a +\nb"},
            {"function_name": "f", "ascii": "c \\"},
        ], cfg_matches=[
            {"function_name": "f", "matched_algorithm": "x\ny", "confidence": 0.99,
             "hash_matched": True},
        ])["f.c"]
        # Sıra, aynı satıra yapılan eklemelerin ters dizilmesinden gelir (eski davranış).
        assert cikti.split("\n")[:7] == [
            "// [Computation] Formula: c \\ .",
            "// [Computation] Formula: a + b",
            "// [Computation] CFG exact match: x y (hash verified)",
            "/**",
            " * @brief F",
            " */",
            "void f(void)",
        ]


# ---------------------------------------------------------------------------
# Kusur 11: üst veri fonksiyonun KENDİ adresiyle
# ---------------------------------------------------------------------------

# tree (Debian 13 arm64) koşusundaki gerçek çift: PLT thunk'ı ve dış sembol.
AYNI_AD_FONKSIYONLAR = {"functions": [
    {"name": "memcpy", "address": "00103ce0", "size": 16, "is_thunk": True},
    {"name": "FUN_00104100", "address": "00104100", "size": 900},
    {"name": "FUN_00106c20", "address": "00106c20", "size": 300},
    {"name": "memcpy", "address": "00135000", "size": 1, "is_thunk": True},
]}
AYNI_AD_GRAFIK = {"edges": [
    {"from": "00103ce0", "to": "00135000", "from_name": "memcpy", "to_name": "memcpy"},
    {"from": "00104100", "to": "00103ce0", "from_name": "FUN_00104100", "to_name": "memcpy"},
    {"from": "00106c20", "to": "00103ce0", "from_name": "FUN_00106c20", "to_name": "memcpy"},
]}
_MEMCPY_IMZA = "void * memcpy(void *__dest,void *__src,size_t __n)\n\n{\n"
THUNK_GOVDE = _MEMCPY_IMZA + "  void *pvVar1;\n  \n  pvVar1 = memcpy(__dest,__src,__n);\n  return pvVar1;\n}\n"
DIS_GOVDE = _MEMCPY_IMZA + "  halt_baddata();\n}\n"
THUNK_DOSYA = _baslik("memcpy", "00103ce0", 16) + THUNK_GOVDE
DIS_DOSYA = _baslik("memcpy", "00135000", 1) + DIS_GOVDE
_MEMCPY_PARAMETRELER = " * @param void *__dest\n * @param void *__src\n * @param size_t __n\n"


class TestAyniAdliIkiFonksiyon:
    def _cikti(self, tmp_path, **ek):
        return _uret(tmp_path, {"memcpy.c": THUNK_DOSYA, "memcpy_00135000.c": DIS_DOSYA},
                     AYNI_AD_FONKSIYONLAR, AYNI_AD_GRAFIK, **ek)

    def test_thunk_kendi_kaydini_alir(self, tmp_path):
        assert _belge_blogu(self._cikti(tmp_path)["memcpy.c"]) == (
            "/**\n"
            " * @brief Memcpy\n"
            " * @address 00103ce0\n"
            " * @size 16 bytes\n"
            + _MEMCPY_PARAMETRELER +
            " * @called_by FUN_00104100, FUN_00106c20 (2 sites)\n"
            " * @calls memcpy\n"
            " */")

    def test_dis_sembol_kendi_kaydini_alir(self, tmp_path):
        assert _belge_blogu(self._cikti(tmp_path)["memcpy_00135000.c"]) == (
            "/**\n"
            " * @brief Memcpy\n"
            " * @address 00135000\n"
            " * @size 1 bytes\n"
            + _MEMCPY_PARAMETRELER +
            " * @called_by memcpy (1 site)\n"
            " */")

    def test_son_kosul(self, tmp_path):
        for metin in self._cikti(tmp_path).values():
            assert adres_uyusmazliklari(metin) == []
            assert yorum_ihlalleri(metin) == []

    def test_kayit_sirasi_sonucu_degistirmez(self, tmp_path):
        """Ada göre indeks son kaydı tutar; adresle arama kayıt sırasından bağımsızdır."""
        ters = {"functions": list(reversed(AYNI_AD_FONKSIYONLAR["functions"]))}
        cikti = _uret(tmp_path, {"memcpy.c": THUNK_DOSYA, "memcpy_00135000.c": DIS_DOSYA},
                      ters, AYNI_AD_GRAFIK)
        assert " * @address 00103ce0\n * @size 16 bytes\n" in cikti["memcpy.c"]
        assert " * @address 00135000\n * @size 1 bytes\n" in cikti["memcpy_00135000.c"]

    def test_ada_gore_veriler_belirsiz_adda_yazilmaz(self, tmp_path):
        """Algoritma, formül, CFG ve dizgi indeksleri yalnız ada göredir: hangi memcpy'nin
        olduğu bilinemez, hiçbirine yazılmaz."""
        cikti = self._cikti(
            tmp_path,
            dizgiler={"strings": [{"value": "kimin", "function": "memcpy"}]},
            algorithm_results=[_algo("CRC32", "memcpy")],
            formulas_extracted=[{"function_name": "memcpy", "ascii": "a+b"}],
            cfg_matches=[{"function_name": "memcpy", "matched_algorithm": "sort",
                          "confidence": 0.99, "hash_matched": True}],
        )
        for metin in cikti.values():
            for iz in ("@algorithm", "ALGORITHM:", "[Computation]", "@strings", "kimin"):
                assert iz not in metin, iz

    def test_adres_bilinmiyorsa_alan_yazilmaz(self, tmp_path):
        """Başlık yok, ad iki fonksiyona ait: adres, boyut, çağıran ve çağrılan YAZILMAZ."""
        cikti = _uret(tmp_path, {"memcpy.c": THUNK_GOVDE}, AYNI_AD_FONKSIYONLAR, AYNI_AD_GRAFIK)
        assert _belge_blogu(cikti["memcpy.c"]) == (
            "/**\n * @brief Memcpy\n" + _MEMCPY_PARAMETRELER + " */")

    def test_adres_bilinmiyorsa_yalniz_fonksiyon_listesi_yeter(self, tmp_path):
        """Çağrı grafiği yokken de belirsizlik fonksiyon listesindeki ad sayısından okunur."""
        cikti = _uret(tmp_path, {"memcpy.c": THUNK_GOVDE}, AYNI_AD_FONKSIYONLAR,
                      dizgiler={"strings": [{"value": "kimin", "function": "memcpy"}]})
        assert _belge_blogu(cikti["memcpy.c"]) == (
            "/**\n * @brief Memcpy\n" + _MEMCPY_PARAMETRELER + " */")

    def test_adres_eslenemiyorsa_alan_yazilmaz(self, tmp_path):
        """Başlık adresi üst veride yok, ad iki fonksiyona ait: alan yazılmaz."""
        dosya = _baslik("memcpy", "00999990", 16) + THUNK_GOVDE
        cikti = _uret(tmp_path, {"memcpy.c": dosya}, AYNI_AD_FONKSIYONLAR, AYNI_AD_GRAFIK)
        assert _belge_blogu(cikti["memcpy.c"]) == (
            "/**\n * @brief Memcpy\n" + _MEMCPY_PARAMETRELER + " */")

    def test_grafik_adres_tasimiyorsa_belirsiz_adda_cagri_yazilmaz(self, tmp_path):
        """Eski biçim grafik (adres yok): ada göre kayıt iki fonksiyonun birleşimidir."""
        adsiz = {"edges": [{"from_name": e["from_name"], "to_name": e["to_name"]}
                           for e in AYNI_AD_GRAFIK["edges"]]}
        cikti = _uret(tmp_path, {"memcpy.c": THUNK_DOSYA}, AYNI_AD_FONKSIYONLAR, adsiz)
        assert _belge_blogu(cikti["memcpy.c"]) == (
            "/**\n * @brief Memcpy\n * @address 00103ce0\n * @size 16 bytes\n"
            + _MEMCPY_PARAMETRELER + " */")


class TestAdSahipligi:
    def test_tek_adli_fonksiyon_basliksiz_ada_gore_bulunur(self, tmp_path):
        """Ad tek fonksiyona aitse adla arama geçerlidir (başlıksız girdi, eski davranış)."""
        cikti = _uret(tmp_path, {"FUN_00104100.c": "void FUN_00104100(int a)\n{\n  return;\n}\n"},
                      AYNI_AD_FONKSIYONLAR, AYNI_AD_GRAFIK)
        assert _belge_blogu(cikti["FUN_00104100.c"]) == (
            "/**\n * @brief Function at address 0x00104100\n * @address 00104100\n"
            " * @size 900 bytes\n * @param int a\n * @calls memcpy\n */")

    def test_yeniden_adlandirilan_fonksiyon_adresle_bulunur(self, tmp_path):
        """İmzadaki ad başka bir fonksiyonun Ghidra adıyla çakışsa da kayıt adresle gelir."""
        fonksiyonlar = {"functions": [
            {"name": "FUN_00001000", "address": "00001000", "size": 64},
            {"name": "parse_config", "address": "00003000", "size": 8},
        ]}
        grafik = {"edges": [
            {"from": "00001000", "to": "00005000", "from_name": "FUN_00001000", "to_name": "open"},
            {"from": "00003000", "to": "00005010", "from_name": "parse_config", "to_name": "close"},
        ]}
        dosya = _baslik("FUN_00001000", "00001000", 64) + "void parse_config(int x)\n{\n  return;\n}\n"
        cikti = _uret(tmp_path, {"FUN_00001000.c": dosya}, fonksiyonlar, grafik,
                      dizgiler={"strings": [{"value": "baskasinin", "function": "parse_config"}]},
                      algorithm_results=[_algo("CRC32", "parse_config")])["FUN_00001000.c"]
        assert _belge_blogu(cikti) == (
            "/**\n * @brief Parse config\n * @address 00001000\n * @size 64 bytes\n"
            " * @param int x\n * @calls open\n */")
        assert "ALGORITHM:" not in cikti

    def test_tek_adin_kaydi_baska_adresteyse_yazilmaz(self, tmp_path):
        """Ad tek ama kaydı başka adreste: bu fonksiyon üst veride yok, öbürünün verisi alınmaz."""
        fonksiyonlar = {"functions": [{"name": "foo", "address": "00001000", "size": 10}]}
        dosya = _baslik("foo", "00002000", 99) + "void foo(int a)\n{\n  return;\n}\n"
        cikti = _uret(tmp_path, {"foo.c": dosya}, fonksiyonlar,
                      algorithm_results=[_algo("CRC32", "foo")])["foo.c"]
        assert _belge_blogu(cikti) == "/**\n * @brief Foo\n * @param int a\n */"
        assert "ALGORITHM:" not in cikti

    def test_grafikte_iki_adreste_gorunen_ad_belirsizdir(self, tmp_path):
        """Fonksiyon listesi yokken belirsizlik çağrı grafiğinden de okunur."""
        grafik = {"edges": [
            {"from": "00001000", "to": "00002000", "from_name": "a", "to_name": "dup"},
            {"from": "00001000", "to": "00003000", "from_name": "b", "to_name": "dup"},
        ]}
        govde = "void dup(int a)\n{\n  return;\n}\n"
        basliksiz = _uret(tmp_path / "1", {"dup.c": govde}, None, grafik,
                          algorithm_results=[_algo("CRC32", "dup")])["dup.c"]
        assert _belge_blogu(basliksiz) == "/**\n * @brief Dup\n * @param int a\n */"
        assert "ALGORITHM:" not in basliksiz
        baslikli = _uret(tmp_path / "2", {"dup.c": _baslik("dup", "00003000", 4) + govde},
                         None, grafik)["dup.c"]
        assert _belge_blogu(baslikli) == (
            "/**\n * @brief Dup\n * @param int a\n * @called_by b (1 site)\n */")

    def test_grafikteki_tek_adres_baskasiysa_ad_sahiplenilmez(self, tmp_path):
        grafik = {"edges": [{"from": "00001000", "to": "00002000", "from_name": "main", "to_name": "foo"}]}
        dosya = _baslik("foo", "00004000", 4) + "void foo(int a)\n{\n  return;\n}\n"
        cikti = _uret(tmp_path, {"foo.c": dosya}, None, grafik,
                      algorithm_results=[_algo("CRC32", "foo")])["foo.c"]
        assert _belge_blogu(cikti) == "/**\n * @brief Foo\n * @param int a\n */"
        assert "ALGORITHM:" not in cikti

    def test_baslik_baska_fonksiyonunsa_adres_alinmaz(self, tmp_path):
        """Başlık ile imza arasına kod giriyorsa başlık öbür fonksiyonundur."""
        fonksiyonlar = {"functions": [{"name": "A", "address": "00001000", "size": 8}]}
        dosya = (_baslik("A", "00001000", 8) + "void A(void)\n{\n  return;\n}\n\n"
                 "void helper(int a)\n{\n  return;\n}\n")
        cikti = _uret(tmp_path, {"A.c": dosya}, fonksiyonlar)["A.c"]
        assert cikti.count("/**\n") == 2
        assert "/**\n * @brief A\n * @address 00001000\n * @size 8 bytes\n */\nvoid A(void)\n" in cikti
        assert "/**\n * @brief Helper\n * @param int a\n */\nvoid helper(int a)\n" in cikti

    def test_dosya_adi_cok_fonksiyonlu_dosyada_kullanilmaz(self):
        """Dosya adı en çok bir fonksiyonu tanımlar; iki tanım varsa hiçbiri onun verisini almaz."""
        gen = CCommentGenerator()
        ust_veri = {"FUN_1000": {"address": "0x1000", "size": 32}}
        tek = "void renamed(int a)\n{\n  return;\n}\n"
        cikti, _ = gen._annotate_file(tek, ust_veri, {}, {}, {}, "FUN_1000.c")
        assert " * @address 0x1000\n * @size 32 bytes\n" in cikti
        cift = tek + "\nvoid other(int b)\n{\n  return;\n}\n"
        cikti, _ = gen._annotate_file(cift, ust_veri, {}, {}, {}, "FUN_1000.c")
        assert cikti.count("/**\n") == 2 and "@address" not in cikti and "@size" not in cikti

    def test_kendi_baslik_adresi(self):
        satirlar = (_baslik("f", "00103ce0", 16) + "/* not */\n#define X 1\nvoid f(void)\n{\n}").split("\n")
        imza = satirlar.index("void f(void)")
        assert CCommentGenerator._own_header_address(satirlar, imza) == "00103ce0"
        assert CCommentGenerator._own_header_address(["void f(void)", "{", "}"], 0) == ""
        assert CCommentGenerator._own_header_address(
            ["// Address:  00001000", "int x;", "void f(void)"], 2) == ""

    def test_adres_bicimi_normallestirilir(self):
        assert ccg._norm_address("0x00103CE0") == ccg._norm_address("00103ce0") == "103ce0"
        assert ccg._norm_address(" 00000000 ") == "0"
        assert ccg._norm_address("") == "" and ccg._norm_address(None) == ""
        assert ccg._norm_address("0x") == ""

    def test_baslik_0x_onekli_kayit_onekli_degil(self, tmp_path):
        fonksiyonlar = {"functions": [{"name": "foo", "address": "0x00001000", "size": 10}]}
        dosya = _baslik("foo", "00001000", 10) + "void foo(int a)\n{\n  return;\n}\n"
        cikti = _uret(tmp_path, {"foo.c": dosya}, fonksiyonlar)["foo.c"]
        assert " * @address 0x00001000\n * @size 10 bytes\n" in cikti

    def test_eski_bicim_ada_gore_sozlukler_calisir(self):
        """Doğrudan çağrı (düz dict, adres yok): eski arama sırası korunur."""
        gen = CCommentGenerator()
        ust_veri = {"FUN_1000": {"address": "0x1000", "size": 32}}
        grafik = {"FUN_1000": {"callers": ["main"], "callees": ["puts"]}}
        dizgiler = {"FUN_1000": ["merhaba"]}
        beklenen_govde = (" * @address 0x1000\n * @size 32 bytes\n * @param int a\n"
                          " * @called_by main (1 site)\n * @calls puts\n * @strings \"merhaba\"\n */")
        dogrudan = gen._build_function_header("FUN_1000", "int a", ust_veri, dizgiler, grafik, {}, "x.c")
        assert dogrudan == "/**\n * @brief Function at address 0x1000\n" + beklenen_govde
        dosya_adindan = gen._build_function_header("renamed", "int a", ust_veri, dizgiler, grafik, {},
                                                   "FUN_1000.c")
        assert dosya_adindan == "/**\n * @brief Renamed\n" + beklenen_govde

    def test_indeksler(self):
        fi = CCommentGenerator._index_functions(AYNI_AD_FONKSIYONLAR)
        assert fi.name_count == {"memcpy": 2, "FUN_00104100": 1, "FUN_00106c20": 1}
        assert fi.by_address["103ce0"]["size"] == 16 and fi.by_address["135000"]["size"] == 1
        assert fi["memcpy"]["address"] == "00135000"          # ada göre: son kayıt (eski davranış)
        gi = CCommentGenerator._index_call_graph(AYNI_AD_GRAFIK)
        assert gi.addresses_by_name["memcpy"] == {"103ce0", "135000"}
        assert gi.by_address["103ce0"] == {"callers": ["FUN_00104100", "FUN_00106c20"],
                                           "callees": ["memcpy"]}
        assert gi.by_address["135000"] == {"callers": ["memcpy"], "callees": []}
        assert gi["memcpy"]["callers"] == ["memcpy", "FUN_00104100", "FUN_00106c20"]


# ---------------------------------------------------------------------------
# Kusursuz blok bayt bayt aynı
# ---------------------------------------------------------------------------

class TestKusursuzBlokDegismez:
    def test_cikti_duzeltme_oncesiyle_bayt_bayt_ayni(self, tmp_path):
        """Yedi yorum yolunun hepsi (belge bloğu, güvenlik, sistem çağrısı, mantık, akış,
        algoritma etiketi, hesaplama) düzeltmeden önceki kodun çıktısını verir."""
        cikti = _uret(tmp_path, {"FUN_00105fc0.c": TEMIZ_GIRDI}, TEMIZ_FONKSIYONLAR, TEMIZ_GRAFIK,
                      TEMIZ_DIZGILER, algorithm_results=temiz_algoritmalar(),
                      formulas_extracted=TEMIZ_FORMULLER, cfg_matches=TEMIZ_CFG)["FUN_00105fc0.c"]
        assert cikti == TEMIZ_BEKLENEN
        assert yorum_ihlalleri(cikti) == [] and adres_uyusmazliklari(cikti) == []

    def test_altin_cikti_butun_yollari_kapsar(self):
        for iz in ("/**\n", " * @strings ", " * @algorithm ", "/* [HIGH] VULN:", "/* malloc:",
                   "/* loop until", "/* Uses goto", "/* ALGORITHM:", "// [Computation] Formula:",
                   "// [Computation] CFG exact match:"):
            assert iz in TEMIZ_BEKLENEN, iz


# ---------------------------------------------------------------------------
# semantic_namer: imzadaki "was:" yorumu birikmez
# ---------------------------------------------------------------------------

def _adlar(ciftler, fonksiyon):
    return [SemanticName(original_name=eski, semantic_name=yeni, function_name=fonksiyon,
                         confidence=0.9, source="algorithm_template", reason="test",
                         domain="generic") for eski, yeni in ciftler]


def _uygula(kod, ciftler, fonksiyon):
    namer = SemanticParameterNamer.__new__(SemanticParameterNamer)
    return namer._apply_names_to_code(kod, _adlar(ciftler, fonksiyon))


# redis-check-aof / hnsw_ground_truth_with_filter'ın küçültülmüş biçimi: param_naming_map
# {"param_1": "param_3", "param_3": "param_7_0xffffffff"} idi.
ZINCIR_GIRDI = ("void f(long param_1,long param_2,uint param_3)\n\n{\n"
                "  g(param_1,param_2);\n  h(param_3);\n}\n")


class TestWasYorumuBirikmez:
    def test_zincirsiz_cikti_duzeltme_oncesiyle_bayt_bayt_ayni(self):
        assert _uygula(ZINCIRSIZ_GIRDI, ZINCIRSIZ_ADLAR, "solve") == ZINCIRSIZ_BEKLENEN

    def test_ayni_adlar_yeniden_uygulaninca_birikmez(self):
        bir = _uygula(ZINCIRSIZ_GIRDI, ZINCIRSIZ_ADLAR, "solve")
        iki = _uygula(bir, ZINCIRSIZ_ADLAR, "solve")
        assert iki == bir
        assert iki.count("/* was: param_2 */") == 1

    def test_zincirde_yorum_birikmez_ve_degiskenler_karismaz(self):
        """Düzeltmeden önce: ``long x /* was: param_3 */ /* was: param_1 */`` ve gövdede
        iki ayrı parametre tek ada çöküyordu."""
        cikti = _uygula(ZINCIR_GIRDI, [("param_1", "param_3"), ("param_2", "count"),
                                       ("param_3", "limit")], "f")
        assert cikti == (
            "void f(long param_3 /* was: param_1 */,long count /* was: param_2 */,"
            "uint limit /* was: param_3 */)\n\n{\n"
            "  g(param_3,count);\n  h(limit);\n}\n")
        assert yorum_ihlalleri(cikti) == []

    def test_zincir_sirasi_sonucu_degistirmez(self):
        bir = _uygula(ZINCIR_GIRDI, [("param_1", "param_3"), ("param_3", "limit")], "f")
        iki = _uygula(ZINCIR_GIRDI, [("param_3", "limit"), ("param_1", "param_3")], "f")
        assert bir == iki == (
            "void f(long param_3 /* was: param_1 */,long param_2,uint limit /* was: param_3 */)\n\n{\n"
            "  g(param_3,param_2);\n  h(limit);\n}\n")

    def test_takas(self):
        cikti = _uygula(ZINCIR_GIRDI, [("param_1", "param_2"), ("param_2", "param_1")], "f")
        assert cikti == (
            "void f(long param_2 /* was: param_1 */,long param_1 /* was: param_2 */,uint param_3)\n\n{\n"
            "  g(param_2,param_1);\n  h(param_3);\n}\n")

    def test_ara_ad_metinde_varsa_cakismaz(self):
        kod = ("void f(long param_1,long param_2)\n\n{\n"
               "  g(param_1,param_2,__karadul_rename_0_0__,__karadul_rename_1_0__);\n}\n")
        cikti = _uygula(kod, [("param_1", "param_2"), ("param_2", "n")], "f")
        assert cikti == (
            "void f(long param_2 /* was: param_1 */,long n /* was: param_2 */)\n\n{\n"
            "  g(param_2,n,__karadul_rename_0_0__,__karadul_rename_1_0__);\n}\n")

    def test_zincir_yalniz_kendi_fonksiyonunu_etkiler(self):
        """Zincir başka bir fonksiyondaysa bu fonksiyonun çıktısı sıradan yoldan gelir."""
        kod = ZINCIRSIZ_GIRDI + "\n" + ZINCIR_GIRDI
        adlar = (_adlar(ZINCIRSIZ_ADLAR, "solve")
                 + _adlar([("param_1", "param_3"), ("param_3", "limit")], "f"))
        namer = SemanticParameterNamer.__new__(SemanticParameterNamer)
        cikti = namer._apply_names_to_code(kod, adlar)
        assert cikti.startswith(ZINCIRSIZ_BEKLENEN)
        assert "__karadul_rename_" not in cikti


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    for arg in sys.argv[1:]:
        print(json.dumps(agaci_say(Path(arg).expanduser()), ensure_ascii=False, indent=2))
    sys.exit(0)
