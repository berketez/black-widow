"""docs/arge/2026-11-10_n4/on_sayim.py — N4 GT'siz ön sayımının sürüm 2 sayaçları.

Bütün testler sentetik ``static/`` dizinleriyle koşar (elle yazılmış AArch64 disassembly); gerçek
ikili, GT ya da Karadul çıktısı okunmaz. Kilitlenen davranışlar:
  (a) işlenen ayrıştırma, sabitin yazmaç genişliğinde yorumu, decompile imzasından dönüş türü ve
      Ghidra'nın dönmeyen çağrı uyarısı (yığın koruyucu hariç),
  (b) taslağın kuralları: destroy (ana yolda parametrenin kendisi bırakılıyor), create (dar ve
      geniş ayırıcı; geniş = ayırıcı + hata bildirimi sarmalayıcısı), init, is,
  (c) Onuncu Adam kalıpları: 1 (0/1 dönen + çağrı), 2 (alan bırak + sabit yaz), 3 (bırakılan
      parametre başka çağrıya da gidiyor), 4 (bırakma yalnız -1 dönen yolda; ortak dönüş
      bloğunda yol duyarlılık), 4_sifir,
  (d) FK3: dönmeyen kütüphane çağrısı ve dönmeyen iç fonksiyon; yığın koruyucu hata yolu değil,
  (e) nüfuslar (bekleyen, export, export_tek, capa), ad tekilliği, istatistik ve hüküm
      fonksiyonları, belirlenimcilik (iki PYTHONHASHSEED).

Mutant denetimi için betik yolu ``N4_ON_SAYIM_YOLU`` ortam değişkeniyle değiştirilebilir.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = Path(os.environ.get("N4_ON_SAYIM_YOLU",
                            _KOK / "docs" / "arge" / "2026-11-10_n4" / "on_sayim.py"))
_spec = importlib.util.spec_from_file_location("n4_on_sayim_under_test", _PATH)
os_ = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = os_
_spec.loader.exec_module(os_)

# --------------------------------------------------------------------------------------------
# Sentetik static/ dizini

FREE, MALLOC, EXIT, MEMCPY, STRCMP, CHK = 0x9000, 0x9010, 0x9020, 0x9030, 0x9040, 0x9050


def _kutuphane() -> list[dict]:
    return [{"ad": ad, "adres": a, "dis": True} for ad, a in (
        ("_free", FREE), ("_malloc", MALLOC), ("_exit", EXIT), ("_memcpy", MEMCPY),
        ("_strcmp", STRCMP), ("___stack_chk_fail", CHK))]


def fonk(adres: int, govde: list[str], imza: str = "undefined8 {ad}(void *param_1)",
         ad: str | None = None, kaynak: str = "DEFAULT") -> dict:
    """``govde``: '<mn> <işlenenler>' satırları; adresler 4'er artar."""
    ad = ad or f"FUN_{adres:x}"
    komutlar = []
    for i, satir in enumerate(govde):
        komutlar.append((adres + 4 * i, satir))
    return {"ad": ad, "adres": adres, "dis": False, "kaynak": kaynak, "komutlar": komutlar,
            "imza": imza.format(ad=ad)}


def statik_yaz(kok: Path, fonksiyonlar: list[dict]) -> Path:
    st = kok / "static"
    dec = st / "ghidra_output" / "decompiled"
    dec.mkdir(parents=True)
    kayit = []
    for f in _kutuphane() + fonksiyonlar:
        kayit.append({"name": f["ad"], "address": f"{f['adres']:x}",
                      "size": 4 * len(f.get("komutlar", [])) or 4,
                      "is_thunk": f["dis"], "is_external": f["dis"],
                      "source": f.get("kaynak", "IMPORTED")})
        if f["dis"]:
            continue
        satirlar = [f"// Function: {f['ad']}", f"// Address:  {f['adres']:x}", "", "",
                    f["imza"], "{", "}", "", "",
                    f"// --- DISASSEMBLY ({len(f['komutlar'])} instructions) ---"]
        satirlar += [f"// {pc:x}  {s}" for pc, s in f["komutlar"]]
        (dec / f"{f['ad']}.c").write_text("\n".join(satirlar) + "\n", encoding="utf-8")
    (st / "ghidra_functions.json").write_text(json.dumps({"functions": kayit}), encoding="utf-8")
    (st / "ghidra_xrefs.json").write_text(json.dumps({"function_xrefs": {}}), encoding="utf-8")
    (st / "ghidra_combined_results.json").write_text(json.dumps(
        {"program_info": {"executable_format": "Mac OS X Mach-O", "processor": "AARCH64"}}),
        encoding="utf-8")
    return st


def olculer(tmp_path: Path, fonksiyonlar: list[dict], capalar=None) -> dict:
    return os_.elf_say(statik_yaz(tmp_path, fonksiyonlar), capalar)["n4"]


def fonksiyon_olculeri(tmp_path: Path, fonksiyonlar: list[dict], adres: int) -> set[str]:
    """Tek fonksiyonun ölçü kümesi (n4_elf'in örnek havuzundan)."""
    n4 = olculer(tmp_path, fonksiyonlar)
    return {o for o, adresler in n4["ornek"].items() if adres in adresler}


PROLOG = ["stp x29,x30,[sp, #-0x20]!", "stp x20,x19,[sp, #0x10]"]
EPILOG = ["ldp x20,x19,[sp, #0x10]", "ldp x29,x30,[sp], #0x20", "ret"]


def hedef(a: int) -> str:
    return f"0x{a:x}"


# --------------------------------------------------------------------------------------------
# (a) ayrıştırma


def test_isleneler_koseli_ayrac_icinde_bolmez():
    assert os_.isleneler("x0,[x1, #0x10]") == ("x0", "[x1, #0x10]")
    assert os_.isleneler("x29,x30,[sp], #0x20") == ("x29", "x30", "[sp]", "#0x20")


def test_yazmac_ve_sabit():
    assert os_.yazmac("w5") == "x5" and os_.yazmac("xzr") == "zr" and os_.yazmac("q0") == "v0"
    assert os_.yazmac("#1") is None
    assert os_.sabit(0xFFFFFFFF, "w0") == -1
    assert os_.sabit(0xFFFFFFFF, "x0") == 0xFFFFFFFF
    assert os_.sabit(-1, "x0") == -1


def test_bellek_isleneni():
    assert os_.bellek(("x0", "[x1, #0x10]")) == (1, "x1", 16, False)
    assert os_.bellek(("x29", "x30", "[sp]", "#0x20")) == (2, "sp", 0, True)
    assert os_.bellek(("x0", "[x8, x9, LSL #3]")) == (1, "x8", None, False)


def test_c_ozeti_donus_turu_ve_donmez_uyarisi():
    c = "// Function: f\n/* WARNING: x */\nvoid FUN_1(void)\n{\n}\n"
    assert os_.c_ozeti(c) == {"donus": "void", "ghidra_donmez": False}
    c2 = ("char * FUN_2(int param_1)\n{\n                    /* WARNING: Subroutine does not "
          "return */\n  ___stack_chk_fail();\n}\n")
    assert os_.c_ozeti(c2) == {"donus": "char *", "ghidra_donmez": False}
    c3 = c2.replace("___stack_chk_fail", "_exit")
    assert os_.c_ozeti(c3)["ghidra_donmez"] is True


# --------------------------------------------------------------------------------------------
# (b, c) kurallar ve kalıplar

D_YIKICI = 0x1000      # alanı ve kendisini bırakan yıkıcı (kuyruk çağrılı free)
D_KALIP3 = 0x1100      # parametreyi başka çağrıya verip bırakan
D_KALIP4 = 0x1200      # bırakma yalnız -1 dönen yolda, ortak dönüş bloğu
D_KALIP4S = 0x1300     # bırakma sonrası NULL, öbür yolda parametre
D_IS_CAGRI = 0x1400    # 0/1 dönen, memcpy çağıran (kalıp 1)
D_IS_YAPRAK = 0x1500   # saf yüklem
D_VOID_01 = 0x1600     # void ama x0'da 0/1: is değil
D_INIT = 0x1700        # üç ofsete sabit/parametre
D_KALIP2 = 0x1800      # alanı bırak, iki ofseti sıfırla
D_XMALLOC = 0x1900     # ayırıcı + hata bildirimi (geniş FK1)
D_CREATE_G = 0x1A00    # geniş sarmalayıcıyla kurucu
D_CREATE_D = 0x1B00    # doğrudan malloc'la kurucu
D_FATAL = 0x1C00       # dönmeyen iç fonksiyon
D_FK3_IC = 0x1D00      # hata yolu dönmeyen iç fonksiyona gidiyor
D_FK3_KUT = 0x1E00     # hata yolu doğrudan exit
D_YIGIN = 0x1F00       # yalnız yığın koruyucu hata yolu
D_IS_SALT = 0x2000     # 0/1 dönen, yalnız strcmp çağıran
D_ICI = 0x2100         # sıradan iç fonksiyon (kalıp 3'te çağrılır)
D_CREATE_P = 0x2200    # boyutu parametreden alan kurucu: sarmalayıcı değil (nesneye yazıyor)


def program() -> list[dict]:
    return [
        fonk(D_YIKICI, PROLOG + ["mov x19,x0", "ldr x0,[x0, #0x10]", f"bl {hedef(FREE)}",
                                  "mov x0,x19", "ldp x20,x19,[sp, #0x10]",
                                  "ldp x29,x30,[sp], #0x20", f"b {hedef(FREE)}"],
             imza="void {ad}(void *param_1)"),
        fonk(D_ICI, ["ldr x8,[x0]", "add x8,x8,#0x1", "str x8,[x0]", "ret"],
             imza="void {ad}(long *param_1)"),
        fonk(D_KALIP3, PROLOG + ["mov x19,x0", f"bl {hedef(D_ICI)}", "mov x0,x19",
                                  f"bl {hedef(FREE)}"] + EPILOG,
             imza="void {ad}(void *param_1)"),
        # if (ici(p) < 0) { free(p); return -1; } ici(p); return 0;   — ortak dönüş bloğu
        fonk(D_KALIP4, PROLOG + [
            "mov x19,x0",                                   # +8
            f"bl {hedef(D_ICI)}",                           # +c
            f"tbnz w0,#0x1f,{hedef(D_KALIP4 + 0x28)}",      # +10
            "mov x0,x19",                                   # +14
            f"bl {hedef(D_ICI)}",                           # +18
            "mov w0,#0x0",                                  # +1c
            f"b {hedef(D_KALIP4 + 0x34)}",                  # +20
            "nop",                                          # +24 (ulaşılmaz)
            "mov x0,x19",                                   # +28 hata yolu
            f"bl {hedef(FREE)}",                            # +2c
            "mov w0,#0xffffffff",                           # +30
        ] + EPILOG, imza="int {ad}(void *param_1)"),       # +34 ortak dönüş
        # if (ici(p) < 0) { free(p); return NULL; } return p;
        fonk(D_KALIP4S, PROLOG + [
            "mov x19,x0",
            f"bl {hedef(D_ICI)}",
            f"tbnz w0,#0x1f,{hedef(D_KALIP4S + 0x20)}",
            "mov x0,x19",
            f"b {hedef(D_KALIP4S + 0x2c)}",
            "nop",
            "mov x0,x19",                                   # +20
            f"bl {hedef(FREE)}",
            "mov x0,#0x0",
        ] + EPILOG, imza="void * {ad}(void *param_1)"),    # +2c
        fonk(D_IS_CAGRI, PROLOG + [
            f"cbz x0,{hedef(D_IS_CAGRI + 0x1c)}",           # +8
            f"bl {hedef(MEMCPY)}",                          # +c
            "mov w0,#0x1",                                  # +10
            f"b {hedef(D_IS_CAGRI + 0x20)}",                # +14
            "nop",                                          # +18
            "mov w0,#0x0",                                  # +1c
        ] + EPILOG, imza="int {ad}(void *param_1,void *param_2)"),   # +20
        fonk(D_IS_YAPRAK, ["ldr w8,[x0, #0x8]", "cmp w8,#0x2", "cset w0,eq", "ret"],
             imza="bool {ad}(long param_1)"),
        fonk(D_VOID_01, ["ldr w8,[x0, #0x8]", "cmp w8,#0x2", "cset w0,eq", "ret"],
             imza="void {ad}(long param_1)"),
        fonk(D_INIT, ["str xzr,[x0]", "str wzr,[x0, #0x8]", "str x1,[x0, #0x10]", "ret"],
             imza="void {ad}(long param_1,long param_2)"),
        fonk(D_KALIP2, PROLOG + ["mov x19,x0", "ldr x0,[x0, #0x8]", f"bl {hedef(FREE)}",
                                  "str xzr,[x19, #0x8]", "str wzr,[x19, #0x10]"] + EPILOG,
             imza="void {ad}(long param_1)"),
        fonk(D_XMALLOC, PROLOG + [
            f"bl {hedef(MALLOC)}",                          # +8
            f"cbz x0,{hedef(D_XMALLOC + 0x1c)}",            # +c
        ] + EPILOG + [                                      # +10 .. +18
            f"bl {hedef(EXIT)}",                            # +1c
        ], imza="void * {ad}(ulong param_1)"),
        fonk(D_CREATE_G, PROLOG + ["mov x19,x0", "mov w0,#0x18", f"bl {hedef(D_XMALLOC)}",
                                    "str x19,[x0]", "str xzr,[x0, #0x8]"] + EPILOG,
             imza="void * {ad}(void *param_1)"),
        fonk(D_CREATE_D, PROLOG + ["mov w0,#0x18", f"bl {hedef(MALLOC)}",
                                    f"cbz x0,{hedef(D_CREATE_D + 0x18)}", "str xzr,[x0]"] + EPILOG,
             imza="void * {ad}(void)"),
        fonk(D_FATAL, PROLOG + [f"bl {hedef(EXIT)}"], imza="void {ad}(char *param_1)"),
        fonk(D_FK3_IC, PROLOG + [f"cbz x0,{hedef(D_FK3_IC + 0x18)}"] + EPILOG
             + [f"bl {hedef(D_FATAL)}"], imza="void {ad}(void *param_1)"),
        fonk(D_FK3_KUT, PROLOG + [f"cbz x0,{hedef(D_FK3_KUT + 0x18)}"] + EPILOG
             + [f"bl {hedef(EXIT)}"], imza="void {ad}(void *param_1)"),
        fonk(D_YIGIN, PROLOG + [f"cbz x0,{hedef(D_YIGIN + 0x18)}"] + EPILOG
             + [f"bl {hedef(CHK)}"], imza="void {ad}(void *param_1)"),
        fonk(D_IS_SALT, PROLOG + [f"bl {hedef(STRCMP)}", "cmp w0,#0x0", "cset w0,eq"] + EPILOG,
             imza="bool {ad}(char *param_1,char *param_2)"),
        fonk(D_CREATE_P, PROLOG + ["mov x19,x0", f"bl {hedef(MALLOC)}",
                                    f"cbz x0,{hedef(D_CREATE_P + 0x18)}", "str x19,[x0]"] + EPILOG,
             imza="void * {ad}(ulong param_1)"),
    ]


@pytest.fixture(scope="module")
def n4(tmp_path_factory):
    return olculer(tmp_path_factory.mktemp("n4"), program())


def ol(n4, adres: int) -> set[str]:
    return {o for o, adresler in n4["ornek"].items() if adres in adresler}


def test_destroy_yikici(n4):
    o = ol(n4, D_YIKICI)
    assert {"fire_destroy", "destroy_her_yolda", "birakici_cagiran", "fetki_ilk"} <= o
    assert not o & {"kalip3", "kalip4", "kalip2", "fire_is", "kalip1"}


def test_kalip3_parametre_baska_cagriya_da_gidiyor(n4):
    o = ol(n4, D_KALIP3)
    assert {"fire_destroy", "kalip3", "kalip3_arg", "destroy_riskli", "fetki_ilk_riskli"} <= o


def test_kalip4_ortak_donus_blogunda_yol_duyarli(n4):
    o = ol(n4, D_KALIP4)
    assert {"fire_destroy", "kalip4", "kalip3"} <= o
    assert "destroy_her_yolda" not in o and "kalip4_sifir" not in o


def test_kalip4_sifir(n4):
    o = ol(n4, D_KALIP4S)
    assert {"fire_destroy", "kalip4_sifir"} <= o
    assert "kalip4" not in o


def test_kalip1_is_ve_alt_kirilim(n4):
    o = ol(n4, D_IS_CAGRI)
    assert {"fire_is", "kalip1", "kalip1_is", "kalip1_is_yan", "kalip1_is_yan_kutuphane"} <= o
    o2 = ol(n4, D_IS_SALT)
    assert {"fire_is", "kalip1_is", "kalip1_is_salt_okur"} <= o2
    assert "kalip1_is_yan" not in o2


def test_is_saf_yuklem_kalip_degil(n4):
    o = ol(n4, D_IS_YAPRAK)
    assert "fire_is" in o and "kalip1" not in o


def test_void_donuslu_is_ateslemez(n4):
    o = ol(n4, D_VOID_01)
    assert "donus_void" in o and "fire_is" not in o and "kalip1" not in o


def test_init_uc_ofset(n4):
    o = ol(n4, D_INIT)
    assert "fire_init" in o and "yazar" in o and "fire_is" not in o


def test_kalip2_alan_birak_sifirla(n4):
    o = ol(n4, D_KALIP2)
    assert {"kalip2", "kalip2_init", "fire_init", "birakici_cagiran"} <= o
    assert "fire_destroy" not in o


def test_create_genis_ve_dar(n4):
    assert n4["sayac"]["elf:fk1_ayirici_genis"] == 1
    assert n4["sayac"]["elf:fk1_ayirici_dar"] == 0
    o = ol(n4, D_CREATE_G)
    assert {"fire_create_genis", "ayirici_cagiran"} <= o and "fire_create_dar" not in o
    o2 = ol(n4, D_CREATE_D)
    assert {"fire_create_dar", "fire_create_genis"} <= o2
    assert "fk1_ayirici_genis" in ol(n4, D_XMALLOC)
    assert "fire_create_genis" not in ol(n4, D_XMALLOC)   # sarmalayıcının kendisi F-API'ye gider
    o3 = ol(n4, D_CREATE_P)                                # kurucu: nesneye yazıyor
    assert {"fire_create_dar", "fire_create_genis"} <= o3 and "fk1_ayirici_genis" not in o3


def test_fk3(n4):
    assert n4["sayac"]["elf:donmez_ic"] == 1                # yalnız D_FATAL
    assert {"tum_yollar_donmez"} <= ol(n4, D_FATAL)
    o = ol(n4, D_FK3_IC)
    assert "fk3_genis" in o and "fk3_dar" not in o
    assert {"fk3_genis", "fk3_dar"} <= ol(n4, D_FK3_KUT)
    assert "fk3_genis" not in ol(n4, D_YIGIN)


def test_ad_tekil(n4):
    s = n4["sayac"]
    # destroy üç fonksiyonda (yıkıcı, kalıp 3, 4, 4_sifir) ateşliyor: tekil ad yok
    assert s["bekleyen:fire_destroy"] == 4 and s["bekleyen:ad_tekil:destroy"] == 0
    assert s["bekleyen:fire_init"] == 2 and s["bekleyen:ad_tekil:init"] == 0
    assert s["bekleyen:fire_create_dar"] == 2 and s["bekleyen:ad_tekil:create_dar"] == 0
    assert s["bekleyen:fire_create_genis"] == 3 and s["bekleyen:ad_tekil:create_genis"] == 0


def test_sinif_ve_komut_kirilimi(n4):
    s = n4["sayac"]
    assert s["bekleyen:fire_is:Y"] == 1 and s["bekleyen:fire_is:K"] == 2
    assert s["bekleyen:n"] == sum(s[f"bekleyen:n:{c}"] for c in "KIY")
    assert s["bekleyen:fire_is:komut_<=8"] == 2 and s["bekleyen:fire_is:komut_9-32"] == 1


def test_export_ve_capa_nufuslari(tmp_path):
    govde = ["mov x19,x0", "ldr x0,[x0, #0x8]", f"bl {hedef(FREE)}", "mov x0,x19",
             f"b {hedef(FREE)}"]
    fs = [fonk(0x1000, govde, ad="obj_free", kaynak="IMPORTED", imza="void {ad}(void *param_1)"),
          fonk(0x1100, govde, imza="void {ad}(void *p)"),
          # yalnız free'ye inen, x0'ı değiştirmeyen: FK1 sarmalayıcısı, F-ETKİ ad vermez
          fonk(0x1200, [f"b {hedef(FREE)}"], imza="void {ad}(void *p)")]
    n4 = olculer(tmp_path, fs, capalar={0x1100: ("tek_sinif", "destroy")})
    s = n4["sayac"]
    assert s["export:n"] == 1 and s["export_tek:n"] == 1 and s["export:fire_destroy"] == 1
    assert s["bekleyen:n"] == 2 and s["capa:n"] == 1 and s["capa_tek:fire_destroy"] == 1
    assert s["elf:fk1_free"] == 1 and s["bekleyen:fk1_free"] == 1
    assert s["bekleyen:fire_destroy"] == 1


def test_eski_sayaclar_n4_ile_degismez(tmp_path):
    st = statik_yaz(tmp_path, program())
    r = os_.elf_say(st)
    assert r["sayim"]["isim_bekleyen"] == len(program())
    assert r["sayim"]["sinif_Y"] + r["sayim"]["sinif_I"] + r["sayim"]["sinif_K"] == len(program())


# --------------------------------------------------------------------------------------------
# (e) istatistik, hüküm, sabitler, belirlenimcilik


def test_wilson_newcombe_katz():
    lo, hi = os_.wilson(0, 10)
    assert lo == 0.0 and abs(hi - 0.2775) < 1e-3
    lo, hi = os_.newcombe(56, 70, 48, 80)          # Newcombe 1998, yöntem 10 örneği
    assert abs(lo - 0.0524) < 1e-3 and abs(hi - 0.3339) < 1e-3
    lo, hi = os_.katz(10, 100, 5, 100)
    assert abs(lo - 0.7090) < 1e-3 and abs(hi - 5.6418) < 2e-3
    assert os_.katz(0, 10, 5, 10) is None


def test_olcum1_hukum_esikleri():
    s = {"bekleyen:n": 100, "bekleyen:fire_is": 8, "bekleyen:kalip1_is": 3,
         "bekleyen:fire_destroy": 4, "bekleyen:destroy_riskli": 1, "bekleyen:fetki_ilk": 4}
    h = os_.olcum1_hukum(s)
    assert h["riskli_pay"]["is"]["esik_asildi"] is True          # 3/8 > 0,25
    assert h["riskli_pay"]["destroy"]["esik_asildi"] is False    # 1/4 = 0,25, aşılmadı
    assert h["create_destroy_esik_alti"] is True                 # 4/100 < 0,05


def test_m1_temsil_hukmu():
    def birim(n, cagiransiz, cd, d):
        return {"n4": {"export:n": n, "export:cagiransiz": cagiransiz,
                       "export:fire_create_genis": cd, "export:fire_destroy": d,
                       "export:fetki_ilk": cd + d,
                       "bekleyen:n": n, "bekleyen:cagiransiz": cagiransiz,
                       "bekleyen:fire_create_genis": cd, "bekleyen:fire_destroy": d,
                       "bekleyen:fetki_ilk": cd + d},
                "n4_ortanca": {"export": {}, "bekleyen": {}}}
    cb = {"debian/htop": birim(100, 10, 10, 10)}
    r = [k for k in os_.m1_temsil(cb) if k["a"] == "debian/htop:export"
         and k["b"] == "debian/htop:bekleyen"][0]
    assert r["hukum_fetki_ilk"] == "oldurme_dayanagi_olabilir"
    cb["debian/htop"]["n4"]["bekleyen:cagiransiz"] = 50     # 40 puan fark
    r = [k for k in os_.m1_temsil(cb) if k["a"] == "debian/htop:export"
         and k["b"] == "debian/htop:bekleyen"][0]
    assert r["hukum_fetki_ilk"] == "yalniz_akil_sagligi"


def test_boyut_tabakasi_ks1_ile_ayni():
    yol = _KOK / "docs" / "arge" / "2026-10-21_g11_n1" / "ks1_sinif.json"
    d = json.loads(yol.read_text(encoding="utf-8"))
    assert {u: b["boyut_tabakasi"] for u, b in d["birimler"].items()} == os_.BOYUT_TABAKASI


def test_belirlenimcilik_iki_tohum(tmp_path):
    st = statik_yaz(tmp_path, program())
    kod = ("import importlib.util,json,sys;from pathlib import Path;"
           f"s=importlib.util.spec_from_file_location('m',{str(_PATH)!r});"
           "m=importlib.util.module_from_spec(s);sys.modules['m']=m;s.loader.exec_module(m);"
           f"r=m.elf_say(Path({str(st)!r}))['n4'];"
           "print(json.dumps({'s':dict(sorted(r['sayac'].items())),"
           "'o':{k:sorted(v) for k,v in sorted(r['ornek'].items())}},sort_keys=True))")
    ciktilar = []
    for tohum in ("0", "12345"):
        ortam = dict(os.environ, PYTHONHASHSEED=tohum, PYTHONDONTWRITEBYTECODE="1")
        ciktilar.append(subprocess.run([sys.executable, "-I", "-c", kod], env=ortam,
                                       capture_output=True, text=True, check=True).stdout)
    assert ciktilar[0] == ciktilar[1] and ciktilar[0]
