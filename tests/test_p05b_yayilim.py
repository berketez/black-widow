"""P05b kalem 3: yayılımın kaybolan doğru adları kanıtla geri alması.

Ürüne giren kural (a): çağıranın dizgi sabitindeki çağrı metni
(``_serverAssert("lpRandomPairsUnique(lp, count, keys, vals, tuple_len) == count", …)``: derleyicinin
yazdığı kaynak metin). Gerçek çağrılar dizgi ve yorum örtülü aranır.

Ön kayıttaki (b) adlı küresel / fonksiyon argümanı, (c) ``*x`` dereferansı ve (d) çağrı yeri oylaması
ölçüldü, kalma ölçütünü geçemedi (DWARF'a göre yanlış adı artırdılar; P05b.md §3) ve ürüne
alınmadı. Aşağıdaki testler bu kararı kilitler: kural ölçülmeden geri gelirse kırmızı olur.
"""
from __future__ import annotations

from karadul.config import Config
from karadul.reconstruction.engineering.semantic_namer import SemanticParameterNamer


def _yay(codes: dict[str, str], callee: str, callers: list[str]) -> dict[str, tuple[str, str]]:
    namer = SemanticParameterNamer(Config())
    namer._func_codes = dict(codes)
    namer._reverse_graph = {callee: list(callers)}
    params = namer._get_function_params(callee)
    return {s.original_name: (s.semantic_name, s.reason)
            for s in namer._propagate_from_callers(callee, params, {})}


CALLEE5 = (
    "uint lpRandomPairsUnique(uint64_t param_1,uint64_t param_2,long *param_3,long *param_4,\n"
    "                        uint64_t param_5)\n{\n  return 0;\n}\n"
)


def _caller_assert(metin: str) -> str:
    return (
        "void hrandfieldCommand(long buf_9,long len_3)\n{\n"
        "  uint uVar19;\n"
        "  long *long_array_98;\n"
        "  uVar19 = lpRandomPairsUnique(buf_9,len_3 & 0xffffffff,long_array_98,0,uVar19);\n"
        f"  _serverAssert(\"{metin}\",\"t_hash.c\",0x4f2);\n"
        "  return;\n}\n"
    )


def test_dizgideki_cagri_metni_ad_verir():
    got = _yay({"hrandfieldCommand": _caller_assert(
        "lpRandomPairsUnique(lp, count, keys, vals, tuple_len) == count"),
        "lpRandomPairsUnique": CALLEE5}, "lpRandomPairsUnique", ["hrandfieldCommand"])
    adlar = {k: v[0] for k, v in got.items()}
    # Kaynak metin, gerçek çağrıdaki değişken adından (buf_9, len_3) önce gelir
    assert adlar == {"param_1": "lp", "param_2": "count", "param_3": "keys",
                     "param_4": "vals", "param_5": "tuple_len"}
    assert all(r.startswith("Source text call") for _, r in got.values())


def test_dizgideki_cagri_arguman_sayisi_tutmazsa_ad_yok():
    got = _yay({"hrandfieldCommand": _caller_assert("lpRandomPairsUnique(lp, count) == 0"),
                "lpRandomPairsUnique": CALLEE5}, "lpRandomPairsUnique", ["hrandfieldCommand"])
    assert not any(r.startswith("Source text call") for _, r in got.values())
    # Gerçek çağrının değişken adları (P05 kuralı) yine yayılır
    assert got["param_1"][0] == "buf_9"


def test_dizgideki_cagri_sabit_ve_ifade_ad_vermez():
    got = _yay({"hrandfieldCommand": _caller_assert(
        "lpRandomPairsUnique(zsetobj->ptr, NULL, OBJ_KEYS, vals, 2) == count"),
        "lpRandomPairsUnique": CALLEE5}, "lpRandomPairsUnique", ["hrandfieldCommand"])
    adlar = {k: v[0] for k, v in got.items()}
    assert adlar.get("param_4") == "vals"
    assert adlar.get("param_2") not in ("NULL",)
    assert adlar.get("param_3") != "OBJ_KEYS"
    assert adlar.get("param_1") == "buf_9"   # ifade (zsetobj->ptr) ad vermez; gerçek çağrı verir


def test_dizgi_ici_cagri_gercek_cagri_sayilmaz():
    # Çağıranın bildirdiği ``count`` yalnız dizginin içinde argüman: değişken yayılımı vermez
    caller = (
        "void zz_f(long count)\n{\n"
        "  puts(\"g(count) failed\");\n"
        "  g(0,1);\n"
        "  return;\n}\n"
    )
    callee = "void g(long param_1,long param_2)\n{\n  return;\n}\n"
    got = _yay({"zz_f": caller, "g": callee}, "g", ["zz_f"])
    assert got == {}


def test_adli_kuresel_ve_fonksiyon_argumani_ad_vermez():
    caller = (
        "void CRT_init(void)\n{\n"
        "  CRT_setColors(CRT_colorScheme,_stdout,NULL,OBJ_STRING,free);\n"
        "  return;\n}\n"
    )
    callee = ("void CRT_setColors(int param_1,long param_2,long param_3,int param_4,"
              "code *param_5)\n{\n  return;\n}\n")
    got = _yay({"CRT_init": caller, "CRT_setColors": callee}, "CRT_setColors", ["CRT_init"])
    # (b) ölçüldü, kalma ölçütünü geçemedi (D: +9 doğru, +6 yanlış): çağıranda bildirilmemiş
    # ad (küresel, fonksiyon), ayrılmış ad, NULL ve sabit ad vermez
    assert got == {}


def test_degisken_kuresel_adindan_once_gelir():
    callee = "void g(long param_1)\n{\n  return;\n}\n"
    c1 = "void zz_a(void)\n{\n  g(globalCount);\n  return;\n}\n"
    c2 = "void zz_b(long count_7)\n{\n  g(count_7);\n  return;\n}\n"
    got = _yay({"zz_a": c1, "zz_b": c2, "g": callee}, "g", ["zz_a", "zz_b"])
    assert got["param_1"][0] == "count_7"


def test_dereferans_ad_vermez():
    caller = (
        "void FUN_00101000(long *ppDb_2,long param_2)\n{\n"
        "  FUN_0012a324(*ppDb_2,param_2);\n"
        "  FUN_0012a324(*(long *)(param_2 + 8),0);\n"
        "  return;\n}\n"
    )
    callee = "void FUN_0012a324(long param_1,long param_2)\n{\n  return;\n}\n"
    got = _yay({"FUN_00101000": caller, "FUN_0012a324": callee}, "FUN_0012a324",
               ["FUN_00101000"])
    # (c) ölçüldü, kalma ölçütünü geçemedi (D: +3 doğru, +11 yanlış)
    assert got == {}


def test_cagri_yerleri_ilk_gorulen():
    callee = "void sdscatrepr(long param_1,long param_2,long param_3)\n{\n  return;\n}\n"
    caller = (
        "void zz_f(long uval_126,long len_365,long len,long buf_1)\n{\n"
        "  sdscatrepr(buf_1,0,uval_126);\n"
        "  sdscatrepr(buf_1,0,len_365);\n"
        "  sdscatrepr(buf_1,0,len);\n"
        "  return;\n}\n"
    )
    got = _yay({"zz_f": caller, "sdscatrepr": callee}, "sdscatrepr", ["zz_f"])
    # (d) oylama ölçüldü, kalma ölçütünü geçemedi (D: −2 doğru, +2 yanlış): ilk görülen kazanır
    assert got["param_3"][0] == "uval_126"


def test_cagiran_sirasi_ilk_gorulen():
    callee = "void g(long param_1)\n{\n  return;\n}\n"
    c1 = "void zz_a(long count_252)\n{\n  g(count_252);\n  return;\n}\n"
    c2 = "void zz_b(long status_932)\n{\n  g(status_932);\n  return;\n}\n"
    codes = {"zz_a": c1, "zz_b": c2, "g": callee}
    assert _yay(codes, "g", ["zz_a", "zz_b"])["param_1"][0] == "count_252"
    assert _yay(codes, "g", ["zz_b", "zz_a"])["param_1"][0] == "status_932"


def test_yorumdaki_cagri_metni_ad_vermez():
    caller = (
        "void hrandfieldCommand(long buf_9,long len_3)\n{\n"
        "  /* see lpRandomPairsUnique(lp, count, keys, vals, tuple_len) */\n"
        "  FUN_00101000(buf_9);\n"
        "  return;\n}\n"
    )
    got = _yay({"hrandfieldCommand": caller, "lpRandomPairsUnique": CALLEE5},
               "lpRandomPairsUnique", ["hrandfieldCommand"])
    assert got == {}
