"""Ad geçerliliği süzgeci: verilen her ad geçerli bir C tanımlayıcısı ve ikili içinde tek anlamlı.

Kanıt: ``docs/arge/2026-11-10_cikti_saglamligi/rapor.md`` bulgu 8 ve bulgu 9'un ad kısmı
(``void break(uint64_t param_1)``, ``int uint64_t(long count …)``, iki ayrı ``write``).

Kilitlenen davranışlar:
  - listeler tek yerde (``karadul.reconstruction.name_validity``); neden sırası sabit;
  - C anahtar sözcüğü, tip adı ve C tanımlayıcısı olmayan ad her kapsamda reddedilir;
  - ikilide başka bir fonksiyonun adı ikili kapsamlı anahtarda reddedilir, yerelde edilmez;
  - reddedilen adayın yerine sıradaki geçerli aday yarışır; yoksa fonksiyon Ghidra adıyla kalır;
  - künyeli ön adlar (elle, KS-1) aynı kurallardan geçer;
  - aynı adı isteyen iki fonksiyondan ilki eksiz, ikincisi ``_2`` alır; ek var olan fonksiyon
    adını atlar;
  - reddedilen her ad sayılır (sonuç nesnesi) ve nedeniyle köken kaydına girer;
  - her aday anahtarı seçim döngüsünden tam bir kez çıkar;
  - süzgece takılan ad yoksa ``naming_map.json`` ve ``.c`` çıktıları bayt bayt aynı.

Mutasyon koruması: ``scripts/measurement/mutation_specs_ad_gecerliligi.json``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_c_namer_determinism as T  # noqa: E402
import test_c_namer_susturma as S  # noqa: E402

from karadul.config import Config  # noqa: E402
from karadul.reconstruction import c_namer  # noqa: E402
from karadul.reconstruction import name_validity as nv  # noqa: E402
from karadul.reconstruction.c_namer import CVariableNamer  # noqa: E402
from karadul.reconstruction.tarif import alt_kanal, baglama  # noqa: E402

GECERSIZ = "all_candidates_invalid_name"


@pytest.fixture
def seri(monkeypatch):
    monkeypatch.setattr(c_namer, "ProcessPoolExecutor", T._SerialExecutor)
    monkeypatch.setattr(c_namer, "_worker_namer", None)


# --------------------------------------------------------------------------------------------
# Sentetik Ghidra çıktısı


def _fonk(ad, adres, dizgiler=(), govde=None, thunk=False):
    return {"ad": ad, "adres": adres, "dizgiler": list(dizgiler), "thunk": thunk,
            "govde": govde if govde is not None else f"void {ad}(void)\n{{\n  return;\n}}\n"}


def _calisma_alani(root: Path, fonklar: list[dict], kenarlar=()) -> dict[str, Path]:
    """Verilen fonksiyonlardan en küçük Ghidra çıktısı. Sıra ``ghidra_functions.json`` sırasıdır."""
    root.mkdir(parents=True)
    dec = root / "decompiled"
    dec.mkdir()
    (root / "ghidra_functions.json").write_text(json.dumps({"functions": [
        {"name": f["ad"], "address": f["adres"], "size": 64, "return_type": "undefined",
         "is_thunk": f["thunk"], "parameters": []} for f in fonklar]}), encoding="utf-8")
    dizgiler, k = [], 0
    for f in fonklar:
        for s in f["dizgiler"]:
            dizgiler.append({"address": f"0002{k:04x}", "value": s, "length": len(s),
                             "type": "string", "function": f["adres"]})
            k += 1
    (root / "ghidra_strings.json").write_text(json.dumps({"strings": dizgiler}), encoding="utf-8")
    adlar = {f["adres"]: f["ad"] for f in fonklar}
    (root / "ghidra_call_graph.json").write_text(json.dumps({
        "nodes": {a: {"name": n, "address": a} for a, n in adlar.items()},
        "edges": [{"from": s, "to": d, "from_name": adlar[s], "to_name": adlar[d]}
                  for s, d in kenarlar]}), encoding="utf-8")
    for f in fonklar:
        (dec / f"{f['ad']}.c").write_text(
            f"// Function: {f['ad']}\n// Address: {f['adres']}\n\n{f['govde']}", encoding="utf-8")
    return {"functions": root / "ghidra_functions.json", "strings": root / "ghidra_strings.json",
            "call_graph": root / "ghidra_call_graph.json", "decompiled": dec}


def _reddedilenler(prov, neden=None):
    return [k for k in prov["name_validity"]["rejected"] if neden is None or k["reason"] == neden]


# --------------------------------------------------------------------------------------------
# name_validity: listeler ve karar


def test_c11_anahtar_sozcukleri_tam_liste():
    # ISO/IEC 9899:2011 §6.4.1: 44 sözcük
    c11 = """auto break case char const continue default do double else enum extern float for
        goto if inline int long register restrict return short signed sizeof static struct switch
        typedef union unsigned void volatile while _Alignas _Alignof _Atomic _Bool _Complex
        _Generic _Imaginary _Noreturn _Static_assert _Thread_local""".split()
    assert len(c11) == 44 and nv.C11_KEYWORDS == frozenset(c11)
    assert nv.C11_KEYWORDS <= nv.C_KEYWORDS
    for ad in c11:
        assert nv.lexical_reject_reason(ad) == nv.REASON_KEYWORD, ad
        assert nv.lexical_reject_reason(ad, local=True) == nv.REASON_KEYWORD, ad
    # C23'ün ekledikleri ve gnu kipinin uzantısı da ad olamaz
    for ad in ("true", "false", "bool", "nullptr", "typeof", "static_assert", "asm"):
        assert nv.lexical_reject_reason(ad) == nv.REASON_KEYWORD, ad
    # anahtar sözcüğe benzeyen ama olmayan adlar serbest (büyük-küçük harf ayrımı dahil)
    for ad in ("Break", "breaker", "do_", "_int", "longer", "returns", "True", "asm_emit"):
        assert nv.lexical_reject_reason(ad) is None, ad


def test_tip_adlari_dosya_kapsaminda_ve_yerelde():
    ghidra = ["undefined"] + [f"undefined{n}" for n in range(1, 9)] + [
        "byte", "code", "uchar", "ushort", "uint", "ulong", "longlong", "uint3", "uint6", "int5"]
    std = ["uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int32_t", "int64_t", "size_t",
           "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t", "wchar_t", "uint_least16_t",
           "int_fast64_t", "uintmax_t"]
    for ad in ghidra + std:
        assert nv.lexical_reject_reason(ad) == nv.REASON_TYPE_NAME, ad
        assert nv.lexical_reject_reason(ad, local=True) == nv.REASON_TYPE_NAME, ad
    # types.h'nin kendi typedef'leri gövdede geçmez: dosya kapsamında yasak, yerelde serbest
    for ad in ("addr", "uaddr"):
        assert nv.lexical_reject_reason(ad) == nv.REASON_TYPE_NAME
        assert nv.lexical_reject_reason(ad, local=True) is None
    assert nv.BODY_TYPE_NAMES < nv.FILE_SCOPE_TYPE_NAMES
    assert nv.FILE_SCOPE_TYPE_NAMES - nv.BODY_TYPE_NAMES == nv.KARADUL_TYPEDEF_NAMES
    # taramada görülmeyen sözcükler ve tipe benzeyen adlar serbest
    for ad in ("word", "string", "undefined9", "undefined_2", "uint64", "size", "bytes", "codec"):
        assert nv.lexical_reject_reason(ad) is None, ad


def test_tanimlayici_bicimi():
    for ad in ("", "1abc", "a-b", "a b", "fopen$DARWIN_EXTSN", "é", "a.b", None, 7, b"abc"):
        assert nv.is_c_identifier(ad) is False
        assert nv.reject_reason(ad) == nv.REASON_NOT_IDENTIFIER
    for ad in ("a", "_", "_a1", "A_b_9", "__libc_start_main"):
        assert nv.is_c_identifier(ad) is True and nv.reject_reason(ad) is None


def test_neden_sirasi_ve_cakisma():
    var = nv.existing_function_names((ad, False) for ad in ("write", "uint64_t", "break", "kendi"))
    assert nv.REJECT_REASONS == (nv.REASON_NOT_IDENTIFIER, nv.REASON_KEYWORD, nv.REASON_TYPE_NAME,
                                 nv.REASON_COLLISION)
    assert (nv.REASON_KEYWORD, nv.REASON_TYPE_NAME, nv.REASON_COLLISION) == (
        "invalid_c_keyword", "invalid_type_name", "collides_with_existing_function")
    # ilk tutan neden kazanır: sözcük nedenleri çakışmadan önce
    assert nv.reject_reason("break", existing_functions=var) == nv.REASON_KEYWORD
    assert nv.reject_reason("uint64_t", existing_functions=var) == nv.REASON_TYPE_NAME
    assert nv.reject_reason("bool") == nv.REASON_KEYWORD           # hem C23 sözcüğü hem Ghidra tipi
    assert nv.reject_reason("write", existing_functions=var) == nv.REASON_COLLISION
    assert nv.reject_reason("write") is None                        # ikilide yoksa serbest
    assert nv.reject_reason("write_2", existing_functions=var) is None
    # fonksiyon kendi adıyla çakışmaz
    assert nv.reject_reason("kendi", existing_functions=var, own_name="kendi") is None
    assert nv.reject_reason("kendi", existing_functions=var, own_name="FUN_1") == nv.REASON_COLLISION
    # yerel ad fonksiyon adını gölgeleyebilir; sözcük nedenleri yerelde de geçerli
    assert nv.reject_reason("write", local=True, existing_functions=var) is None
    assert nv.reject_reason("break", local=True, existing_functions=var) == nv.REASON_KEYWORD


def test_ithal_adinin_alt_cizgisiz_hali():
    """Mach-O'da Ghidra ithal adını ``_gettimeofday`` diye verir; C'deki adı ``gettimeofday``."""
    assert nv.import_alias("_gettimeofday") == "gettimeofday"
    assert nv.import_alias("__assert_rtn") == "_assert_rtn"          # yalnız TEK alt çizgi soyulur
    assert nv.import_alias("write") is None and nv.import_alias("_") is None
    var = nv.existing_function_names([
        ("_gettimeofday", True), ("_usage", False), ("FUN_1", False), ("_exit", True),
        ("exit", False), ("", True), ("_", True), ("_gettimeofday", True)])
    # tam ad önce gelir: exit adının sahibi exit'tir, _exit değil; ithal olmayan ad soyulmaz
    assert var == {"_gettimeofday": "_gettimeofday", "_usage": "_usage", "FUN_1": "FUN_1",
                   "_exit": "_exit", "exit": "exit", "_": "_", "gettimeofday": "_gettimeofday"}
    assert nv.reject_reason("gettimeofday", existing_functions=var) == nv.REASON_COLLISION
    assert nv.reject_reason("usage", existing_functions=var) is None
    # ithal fonksiyonun kendisi _'siz adını alabilir: adın sahibi odur
    assert nv.reject_reason("gettimeofday", existing_functions=var, own_name="_gettimeofday") is None
    assert nv.reject_reason("exit", existing_functions=var, own_name="_exit") == nv.REASON_COLLISION
    assert nv.reject_reason("gettimeofday", local=True, existing_functions=var) is None
    assert nv.reject_reason("write", existing_functions={}) is None
    assert nv.reject_reason("write", existing_functions=None) is None


def test_unique_name_eki():
    assert nv.unique_name("ad", set()) == "ad"
    assert nv.unique_name("ad", {"baska"}, {"ad"}) == "ad"     # taban ada ret kuralı bakar, ek değil
    assert nv.unique_name("ad", {"ad"}) == "ad_2"
    assert nv.unique_name("ad", {"ad", "ad_2", "ad_3"}) == "ad_4"
    assert nv.unique_name("ad", {"ad"}, {"ad_2", "ad_3"}) == "ad_4"
    assert nv.unique_name("ad", {"ad", "ad_3"}, {"ad_2"}) == "ad_4"


def test_listeler_tek_yerde():
    """c_namer kendi listesini taşımaz: modülü içe aktarır ve nedenleri oradan alır."""
    assert c_namer._name_validity is nv
    kaynak = Path(c_namer.__file__).read_text(encoding="utf-8")
    for neden in nv.REJECT_REASONS:
        assert f'"{neden}"' not in kaynak, neden
    assert GECERSIZ in c_namer._ProvenanceRecorder.ELIMINATION_REASONS


# --------------------------------------------------------------------------------------------
# c_namer: aday süzgeci (uçtan uca)


def test_anahtar_sozcuk_adi_verilmez(tmp_path, seri):
    """rapor.md bulgu 8: ``"break"`` dizgisi → ``void break(…)``. Artık fonksiyon FUN_ kalır."""
    ws = _calisma_alani(tmp_path / "ws", [_fonk("FUN_00001000", "00001000", ["break"])])
    res, prov, harita = S._kos(ws, tmp_path / "out")
    assert harita["global"] == {}
    assert res.rejected_name_counts == {nv.REASON_KEYWORD: 1}
    assert "string_context" not in res.by_strategy
    (kayit,) = _reddedilenler(prov)
    assert kayit == {"key": "FUN_00001000", "scope": "global", "source": "candidate",
                     "reason": nv.REASON_KEYWORD, "proposed_name": "break",
                     "strategy": "string_context", "confidence": 0.75, "evidence": "break",
                     "code_path": "classic", "rule": "keywords", "evidence_origin": "string_ref"}
    assert prov["name_validity"]["rejected_counts"] == {
        "candidate": {nv.REASON_KEYWORD: 1}, "pre_names": {}}
    assert prov["name_validity"]["definition_version"] == nv.DEFINITION_VERSION
    assert prov["eliminated_keys"][GECERSIZ] == {"global": {"string_context": 1}}
    assert S._hesap_tutar(prov)
    # çıktı dosyası girdiyle aynı: ad değişmedi
    girdi = (ws["decompiled"] / "FUN_00001000.c").read_bytes()
    assert (tmp_path / "out" / "FUN_00001000.c").read_bytes() == girdi


def test_tip_adi_verilmez(tmp_path, seri):
    """rapor.md bulgu 9: openssl'de ``"<undefined>"`` dizgisinden ``undefined`` adlı fonksiyon."""
    ws = _calisma_alani(tmp_path / "ws", [
        _fonk("FUN_00001000", "00001000", ["<undefined>"]),
        _fonk("FUN_00002000", "00002000", ["<undefined>"]),
        _fonk("FUN_00003000", "00003000", ["uint64_t"]),       # klasik yol: "uint"
        _fonk("FUN_00004000", "00004000", ["byte"]),
    ])
    res, prov, harita = S._kos(ws, tmp_path / "out")
    assert harita["global"] == {}                               # undefined_2 de yok
    assert res.rejected_name_counts == {nv.REASON_TYPE_NAME: 4}
    assert sorted(k["proposed_name"] for k in _reddedilenler(prov, nv.REASON_TYPE_NAME)) == [
        "byte", "uint", "undefined", "undefined"]
    assert prov["eliminated_keys"][GECERSIZ] == {"global": {"string_context": 4}}
    assert S._hesap_tutar(prov)


def test_var_olan_fonksiyon_adi_verilmez(tmp_path, seri):
    """rapor.md bulgu 8: ``"write error"`` → ikinci bir ``write``. İthal adı tek kalır."""
    ws = _calisma_alani(tmp_path / "ws", [
        _fonk("write", "00000100", thunk=True),
        _fonk("FUN_00001000", "00001000", ["write error"]),
        _fonk("FUN_00002000", "00002000", ["sampler_reset"]),
    ])
    res, prov, harita = S._kos(ws, tmp_path / "out")
    assert harita["global"] == {"FUN_00002000": "sampler_reset"}
    assert res.rejected_name_counts == {nv.REASON_COLLISION: 1}
    (kayit,) = _reddedilenler(prov)
    assert kayit["key"] == "FUN_00001000" and kayit["proposed_name"] == "write"
    assert kayit["reason"] == nv.REASON_COLLISION and kayit["existing_address"] == "00000100"
    assert "existing_name" not in kayit                          # sahibin adı reddedilen adla aynı
    assert kayit["evidence"] == "write error" and kayit["source"] == "candidate"
    assert S._hesap_tutar(prov)
    # çıktıda "write" adını taşıyan tek tanım ithal fonksiyon
    tanimlar = [p.name for p in (tmp_path / "out").glob("*.c") if "void write(void)" in p.read_text()]
    assert tanimlar == ["write.c"]


def test_ithal_adinin_alt_cizgisiz_hali_verilmez(tmp_path, seri):
    """Mac tmux'ta ``_gettimeofday`` ithal edilirken bir FUN_ ``gettimeofday`` adını alıyordu."""
    ws = _calisma_alani(tmp_path / "ws", [
        _fonk("_gettimeofday", "00000100", thunk=True),
        _fonk("_usage", "00000200"),                               # ithal değil: soyulmaz
        _fonk("FUN_00001000", "00001000", ["gettimeofday"]),
        _fonk("FUN_00002000", "00002000", ["usage"]),
    ])
    res, prov, harita = S._kos(ws, tmp_path / "out")
    assert harita["global"] == {"FUN_00002000": "usage"}
    assert res.rejected_name_counts == {nv.REASON_COLLISION: 1}
    (kayit,) = _reddedilenler(prov)
    assert (kayit["key"], kayit["proposed_name"], kayit["reason"]) == (
        "FUN_00001000", "gettimeofday", nv.REASON_COLLISION)
    assert kayit["existing_name"] == "_gettimeofday" and kayit["existing_address"] == "00000100"
    assert S._hesap_tutar(prov)


def test_reddedilen_adayin_yerine_siradaki_gecerli_aday(tmp_path, seri):
    """En iyi aday geçersizse anahtar ad almadan düşmez: sıradaki geçerli aday yarışır."""
    def kur(kok, dizgi):
        return _calisma_alani(kok, [
            _fonk("FUN_00005000", "00005000",
                  govde="void FUN_00005000(void)\n{\n  atexit(FUN_0000c000);\n  return;\n}\n"),
            _fonk("FUN_0000c000", "0000c000", [dizgi]),
        ], kenarlar=[("00005000", "0000c000")])

    # önkoşul: aynı biçimde geçerli bir dizgi adı (0,80) geri çağrı adını (0,75) yener
    _, taban_prov, taban = S._kos(kur(tmp_path / "taban", "sampler() failed: %s"), tmp_path / "t_out")
    assert taban["global"]["FUN_0000c000"] == "sampler"
    assert taban_prov["global"]["FUN_0000c000"]["runners_up"][0]["new_name"] == "exit_handler"
    assert taban_prov["name_validity"]["rejected"] == []

    res, prov, harita = S._kos(kur(tmp_path / "ws", "switch() failed: %s"), tmp_path / "out")
    assert harita["global"]["FUN_0000c000"] == "exit_handler"
    assert res.rejected_name_counts == {nv.REASON_KEYWORD: 1}
    kazanan = prov["global"]["FUN_0000c000"]
    assert kazanan["strategy"] != "string_context" and kazanan["confidence"] == 0.75
    assert all(r["new_name"] != "switch" for r in kazanan["runners_up"])
    (kayit,) = _reddedilenler(prov)
    assert (kayit["proposed_name"], kayit["confidence"], kayit["rule"]) == ("switch", 0.8, "func_paren")
    assert prov["eliminated_keys"][GECERSIZ] == {}              # anahtar ad aldı, elenmedi
    assert S._hesap_tutar(prov)
    assert "void exit_handler(void)" in (tmp_path / "out" / "FUN_0000c000.c").read_text()
    assert "atexit(exit_handler)" in (tmp_path / "out" / "FUN_00005000.c").read_text()


def test_ayni_adi_isteyen_iki_fonksiyon(tmp_path, seri):
    """Belgelenen kural: ``ghidra_functions.json`` sırasında ilk gelen eksiz, sonraki ``_2``;
    ek var olan fonksiyon adını atlar. Sıra değişince adlar da yer değiştirir (belirlenimli)."""
    a = _fonk("FUN_00001000", "00001000", ["sampler_reset"])
    b = _fonk("FUN_00002000", "00002000", ["sampler_reset"])
    c = _fonk("FUN_00003000", "00003000", ["sampler_reset"])
    _, prov, harita = S._kos(_calisma_alani(tmp_path / "duz", [a, b, c]), tmp_path / "o1")
    assert harita["global"] == {"FUN_00001000": "sampler_reset", "FUN_00002000": "sampler_reset_2",
                                "FUN_00003000": "sampler_reset_3"}
    assert prov["global"]["FUN_00002000"]["proposed_name"] == "sampler_reset"
    assert prov["name_validity"]["rejected"] == []
    _, _, ters = S._kos(_calisma_alani(tmp_path / "ters", [c, b, a]), tmp_path / "o2")
    assert ters["global"] == {"FUN_00003000": "sampler_reset", "FUN_00002000": "sampler_reset_2",
                              "FUN_00001000": "sampler_reset_3"}
    # ikilide zaten sampler_reset_2 adlı bir fonksiyon var: ek onu atlar
    dolu = _fonk("sampler_reset_2", "00000100")
    res, prov3, atlayan = S._kos(_calisma_alani(tmp_path / "dolu", [dolu, a, b, c]), tmp_path / "o3")
    assert atlayan["global"] == {"FUN_00001000": "sampler_reset", "FUN_00002000": "sampler_reset_3",
                                 "FUN_00003000": "sampler_reset_4"}
    assert res.rejected_name_counts == {} and S._hesap_tutar(prov3)
    assert sorted(atlayan["global"].values()) == sorted(set(atlayan["global"].values()))


def test_dis_fonksiyon_da_ithaldir(tmp_path, seri):
    """İthal: Ghidra'nın ``is_thunk`` ya da ``is_external`` dediği fonksiyon."""
    ws = _calisma_alani(tmp_path / "ws", [
        _fonk("_socketpair", "00000100"),
        _fonk("FUN_00001000", "00001000", ["socketpair"]),
    ])
    veri = json.loads(ws["functions"].read_text(encoding="utf-8"))
    veri["functions"][0]["is_external"] = True
    ws["functions"].write_text(json.dumps(veri), encoding="utf-8")
    res, prov, harita = S._kos(ws, tmp_path / "out")
    assert harita["global"] == {} and res.rejected_name_counts == {nv.REASON_COLLISION: 1}
    assert _reddedilenler(prov)[0]["existing_name"] == "_socketpair"


def test_yerel_adin_eki_fonksiyon_adina_bakmaz(tmp_path, seri):
    """Yerel adlar var olan fonksiyon adlarına karşı sınanmaz; ek alırken de atlamaz."""
    def govde(ad):
        return (f"int {ad}(char *param_1)\n{{\n  int local_8;\n"
                "  local_8 = strlen(param_1);\n  return local_8;\n}\n")

    fonklar = [_fonk("len_2", "00000100"), _fonk("len", "00000200"),
               _fonk("FUN_00001000", "00001000", govde=govde("FUN_00001000")),
               _fonk("FUN_00002000", "00002000", govde=govde("FUN_00002000"))]
    res, prov, harita = S._kos(_calisma_alani(tmp_path / "ws", fonklar), tmp_path / "out")
    assert harita["per_function"]["FUN_00001000"]["local_8"] == "len"
    assert harita["per_function"]["FUN_00002000"]["local_8"] == "len_2"
    assert res.rejected_name_counts == {} and S._hesap_tutar(prov)


def test_suzgec_dogrudan_kapsam_ve_sira():
    """Süzgeç doğrudan: kapsam kuralları, liste sırası, sayaç ve "tam bir kez" sayımı."""
    def aday(eski, ad, guven, strateji="dataflow"):
        return c_namer._NamingCandidate(eski, ad, guven, strateji)

    namer = CVariableNamer(Config())
    namer._func_by_name = {"write": c_namer._FunctionInfo("write", "00000100"),
                           "_ZN3Foo3barEv": c_namer._FunctionInfo("_ZN3Foo3barEv", "00000200"),
                           "foo_bar": c_namer._FunctionInfo("foo_bar", "00000300"),
                           # tip adını taşıyan bir fonksiyon: neden yine tip adıdır, çakışma değil
                           "byte": c_namer._FunctionInfo("byte", "00000400")}
    var = namer._existing_function_names()
    assert var == {ad: ad for ad in namer._func_by_name}
    g1, g2, g3 = aday("FUN_1", "write", 0.9), aday("FUN_1", "copy_1", 0.5), aday("FUN_1", "int", 0.4)
    y_kw, y_tip, y_addr, y_fn = (aday("param_1", "for", 0.6), aday("param_1", "byte", 0.5),
                                 aday("param_1", "addr", 0.4), aday("param_1", "write", 0.3))
    v_addr = aday("DAT_9", "addr", 0.3)
    kendi = aday("_ZN3Foo3barEv", "foo_bar", 0.95, "symbol")
    ozdes = aday("write", "write", 0.95, "symbol")
    kotu = aday("local_8", "2fast", 0.5)
    namer._candidates = {
        "FUN_1": [g1, g2, g3], "FUN_2::param_1": [y_kw, y_tip, y_addr, y_fn], "DAT_9": [v_addr],
        "_ZN3Foo3barEv::_ZN3Foo3barEv": [kendi], "write::write": [ozdes],
        "FUN_3::local_8": [kotu], "FUN_bos": [],
    }
    kaydedici = c_namer._ProvenanceRecorder(0.15)
    atilan = namer._reject_invalid_names(var, kaydedici)
    assert atilan == {nv.REASON_COLLISION: 2, nv.REASON_KEYWORD: 2, nv.REASON_TYPE_NAME: 2,
                      nv.REASON_NOT_IDENTIFIER: 1}
    assert namer._candidates["FUN_1"] == [g2]                         # sıra korunur
    assert namer._candidates["FUN_2::param_1"] == [y_addr, y_fn]      # yerelde addr ve write serbest
    assert namer._candidates["DAT_9"] == []                           # genel veri: addr typedef'i
    assert namer._candidates["_ZN3Foo3barEv::_ZN3Foo3barEv"] == []    # kendi adını değiştiren: ikili kapsam
    assert namer._candidates["write::write"] == [ozdes]               # kendi adıyla çakışmaz
    assert namer._candidates["FUN_3::local_8"] == [] and namer._candidates["FUN_bos"] == []
    # bütün adayları atılan her anahtar bir kez, en yüksek güvenli adayının stratejisiyle
    assert kaydedici.eliminated_keys[GECERSIZ] == {"global": {"dataflow": 1},
                                                    "local": {"symbol": 1, "dataflow": 1}}
    kayitlar = kaydedici.name_validity["rejected"]
    assert [(k["key"], k["proposed_name"], k["reason"]) for k in kayitlar] == [
        ("DAT_9", "addr", nv.REASON_TYPE_NAME),
        ("FUN_1", "write", nv.REASON_COLLISION), ("FUN_1", "int", nv.REASON_KEYWORD),
        ("FUN_2::param_1", "for", nv.REASON_KEYWORD), ("FUN_2::param_1", "byte", nv.REASON_TYPE_NAME),
        ("FUN_3::local_8", "2fast", nv.REASON_NOT_IDENTIFIER),
        ("_ZN3Foo3barEv::_ZN3Foo3barEv", "foo_bar", nv.REASON_COLLISION)]
    assert kayitlar[1]["existing_address"] == "00000100" and "existing_address" not in kayitlar[2]
    # adres yalnız çakışma nedeninde yazılır (byte adlı fonksiyon var ama neden tip adı)
    assert kayitlar[4]["reason"] == nv.REASON_TYPE_NAME and "existing_address" not in kayitlar[4]
    assert kayitlar[6]["existing_address"] == "00000300"
    assert kayitlar[3]["scope"] == "local" and kayitlar[1]["scope"] == "global"
    assert kaydedici.name_validity["rejected_counts"]["candidate"] == atilan
    assert not kaydedici.failed
    # geçerli adaylarla ikinci geçiş hiçbir şeyi değiştirmez ve köken kaydı olmadan da çalışır
    onceki = {k: list(v) for k, v in namer._candidates.items()}
    assert namer._reject_invalid_names(var, None) == {} and namer._candidates == onceki
    assert CVariableNamer._is_local_name_key("FUN_2::param_1") is True
    assert CVariableNamer._is_local_name_key("FUN_1") is False
    assert CVariableNamer._is_local_name_key("ad::ad") is False


def test_susan_aday_yeniden_sayilmaz(tmp_path, seri):
    """Susturma önce çalışır: susan ``"break"`` adayı geçersiz ad diye ikinci kez sayılmaz."""
    ws = _calisma_alani(tmp_path / "ws", [_fonk("FUN_00001000", "00001000", ["break"])])
    res, prov, harita = S._kos(ws, tmp_path / "out", silenced_subchannels=alt_kanal.SILENCED_SUBCHANNELS)
    assert harita["global"] == {} and res.rejected_name_counts == {}
    assert res.silenced_counts == {"tek_sozcuk": 1}
    assert prov["eliminated_keys"]["all_candidates_silenced"] == {"global": {"string_context": 1}}
    assert prov["eliminated_keys"][GECERSIZ] == {} and prov["name_validity"]["rejected"] == []
    assert S._hesap_tutar(prov)


def test_koken_kaydi_kapaliyken_de_ayni_karar(tmp_path, seri):
    ws = _calisma_alani(tmp_path / "ws", [
        _fonk("write", "00000100", thunk=True),
        _fonk("FUN_00001000", "00001000", ["write error"]),
        _fonk("FUN_00002000", "00002000", ["break"]),
        _fonk("FUN_00003000", "00003000", ["sampler_reset"]),
    ])
    acik, _, harita = S._kos(ws, tmp_path / "acik")
    namer = CVariableNamer(Config(), min_confidence=0.15, record_provenance=False)
    kapali = namer.analyze_and_rename(ws["decompiled"], ws["functions"], ws["strings"],
                                      ws["call_graph"], tmp_path / "kapali")
    assert not (tmp_path / "kapali" / c_namer.NAMING_PROVENANCE_FILE).exists()
    assert kapali.naming_map == acik.naming_map == harita["global"] == {"FUN_00003000": "sampler_reset"}
    assert kapali.rejected_name_counts == acik.rejected_name_counts == {
        nv.REASON_COLLISION: 1, nv.REASON_KEYWORD: 1}
    assert list(acik.rejected_name_counts) == sorted(acik.rejected_name_counts)
    assert S._ozet(tmp_path / "kapali") == S._ozet(tmp_path / "acik")


# --------------------------------------------------------------------------------------------
# Ön adlar


def _on_ad_alani(kok):
    return _calisma_alani(kok, [
        _fonk("write", "00000100", thunk=True),
        _fonk("FUN_00001000", "00001000", ["sampler_reset"]),
        _fonk("FUN_00002000", "00002000"),
        _fonk("FUN_00003000", "00003000"),
        _fonk("FUN_00004000", "00004000"),
        _fonk("FUN_00005000", "00005000"),
    ])


def test_on_ad_ayni_kurallardan_gecer(tmp_path, seri):
    on = {"FUN_00001000": "break", "FUN_00002000": "uint64_t", "FUN_00003000": "write",
          "FUN_00004000": "123abc", "FUN_00005000": "gecerli_ad"}
    res, prov, harita = S._kos(_on_ad_alani(tmp_path / "ws"), tmp_path / "out", pre_names=on)
    # reddedilen ön adın anahtarı aday listesine kalır: FUN_00001000 dizgi adını alır
    assert harita["global"] == {"FUN_00001000": "sampler_reset", "FUN_00005000": "gecerli_ad"}
    assert res.strategy_map == {"FUN_00001000": "string_context", "FUN_00005000": "binary_extract"}
    assert res.rejected_name_counts == {
        nv.REASON_COLLISION: 1, nv.REASON_NOT_IDENTIFIER: 1, nv.REASON_KEYWORD: 1,
        nv.REASON_TYPE_NAME: 1}
    assert prov["name_validity"]["rejected_counts"] == {
        "candidate": {}, "pre_names": res.rejected_name_counts}
    kayitlar = {k["key"]: k for k in _reddedilenler(prov)}
    assert kayitlar["FUN_00001000"] == {
        "key": "FUN_00001000", "scope": "global", "source": "pre_names",
        "reason": nv.REASON_KEYWORD, "proposed_name": "break", "strategy": "binary_extract"}
    assert kayitlar["FUN_00002000"]["reason"] == nv.REASON_TYPE_NAME
    assert kayitlar["FUN_00003000"]["reason"] == nv.REASON_COLLISION
    assert kayitlar["FUN_00003000"]["existing_address"] == "00000100"
    assert kayitlar["FUN_00004000"]["reason"] == nv.REASON_NOT_IDENTIFIER
    assert kayitlar["FUN_00004000"]["proposed_name"] == "123abc"
    s = prov["summary"]
    assert (s["pre_names_given"], s["pre_names_applied"], s["pre_names_dropped_duplicate"]) == (5, 1, 0)
    assert prov["global"]["FUN_00001000"]["source"] == "candidate"
    assert S._hesap_tutar(prov)


def test_kunyeli_on_ad_da_reddedilir(tmp_path, seri):
    """Elle verilen ve KS-1 adı tam yazılır ama geçersiz adı tam yazmak da geçersizdir."""
    on = {"FUN_00001000": "continue", "FUN_00002000": "size_t", "FUN_00003000": "write",
          "FUN_00004000": "Elle_Verilen", "FUN_00005000": "Vector_add"}
    meta = {"FUN_00001000": {"kind": baglama.KIND_MANUAL, "name": "continue", "exact": True},
            "FUN_00002000": S._ks1_kunye("size_t"),
            "FUN_00003000": {"kind": baglama.KIND_MANUAL, "name": "write", "exact": True},
            "FUN_00004000": {"kind": baglama.KIND_MANUAL, "name": "Elle_Verilen", "exact": True},
            "FUN_00005000": S._ks1_kunye("Vector_add")}
    res, prov, harita = S._kos(_on_ad_alani(tmp_path / "ws"), tmp_path / "out", pre_names=on, meta=meta)
    assert harita["global"] == {"FUN_00001000": "sampler_reset", "FUN_00004000": "Elle_Verilen",
                                "FUN_00005000": "Vector_add"}
    assert res.label_map == {"FUN_00001000": "doğrulanmadı", "FUN_00005000": "kesin"}
    assert res.rejected_name_counts == {nv.REASON_COLLISION: 1, nv.REASON_KEYWORD: 1,
                                        nv.REASON_TYPE_NAME: 1}
    kayitlar = {k["key"]: k for k in _reddedilenler(prov)}
    assert (kayitlar["FUN_00001000"]["pre_name_kind"], kayitlar["FUN_00001000"]["strategy"]) == (
        "elle", "binary_extract")
    assert (kayitlar["FUN_00002000"]["pre_name_kind"], kayitlar["FUN_00002000"]["strategy"]) == (
        "ks1", "ks1")
    assert kayitlar["FUN_00003000"]["reason"] == nv.REASON_COLLISION
    assert "ks1" not in res.by_strategy or res.by_strategy["ks1"] == 1
    assert prov["summary"]["pre_names_applied"] == 2 and S._hesap_tutar(prov)


def test_on_ad_ozdes_esleme_ve_ham_ad(tmp_path, seri):
    """Fonksiyon kendi adıyla çakışmaz; temizlenince geçersizleşen ön adın ham hâli kayda geçer."""
    on = {"write": "write", "FUN_00002000": "__uint64_t__", "FUN_00003000": "Int"}
    res, prov, harita = S._kos(_on_ad_alani(tmp_path / "ws"), tmp_path / "out", pre_names=on)
    assert harita["global"]["write"] == "write"
    assert "FUN_00002000" not in harita["global"] and "FUN_00003000" not in harita["global"]
    assert res.rejected_name_counts == {nv.REASON_KEYWORD: 1, nv.REASON_TYPE_NAME: 1}
    kayitlar = {k["key"]: k for k in _reddedilenler(prov)}
    assert kayitlar["FUN_00002000"]["proposed_name"] == "uint64_t"
    assert kayitlar["FUN_00002000"]["raw_name"] == "__uint64_t__"
    assert kayitlar["FUN_00003000"]["proposed_name"] == "int" and kayitlar["FUN_00003000"]["raw_name"] == "Int"


def test_on_ad_anahtari_ayni_fonksiyonu_gosteriyorsa_cakisma_degil(tmp_path, seri):
    """htop: ön ad anahtarı adresten kurulmuş (``FUN_001322e4``), o adresteki fonksiyonun Ghidra
    adı zaten ``full_write``. Ad fonksiyonun kendi adıdır; eskisi gibi haritaya girer."""
    ws = _calisma_alani(tmp_path / "ws", [
        _fonk("full_write", "001322e4"),
        _fonk("FUN_00002000", "00002000"),
        _fonk("FUN_00003000", "00003000"),
    ])
    on = {"FUN_001322E4": "full_write", "FUN_00002000": "full_write", "FUN_0000beef": "full_write"}
    res, prov, harita = S._kos(ws, tmp_path / "out", pre_names=on)
    assert harita["global"] == {"FUN_001322E4": "full_write"}          # büyük-küçük harf: aynı adres
    assert res.rejected_name_counts == {nv.REASON_COLLISION: 2}
    kayitlar = {k["key"]: k for k in _reddedilenler(prov)}
    # başka bir fonksiyon ve hiçbir fonksiyonu göstermeyen anahtar: ad full_write'ın, reddedilir
    assert set(kayitlar) == {"FUN_00002000", "FUN_0000beef"}
    assert kayitlar["FUN_00002000"]["existing_address"] == "001322e4"
    namer = CVariableNamer(Config())
    namer._functions = {"001322e4": c_namer._FunctionInfo("full_write", "001322e4"),
                        "bozuk": c_namer._FunctionInfo("x", "bozuk")}
    namer._func_by_name = {"full_write": namer._functions["001322e4"]}
    adresler = namer._function_names_by_address()
    assert adresler == {0x1322E4: "full_write"}
    assert namer._own_function_name("FUN_001322e4", adresler) == "full_write"
    assert namer._own_function_name("FUN_00002000", adresler) == "FUN_00002000"
    assert namer._own_function_name("DAT_001322e4", adresler) == "DAT_001322e4"
    assert namer._own_function_name("full_write", adresler) == "full_write"


def test_on_adlar_arasi_cakisma_kurali_degismedi(tmp_path, seri):
    """Belgelenen kural: aynı adı isteyen iki ön addan ilki alır, ikincisi ad almaz (ek yok) ve
    bu düşme ad geçerliliği reddi sayılmaz."""
    on = {"FUN_00002000": "ortak_ad", "FUN_00003000": "ortak_ad"}
    res, prov, harita = S._kos(_on_ad_alani(tmp_path / "ws"), tmp_path / "out", pre_names=on)
    assert harita["global"]["FUN_00002000"] == "ortak_ad" and "FUN_00003000" not in harita["global"]
    assert prov["summary"]["pre_names_dropped_duplicate"] == 1
    assert res.rejected_name_counts == {} and prov["name_validity"]["rejected"] == []


# --------------------------------------------------------------------------------------------
# Süzgecin dokunmadığı adlar değişmez


def test_gecersiz_ad_yoksa_cikti_bayt_bayt_ayni(tmp_path, seri):
    ws = T.build_workspace(tmp_path / "ws")
    res, prov, _ = S._kos(ws, tmp_path / "out")
    assert S._ozet(tmp_path / "out") == S.ONCEKI_CIKTI_OZETI
    assert res.rejected_name_counts == {}
    assert prov["name_validity"] == {
        "definition_version": nv.DEFINITION_VERSION,
        "rejected_counts": {"candidate": {}, "pre_names": {}}, "rejected": []}
    assert prov["eliminated_keys"][GECERSIZ] == {}
    assert S._hesap_tutar(prov)


def test_gecersiz_ad_varken_obur_adlar_ve_dosyalar_ayni(tmp_path, seri, monkeypatch):
    """Belirlenimcilik fikstürüne geçersiz adlı üç fonksiyon eklenir: fikstürün kendi adları ve
    ``.c`` dosyaları bayt bayt aynı kalır; eklenenler ad almaz."""
    ws = T.build_workspace(tmp_path / "ws")
    _, _, taban = S._kos(ws, tmp_path / "taban")
    # dönüş tipi "undefined": tip stratejisi aday üretmez, dizgi adayı tek adaydır
    ek = [("FUN_000f1000", "000f1000", "undefined", "break"),
          ("FUN_000f2000", "000f2000", "undefined", "<undefined>"),
          ("FUN_000f3000", "000f3000", "undefined", "lib_alpha() failed")]
    monkeypatch.setattr(T, "_FUNCS", T._FUNCS + [(n, a, [], r, s) for n, a, r, s in ek])
    monkeypatch.setattr(T, "_BODIES", {**T._BODIES, **{
        n: f"void {n}(void)\n{{\n  return;\n}}\n" for n, *_ in ek}})
    genis = T.build_workspace(tmp_path / "genis")
    res, prov, harita = S._kos(genis, tmp_path / "out")
    # lib_alpha fikstürde çağrılan bir addır ama ghidra_functions.json'da fonksiyon değildir:
    # çakışma yalnız var olan FONKSİYON adına bakar
    assert harita["global"] == {**taban["global"], "FUN_000f3000": "lib_alpha"}
    assert harita["per_function"] == taban["per_function"]
    assert res.rejected_name_counts == {nv.REASON_KEYWORD: 1, nv.REASON_TYPE_NAME: 1}
    for p in sorted((tmp_path / "taban").glob("*.c")):
        assert (tmp_path / "out" / p.name).read_bytes() == p.read_bytes(), p.name
    for n, *_ in ek[:2]:
        assert (tmp_path / "out" / f"{n}.c").read_bytes() == (genis["decompiled"] / f"{n}.c").read_bytes()
    assert S._hesap_tutar(prov)
