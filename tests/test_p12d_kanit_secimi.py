"""P12d: klasik dizgi aşamasında kanıt seçimi, aynı adı aynı puanla veren dizgiler arasında.

Kusur (birleşik 119 ölçümü, ``docs/arge/2026-11-18_onarim/P12d.md``): GHIDRA-16'dan sonra
fonksiyonun dizgi bağları dizgi adresi sırasıyla yükleniyor. ``__assert_fail(ifade, dosya, satır,
"cycle_check")`` çağrısında ``"lib/cycle-check.c"`` ile ``"cycle_check"`` aynı anahtar sözcükleri
(dolayısıyla aynı adı ve aynı puanı) verir; eşitlikte ilk görülen kanıt olur. Kanıt dosya yolu
olunca aday ``diger`` alt kanalına düşüp susar, ad kaybolur; oysa aynı adı öz-ad dizgisi de
veriyor. Onarım: susturma açıkken, AYNI puanı ve AYNI adı veren dizgiler arasında susmayan alt
kanala düşen kanıt seçilir. Farklı ad veren dizgiye geçilmez; susturma kapalıyken davranış aynı.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.reconstruction.c_namer import CVariableNamer
from karadul.reconstruction.tarif import alt_kanal

DZ_SUSAN = alt_kanal.SILENCED_SUBCHANNELS

DZ_YOL = "lib/cycle-check.c"          # anahtar sözcük: cycle, check → ad cycle_check (diger)
DZ_OZ_AD = "cycle_check"              # aynı ad, aynı puan (oz_ad: kalan alt kanal)
DZ_IFADE = "state->magic == 9827862"  # state, magic → aynı puan, FARKLI ad (diger)
DZ_KEBAP = "cycle-check"              # aynı ad, aynı puan, ama kebap_ad (susar)


def _adaylar(strings: list[str], *, susan=DZ_SUSAN, govde: str = "") -> list:
    """Gerçek _strategy_string_context; dizgiler fonksiyonun dizgi bağları (string_ref)."""
    namer = CVariableNamer(Config(), min_confidence=0.15, silenced_subchannels=susan)
    namer._string_refs_by_func["0x1000"] = list(strings)
    namer._func_bodies["FUN_00001000"] = govde
    namer._strategy_string_context(
        SimpleNamespace(name="FUN_00001000", address="0x1000", params=[]))
    return [c for c in namer._candidates.get("FUN_00001000", []) if c.code_path == "classic"]


def _alt(c) -> str:
    return CVariableNamer._string_sub_channel(c)


# --- birim: kanıt seçimi -------------------------------------------------------------------


def test_ayni_ad_ayni_puan_susmayan_kanit_secilir():
    """Dosya yolu önde, öz-ad dizgisi arkada: ad aynı, kanıt öz-ad dizgisi (oz_ad, kalır)."""
    (c,) = _adaylar([DZ_YOL, DZ_IFADE, DZ_OZ_AD])
    assert c.new_name == "cycle_check"
    assert c.evidence == DZ_OZ_AD
    assert c.evidence_origin == "string_ref"
    assert _alt(c) == alt_kanal.SUB_OWN_NAME and _alt(c) not in DZ_SUSAN
    assert c.confidence == pytest.approx(0.8)


def test_susturma_kapaliyken_ilk_gorulen_kalir():
    """Susturma yoksa seçim eskisi gibi: eşitlikte ilk görülen dizgi."""
    (c,) = _adaylar([DZ_YOL, DZ_IFADE, DZ_OZ_AD], susan=frozenset())
    assert c.new_name == "cycle_check"
    assert c.evidence == DZ_YOL


def test_farkli_ad_veren_dizgiye_gecilmez():
    """Aynı puanlı öz-ad dizgisi FARKLI ad veriyorsa seçim değişmez (aday susar)."""
    (c,) = _adaylar([DZ_IFADE, DZ_OZ_AD])
    assert c.new_name == "state_magic"
    assert c.evidence == DZ_IFADE
    assert _alt(c) in DZ_SUSAN


def test_farkli_ad_kurali_susturma_kumesinden_bagimsiz():
    """`tanimlayici` da kalan alt kanal olsa bile farklı ad veren dizgiye geçilmez.

    Bugünkü kararda yalnız `oz_ad` kalır ve öz-ad yüklemi adı kanıta bağladığı için "aynı ad"
    şartı oradan da çıkar; bu test şartı karar tablosundan bağımsız kilitler.
    """
    susan = DZ_SUSAN - {alt_kanal.SUB_IDENTIFIER}
    (c,) = _adaylar([DZ_IFADE, DZ_OZ_AD], susan=susan)
    assert c.new_name == "state_magic"
    assert c.evidence == DZ_IFADE


def test_dusuk_puanli_ayni_ad_secilmez():
    """Aynı adı veren ama puanı düşük dizgiye geçilmez (yalnız eşit puan)."""
    uzun = "lib/foo-bar-baz-quux.c"   # foo, bar, baz, quux → ad foo_bar_baz, puan 13
    (c,) = _adaylar([uzun, "foo_bar_baz"])  # öz-ad dizgisi puan 9
    assert c.new_name == "foo_bar_baz"
    assert c.evidence == uzun
    assert _alt(c) in DZ_SUSAN


def test_esdeger_aday_da_susuyorsa_ilk_kalir():
    """Aynı adı aynı puanla veren öbür dizgi de susuyorsa (kebap) kanıt değişmez."""
    (c,) = _adaylar([DZ_YOL, DZ_KEBAP])
    assert c.evidence == DZ_YOL
    assert _alt(c) in DZ_SUSAN


def test_ilk_kanit_zaten_kaliyorsa_degismez():
    """Öndeki dizgi zaten kalan alt kanaldaysa aynı adlı sonraki dizgiye geçilmez."""
    (c,) = _adaylar([DZ_OZ_AD, " cycle_check ", DZ_YOL])
    assert c.evidence == DZ_OZ_AD


# --- ad çıkar / ad yok (susturma sonrası, P12d paket metni §5) ----------------------------


def _susturma_sonrasi(strings: list[str], govde: str = "") -> list:
    namer = CVariableNamer(Config(), min_confidence=0.15, silenced_subchannels=DZ_SUSAN)
    namer._string_refs_by_func["0x1000"] = list(strings)
    namer._func_bodies["FUN_00001000"] = govde
    namer._strategy_string_context(
        SimpleNamespace(name="FUN_00001000", address="0x1000", params=[]))
    namer._silence_candidates(DZ_SUSAN, None)
    return namer._candidates.get("FUN_00001000", [])


def test_agresif_ve_klasik_aday_klasik_ad_cikar():
    """Agresif aday (assert_expr 0,45; susar) + klasik aday → klasik öz-ad kalır."""
    kalan = _susturma_sonrasi([DZ_YOL, "count > 0", DZ_OZ_AD])
    assert [(c.new_name, c.code_path, c.evidence) for c in kalan] == [
        ("cycle_check", "classic", DZ_OZ_AD)]


def test_yalniz_susan_adaylar_ad_yok():
    """Yalnız agresif ve susan klasik aday → ad yok."""
    assert _susturma_sonrasi(["frame_len > 0"]) == []
    assert _susturma_sonrasi([DZ_YOL]) == []


def test_hic_dizgi_yok_ad_yok():
    assert _susturma_sonrasi([]) == []


# --- uçtan uca: gerçek süreç havuzu (susan küme işçiye taşınmalı) -------------------------


def _calisma_alani(kok: Path) -> dict[str, Path]:
    """GHIDRA-16 biçimi: dizgilerin ``xrefs``'i fonksiyona bağlı, dizgi adresi sırasıyla."""
    static = kok / "static"
    dec = static / "decompiled"
    dec.mkdir(parents=True)
    fonks = [("FUN_00001000", "00001000"), ("FUN_00002000", "00002000"),
             ("FUN_00003000", "00003000")]
    dizgiler = [
        ("00010000", DZ_YOL, "00001000"),
        ("00010100", DZ_IFADE, "00001000"),
        ("00010200", DZ_OZ_AD, "00001000"),
        ("00010300", DZ_IFADE + " ", "00002000"),
        ("00010400", DZ_OZ_AD + " ", "00002000"),
        ("00010500", DZ_YOL + " ", "00003000"),
    ]
    (static / "ghidra_functions.json").write_text(json.dumps({"functions": [
        {"name": n, "address": a, "size": 64, "parameters": [], "return_type": "void",
         "calling_convention": "cdecl"} for n, a in fonks]}), encoding="utf-8")
    (static / "ghidra_strings.json").write_text(json.dumps({"strings": [
        {"address": a, "value": v, "length": len(v), "type": "string", "function": None,
         "xrefs": [{"from_address": a, "from_function": "FUN_" + f, "from_func_addr": f}]}
        for a, v, f in dizgiler]}), encoding="utf-8")
    (static / "ghidra_call_graph.json").write_text(json.dumps({
        "nodes": {a: {"name": n, "address": a} for n, a in fonks}, "edges": []}),
        encoding="utf-8")
    for n, a in fonks:
        (dec / f"{n}.c").write_text(
            f"// Function: {n}\n// Address: {a}\n\nvoid {n}(void)\n{{\n  return;\n}}\n",
            encoding="utf-8")
    return {"dec": dec, "functions": static / "ghidra_functions.json",
            "strings": static / "ghidra_strings.json",
            "call_graph": static / "ghidra_call_graph.json"}


def test_gercek_havuzda_oz_ad_kaniti_ad_verir(tmp_path):
    """Gerçek ProcessPool + susturma + ürün eşiği (0,7): FUN_1000 adını alır (oz_ad);
    FUN_2000 (farklı ad) ve FUN_3000 (yalnız dosya yolu) adsız kalır."""
    ws = _calisma_alani(tmp_path / "ws")
    out = tmp_path / "out"
    namer = CVariableNamer(Config(), min_confidence=0.15, silenced_subchannels=DZ_SUSAN,
                           global_min_confidence=0.7)
    res = namer.analyze_and_rename(ws["dec"], ws["functions"], ws["strings"],
                                   ws["call_graph"], out)
    assert res.success, res.errors
    nm = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))["global"]
    prov = json.loads((out / "naming_provenance.json").read_text(encoding="utf-8"))["global"]
    assert nm.get("FUN_00001000") == "cycle_check"
    assert prov["FUN_00001000"]["evidence"] == DZ_OZ_AD
    assert prov["FUN_00001000"]["sub_channel"] == alt_kanal.SUB_OWN_NAME
    assert "FUN_00002000" not in nm
    assert "FUN_00003000" not in nm
