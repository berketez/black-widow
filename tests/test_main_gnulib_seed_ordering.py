"""main + gnulib tohumunun (pre_names) c_naming'den ONCE enjekte edilmesi.

KOK SEBEP (2026-07-16): step-registry yolunda Phase-2 ``feedback_loop`` naming
step'i, ``_recover_main_from_entry`` / ``_recover_gnulib_from_fingerprints``
recovery'sinden ONCE calisiyordu. c_namer, henuz ``main`` pre_name'i olmadigi
icin ``FUN_00101b00``'i davranissal sablonla (ol. ``version_output_version``)
yeniden adlandiriyor; recovery main'i sonradan ``extracted_names``'e yazsa da
AhoReplacer dosyada artik ``FUN_00101b00`` literalini BULAMIYOR -> main/gnulib
cikti dosyasina ULASMIYOR ("makine dogru cevabi hesaplayip cope atiyor").

Fix: ``ReconstructionStage._seed_recovery_pre_names`` tek-tanim yardimcisi hem
Phase-2 oncesi (step-registry) hem ortak birlesme noktasinda cagrilir; guard'lar
sayesinde ikinci cagri no-op. Bu test yardimciyi dogrudan kilitler.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.stages import ReconstructionStage


# __libc_start_main(main_addr, ...) -- _start govdesi (loader-kesin main sinyali).
_START_C = """\
// Function: FUN_00102cc0
// Address:  00102cc0
void FUN_00102cc0(void)
{
  __libc_start_main(FUN_00101b00,in_stack_00000000,&stack0x00000008,0,0,0,in_R9);
  return;
}
"""

# main govdesi -- FUN_00101b00. Version string'i tasir; c_namer'in string_context
# stratejisi bunu pre_name YOKKEN "version_output_version" sablonuna donusturur.
_MAIN_C = """\
// Function: FUN_00101b00
// Address:  00101b00
void FUN_00101b00(int param_1,undefined8 *param_2)
{
  setlocale(6,"");
  bindtextdomain("coreutils","/usr/share/locale");
  version_etc(stdout,"cat","GNU coreutils","output version",0);
  return;
}
"""


def _make_static_dir(tmp_path: Path) -> Path:
    """FUN_*.c iceren minimal static/decompiled workspace kur."""
    static_dir = tmp_path / "static"
    decompiled = static_dir / "decompiled"
    decompiled.mkdir(parents=True)
    (decompiled / "FUN_00102cc0.c").write_text(_START_C, encoding="utf-8")
    (decompiled / "FUN_00101b00.c").write_text(_MAIN_C, encoding="utf-8")
    return static_dir


def _fake_context() -> SimpleNamespace:
    # _apply_manual_overrides yalnizca context.target.file_hash / context.config'e
    # getattr ile bakar ve override deposu yoksa bos map doner -> None yeter.
    return SimpleNamespace(target=None, config=None)


class TestSeedRecoveryMain:
    def test_seeds_main_into_pre_names(self, tmp_path: Path) -> None:
        """Tohum, __libc_start_main arg0'dan main'i extracted_names'e yazar.

        KANIT: recovery c_naming'den ONCE cagrilirsa pre_names main'i tasir.
        Bu, kirilan uctan-uca davranisin (main -> version_output_version)
        onlendigi tek dikis.
        """
        stage = ReconstructionStage()
        static_dir = _make_static_dir(tmp_path)
        extracted_names: dict[str, str] = {}
        stats: dict = {}

        stage._seed_recovery_pre_names(
            extracted_names, static_dir, _fake_context(), stats,
        )

        assert extracted_names.get("FUN_00101b00") == "main", (
            "main tohumlanmadi -- c_namer FUN_00101b00'i sablonla ezerdi"
        )
        assert stats.get("main_recovered") == "FUN_00101b00"

    def test_idempotent_second_call_noop(self, tmp_path: Path) -> None:
        """Iki kez cagri guvenli (Phase-2 oncesi + ortak nokta). main korunur."""
        stage = ReconstructionStage()
        static_dir = _make_static_dir(tmp_path)
        extracted_names: dict[str, str] = {}

        stage._seed_recovery_pre_names(extracted_names, static_dir, _fake_context(), {})
        snapshot = dict(extracted_names)
        stage._seed_recovery_pre_names(extracted_names, static_dir, _fake_context(), {})

        assert extracted_names == snapshot, "ikinci cagri idempotent degil"
        assert extracted_names.get("FUN_00101b00") == "main"

    def test_main_overwrites_behavioral_name(self, tmp_path: Path) -> None:
        """main (loader-kesin) davranissal/sablon ismi EZER -- fix'in ozu.

        Bug'in tam tersi: c_namer ``FUN_00101b00``'i ``version_output_version``
        gibi bir davranissal sablona koymustu. main loader-kesinligindedir; bu
        sablon extracted_names'te onceden olsa bile main kazanmali (yoksa cikti
        gene yanlis isimle doner). ``_recover_main_from_entry`` bilincli EZER.
        (Analist override ise main'den SONRA ``_apply_manual_overrides`` ile
        yeniden zorlanir -> analist > main sirasi ayrica korunur.)
        """
        stage = ReconstructionStage()
        static_dir = _make_static_dir(tmp_path)
        # c_namer'in urettigi davranissal sablon extracted_names'te onceden olsun.
        extracted_names: dict[str, str] = {"FUN_00101b00": "version_output_version"}

        stage._seed_recovery_pre_names(extracted_names, static_dir, _fake_context(), {})

        assert extracted_names["FUN_00101b00"] == "main", (
            "main davranissal sablonu ezmedi -- cikti yanlis isimle doner"
        )

    def test_non_dict_returns_empty(self, tmp_path: Path) -> None:
        """extracted_names dict degilse guvenli bos map doner (crash yok)."""
        stage = ReconstructionStage()
        static_dir = _make_static_dir(tmp_path)
        result = stage._seed_recovery_pre_names(None, static_dir, _fake_context(), {})  # type: ignore[arg-type]
        assert result == {}


# ---------------------------------------------------------------------------
# gnulib fingerprint recovery -- mutasyon deligi (2026-07-16).
#
# "gerçek kurtarma 0->8" (commit 7c83288) fix'inin regresyona EN ACIK noktasi:
# _recover_gnulib_from_fingerprints HIC test edilmiyordu. Bu testler string-fp
# kurtarma yolunu, unique-in-binary kisitini ve pre_name guard'ini GERCEK
# metotla (fixture .c anchor'lari) kilitler. Anchor'lar gnulib UPSTREAM'den
# (GT-leakage yok) -- karadul/analyzers/gnulib_fingerprints.py.
# ---------------------------------------------------------------------------

def _write_c(decompiled: Path, fun_key: str, body: str) -> None:
    (decompiled / f"{fun_key}.c").write_text(
        f"void {fun_key}(void)\n{{\n{body}\n}}\n", encoding="utf-8"
    )


class TestSeedRecoveryGnulib:
    def _gnulib_static_dir(self, tmp_path: Path) -> Path:
        """Unique-in-binary gnulib anchor'li minimal decompiled workspace."""
        static_dir = tmp_path / "static"
        decompiled = static_dir / "decompiled"
        decompiled.mkdir(parents=True)
        # Her anchor gnulib upstream lib/<src>'da birebir gecer (dogrulandi):
        _write_c(decompiled, "FUN_00201000", '  error(1,0,"memory exhausted");')      # xalloc_die
        _write_c(decompiled, "FUN_00202000", '  printf("Usage: %s [OPTION]...");')     # usage
        _write_c(decompiled, "FUN_00203000", '  error(0,0,"invalid suffix in %s");')   # xstrtol_error
        return static_dir

    def test_string_fp_recovers_unique_names(self, tmp_path: Path) -> None:
        """String-anchor fingerprint 3 gnulib adini extracted_names'e YAZAR.

        KANIT: recovery gercekten isim uretiyor (0 degil). Mutant `if name:`
        veya atama satirini bozarsa bu assert kirmizi olur -> "makine dogru
        cevabi hesaplayip cope atiyor" regresyonu yakalanir.
        """
        stage = ReconstructionStage()
        static_dir = self._gnulib_static_dir(tmp_path)
        extracted: dict[str, str] = {}
        stats: dict = {}

        stage._recover_gnulib_from_fingerprints(extracted, static_dir, stats)

        assert extracted.get("FUN_00201000") == "xalloc_die"
        assert extracted.get("FUN_00202000") == "usage"
        assert extracted.get("FUN_00203000") == "xstrtol_error"
        assert stats.get("gnulib_recovered") == 3

    def test_does_not_overwrite_existing_prename(self, tmp_path: Path) -> None:
        """unique-in-binary atamasi ONCEDEN isimli FUN'u EZMEZ (guard).

        main (FIX-1) ve binary_extractor gnulib'den ONCE pre_name yazar; guard
        `if extracted_names.get(fun_key) is not None: continue` bunlari korur.
        Mutant guard'i tersine cevirirse (is None) mevcut isim ezilir -> kirmizi.
        """
        stage = ReconstructionStage()
        static_dir = self._gnulib_static_dir(tmp_path)
        # FUN_00201000 (xalloc_die adayi) onceden 'main' olarak isimli olsun:
        extracted: dict[str, str] = {"FUN_00201000": "main"}

        stage._recover_gnulib_from_fingerprints(extracted, static_dir, {})

        assert extracted["FUN_00201000"] == "main", "gnulib mevcut pre_name'i ezdi"
        # Diger unique adaylar yine kurtarilir (guard tekil calisir):
        assert extracted.get("FUN_00202000") == "usage"

    def test_ambiguous_name_not_assigned_by_unique_path(self, tmp_path: Path) -> None:
        """Ayni anchor IKI FUN'da -> unique-in-binary kisiti atamayi BLOKLAR.

        Mutant `if len(keys) != 1` -> `== 1`: belirsiz ad atanir (FP). Bu test
        kisitin dogru yonde calistigini (belirsizi ATLA) kilitler.
        """
        stage = ReconstructionStage()
        static_dir = tmp_path / "static"
        decompiled = static_dir / "decompiled"
        decompiled.mkdir(parents=True)
        # IKI dosya da "memory exhausted" -> xalloc_die adayi (belirsiz):
        _write_c(decompiled, "FUN_00301000", '  error(1,0,"memory exhausted");')
        _write_c(decompiled, "FUN_00302000", '  error(1,0,"memory exhausted");')

        extracted: dict[str, str] = {}
        stats: dict = {}
        stage._recover_gnulib_from_fingerprints(extracted, static_dir, stats)

        # Belirsiz -> unique-path atamaz (call_graph yoksa disambiguation da yok):
        assert extracted.get("FUN_00301000") != "xalloc_die"
        assert extracted.get("FUN_00302000") != "xalloc_die"
        assert "xalloc_die" not in extracted.values()
        assert "xalloc_die" in stats.get("gnulib_ambiguous", [])

    def test_seed_helper_calls_both_main_and_gnulib(self, tmp_path: Path) -> None:
        """_seed_recovery_pre_names main VE gnulib recovery'i BIRLIKTE cagirir.

        Mutant line 2436'daki gnulib cagrisini kaldirirsa gnulib adlari
        tohumlanmaz -> assert kirmizi. main + gnulib ayni dikiste kurtarilir.
        """
        stage = ReconstructionStage()
        static_dir = tmp_path / "static"
        decompiled = static_dir / "decompiled"
        decompiled.mkdir(parents=True)
        # _start -> __libc_start_main(FUN_00101b00) -> main sinyali
        (decompiled / "FUN_00102cc0.c").write_text(_START_C, encoding="utf-8")
        # main govdesi (version string)
        (decompiled / "FUN_00101b00.c").write_text(_MAIN_C, encoding="utf-8")
        # gnulib anchor
        _write_c(decompiled, "FUN_00201000", '  error(1,0,"memory exhausted");')

        extracted: dict[str, str] = {}
        stats: dict = {}
        stage._seed_recovery_pre_names(extracted, static_dir, _fake_context(), stats)

        assert extracted.get("FUN_00101b00") == "main", "main tohumlanmadi"
        assert extracted.get("FUN_00201000") == "xalloc_die", "gnulib tohumlanmadi"


# ---------------------------------------------------------------------------
# Plan v2.2 N1 adım 3 (7. commit): KS-1 çapalarının tohum sırasındaki yeri, ön ad
# künyesi (pre_name_meta) ve künyenin Faz 2 tohumuna ulaşması.
#
# Öncelik: elle > main > KS-1 > Faz 1 > gnulib > ELF önyükü. Çağrı sırası:
# main -> KS-1 -> gnulib -> önyük -> elle. Künye verilmezse (KS-1 kapalı) tohum
# eskisi gibi çalışır. Tasarım: docs/arge/2026-11-10_n1_adim3/
# baglama_tasarimi_taslak.md §2.3, §2.8; mutantlar:
# scripts/measurement/mutation_specs_adim3_hat.json.
# ---------------------------------------------------------------------------

import copy  # noqa: E402
import json  # noqa: E402

from karadul.config import Config  # noqa: E402
from karadul.reconstruction.tarif import baglama as B  # noqa: E402
from karadul.reconstruction.tarif import kesin as K  # noqa: E402

_MAIN = "FUN_00101b00"          # __libc_start_main'in ilk argümanı (_START_C)
_KS1_MAIN_ADLI = "FUN_00300000"  # KS-1 buna "main" demek ister
_GNULIB = "FUN_00201000"        # "memory exhausted" -> xalloc_die adayı
_FAZ1 = "FUN_00400000"          # Faz 1 adı taşıyan, KS-1 çapalı
_FAZ1_GNULIB = "FUN_00202000"   # Faz 1 adı taşıyan gnulib adayı (usage)
_GNULIB_ONYUK = "FUN_00500000"  # hem gnulib (xstrtol_error) hem önyük (register_tm_clones) adayı
_ONYUK = "FUN_00600000"         # yalnız önyük adayı (deregister_tm_clones)
_AKIS_A, _AKIS_B = "FUN_00700000", "FUN_00701000"   # ikisi de close_stream çağrı şekli


def _ks1_binding(*capalar: tuple[str, str]) -> B.Binding:
    """(anahtar, ad) çiftlerinden ad veren KS-1 bağlaması (satır tablosu: func_kalibi kesin).

    Ürün tablosu "aç" commit'ine kadar susar; ad veren durum sınama tablosuyla kurulur.
    """
    anchors, functions = {}, {}
    for key, name in capalar:
        adres = int(key[4:], 16)
        kanit = (K.Evidence(K.TYPE_FUNC, 0x5000, adres, adres + 8, "FUN_gunluk", K.ROLE_OWN),)
        anchors[f"{adres:x}"] = K.Anchor(f"{adres:x}", name, (K.TYPE_FUNC,), K.ROLE_OWN, kanit)
        functions[adres] = K.Function(adres, key, False, False, "DEFAULT", 16)
    result = K.Ks1Result("prog", K.ABI_AAPCS, K.ALL_TYPES, anchors, {}, [])
    return B.bind(result, functions, cpp=False, row_status={B.ROW_FUNC: B.STATUS_KESIN})


def _full_static_dir(tmp_path: Path) -> Path:
    """main, gnulib (dizgi ve çağrı şekli) ve ELF önyükü adaylarını birlikte taşıyan static/."""
    static_dir = tmp_path / "static"
    decompiled = static_dir / "decompiled"
    decompiled.mkdir(parents=True)
    (decompiled / "FUN_00102cc0.c").write_text(_START_C, encoding="utf-8")
    (decompiled / f"{_MAIN}.c").write_text(_MAIN_C, encoding="utf-8")
    _write_c(decompiled, _GNULIB, '  error(1,0,"memory exhausted");')           # xalloc_die
    _write_c(decompiled, _FAZ1_GNULIB, '  printf("Usage: %s [OPTION]...");')      # usage
    _write_c(decompiled, _GNULIB_ONYUK, '  error(0,0,"invalid suffix in %s");')   # xstrtol_error
    for key in (_KS1_MAIN_ADLI, _FAZ1, _ONYUK, _AKIS_A, _AKIS_B):
        _write_c(decompiled, key, "  return;")

    def node(*callees: str) -> dict:
        return {"callees": [{"name": c} for c in callees], "callee_count": len(callees)}

    nodes = {
        _GNULIB_ONYUK[4:]: node("_ITM_registerTMCloneTable"),     # register_tm_clones şekli
        _ONYUK[4:]: node("_ITM_deregisterTMCloneTable"),           # deregister_tm_clones şekli
        _AKIS_A[4:]: node("__fpending", "fclose"),                 # close_stream şekli (iki aday)
        _AKIS_B[4:]: node("__fpending", "fclose"),
    }
    (static_dir / "call_graph.json").write_text(json.dumps({"nodes": nodes}), encoding="utf-8")
    return static_dir


def _context_with_overrides(tmp_path: Path, overrides: dict[str, str]) -> SimpleNamespace:
    path = tmp_path / "elle.json"
    path.write_text(json.dumps({"overrides": {k: {"name": v} for k, v in overrides.items()}}),
                    encoding="utf-8")
    return SimpleNamespace(target=None, config=SimpleNamespace(
        binary_reconstruction=SimpleNamespace(overrides_path=str(path))))


def _kinds(meta: dict) -> dict[str, str]:
    return {key: entry["kind"] for key, entry in meta.items()}


class TestSeedKs1Order:
    def _seed(self, tmp_path: Path, *, binding=None, context=None, initial=None):
        stage = ReconstructionStage()
        static_dir = _full_static_dir(tmp_path)
        names: dict[str, str] = dict(initial or {})
        meta: dict = {}
        stats: dict = {}
        manual = stage._seed_recovery_pre_names(
            names, static_dir, context or _fake_context(), stats, kesin=binding, meta=meta)
        return SimpleNamespace(stage=stage, static_dir=static_dir, names=names, meta=meta,
                               stats=stats, manual=manual, context=context or _fake_context())

    def test_without_meta_ks1_is_not_applied(self, tmp_path: Path) -> None:
        """Künye verilmezse (KS-1 kapalı) bağlama elde olsa da tohum eskisi gibi çalışır."""
        stage = ReconstructionStage()
        static_dir = _full_static_dir(tmp_path)
        binding = _ks1_binding((_FAZ1, "Vector_add"), (_GNULIB, "bellek_bitti"))
        plain: dict[str, str] = {_FAZ1: "eski_faz1"}
        stats_plain: dict = {}
        stage._seed_recovery_pre_names(plain, static_dir, _fake_context(), stats_plain)

        with_binding: dict[str, str] = {_FAZ1: "eski_faz1"}
        stats: dict = {}
        stage._seed_recovery_pre_names(
            with_binding, static_dir, _fake_context(), stats, kesin=binding)

        assert with_binding == plain and list(with_binding) == list(plain)
        assert with_binding[_FAZ1] == "eski_faz1" and with_binding[_GNULIB] == "xalloc_die"
        assert stats == stats_plain and not any(k.startswith("ks1_") for k in stats)

    def test_tracking_alone_does_not_change_names(self, tmp_path: Path) -> None:
        """KS-1 yapıtı yokken (kesin=None) künye tutmak adları ve sıralarını değiştirmez."""
        plain_stage = ReconstructionStage()
        static_dir = _full_static_dir(tmp_path / "duz")
        plain: dict[str, str] = {_FAZ1: "eski_faz1", _FAZ1_GNULIB: "faz1_usage"}
        plain_stats: dict = {}
        plain_stage._seed_recovery_pre_names(plain, static_dir, _fake_context(), plain_stats)

        r = self._seed(tmp_path / "kunyeli",
                       initial={_FAZ1: "eski_faz1", _FAZ1_GNULIB: "faz1_usage"})
        assert r.names == plain and list(r.names) == list(plain)
        assert r.stats == plain_stats and not any(k.startswith("ks1_") for k in r.stats)
        assert set(r.meta) == set(r.names)          # her ön adın künyesi var

    def test_kinds_are_marked_per_seed(self, tmp_path: Path) -> None:
        """Tür, sözlüğün önceki ve sonraki hâli karşılaştırılarak bulunur (imzalar değişmedi)."""
        ctx = _context_with_overrides(tmp_path, {_KS1_MAIN_ADLI: "Analist_adi"})
        r = self._seed(tmp_path, binding=_ks1_binding((_FAZ1, "Vector_add")), context=ctx,
                       initial={_FAZ1: "eski_faz1", _FAZ1_GNULIB: "faz1_usage"})
        assert r.names == {
            _FAZ1: "Vector_add", _FAZ1_GNULIB: "faz1_usage", _MAIN: "main",
            _GNULIB: "xalloc_die", _GNULIB_ONYUK: "xstrtol_error",
            _ONYUK: "deregister_tm_clones", _KS1_MAIN_ADLI: "Analist_adi",
        }
        assert _kinds(r.meta) == {
            _FAZ1: "ks1", _FAZ1_GNULIB: "faz1", _MAIN: "main_giris", _GNULIB: "gnulib",
            _GNULIB_ONYUK: "gnulib", _ONYUK: "elf_onyuk", _KS1_MAIN_ADLI: "elle",
        }
        # künyedeki ad sözlükteki adla aynı: c_namer künyeyi geçerli sayar
        assert all(B.meta_for(r.meta, k, v) is r.meta[k] for k, v in r.names.items())
        # tam ad türleri: KS-1, elle ve ELF önyükü; KS-1 künyesi etiket ve kanıt taşır
        assert {k for k, e in r.meta.items() if e["exact"]} == {_FAZ1, _KS1_MAIN_ADLI, _ONYUK}
        assert r.meta[_FAZ1]["label"] == "kesin"
        assert r.meta[_FAZ1]["ks1"]["satirlar"] == ["func_kalibi"]
        assert r.manual == {_KS1_MAIN_ADLI: "Analist_adi"}

    def test_priority_order(self, tmp_path: Path) -> None:
        """elle > main > KS-1 > Faz 1 > gnulib > ELF önyükü."""
        binding = _ks1_binding(
            (_MAIN, "ana_dongu"),            # main'in anahtarı: KS-1 yazamaz
            (_KS1_MAIN_ADLI, "main"),        # "main" adı ikinci anahtara verilmez
            (_GNULIB, "bellek_bitti"),       # gnulib adayı: KS-1 önce yazar, gnulib boş yuva bulamaz
            (_FAZ1, "Vector_add"),           # Faz 1 adını ezer
        )
        r = self._seed(tmp_path, binding=binding,
                       initial={_FAZ1: "eski_faz1", _FAZ1_GNULIB: "faz1_usage"})
        assert r.names[_MAIN] == "main"                     # main > KS-1
        assert _KS1_MAIN_ADLI not in r.names                # main adı tek anahtarda
        assert list(r.names.values()).count("main") == 1
        assert r.names[_GNULIB] == "bellek_bitti"           # KS-1 > gnulib
        assert r.names[_FAZ1] == "Vector_add"               # KS-1 > Faz 1
        assert r.names[_FAZ1_GNULIB] == "faz1_usage"        # Faz 1 > gnulib
        assert r.names[_GNULIB_ONYUK] == "xstrtol_error"    # gnulib > önyük
        assert r.names[_ONYUK] == "deregister_tm_clones"
        assert _kinds(r.meta)[_GNULIB] == "ks1" and _kinds(r.meta)[_MAIN] == "main_giris"
        # sayaçlar: iki çapa ad verdi, ikisi korunan ad yüzünden atlandı; yalnız Faz 1 adı ezildi
        assert r.stats["ks1_status"] == "ok" and r.stats["ks1_anchors"] == 4
        assert r.stats["ks1_named"] == 2 and r.stats["ks1_kesin"] == 2
        assert r.stats["ks1_skipped"] == {"ad_main_dolu": 1, "korunan_anahtar": 1}
        assert r.stats["ks1_overrode"] == {"faz1": 1}       # gnulib adı hiç yazılmadı ki ezilsin
        assert r.stats["gnulib_recovered"] == 1             # yalnız xstrtol_error
        assert r.stats["main_recovered"] == _MAIN

    def test_manual_override_beats_everything(self, tmp_path: Path) -> None:
        ctx = _context_with_overrides(
            tmp_path, {_MAIN: "Giris_noktasi", _FAZ1: "Analist_adi", _GNULIB: "elle_gnulib"})
        r = self._seed(tmp_path, binding=_ks1_binding((_FAZ1, "Vector_add")), context=ctx)
        assert r.names[_MAIN] == "Giris_noktasi"            # elle > main
        assert r.names[_FAZ1] == "Analist_adi"              # elle > KS-1
        assert r.names[_GNULIB] == "elle_gnulib"            # elle > gnulib
        for key in (_MAIN, _FAZ1, _GNULIB):
            assert r.meta[key] == B.make_meta(B.KIND_MANUAL, r.names[key])
            assert r.meta[key]["exact"] is True and "label" not in r.meta[key]
        assert r.stats["manual_overrides_applied"] == 3

    def test_manual_name_equal_to_seeded_name_is_still_manual(self, tmp_path: Path) -> None:
        """Analist tohumun verdiği adın aynısını verirse sözlük değişmez; tür yine ``elle`` olur
        (bu yüzden elle tür karşılaştırmayla değil, dönen haritayla işaretlenir)."""
        ctx = _context_with_overrides(tmp_path, {_GNULIB: "xalloc_die"})
        r = self._seed(tmp_path, context=ctx)
        assert r.names[_GNULIB] == "xalloc_die" and _kinds(r.meta)[_GNULIB] == "elle"

    def test_ks1_runs_before_gnulib_call_shape(self, tmp_path: Path) -> None:
        """KS-1 gnulib'den önce yazar: KS-1'in adlandırdığı fonksiyon çağrı şekli adayı olmaktan
        çıkar, kalan tek aday gnulib adını alır. Sıra tersine dönerse iki aday belirsiz kalır."""
        r = self._seed(tmp_path, binding=_ks1_binding((_AKIS_A, "akisi_kapat")))
        assert r.names[_AKIS_A] == "akisi_kapat"
        assert r.names[_AKIS_B] == "close_stream"
        assert r.stats["gnulib_callshape_recovered"] == 1
        assert _kinds(r.meta)[_AKIS_B] == "gnulib" and r.stats["ks1_overrode"] == {}
        # KS-1 yokken iki aday belirsizdir: hiçbiri ad almaz
        plain = self._seed(tmp_path / "ks1siz")
        assert _AKIS_A not in plain.names and _AKIS_B not in plain.names

    def test_second_call_changes_nothing(self, tmp_path: Path) -> None:
        """Tohum iki kez çağrılır (Faz 2 öncesi ve ortak nokta); ikinci çağrı değişiklik yapmaz."""
        ctx = _context_with_overrides(tmp_path, {_ONYUK: "Analist_adi"})
        binding = _ks1_binding((_MAIN, "ana_dongu"), (_GNULIB, "bellek_bitti"),
                               (_FAZ1, "Vector_add"))
        r = self._seed(tmp_path, binding=binding, context=ctx, initial={_FAZ1: "eski_faz1"})
        names, order = dict(r.names), list(r.names)
        meta, stats = copy.deepcopy(r.meta), copy.deepcopy(r.stats)

        manual = r.stage._seed_recovery_pre_names(
            r.names, r.static_dir, ctx, r.stats, kesin=binding, meta=r.meta)

        assert r.names == names and list(r.names) == order
        assert r.meta == meta
        assert r.stats == stats                     # ks1_overrode iki kez sayılmadı
        assert manual == r.manual == {_ONYUK: "Analist_adi"}

    def test_binding_without_names_changes_nothing(self, tmp_path: Path) -> None:
        """Bütün satırları susan tabloyla KS-1 ad vermez: adlar KS-1'siz tohumla aynı, yalnız
        sayaçlar yazılır ("aç" commit'ine kadar ürün tablosunun durumu budur)."""
        adres = int(_FAZ1[4:], 16)
        kanit = (K.Evidence(K.TYPE_FUNC, 0x5000, adres, adres + 8, "FUN_gunluk", K.ROLE_OWN),)
        result = K.Ks1Result("prog", K.ABI_AAPCS, K.ALL_TYPES, {
            f"{adres:x}": K.Anchor(f"{adres:x}", "Vector_add", (K.TYPE_FUNC,), K.ROLE_OWN, kanit),
        }, {}, [])
        binding = B.bind(result, {adres: K.Function(adres, _FAZ1, False, False, "DEFAULT", 16)},
                         cpp=False, row_status=dict.fromkeys(B.DECISION_ROWS, B.STATUS_SILENT))
        r = self._seed(tmp_path / "ks1", binding=binding, initial={_FAZ1: "eski_faz1"})
        plain = self._seed(tmp_path / "duz", initial={_FAZ1: "eski_faz1"})
        assert r.names == plain.names and r.names[_FAZ1] == "eski_faz1"
        assert _kinds(r.meta) == _kinds(plain.meta)
        assert r.stats["ks1_named"] == 0 and r.stats["ks1_skipped"] == {"satir_sus": 1}

    def test_non_dict_with_meta_returns_empty(self, tmp_path: Path) -> None:
        stage = ReconstructionStage()
        meta: dict = {}
        assert stage._seed_recovery_pre_names(
            None, tmp_path, _fake_context(), {}, kesin=None, meta=meta) == {}  # type: ignore[arg-type]
        assert meta == {}


# --- _execute_binary: adım listesi ve künyenin Faz 2 tohumuna ulaşması ---------------------

class _Artifacts(dict):
    """Faz 1 yapıtları: sınamada kullanılmayan anahtarlar None döner."""

    def __missing__(self, key: str):
        return None


class _StopPhase2(RuntimeError):
    pass


def _run_execute_binary(tmp_path: Path, monkeypatch, kesin_artifact):
    """``_execute_binary``'yi sahte koşucuyla Faz 2'nin eşiğine kadar yürüt.

    Faz 1 koşucusu hazır yapıtları döndürür; Faz 2 koşucusu tohumunu kaydedip durur. Dönen:
    (Faz 1 adım listesi, Faz 2 tohumu, StageResult).
    """
    import karadul.pipeline.runner as runner_mod

    static_dir = _full_static_dir(tmp_path)
    recorded: dict = {}

    class _FakeRunner:
        def __init__(self, steps):
            self.steps = list(steps)

        def run(self, context, seed_artifacts=None):
            if "feedback_loop" in self.steps:
                recorded["seed"] = seed_artifacts
                raise _StopPhase2("dur")
            recorded["phase1_steps"] = self.steps
            artifacts = _Artifacts(extracted_names={_FAZ1: "eski_faz1"})
            if kesin_artifact is not None:
                artifacts["kesin_anchors"] = kesin_artifact
            return SimpleNamespace(artifacts=artifacts, stats={"ks1_status": "ok"}, errors=[],
                                   stage_artifacts={})

    monkeypatch.setattr(runner_mod, "PipelineRunner", _FakeRunner)

    def stage_dir(stage: str) -> Path:
        d = static_dir if stage == "static" else tmp_path / stage
        d.mkdir(parents=True, exist_ok=True)
        return d

    context = SimpleNamespace(
        target=SimpleNamespace(path=tmp_path / "ikili", file_hash=""),
        workspace=SimpleNamespace(get_stage_dir=stage_dir, path=tmp_path),
        config=Config(), metadata={},
    )
    result = ReconstructionStage()._execute_binary(context, 0.0)
    assert result.success is False and result.errors == ["dur"]   # Faz 2 eşiğinde durduk
    return recorded["phase1_steps"], recorded["seed"], result


class TestExecuteBinaryKs1Wiring:
    def test_step_list_has_kesin_anchors_after_ghidra_metadata(self, tmp_path, monkeypatch):
        steps, _, _ = _run_execute_binary(tmp_path, monkeypatch, None)
        assert steps.count("kesin_anchors") == 1
        assert steps.index("kesin_anchors") == steps.index("ghidra_metadata") + 1
        assert steps.index("kesin_anchors") < steps.index("confidence_filter")

    def test_meta_reaches_phase2_seed(self, tmp_path, monkeypatch):
        """Künye Faz 2 tohumuna ``pre_name_meta`` olarak girer; adlar aynı tohumdaki sözlükte."""
        binding = _ks1_binding((_FAZ1, "Vector_add"), (_MAIN, "ana_dongu"))
        _, seed, result = _run_execute_binary(tmp_path, monkeypatch, binding)
        names, meta = seed["extracted_names"], seed["pre_name_meta"]
        assert names[_FAZ1] == "Vector_add" and names[_MAIN] == "main"
        assert meta[_FAZ1]["kind"] == "ks1" and meta[_FAZ1]["label"] == "kesin"
        assert meta[_FAZ1]["exact"] is True
        assert _kinds(meta)[_MAIN] == "main_giris" and _kinds(meta)[_GNULIB] == "gnulib"
        assert set(meta) == set(names)
        assert seed["kesin_anchors"] is binding
        # sayaçlar aşama istatistiklerinde (rapora buradan gider)
        assert result.stats["ks1_named"] == 1 and result.stats["ks1_kesin"] == 1
        assert result.stats["ks1_skipped"] == {"korunan_anahtar": 1}
        assert result.stats["ks1_overrode"] == {"faz1": 1}

    @pytest.mark.parametrize("artifact", [None, "kapali"])
    def test_without_ks1_today_behaviour(self, tmp_path, monkeypatch, artifact):
        """KS-1 yapıtı yokken ya da adım kapalıyken: künye tohuma girmez, adlar bugünkü gibi."""
        kesin = B.disabled() if artifact == "kapali" else None
        _, seed, result = _run_execute_binary(tmp_path, monkeypatch, kesin)
        assert "pre_name_meta" not in seed
        plain: dict[str, str] = {_FAZ1: "eski_faz1"}
        ReconstructionStage()._seed_recovery_pre_names(
            plain, tmp_path / "static", _fake_context(), {})
        assert seed["extracted_names"] == plain
        assert list(seed["extracted_names"]) == list(plain)
        assert seed["extracted_names"][_FAZ1] == "eski_faz1"
        assert not any(k.startswith("ks1_") and k != "ks1_status" for k in result.stats)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
