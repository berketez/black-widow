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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
