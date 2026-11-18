"""P-S3b kalem 1: gnulib varlık kanıtı sürümden ve platformdan bağımsız.

P-S3'ün işaretleri Homebrew coreutils 9.12'de (Mach-O, gnulib 2024+) yalnız 1 modül buluyordu
(progname iletisi yeni gnulib'de yok; ``__fpending`` / ``__freading`` macOS'ta gnulib'in kendi
adsız fonksiyonu) ve kanal susuyordu. Yeni:
  - getopt ('%s%s' biçimli uzun seçenek iletileri) ve error ("Unknown system error") modülleri;
    ikisinin metni glibc'yle ortak, bu yüzden yalnız ikisi yetmez (gnulib'e özgü bir modül şart);
  - dizgi işaretleri Ghidra'nın tırnak kaçışları (``\\'``) çözülmüş metinde aranır (P-S3'ün
    xstrtol-error işaretleri bu yüzden hiç eşleşmiyordu).

Ölçüm ve ön kayıt: ``docs/arge/2026-11-18_onarim/P-S3b.md``, ``P-S3b_on_kayit.md``.
"""

from __future__ import annotations

import json
from pathlib import Path

from karadul.analyzers.gnulib_fingerprints import (
    GNULIB_PRESENCE_MARKERS,
    presence_evidence,
    unescape_ghidra_quotes,
)
from karadul.stages import ReconstructionStage

GNULIB_LIB = Path(__file__).resolve().parents[1] / "vendor" / "gnulib-ref" / "lib"

# Ghidra'nın decompile çıktısındaki biçim: tek tırnak \' diye kaçırılmış.
GETOPT_GHIDRA = "%s: option \\'%s%s\\' doesn\\'t allow an argument\\n"
VERSION_ETC_GHIDRA = "General help using GNU software: <%s>\\n"
ERROR_C = "Unknown system error"
XSTRTOL_GHIDRA = "invalid suffix in %s%s argument \\'%s\\'"


def _write_c(decompiled: Path, stem: str, body: str) -> None:
    (decompiled / f"{stem}.c").write_text(f"void {stem}(void)\n{{\n{body}\n}}\n", encoding="utf-8")


def _static(tmp_path: Path, literals: dict[str, str]) -> Path:
    """``literals``: adlı fonksiyon -> dizgi (Ghidra biçiminde). Parmak izi adayı olmazlar."""
    static_dir = tmp_path / "static"
    decompiled = static_dir / "decompiled"
    decompiled.mkdir(parents=True)
    _write_c(decompiled, "FUN_00100000", "  return;")
    for stem, lit in literals.items():
        _write_c(decompiled, stem, f'  fprintf(stderr,"{lit}");')
    (static_dir / "call_graph.json").write_text(json.dumps({"nodes": {}}), encoding="utf-8")
    return static_dir


def _run(static_dir: Path) -> tuple[dict, dict, dict]:
    _write_c(static_dir / "decompiled", "FUN_00101000", '  error(0,0,"write error");')
    names: dict[str, str] = {}
    stats: dict = {}
    ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, stats)
    kayit = json.loads((static_dir / "gnulib_candidates.json").read_text(encoding="utf-8"))
    return names, stats, kayit


class TestMachOGnulib:
    def test_version_etc_ve_getopt_yeter(self, tmp_path):
        """Homebrew coreutils 9.12 düzeni: version-etc + getopt (Ghidra kaçışlı) -> ad yazılır."""
        static_dir = _static(tmp_path, {"emit_bug_reporting_address": VERSION_ETC_GHIDRA,
                                        "process_long_option": GETOPT_GHIDRA})
        names, stats, kayit = _run(static_dir)
        assert names == {"FUN_00101000": "close_stdout"}
        assert stats["gnulib_evidence"]["modules"] == ["version-etc", "getopt"]
        assert stats["gnulib_evidence"]["sufficient"] is True
        assert kayit["presence"]["sufficient"] is True

    def test_version_etc_ve_error_yeter(self, tmp_path):
        """gettext 1.0 düzeni: version-etc + error.c -> ad yazılır."""
        static_dir = _static(tmp_path, {"emit_bug_reporting_address": VERSION_ETC_GHIDRA,
                                        "print_errno_message": ERROR_C})
        names, stats, _ = _run(static_dir)
        assert names == {"FUN_00101000": "close_stdout"}
        assert stats["gnulib_evidence"]["modules"] == ["version-etc", "error"]

    def test_yalniz_glibc_ortak_moduller_yetmez(self, tmp_path):
        """getopt + error: statik glibc'li gnulib'siz programda da bulunur -> ad yok, aday kayıtta."""
        static_dir = _static(tmp_path, {"process_long_option": GETOPT_GHIDRA,
                                        "print_errno_message": ERROR_C})
        names, stats, kayit = _run(static_dir)
        assert names == {}
        assert stats["gnulib_evidence"] == {"sufficient": False, "min_modules": 2,
                                            "modules": ["getopt", "error"]}
        assert "glibc" in kayit["presence"]["evidence"]
        [karar] = kayit["decisions"]
        assert (karar["decision"], karar["reason"]) == ("withheld", "gnulib_kaniti_yetersiz")

    def test_version_etc_arn_dizgisi_version_etc_sayilir(self, tmp_path):
        """emit_bug_reporting_address'siz program: version_etc_arn'ın "Written by" dizgisi yeter."""
        static_dir = _static(tmp_path, {"version_etc_arn": "Written by %s, %s, and %s.\\n",
                                        "process_long_option": GETOPT_GHIDRA})
        names, stats, _ = _run(static_dir)
        assert names == {"FUN_00101000": "close_stdout"}
        assert stats["gnulib_evidence"]["modules"] == ["version-etc", "getopt"]

    def test_tek_yeni_modul_yetmez(self, tmp_path):
        """Yalnız getopt (gnulib'siz Mach-O'da beklenmez ama tek modül yine kanıt değil)."""
        static_dir = _static(tmp_path, {"process_long_option": GETOPT_GHIDRA})
        names, stats, _ = _run(static_dir)
        assert names == {} and stats["gnulib_evidence"]["sufficient"] is False


class TestKacisCozumu:
    def test_tek_tirnakli_isaret_ghidra_kacisiyla_eslesir(self, tmp_path):
        """xstrtol-error işareti Ghidra'nın \\' kaçışıyla da bulunur (P-S3'te ham 0 / çözülmüş 8)."""
        pr = presence_evidence([XSTRTOL_GHIDRA, VERSION_ETC_GHIDRA], set())
        assert [m for m, *_ in pr.found] == ["version-etc", "xstrtol-error"]
        assert pr.sufficient is True

    def test_unescape(self):
        assert unescape_ghidra_quotes("a \\'b\\' \\\"c\\\"") == "a 'b' \"c\""

    def test_kacissiz_metin_degismez(self):
        assert unescape_ghidra_quotes("Usage: %s [OPTION]...\\n") == "Usage: %s [OPTION]...\\n"


def test_evidence_line_glibc_notu_yalniz_glibc_ortakken():
    yalniz = presence_evidence([GETOPT_GHIDRA, ERROR_C], set())
    karisik = presence_evidence([GETOPT_GHIDRA, VERSION_ETC_GHIDRA], set())
    assert yalniz.glibc_shared_modules == ("getopt", "error") and not yalniz.sufficient
    assert "glibc ile ortak" in yalniz.evidence_line()
    assert karisik.sufficient and "glibc ile ortak" not in karisik.evidence_line()


def test_yeni_isaretler_upstream_kaynakta_ve_glibc_isaretli():
    """Her işaret vendor/gnulib-ref/lib/<kaynak>'ta birebir; yalnız getopt ve error glibc ile ortak."""
    by_module = {m.module: m for m in GNULIB_PRESENCE_MARKERS}
    assert {"getopt", "error"} <= set(by_module)
    assert {m.module for m in GNULIB_PRESENCE_MARKERS if m.glibc_shared} == {"getopt", "error"}
    assert "Written by %s, %s, and %s." in by_module["version-etc"].anchors
    for m in GNULIB_PRESENCE_MARKERS:
        src = (GNULIB_LIB / m.source).read_text(encoding="utf-8", errors="replace")
        for a in m.anchors:
            if m.kind == "dizgi":
                assert a in src, (m.module, a)
