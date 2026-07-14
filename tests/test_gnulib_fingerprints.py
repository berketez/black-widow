"""gnulib string-anchor fingerprint DB testleri (FIX-2).

Iki tur:
1. Matcher davranisi (extract_string_literals + match_function + unique-in-binary
   semantigi).
2. GT-LEAKAGE DENETIMI: her fingerprint anchor'inin gnulib UPSTREAM kaynaginda
   (vendor/gnulib-ref/lib/<source>) birebir gectigini dogrular. Bu, imzalarin
   test binary'lerinin .rodata'sindan degil, bagimsiz kaynaktan turetildigini
   garanti eder (overfit/sahte-basari koruması). Kaynak yoksa (CI) atlanir.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from karadul.analyzers.gnulib_fingerprints import (
    EXPECTED_COREUTILS,
    GNULIB_CALL_SHAPES,
    GNULIB_FINGERPRINTS,
    GNULIB_REF_COMMIT,
    extract_string_literals,
    match_call_shape,
    match_function,
)

GNULIB_LIB = Path(__file__).resolve().parents[1] / "vendor" / "gnulib-ref" / "lib"
GNULIB_ROOT = GNULIB_LIB.parent  # vendor/gnulib-ref


@pytest.mark.skipif(
    not (GNULIB_ROOT / ".git").exists(),
    reason="vendor/gnulib-ref git checkout'u yok (upstream clone edilmemis)",
)
class TestVendorPin:
    """Drift-guard: vendor/gnulib-ref, olcum hedefi coreutils 9.4'un gnulib
    commit'ine pin'li olmali. Yanlislikla master'a fetch edilirse leakage-oracle
    olcum binary'lerinden ayrilir -> anchor'lar sessizce gecersizlesir (07-14
    quotearg_buffer_restyled bunu yasadi)."""

    def test_vendor_head_matches_pin(self):
        import subprocess
        try:
            head = subprocess.run(
                ["git", "-C", str(GNULIB_ROOT), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=15,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pytest.skip("git calistirilamadi")
        assert head == GNULIB_REF_COMMIT, (
            f"vendor/gnulib-ref HEAD ({head[:12]}) beklenen pin "
            f"({GNULIB_REF_COMMIT[:12]}, coreutils {EXPECTED_COREUTILS}) ile "
            f"eslesmiyor. scripts/fetch_gnulib_ref.sh ile yeniden pin'le."
        )


class TestStringExtraction:
    def test_extracts_simple_literals(self):
        src = 'void f(void){ puts("memory exhausted"); log("write error"); }'
        lits = extract_string_literals(src)
        assert "memory exhausted" in lits
        assert "write error" in lits

    def test_handles_escapes(self):
        src = r'const char *s = "Written by %s.\n";'
        lits = extract_string_literals(src)
        assert any("Written by" in s for s in lits)

    def test_empty_source(self):
        assert extract_string_literals("") == []
        assert extract_string_literals("int x = 5;") == []


class TestMatchFunction:
    def test_xalloc_die(self):
        assert match_function(["memory exhausted"]) == "xalloc_die"

    def test_version_etc(self):
        assert match_function(["Written by %s.\n", "coreutils"]) == "version_etc"

    def test_and_semantics_argmatch(self):
        # argmatch iki anchor birden ister
        assert match_function(["ambiguous argument %s for %s"]) is None
        assert (
            match_function(["ambiguous argument %s for %s", "Valid arguments are:"])
            == "argmatch"
        )

    def test_no_match(self):
        assert match_function(["hello world", "foo"]) is None
        assert match_function([]) is None

    def test_first_match_wins_deterministic(self):
        # Ayni girdi hep ayni sonucu vermeli (siralama deterministik)
        strings = ["memory exhausted", "Written by %s"]
        assert match_function(strings) == match_function(strings)


class TestNoEmitInlineFingerprints:
    """emit_* fingerprint'leri main'e inline FP riski nedeniyle CIKARILMIS olmali."""

    def test_no_emit_fingerprints(self):
        names = {fp.name for fp in GNULIB_FINGERPRINTS}
        assert "emit_bug_reporting_address" not in names
        assert "emit_ancillary_info" not in names


class TestCallShapeMatch:
    def test_close_stream(self):
        # __fpending cagiran, fout>=2, thunk degil
        assert match_call_shape({"__fpending", "__errno_location"}, 3) == "close_stream"

    def test_thunk_filtered_by_min_fanout(self):
        # fout=1 PLT thunk (sadece __fpending) elenir
        assert match_call_shape({"__fpending"}, 1) is None

    def test_max_fanout_filter(self):
        # write cagiran ama cok buyuk fonksiyon full_write degil
        assert match_call_shape({"write", "__errno_location"}, 2) == "full_write"
        assert match_call_shape({"write"}, 40) is None  # fout>max_fanout

    def test_hard_locale(self):
        assert match_call_shape({"setlocale", "strlen", "memcpy"}, 5) == "hard_locale"

    def test_no_match(self):
        assert match_call_shape({"printf", "malloc"}, 3) is None
        assert match_call_shape(set(), 3) is None

    def test_gettext_quote_excluded(self):
        # gettext_quote call-shape'ten cikarildi (thunk ile karisir)
        names = {cs.name for cs in GNULIB_CALL_SHAPES}
        assert "gettext_quote" not in names


@pytest.mark.skipif(
    not GNULIB_LIB.exists(),
    reason="vendor/gnulib-ref yok (upstream kaynak clone edilmemis)",
)
class TestCallShapeNoLeakage:
    """Call-shape callee davranisi gnulib kaynaginda gecmeli (GT'den degil).

    Ghidra libc callee'yi PLT'den cozer (``__fpending``), kaynakta gnulib
    wrapper/makro adiyla gecer (``fpending``, ``MB_CUR_MAX``). Davranis
    anahtarini esnek eslestiririz.
    """

    _BEHAVIOR_KEY = {
        "__fpending": "fpending",
        "setlocale": "setlocale",
        "write": "write",
        "__ctype_get_mb_cur_max": "MB_CUR_MAX",
        "fclose": "fclose",
        "__freading": "freading",
    }

    def test_callee_behavior_in_source(self):
        failures: list[str] = []
        for cs in GNULIB_CALL_SHAPES:
            src = GNULIB_LIB / cs.source
            if not src.exists():
                failures.append(f"{cs.name}: kaynak {cs.source} yok")
                continue
            text = src.read_text(errors="ignore")
            for callee in cs.required_callees:
                key = self._BEHAVIOR_KEY.get(callee, callee)
                if key not in text:
                    failures.append(
                        f"{cs.name}: callee davranisi '{key}' {cs.source}'da YOK"
                    )
        assert not failures, "\n".join(failures)


@pytest.mark.skipif(
    not GNULIB_LIB.exists(),
    reason="vendor/gnulib-ref yok (upstream kaynak clone edilmemis)",
)
class TestNoGroundTruthLeakage:
    """Her anchor gnulib UPSTREAM kaynaginda gecmeli (GT'den turetilmemis)."""

    def test_every_anchor_in_declared_source(self):
        failures: list[str] = []
        for fp in GNULIB_FINGERPRINTS:
            src = GNULIB_LIB / fp.source
            if not src.exists():
                failures.append(f"{fp.name}: kaynak {fp.source} bulunamadi")
                continue
            text = src.read_text(errors="ignore")
            for anchor in fp.anchors:
                if anchor not in text:
                    failures.append(
                        f"{fp.name}: anchor '{anchor}' {fp.source}'da YOK "
                        "(GT-leakage suphesi!)"
                    )
        assert not failures, "\n".join(failures)
