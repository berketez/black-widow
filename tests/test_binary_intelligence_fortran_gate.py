"""Fortran binary-type gate testleri (v1.10.0 Batch 3D)."""
from __future__ import annotations

import pytest

from karadul.analyzers.binary_intelligence import (
    BinaryIntelligence,
    FORTRAN_RUNTIME_MARKERS,
    _is_fortran_binary,
)
from karadul.config import Config


# ---------------------------------------------------------------------------
# _is_fortran_binary helper
# ---------------------------------------------------------------------------


class TestIsFortranBinaryHelper:
    def test_empty_list_is_not_fortran(self) -> None:
        assert _is_fortran_binary([]) is False

    def test_single_marker_is_not_enough(self) -> None:
        # Tek marker yetmez -- iki ayri marker gerek.
        assert _is_fortran_binary(["_gfortran_main"]) is False

    def test_two_distinct_markers_opens_gate(self) -> None:
        symbols = ["_gfortran_main", "_gfortran_stop_string"]
        assert _is_fortran_binary(symbols) is True

    def test_two_same_markers_do_not_open_gate(self) -> None:
        # Ayni marker iki kere = yine tek distinct marker.
        assert _is_fortran_binary(["_gfortran_main", "_gfortran_main x"]) is False

    def test_intel_ifort_markers_open_gate(self) -> None:
        symbols = ["for_write_seq_lis", "for_read_seq_lis"]
        assert _is_fortran_binary(symbols) is True

    def test_flang_markers_open_gate(self) -> None:
        symbols = ["_FortranAioOutput", "flangrti_abort"]
        assert _is_fortran_binary(symbols) is True

    def test_non_fortran_binary_rejected(self) -> None:
        # Baska pattern'lerde "gfortran" kelimesi gecse bile marker degil.
        symbols = [
            "error: gfortran compilation failed",
            "foo_bar_baz",
            "main",
            "SHA256",
        ]
        assert _is_fortran_binary(symbols) is False

    def test_all_markers_declared(self) -> None:
        # Modul-level sabitlerin silinmedigi regresyon kontrolu.
        assert "_gfortran_main" in FORTRAN_RUNTIME_MARKERS
        assert "_FortranA" in FORTRAN_RUNTIME_MARKERS
        assert len(FORTRAN_RUNTIME_MARKERS) >= 5


# ---------------------------------------------------------------------------
# Entegrasyon: _detect_algorithms Fortran false positive bastiriyor mu?
# ---------------------------------------------------------------------------


@pytest.fixture
def bi() -> BinaryIntelligence:
    return BinaryIntelligence(Config())


class TestDetectAlgorithmsFortranGate:
    def test_non_fortran_binary_no_fortran_match(self, bi: BinaryIntelligence) -> None:
        # Normal C binary'si -- Fortran algoritmasi raporlanmamali.
        all_text = [
            "main",
            "printf",
            "SHA256_Update",
            "AES_encrypt",
            "error: _gfortran_stop_string contiguous",  # tek kelime gecse de
        ]
        algorithms = bi._detect_algorithms(all_text)
        categories = {a.category for a in algorithms}
        assert "fortran_runtime" not in categories

    def test_real_fortran_binary_matches(self, bi: BinaryIntelligence) -> None:
        # Gercek Fortran binary'si -- Fortran runtime raporlanmali.
        all_text = [
            "_gfortran_main",
            "_gfortran_st_write",
            "_gfortran_transfer_real",
            "_gfortran_stop_string",
            "_gfortran_runtime_error",
        ]
        algorithms = bi._detect_algorithms(all_text)
        categories = {a.category for a in algorithms}
        assert "fortran_runtime" in categories


class TestFindAlgorithmsInCodeFortranGate:
    def test_code_without_fortran_markers_skipped(self, bi: BinaryIntelligence) -> None:
        # Decompiled C kodunda rastgele gecen "gfortran" kelimeleri
        # Fortran algoritmasi olarak raporlanmamali.
        code = """
        void main(void) {
            log_error("_gfortran_stop_string called from wrapper");
            sha256_init(&ctx);
        }
        """
        found = bi._find_algorithms_in_code(code)
        assert "gfortran Runtime" not in found
        assert "gfortran I/O" not in found

    def test_code_with_fortran_markers_detected(self, bi: BinaryIntelligence) -> None:
        code = """
        extern void _gfortran_main(int, char**);
        extern void _gfortran_st_write(void*);
        extern void _gfortran_transfer_real(void*);
        extern void _gfortran_stop_string(char*);
        _gfortran_runtime_error("boom");
        """
        found = bi._find_algorithms_in_code(code)
        # En az bir Fortran category esleşmeli (gate acik).
        assert any("gfortran" in name for name in found)
