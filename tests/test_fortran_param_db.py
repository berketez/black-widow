"""Tests for Fortran parameter DB and in_stack reconstruction.

Tests cover:
- FortranParamDB: gfortran runtime, BLAS, LAPACK param name lookups
- InStackReconstructor: ARM64 in_stack_XXXXXXXX -> param_N conversion
- FortranSourceParser: Fortran SUBROUTINE/FUNCTION source parsing
- APIParamDB Fortran integration: Fortran entries in unified DB
- c_namer strategy: fortran_in_stack strategy integration
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from karadul.reconstruction.fortran_param_db import (
    FortranParamDB,
    FortranSourceParser,
    InStackReconstructor,
    InStackResult,
    _ALL_FORTRAN_PARAMS,
    _BLAS_PARAMS,
    _GFORTRAN_RUNTIME_PARAMS,
    _LAPACK_PARAMS,
)


# ---------------------------------------------------------------------------
# FortranParamDB tests
# ---------------------------------------------------------------------------

class TestFortranParamDB:
    """FortranParamDB temel islevsellik testleri."""

    @pytest.fixture
    def db(self):
        return FortranParamDB()

    def test_gfortran_transfer_integer(self, db):
        """gfortran transfer fonksiyonlari dogru parametre isimlerine sahip olmali."""
        names = db.get_param_names("__gfortran_transfer_integer")
        assert names is not None
        assert names == ["unit_desc", "value", "kind"]

    def test_gfortran_single_underscore(self, db):
        """Tek underscore prefix de desteklenmeli."""
        names = db.get_param_names("_gfortran_transfer_real")
        assert names is not None
        assert names == ["unit_desc", "value", "kind"]

    def test_gfortran_st_write(self, db):
        names = db.get_param_names("__gfortran_st_write")
        assert names is not None
        assert names == ["unit_desc"]

    def test_gfortran_st_read_done(self, db):
        names = db.get_param_names("__gfortran_st_read_done")
        assert names is not None
        assert names == ["unit_desc"]

    def test_gfortran_compare_string(self, db):
        names = db.get_param_names("__gfortran_compare_string")
        assert names == ["len1", "s1", "len2", "s2"]

    def test_gfortran_pow(self, db):
        names = db.get_param_names("__gfortran_pow_i4_i4")
        assert names == ["base", "exponent"]

    def test_blas_dgemm(self, db):
        """DGEMM parametre sayisi ve isimleri dogru olmali."""
        names = db.get_param_names("_dgemm_")
        assert names is not None
        assert len(names) == 13
        assert names[0] == "transa"
        assert names[1] == "transb"
        assert names[2] == "m"
        assert names[3] == "n"
        assert names[4] == "k"
        assert names[5] == "alpha"

    def test_blas_dgemv(self, db):
        names = db.get_param_names("_dgemv_")
        assert names is not None
        assert len(names) == 11
        assert names[0] == "trans"
        assert names[-1] == "incy"

    def test_blas_daxpy(self, db):
        names = db.get_param_names("_daxpy_")
        assert names == ["n", "da", "dx", "incx", "dy", "incy"]

    def test_blas_ddot(self, db):
        names = db.get_param_names("_ddot_")
        assert names == ["n", "dx", "incx", "dy", "incy"]

    def test_blas_dnrm2(self, db):
        names = db.get_param_names("_dnrm2_")
        # CCX Fortran source override: "dx" (BLAS standard) vs simplified "x"
        assert names is not None
        assert len(names) == 3
        assert names[0] == "n"
        assert names[2] == "incx"

    def test_lapack_dgesv(self, db):
        """LAPACK DGESV parametre isimleri dogru olmali."""
        names = db.get_param_names("_dgesv_")
        assert names is not None
        assert len(names) == 8
        assert names[0] == "n"
        assert names[1] == "nrhs"
        assert names[-1] == "info"

    def test_lapack_dgetrf(self, db):
        names = db.get_param_names("_dgetrf_")
        assert names is not None
        assert "info" in names
        assert "ipiv" in names

    def test_lapack_dsyev(self, db):
        names = db.get_param_names("_dsyev_")
        assert names is not None
        assert names[0] == "jobz"
        assert names[1] == "uplo"

    def test_lapack_dgesvd(self, db):
        names = db.get_param_names("_dgesvd_")
        assert names is not None
        assert names[0] == "jobu"
        assert names[1] == "jobvt"
        assert names[-1] == "info"

    def test_unknown_function_returns_none(self, db):
        assert db.get_param_names("_nonexistent_func_") is None

    def test_is_fortran_function_trailing_underscore(self, db):
        """_name_ formatinda Fortran fonksiyon tespiti."""
        assert db.is_fortran_function("_results_")
        assert db.is_fortran_function("_mafillsmas_")
        assert db.is_fortran_function("_dgemm_")

    def test_is_fortran_function_gfortran(self, db):
        """gfortran runtime fonksiyonlari Fortran olarak tespiti."""
        assert db.is_fortran_function("__gfortran_st_write")
        assert db.is_fortran_function("_gfortran_transfer_real")

    def test_is_fortran_function_negative(self, db):
        """Normal C fonksiyonlari Fortran olarak tespit edilmemeli."""
        assert not db.is_fortran_function("malloc")
        assert not db.is_fortran_function("printf")
        assert not db.is_fortran_function("_main")  # tek underscore, sonda yok

    def test_is_fortran_function_double_underscore(self, db):
        """__name_ formatindaki (C++ mangled) fonksiyonlar Fortran degil."""
        assert not db.is_fortran_function("__ZN3foo3barEv")

    def test_has_gfortran_callees(self, db):
        callees = ["_malloc", "__gfortran_st_write", "_printf"]
        assert db.has_gfortran_callees(callees)

    def test_has_gfortran_callees_negative(self, db):
        callees = ["_malloc", "_printf", "_exit"]
        assert not db.has_gfortran_callees(callees)

    def test_register(self, db):
        """Yeni fonksiyon kaydedebilmeli."""
        db.register("_my_fortran_func_", ["a", "b", "c"])
        assert db.get_param_names("_my_fortran_func_") == ["a", "b", "c"]

    def test_register_batch(self, db):
        db.register_batch({
            "_func_a_": ["x", "y"],
            "_func_b_": ["p", "q", "r"],
        })
        assert db.get_param_names("_func_a_") == ["x", "y"]
        assert db.get_param_names("_func_b_") == ["p", "q", "r"]

    def test_contains(self, db):
        assert "_dgemm_" in db
        assert "_nonexistent_" not in db

    def test_len(self, db):
        assert len(db) > 100  # BLAS + LAPACK + gfortran = 100+ entry


# ---------------------------------------------------------------------------
# InStackReconstructor tests
# ---------------------------------------------------------------------------

class TestInStackReconstructor:
    """ARM64 in_stack reconstruction testleri."""

    @pytest.fixture
    def recon(self):
        return InStackReconstructor()

    def test_basic_in_stack_detection(self, recon):
        """Temel in_stack variable tespiti."""
        code = textwrap.dedent("""\
            void _test_func_(long param_1, long param_2)
            {
              long in_stack_00000010;
              long in_stack_00000018;
              undefined8 in_stack_00000020;
              int iVar1;
              iVar1 = (int)in_stack_00000010;
            }
        """)
        vars = recon.detect_in_stack_vars(code)
        assert len(vars) == 3
        assert vars[0] == ("in_stack_00000010", 0x10, "long")
        assert vars[1] == ("in_stack_00000018", 0x18, "long")
        assert vars[2] == ("in_stack_00000020", 0x20, "undefined8")

    def test_in_stack_with_pointer_types(self, recon):
        """Pointer tipleri de dogru parse edilmeli."""
        code = textwrap.dedent("""\
            void _func_(long param_1)
            {
              int *in_stack_00000010;
              long in_stack_00000018;
              int *in_stack_00000020;
            }
        """)
        vars = recon.detect_in_stack_vars(code)
        assert len(vars) == 3
        assert vars[0][2] == "int *"
        assert vars[1][2] == "long"
        assert vars[2][2] == "int *"

    def test_count_signature_params(self, recon):
        """Fonksiyon signature parametre sayisi dogru sayilmali."""
        code = "void _mafillsmas_(undefined8 param_1,undefined8 param_2,long param_3,long param_4,long param_5)"
        name, count = recon.count_signature_params(code)
        assert name == "_mafillsmas_"
        assert count == 5

    def test_count_signature_params_void(self, recon):
        code = "void _simple_func_(void)"
        name, count = recon.count_signature_params(code)
        assert name == "_simple_func_"
        assert count == 0

    def test_count_signature_params_empty(self, recon):
        code = "int _func_()"
        name, count = recon.count_signature_params(code)
        assert name == "_func_"
        assert count == 0

    def test_reconstruct_basic(self, recon):
        """Temel in_stack -> param_N donusumu."""
        code = textwrap.dedent("""\
            void _test_func_(long param_1, long param_2, long param_3,
                            long param_4, long param_5)
            {
              long in_stack_00000010;
              long in_stack_00000018;
              undefined8 in_stack_00000020;
              int iVar1;
              iVar1 = (int)in_stack_00000010 + (int)in_stack_00000018;
              if (in_stack_00000020 != 0) {
                return;
              }
            }
        """)
        result = recon.reconstruct(code)
        assert result.success
        assert result.function_name == "_test_func_"
        assert result.register_param_count == 5
        assert result.in_stack_count == 3
        assert len(result.mappings) == 3

        # Mapping kontrolu
        assert result.mappings[0].in_stack_name == "in_stack_00000010"
        assert result.mappings[0].param_name == "param_6"
        assert result.mappings[0].param_index == 6

        assert result.mappings[1].param_name == "param_7"
        assert result.mappings[2].param_name == "param_8"

        # Renamed code kontrolu
        assert "in_stack_00000010" not in result.renamed_code
        assert "param_6" in result.renamed_code
        assert "param_7" in result.renamed_code
        assert "param_8" in result.renamed_code
        assert "iVar1" in result.renamed_code  # diger degiskenler dokunulmamali

    def test_reconstruct_no_in_stack(self, recon):
        """in_stack yoksa bos sonuc donmeli."""
        code = textwrap.dedent("""\
            void _simple_(long param_1)
            {
              int iVar1;
              iVar1 = (int)param_1;
            }
        """)
        result = recon.reconstruct(code)
        assert result.success
        assert result.in_stack_count == 0
        assert result.renamed_code == code

    def test_reconstruct_preserves_original_params(self, recon):
        """in_stack rename, mevcut param_N'lere dokunmamali."""
        code = textwrap.dedent("""\
            void _func_(long param_1, long param_2)
            {
              long in_stack_00000010;
              int x = (int)param_1 + (int)param_2 + (int)in_stack_00000010;
            }
        """)
        result = recon.reconstruct(code)
        assert result.success
        assert "param_1" in result.renamed_code
        assert "param_2" in result.renamed_code
        assert "param_3" in result.renamed_code
        assert "in_stack_00000010" not in result.renamed_code

    def test_reconstruct_sorted_by_offset(self, recon):
        """in_stack'ler offset sirasina gore param_N almali."""
        code = textwrap.dedent("""\
            void _func_(long param_1)
            {
              undefined8 in_stack_00000030;
              undefined8 in_stack_00000010;
              undefined8 in_stack_00000020;
            }
        """)
        result = recon.reconstruct(code)
        assert result.success
        # Offset sirasina gore: 0x10 -> param_2, 0x20 -> param_3, 0x30 -> param_4
        assert result.mappings[0].offset == 0x10
        assert result.mappings[0].param_name == "param_2"
        assert result.mappings[1].offset == 0x20
        assert result.mappings[1].param_name == "param_3"
        assert result.mappings[2].offset == 0x30
        assert result.mappings[2].param_name == "param_4"

    def test_reconstruct_no_signature(self, recon):
        """Fonksiyon signature bulunamazsa hata donmeli."""
        code = "// no function here\nint x = 5;"
        result = recon.reconstruct(code)
        assert not result.success
        assert "bulunamadi" in result.errors[0].lower() or "signature" in result.errors[0].lower()

    def test_reconstruct_with_names_from_db(self, recon):
        """FortranParamDB'den bilinen isimler uygulanmali."""
        # Once DB'ye gercek parametre isimleri ekle
        recon.fortran_db.register("_test_func_", [
            "co", "nkon", "nelem", "kon", "ipkon",  # param_1..5
            "lakon", "ne", "nkon2",  # param_6..8 (in_stack)
        ])

        code = textwrap.dedent("""\
            void _test_func_(long param_1, long param_2, long param_3,
                            long param_4, long param_5)
            {
              long in_stack_00000010;
              long in_stack_00000018;
              undefined8 in_stack_00000020;
              int x = (int)param_1 + (int)in_stack_00000010;
            }
        """)
        result = recon.reconstruct_with_names(code)
        assert result.success
        # in_stack -> param_6..8, sonra tum param'lar isimlendirilmeli
        assert "co" in result.renamed_code      # param_1 -> co
        assert "nkon" in result.renamed_code     # param_2 -> nkon
        assert "lakon" in result.renamed_code    # param_6 -> lakon (in_stack_00000010)

    def test_reconstruct_with_explicit_names(self, recon):
        """Acik parametre isim listesi verildiginde uygulanmali."""
        code = textwrap.dedent("""\
            void _func_(long param_1, long param_2)
            {
              long in_stack_00000010;
              int x = (int)param_1 + (int)in_stack_00000010;
            }
        """)
        result = recon.reconstruct_with_names(
            code,
            source_param_names=["matrix", "size", "result"],
        )
        assert result.success
        assert "matrix" in result.renamed_code
        assert "size" in result.renamed_code
        assert "result" in result.renamed_code

    def test_mafillsmas_like_reconstruction(self, recon):
        """CalculiX _mafillsmas_ benzeri 5 register + cok in_stack."""
        code = textwrap.dedent("""\
            void _mafillsmas_(undefined8 param_1,undefined8 param_2,long param_3,long param_4,long param_5)

            {
              long in_stack_00000010;
              long in_stack_00000018;
              long in_stack_00000020;
              int *in_stack_00000028;
              undefined8 in_stack_00000050;
              undefined8 in_stack_00000058;
              int iVar1;
              iVar1 = (int)in_stack_00000010;
            }
        """)
        result = recon.reconstruct(code)
        assert result.success
        assert result.function_name == "_mafillsmas_"
        assert result.register_param_count == 5
        assert result.in_stack_count == 6
        assert result.mappings[0].param_name == "param_6"
        assert result.mappings[5].param_name == "param_11"


# ---------------------------------------------------------------------------
# FortranSourceParser tests
# ---------------------------------------------------------------------------

class TestFortranSourceParser:
    """Fortran kaynak kodu parse testleri."""

    @pytest.fixture
    def parser(self):
        return FortranSourceParser()

    def test_simple_subroutine(self, parser):
        """Basit SUBROUTINE parse."""
        text = "      SUBROUTINE RESULTS(CO,NKON,NELEM,KON,IPKON,LAKON,NE)\n"
        entries = parser.parse_text(text)
        assert len(entries) == 1
        assert entries[0].fortran_name == "RESULTS"
        assert entries[0].c_symbol == "_results_"
        assert entries[0].param_names == ["co", "nkon", "nelem", "kon", "ipkon", "lakon", "ne"]

    def test_subroutine_lowercase(self, parser):
        """Kucuk harfli subroutine da parse edilmeli."""
        text = "      subroutine mafillsmas(co,nk,ne,kon,ipkon)\n"
        entries = parser.parse_text(text)
        assert len(entries) == 1
        assert entries[0].c_symbol == "_mafillsmas_"
        assert entries[0].param_names == ["co", "nk", "ne", "kon", "ipkon"]

    def test_function_with_type(self, parser):
        """Type prefix'li FUNCTION parse."""
        text = "      DOUBLE PRECISION FUNCTION DNRM2(N,X,INCX)\n"
        entries = parser.parse_text(text)
        assert len(entries) == 1
        assert entries[0].fortran_name == "DNRM2"
        assert entries[0].c_symbol == "_dnrm2_"
        assert entries[0].param_names == ["n", "x", "incx"]

    def test_function_without_type(self, parser):
        text = "      FUNCTION MYFUNC(A, B, C)\n"
        entries = parser.parse_text(text)
        assert len(entries) == 1
        assert entries[0].c_symbol == "_myfunc_"

    def test_subroutine_no_params(self, parser):
        text = "      SUBROUTINE INIT()\n"
        entries = parser.parse_text(text)
        assert len(entries) == 1
        assert entries[0].param_names == []

    def test_multiple_subroutines(self, parser):
        """Birden fazla SUBROUTINE parse."""
        text = textwrap.dedent("""\
              SUBROUTINE FUNC_A(X, Y)
              IMPLICIT NONE
              DOUBLE PRECISION X, Y
              RETURN
              END

              SUBROUTINE FUNC_B(A, B, C, D)
              IMPLICIT NONE
              INTEGER A, B, C, D
              RETURN
              END
        """)
        entries = parser.parse_text(text)
        assert len(entries) == 2
        assert entries[0].c_symbol == "_func_a_"
        assert entries[0].param_names == ["x", "y"]
        assert entries[1].c_symbol == "_func_b_"
        assert entries[1].param_names == ["a", "b", "c", "d"]

    def test_comment_lines_skipped(self, parser):
        """Comment satirlari atlanmali."""
        text = textwrap.dedent("""\
        C     This is a comment
        c     This too
        *     And this
              SUBROUTINE REAL_FUNC(X)
              RETURN
              END
        """)
        entries = parser.parse_text(text)
        assert len(entries) == 1
        assert entries[0].c_symbol == "_real_func_"

    def test_continuation_lines(self, parser):
        """Fortran fixed-form continuation satirlari birlesmeli."""
        text = (
            "      SUBROUTINE LONGFUNC(A, B, C,\n"
            "     &                    D, E, F)\n"
            "      RETURN\n"
            "      END\n"
        )
        entries = parser.parse_text(text)
        assert len(entries) == 1
        assert entries[0].param_names == ["a", "b", "c", "d", "e", "f"]

    def test_parse_file(self, parser, tmp_path):
        """Dosyadan parse etme."""
        f = tmp_path / "test.f"
        f.write_text(
            "      SUBROUTINE TEST(X,Y,Z)\n"
            "      RETURN\n"
            "      END\n"
        )
        entries = parser.parse_file(f)
        assert len(entries) == 1
        assert entries[0].c_symbol == "_test_"
        assert entries[0].source_file == str(f)

    def test_parse_file_not_found(self, parser):
        with pytest.raises(FileNotFoundError):
            parser.parse_file(Path("/nonexistent/file.f"))

    def test_parse_directory(self, parser, tmp_path):
        """Dizinden toplu parse."""
        (tmp_path / "a.f").write_text(
            "      SUBROUTINE FUNC_A(X)\n"
            "      END\n"
        )
        (tmp_path / "b.f90").write_text(
            "subroutine func_b(y, z)\n"
            "end subroutine\n"
        )
        entries = parser.parse_directory(tmp_path)
        assert len(entries) == 2

    def test_build_param_db(self, parser):
        """Entry listesinden dict uretme."""
        text = textwrap.dedent("""\
              SUBROUTINE FUNC_A(X, Y)
              END
              SUBROUTINE FUNC_B(P, Q, R)
              END
        """)
        entries = parser.parse_text(text)
        db = parser.build_param_db(entries)
        assert db == {
            "_func_a_": ["x", "y"],
            "_func_b_": ["p", "q", "r"],
        }


# ---------------------------------------------------------------------------
# APIParamDB Fortran entegrasyonu testi
# ---------------------------------------------------------------------------

class TestAPIParamDBFortranIntegration:
    """Fortran parametreleri APIParamDB'ye entegre edilmis mi?"""

    def test_fortran_in_api_param_db(self):
        from karadul.reconstruction.api_param_db import APIParamDB
        db = APIParamDB()
        # gfortran runtime fonksiyonu
        assert db.get_param_names("__gfortran_transfer_integer") is not None
        # BLAS
        assert db.get_param_names("_dgemm_") is not None
        # LAPACK
        assert db.get_param_names("_dgesv_") is not None

    def test_posix_still_works(self):
        """Fortran eklenmesi mevcut POSIX parametrelerini bozmamalı."""
        from karadul.reconstruction.api_param_db import APIParamDB
        db = APIParamDB()
        assert db.get_param_names("malloc") == ["size"]
        assert db.get_param_names("send") == ["sockfd", "buf", "len", "flags"]

    def test_no_duplicate_overwrite(self):
        """Fortran eklenmesi POSIX'teki ayni isimli fonksiyonlari ezmemeli."""
        from karadul.reconstruction.api_param_db import APIParamDB
        db = APIParamDB()
        # "write" POSIX'te var: ["fd", "buf", "count"]
        # Fortran'da yok (gfortran runtime isimleri farkli)
        assert db.get_param_names("write") == ["fd", "buf", "count"]


# ---------------------------------------------------------------------------
# Param DB consistency
# ---------------------------------------------------------------------------

class TestParamDBConsistency:
    """Parametrik veritabani tutarliligi testleri."""

    def test_blas_dgemm_13_params(self):
        """DGEMM her zaman 13 parametreye sahip olmali."""
        assert len(_BLAS_PARAMS["_dgemm_"]) == 13

    def test_blas_dgemv_11_params(self):
        assert len(_BLAS_PARAMS["_dgemv_"]) == 11

    def test_blas_daxpy_6_params(self):
        assert len(_BLAS_PARAMS["_daxpy_"]) == 6

    def test_lapack_dgesv_8_params(self):
        assert len(_LAPACK_PARAMS["_dgesv_"]) == 8

    def test_gfortran_transfer_3_params(self):
        assert len(_GFORTRAN_RUNTIME_PARAMS["__gfortran_transfer_integer"]) == 3
        assert len(_GFORTRAN_RUNTIME_PARAMS["__gfortran_transfer_real"]) == 3

    def test_all_fortran_params_merged(self):
        """_ALL_FORTRAN_PARAMS tum kaynaklarin birlesimi olmali."""
        for key in _GFORTRAN_RUNTIME_PARAMS:
            assert key in _ALL_FORTRAN_PARAMS
        for key in _BLAS_PARAMS:
            assert key in _ALL_FORTRAN_PARAMS
        for key in _LAPACK_PARAMS:
            assert key in _ALL_FORTRAN_PARAMS

    def test_single_and_double_underscore_gfortran(self):
        """Her gfortran fonksiyonu hem __ hem _ prefix ile bulunmali."""
        for key in list(_GFORTRAN_RUNTIME_PARAMS.keys()):
            if key.startswith("__gfortran_"):
                single = key.replace("__gfortran_", "_gfortran_", 1)
                assert single in _GFORTRAN_RUNTIME_PARAMS, f"{single} eksik"
            elif key.startswith("_gfortran_"):
                double = key.replace("_gfortran_", "__gfortran_", 1)
                assert double in _GFORTRAN_RUNTIME_PARAMS, f"{double} eksik"
