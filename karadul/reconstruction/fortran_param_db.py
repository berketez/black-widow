"""Fortran Parametre Veritabani ve in_stack Reconstruction -- Karadul v1.7

Fortran->C derlenmis bilimsel binary'lerde (CalculiX, OpenFOAM, ABAQUS):
  1. gfortran runtime fonksiyonlarinin parametre isimlerini tutar
  2. BLAS/LAPACK rutinlerinin parametre isimlerini tutar
  3. ARM64 in_stack_XXXXXXXX degiskenlerini param_N formatina donusturur
  4. Opsiyonel: Fortran SUBROUTINE kaynak kodundan parametre isim DB'si uretir

Arka plan:
  Fortran SUBROUTINE isimleri C symbol'e _isim_ (trailing underscore) seklinde
  derlenir. ARM64'te ilk 8 parametre register'da (x0-x7, param_1..param_8),
  fazlasi stack'te gecirilir. Ghidra bunlari in_stack_XXXXXXXX olarak gosterir.

Kullanim:
    from karadul.reconstruction.fortran_param_db import (
        FortranParamDB,
        InStackReconstructor,
        FortranSourceParser,
    )

    # 1. Parametre DB
    db = FortranParamDB()
    names = db.get_param_names("_dgemm_")
    # -> ["transa", "transb", "m", "n", "k", "alpha", "a", "lda", "b", "ldb",
    #     "beta", "c", "ldc"]

    # 2. in_stack reconstruction
    recon = InStackReconstructor()
    result = recon.reconstruct(c_code)
    # in_stack_00000010 -> param_9, in_stack_00000018 -> param_10, ...

    # 3. Fortran kaynak parser (opsiyonel)
    parser = FortranSourceParser()
    entries = parser.parse_file(Path("results.f"))
    # {"_results_": ["co", "nkon", "nelem", "kon", "ipkon", "lakon", "ne"]}
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------
# gfortran runtime I/O
# ---------------------------------------------------------------
_GFORTRAN_RUNTIME_PARAMS: dict[str, list[str]] = {
    # Formatted I/O - write
    "__gfortran_st_write": ["unit_desc"],
    "_gfortran_st_write": ["unit_desc"],
    "__gfortran_st_write_done": ["unit_desc"],
    "_gfortran_st_write_done": ["unit_desc"],
    # Formatted I/O - read
    "__gfortran_st_read": ["unit_desc"],
    "_gfortran_st_read": ["unit_desc"],
    "__gfortran_st_read_done": ["unit_desc"],
    "_gfortran_st_read_done": ["unit_desc"],
    # Formatted I/O - print
    "__gfortran_st_open": ["unit_desc"],
    "_gfortran_st_open": ["unit_desc"],
    "__gfortran_st_close": ["unit_desc"],
    "_gfortran_st_close": ["unit_desc"],
    "__gfortran_st_rewind": ["unit_desc"],
    "_gfortran_st_rewind": ["unit_desc"],
    "__gfortran_st_backspace": ["unit_desc"],
    "_gfortran_st_backspace": ["unit_desc"],
    "__gfortran_st_inquire": ["unit_desc"],
    "_gfortran_st_inquire": ["unit_desc"],

    # Transfer functions (veri okuma/yazma)
    "__gfortran_transfer_integer": ["unit_desc", "value", "kind"],
    "_gfortran_transfer_integer": ["unit_desc", "value", "kind"],
    "__gfortran_transfer_integer_write": ["unit_desc", "value", "kind"],
    "_gfortran_transfer_integer_write": ["unit_desc", "value", "kind"],
    "__gfortran_transfer_real": ["unit_desc", "value", "kind"],
    "_gfortran_transfer_real": ["unit_desc", "value", "kind"],
    "__gfortran_transfer_real_write": ["unit_desc", "value", "kind"],
    "_gfortran_transfer_real_write": ["unit_desc", "value", "kind"],
    "__gfortran_transfer_complex": ["unit_desc", "value", "kind"],
    "_gfortran_transfer_complex": ["unit_desc", "value", "kind"],
    "__gfortran_transfer_complex_write": ["unit_desc", "value", "kind"],
    "_gfortran_transfer_complex_write": ["unit_desc", "value", "kind"],
    "__gfortran_transfer_character": ["unit_desc", "value", "len"],
    "_gfortran_transfer_character": ["unit_desc", "value", "len"],
    "__gfortran_transfer_character_write": ["unit_desc", "value", "len"],
    "_gfortran_transfer_character_write": ["unit_desc", "value", "len"],
    "__gfortran_transfer_character_wide": ["unit_desc", "value", "len", "kind"],
    "_gfortran_transfer_character_wide": ["unit_desc", "value", "len", "kind"],
    "__gfortran_transfer_logical": ["unit_desc", "value", "kind"],
    "_gfortran_transfer_logical": ["unit_desc", "value", "kind"],
    "__gfortran_transfer_logical_write": ["unit_desc", "value", "kind"],
    "_gfortran_transfer_logical_write": ["unit_desc", "value", "kind"],
    "__gfortran_transfer_array": ["unit_desc", "desc", "kind", "charlen"],
    "_gfortran_transfer_array": ["unit_desc", "desc", "kind", "charlen"],
    "__gfortran_transfer_array_write": ["unit_desc", "desc", "kind", "charlen"],
    "_gfortran_transfer_array_write": ["unit_desc", "desc", "kind", "charlen"],

    # String operations
    "__gfortran_compare_string": ["len1", "s1", "len2", "s2"],
    "_gfortran_compare_string": ["len1", "s1", "len2", "s2"],
    "__gfortran_concat_string": ["destlen", "dest", "len1", "s1", "len2", "s2"],
    "_gfortran_concat_string": ["destlen", "dest", "len1", "s1", "len2", "s2"],
    "__gfortran_string_trim": ["destlen", "dest", "srclen", "src"],
    "_gfortran_string_trim": ["destlen", "dest", "srclen", "src"],
    "__gfortran_adjustl": ["dest", "destlen", "src", "srclen"],
    "_gfortran_adjustl": ["dest", "destlen", "src", "srclen"],
    "__gfortran_adjustr": ["dest", "destlen", "src", "srclen"],
    "_gfortran_adjustr": ["dest", "destlen", "src", "srclen"],
    "__gfortran_string_index": ["slen", "s", "sslen", "ss", "back"],
    "_gfortran_string_index": ["slen", "s", "sslen", "ss", "back"],
    "__gfortran_string_len_trim": ["len", "s"],
    "_gfortran_string_len_trim": ["len", "s"],
    "__gfortran_copy_string": ["destlen", "dest", "srclen", "src"],
    "_gfortran_copy_string": ["destlen", "dest", "srclen", "src"],

    # Math intrinsics
    "__gfortran_pow_i4_i4": ["base", "exponent"],
    "_gfortran_pow_i4_i4": ["base", "exponent"],
    "__gfortran_pow_i8_i4": ["base", "exponent"],
    "_gfortran_pow_i8_i4": ["base", "exponent"],
    "__gfortran_pow_r4_i4": ["base", "exponent"],
    "_gfortran_pow_r4_i4": ["base", "exponent"],
    "__gfortran_pow_r8_i4": ["base", "exponent"],
    "_gfortran_pow_r8_i4": ["base", "exponent"],
    "__gfortran_pow_c4_i4": ["base", "exponent"],
    "_gfortran_pow_c4_i4": ["base", "exponent"],
    "__gfortran_pow_c8_i4": ["base", "exponent"],
    "_gfortran_pow_c8_i4": ["base", "exponent"],
    "__gfortran_specific__abs_r8": ["x"],
    "_gfortran_specific__abs_r8": ["x"],
    "__gfortran_specific__abs_r4": ["x"],
    "_gfortran_specific__abs_r4": ["x"],
    "__gfortran_specific__sqrt_r8": ["x"],
    "_gfortran_specific__sqrt_r8": ["x"],
    "__gfortran_specific__exp_r8": ["x"],
    "_gfortran_specific__exp_r8": ["x"],
    "__gfortran_specific__log_r8": ["x"],
    "_gfortran_specific__log_r8": ["x"],

    # Error handling / STOP
    "__gfortran_runtime_error": ["message"],
    "_gfortran_runtime_error": ["message"],
    "__gfortran_runtime_error_at": ["where", "message"],
    "_gfortran_runtime_error_at": ["where", "message"],
    "__gfortran_os_error": ["message"],
    "_gfortran_os_error": ["message"],
    "__gfortran_stop_string": ["message", "len"],
    "_gfortran_stop_string": ["message", "len"],
    "__gfortran_stop_numeric": ["code"],
    "_gfortran_stop_numeric": ["code"],
    "__gfortran_exit_i4": ["status"],
    "_gfortran_exit_i4": ["status"],

    # Memory allocation
    "__gfortran_allocate": ["size", "stat"],
    "_gfortran_allocate": ["size", "stat"],
    "__gfortran_allocate_array": ["desc", "size", "stat"],
    "_gfortran_allocate_array": ["desc", "size", "stat"],
    "__gfortran_deallocate": ["ptr", "stat"],
    "_gfortran_deallocate": ["ptr", "stat"],

    # Array intrinsics
    "__gfortran_reshape": ["ret", "source", "shape", "pad", "order"],
    "_gfortran_reshape": ["ret", "source", "shape", "pad", "order"],
    "__gfortran_spread": ["ret", "source", "dim", "ncopies"],
    "_gfortran_spread": ["ret", "source", "dim", "ncopies"],
    "__gfortran_pack": ["ret", "array", "mask", "vector"],
    "_gfortran_pack": ["ret", "array", "mask", "vector"],
    "__gfortran_unpack0": ["ret", "vector", "mask", "field"],
    "_gfortran_unpack0": ["ret", "vector", "mask", "field"],

    # Reduction intrinsics
    "__gfortran_sum_r8": ["ret", "array", "dim", "mask"],
    "_gfortran_sum_r8": ["ret", "array", "dim", "mask"],
    "__gfortran_maxval_r8": ["ret", "array", "dim", "mask"],
    "_gfortran_maxval_r8": ["ret", "array", "dim", "mask"],
    "__gfortran_minval_r8": ["ret", "array", "dim", "mask"],
    "_gfortran_minval_r8": ["ret", "array", "dim", "mask"],
    "__gfortran_product_r8": ["ret", "array", "dim", "mask"],
    "_gfortran_product_r8": ["ret", "array", "dim", "mask"],
    "__gfortran_matmul_r8": ["retarray", "a", "b"],
    "_gfortran_matmul_r8": ["retarray", "a", "b"],
    "__gfortran_matmul_r4": ["retarray", "a", "b"],
    "_gfortran_matmul_r4": ["retarray", "a", "b"],

    # Date/time
    "__gfortran_system_clock_4": ["count", "rate", "max"],
    "_gfortran_system_clock_4": ["count", "rate", "max"],
    "__gfortran_system_clock_8": ["count", "rate", "max"],
    "_gfortran_system_clock_8": ["count", "rate", "max"],
    "__gfortran_cpu_time_4": ["time"],
    "_gfortran_cpu_time_4": ["time"],
    "__gfortran_cpu_time_8": ["time"],
    "_gfortran_cpu_time_8": ["time"],
    "__gfortran_date_and_time": ["date", "time", "zone", "values"],
    "_gfortran_date_and_time": ["date", "time", "zone", "values"],
}


# ---------------------------------------------------------------
# BLAS (Basic Linear Algebra Subprograms)
# ---------------------------------------------------------------
_BLAS_PARAMS: dict[str, list[str]] = {
    # Level 1 BLAS
    "_dscal_": ["n", "da", "dx", "incx"],
    "_sscal_": ["n", "sa", "sx", "incx"],
    "_dcopy_": ["n", "dx", "incx", "dy", "incy"],
    "_scopy_": ["n", "sx", "incx", "sy", "incy"],
    "_daxpy_": ["n", "da", "dx", "incx", "dy", "incy"],
    "_saxpy_": ["n", "sa", "sx", "incx", "sy", "incy"],
    "_ddot_": ["n", "dx", "incx", "dy", "incy"],
    "_sdot_": ["n", "sx", "incx", "sy", "incy"],
    "_dnrm2_": ["n", "x", "incx"],
    "_snrm2_": ["n", "x", "incx"],
    "_dasum_": ["n", "dx", "incx"],
    "_sasum_": ["n", "sx", "incx"],
    "_idamax_": ["n", "dx", "incx"],
    "_isamax_": ["n", "sx", "incx"],
    "_dswap_": ["n", "dx", "incx", "dy", "incy"],
    "_sswap_": ["n", "sx", "incx", "sy", "incy"],
    "_drot_": ["n", "dx", "incx", "dy", "incy", "c", "s"],
    "_srot_": ["n", "sx", "incx", "sy", "incy", "c", "s"],
    "_drotg_": ["da", "db", "c", "s"],
    "_srotg_": ["sa", "sb", "c", "s"],

    # Level 2 BLAS
    "_dgemv_": ["trans", "m", "n", "alpha", "a", "lda", "x", "incx",
                "beta", "y", "incy"],
    "_sgemv_": ["trans", "m", "n", "alpha", "a", "lda", "x", "incx",
                "beta", "y", "incy"],
    "_dsymv_": ["uplo", "n", "alpha", "a", "lda", "x", "incx",
                "beta", "y", "incy"],
    "_ssymv_": ["uplo", "n", "alpha", "a", "lda", "x", "incx",
                "beta", "y", "incy"],
    "_dtrmv_": ["uplo", "trans", "diag", "n", "a", "lda", "x", "incx"],
    "_strmv_": ["uplo", "trans", "diag", "n", "a", "lda", "x", "incx"],
    "_dtrsv_": ["uplo", "trans", "diag", "n", "a", "lda", "x", "incx"],
    "_strsv_": ["uplo", "trans", "diag", "n", "a", "lda", "x", "incx"],
    "_dger_": ["m", "n", "alpha", "x", "incx", "y", "incy", "a", "lda"],
    "_sger_": ["m", "n", "alpha", "x", "incx", "y", "incy", "a", "lda"],
    "_dsyr_": ["uplo", "n", "alpha", "x", "incx", "a", "lda"],
    "_ssyr_": ["uplo", "n", "alpha", "x", "incx", "a", "lda"],
    "_dsyr2_": ["uplo", "n", "alpha", "x", "incx", "y", "incy", "a", "lda"],
    "_ssyr2_": ["uplo", "n", "alpha", "x", "incx", "y", "incy", "a", "lda"],

    # Level 3 BLAS
    "_dgemm_": ["transa", "transb", "m", "n", "k", "alpha", "a", "lda",
                "b", "ldb", "beta", "c", "ldc"],
    "_sgemm_": ["transa", "transb", "m", "n", "k", "alpha", "a", "lda",
                "b", "ldb", "beta", "c", "ldc"],
    "_dsymm_": ["side", "uplo", "m", "n", "alpha", "a", "lda",
                "b", "ldb", "beta", "c", "ldc"],
    "_ssymm_": ["side", "uplo", "m", "n", "alpha", "a", "lda",
                "b", "ldb", "beta", "c", "ldc"],
    "_dsyrk_": ["uplo", "trans", "n", "k", "alpha", "a", "lda",
                "beta", "c", "ldc"],
    "_ssyrk_": ["uplo", "trans", "n", "k", "alpha", "a", "lda",
                "beta", "c", "ldc"],
    "_dsyr2k_": ["uplo", "trans", "n", "k", "alpha", "a", "lda",
                 "b", "ldb", "beta", "c", "ldc"],
    "_ssyr2k_": ["uplo", "trans", "n", "k", "alpha", "a", "lda",
                 "b", "ldb", "beta", "c", "ldc"],
    "_dtrmm_": ["side", "uplo", "transa", "diag", "m", "n", "alpha",
                "a", "lda", "b", "ldb"],
    "_strmm_": ["side", "uplo", "transa", "diag", "m", "n", "alpha",
                "a", "lda", "b", "ldb"],
    "_dtrsm_": ["side", "uplo", "transa", "diag", "m", "n", "alpha",
                "a", "lda", "b", "ldb"],
    "_strsm_": ["side", "uplo", "transa", "diag", "m", "n", "alpha",
                "a", "lda", "b", "ldb"],
}


# ---------------------------------------------------------------
# LAPACK (Linear Algebra PACKage)
# ---------------------------------------------------------------
_LAPACK_PARAMS: dict[str, list[str]] = {
    # Linear solve
    "_dgesv_": ["n", "nrhs", "a", "lda", "ipiv", "b", "ldb", "info"],
    "_sgesv_": ["n", "nrhs", "a", "lda", "ipiv", "b", "ldb", "info"],
    "_dposv_": ["uplo", "n", "nrhs", "a", "lda", "b", "ldb", "info"],
    "_sposv_": ["uplo", "n", "nrhs", "a", "lda", "b", "ldb", "info"],

    # LU factorization
    "_dgetrf_": ["m", "n", "a", "lda", "ipiv", "info"],
    "_sgetrf_": ["m", "n", "a", "lda", "ipiv", "info"],
    "_dgetrs_": ["trans", "n", "nrhs", "a", "lda", "ipiv", "b", "ldb", "info"],
    "_sgetrs_": ["trans", "n", "nrhs", "a", "lda", "ipiv", "b", "ldb", "info"],
    "_dgetri_": ["n", "a", "lda", "ipiv", "work", "lwork", "info"],
    "_sgetri_": ["n", "a", "lda", "ipiv", "work", "lwork", "info"],

    # Cholesky
    "_dpotrf_": ["uplo", "n", "a", "lda", "info"],
    "_spotrf_": ["uplo", "n", "a", "lda", "info"],
    "_dpotrs_": ["uplo", "n", "nrhs", "a", "lda", "b", "ldb", "info"],
    "_spotrs_": ["uplo", "n", "nrhs", "a", "lda", "b", "ldb", "info"],

    # QR factorization
    "_dgeqrf_": ["m", "n", "a", "lda", "tau", "work", "lwork", "info"],
    "_sgeqrf_": ["m", "n", "a", "lda", "tau", "work", "lwork", "info"],
    "_dorgqr_": ["m", "n", "k", "a", "lda", "tau", "work", "lwork", "info"],
    "_sorgqr_": ["m", "n", "k", "a", "lda", "tau", "work", "lwork", "info"],

    # Eigenvalue
    "_dsyev_": ["jobz", "uplo", "n", "a", "lda", "w", "work", "lwork", "info"],
    "_ssyev_": ["jobz", "uplo", "n", "a", "lda", "w", "work", "lwork", "info"],
    "_dsyevd_": ["jobz", "uplo", "n", "a", "lda", "w", "work", "lwork",
                 "iwork", "liwork", "info"],
    "_dgeev_": ["jobvl", "jobvr", "n", "a", "lda", "wr", "wi",
                "vl", "ldvl", "vr", "ldvr", "work", "lwork", "info"],
    "_sgeev_": ["jobvl", "jobvr", "n", "a", "lda", "wr", "wi",
                "vl", "ldvl", "vr", "ldvr", "work", "lwork", "info"],

    # SVD
    "_dgesvd_": ["jobu", "jobvt", "m", "n", "a", "lda", "s",
                 "u", "ldu", "vt", "ldvt", "work", "lwork", "info"],
    "_sgesvd_": ["jobu", "jobvt", "m", "n", "a", "lda", "s",
                 "u", "ldu", "vt", "ldvt", "work", "lwork", "info"],
    "_dgesdd_": ["jobz", "m", "n", "a", "lda", "s",
                 "u", "ldu", "vt", "ldvt", "work", "lwork", "iwork", "info"],

    # Banded
    "_dgbsv_": ["n", "kl", "ku", "nrhs", "ab", "ldab", "ipiv", "b", "ldb", "info"],
    "_dgbtrf_": ["m", "n", "kl", "ku", "ab", "ldab", "ipiv", "info"],
    "_dgbtrs_": ["trans", "n", "kl", "ku", "nrhs", "ab", "ldab",
                 "ipiv", "b", "ldb", "info"],

    # Tridiagonal
    "_dgtsv_": ["n", "nrhs", "dl", "d", "du", "b", "ldb", "info"],
    "_sgtsv_": ["n", "nrhs", "dl", "d", "du", "b", "ldb", "info"],

    # Symmetric packed
    "_dspsv_": ["uplo", "n", "nrhs", "ap", "ipiv", "b", "ldb", "info"],
    "_dsptrf_": ["uplo", "n", "ap", "ipiv", "info"],

    # Least squares
    "_dgels_": ["trans", "m", "n", "nrhs", "a", "lda", "b", "ldb",
                "work", "lwork", "info"],
    "_sgels_": ["trans", "m", "n", "nrhs", "a", "lda", "b", "ldb",
                "work", "lwork", "info"],
    "_dgelsd_": ["m", "n", "nrhs", "a", "lda", "b", "ldb", "s",
                 "rcond", "rank", "work", "lwork", "iwork", "info"],

    # Norms
    "_dlange_": ["norm", "m", "n", "a", "lda", "work"],
    "_slange_": ["norm", "m", "n", "a", "lda", "work"],

    # Condition number
    "_dgecon_": ["norm", "n", "a", "lda", "anorm", "rcond", "work", "iwork", "info"],

    # Scaling / balancing
    "_dlascl_": ["type", "kl", "ku", "cfrom", "cto", "m", "n", "a", "lda", "info"],
    "_dlacpy_": ["uplo", "m", "n", "a", "lda", "b", "ldb"],

    # ARPACK (sparse eigenvalue - often linked with Fortran codes)
    "_dsaupd_": ["ido", "bmat", "n", "which", "nev", "tol", "resid",
                 "ncv", "v", "ldv", "iparam", "ipntr", "workd",
                 "workl", "lworkl", "info"],
    "_dseupd_": ["rvec", "howmny", "select", "d", "z", "ldz", "sigma",
                 "bmat", "n", "which", "nev", "tol", "resid",
                 "ncv", "v", "ldv", "iparam", "ipntr", "workd",
                 "workl", "lworkl", "info"],
    "_dnaupd_": ["ido", "bmat", "n", "which", "nev", "tol", "resid",
                 "ncv", "v", "ldv", "iparam", "ipntr", "workd",
                 "workl", "lworkl", "info"],
    "_dneupd_": ["rvec", "howmny", "select", "dr", "di", "z", "ldz",
                 "sigmar", "sigmai", "workev", "bmat", "n", "which",
                 "nev", "tol", "resid", "ncv", "v", "ldv", "iparam",
                 "ipntr", "workd", "workl", "lworkl", "info"],

    # SPOOLES (sparse direct solver, Fortran interface)
    "_spooles_factor_": ["neq", "nnz", "irow", "icol", "aval", "symmetry", "info"],
    "_spooles_solve_": ["op", "neq", "nrhs", "b", "ldb", "info"],
}


# ---------------------------------------------------------------
# Common scientific library functions (Fortran-callable)
# ---------------------------------------------------------------
_SCIENTIFIC_PARAMS: dict[str, list[str]] = {
    # PARDISO (Intel MKL sparse solver, often in FEM codes)
    "_pardiso_": ["pt", "maxfct", "mnum", "mtype", "phase", "n",
                  "a", "ia", "ja", "perm", "nrhs", "iparm",
                  "msglvl", "b", "x", "error"],

    # MUMPS (MUltifrontal Massively Parallel Solver)
    "_dmumps_c_": ["dmumps_par"],

    # TAUCS (sparse solver, used in some FEM)
    "_taucs_factor_": ["matrix", "factorization", "perm", "info"],
    "_taucs_solve_": ["factorization", "rhs", "solution", "info"],
}


# ---------------------------------------------------------------
# Tum Fortran param tablosu
# ---------------------------------------------------------------
_ALL_FORTRAN_PARAMS: dict[str, list[str]] = {}
_ALL_FORTRAN_PARAMS.update(_GFORTRAN_RUNTIME_PARAMS)
_ALL_FORTRAN_PARAMS.update(_BLAS_PARAMS)
_ALL_FORTRAN_PARAMS.update(_LAPACK_PARAMS)
_ALL_FORTRAN_PARAMS.update(_SCIENTIFIC_PARAMS)


class FortranParamDB:
    """Fortran runtime + BLAS/LAPACK + bilimsel kutuphane parametre veritabani.

    APIParamDB'ye paralel calisir. Fortran'a ozgu fonksiyonlari kapsar:
    gfortran runtime, BLAS Level 1-3, LAPACK, ARPACK, PARDISO vb.
    """

    def __init__(self) -> None:
        self._db: dict[str, list[str]] = dict(_ALL_FORTRAN_PARAMS)

        # v1.9.0: sigs/fortran_params.json varsa otomatik yukle
        _sigs_dir = Path(__file__).resolve().parents[2] / "sigs"
        for _fp in sorted(_sigs_dir.glob("fortran_params*.json")):
            try:
                import json as _json
                _data = _json.loads(_fp.read_text(encoding="utf-8"))
                if isinstance(_data, dict):
                    _before = len(self._db)
                    self._db.update(_data)
                    _added = len(self._db) - _before
                    if _added > 0:
                        logger.info("FortranParamDB: %s'den %d fonksiyon eklendi", _fp.name, _added)
            except Exception as exc:
                logger.debug("FortranParamDB: %s yuklenemedi: %s", _fp.name, exc)

        logger.info("FortranParamDB: %d Fortran fonksiyon yukendi", len(self._db))

    def get_param_names(self, func_name: str) -> list[str] | None:
        """Fortran fonksiyonunun parametre isimlerini dondur.

        Args:
            func_name: C symbol adi (orn. "_dgemm_", "__gfortran_transfer_real").

        Returns:
            Parametre isim listesi veya None.
        """
        return self._db.get(func_name)

    def is_fortran_function(self, func_name: str) -> bool:
        """Fonksiyon isminin Fortran-derlenmi gibi gorunup gorunmedigini kontrol et.

        Fortran -> C derlemede uc ana pattern:
        - _isim_  (trailing underscore, standart gfortran)
        - __isim_ (double underscore ile baslayan, bazi derleyiciler)
        - __gfortran_xxx veya _gfortran_xxx (runtime)

        Not: Tek basa _isim_ her C fonksiyonu olabilir. Daha guvenli tespit
        icin callee listesinde gfortran runtime cagrilari aranir.
        """
        if func_name in self._db:
            return True
        # gfortran runtime
        if "gfortran" in func_name:
            return True
        # Trailing underscore pattern: _name_ (en az 3 karakter)
        if (len(func_name) >= 3
                and func_name.startswith("_")
                and func_name.endswith("_")
                and not func_name.startswith("__")):
            return True
        return False

    def has_gfortran_callees(self, callees: list[str] | set[str]) -> bool:
        """Callee listesinde gfortran runtime cagrilari var mi?

        Bu, bir fonksiyonun Fortran-derlenmi oldugunu kesin olarak gosteren
        en guvenilir tespit yontemidir.
        """
        for callee in callees:
            if "gfortran" in callee:
                return True
        return False

    def register(self, func_name: str, param_names: list[str]) -> None:
        """Yeni fonksiyon + parametre isim eslesmesi ekle.

        Args:
            func_name: C symbol adi.
            param_names: Parametre isim listesi.
        """
        self._db[func_name] = param_names

    def register_batch(self, entries: dict[str, list[str]]) -> None:
        """Toplu ekleme.

        Args:
            entries: {func_name: [param_names]} dict'i.
        """
        self._db.update(entries)

    def __len__(self) -> int:
        return len(self._db)

    def __contains__(self, func_name: str) -> bool:
        return func_name in self._db


# ---------------------------------------------------------------
# in_stack reconstruction
# ---------------------------------------------------------------

# ARM64 ABI: ilk 8 integer/pointer arg x0-x7 register'larinda gecirilir.
# Ghidra bunlari param_1..param_8 olarak gosterir.
# 9. ve sonraki parametreler stack'te gecirilir, her biri 8 byte.
# Ghidra bunlari in_stack_XXXXXXXX olarak gosterir.
#
# Offset hesabi:
#   in_stack_00000010 -> param_9  (ilk stack parametresi, frame base + 0x10)
#   in_stack_00000018 -> param_10
#   in_stack_00000020 -> param_11
#   vb.
#
# NOT: Offset'ler her zaman 0x10'dan baslamayabilir. Bazi durumlarda
# Ghidra farkli bir base offset kullanabilir. Bu yuzden offset'leri
# siralamak ve sirayla param_N atamak gerekir.

_IN_STACK_RE = re.compile(
    r'\b((?:int|long|undefined[0-9]*|uint|ulong|double|float|char|'
    r'void|bool)\s*\*?\s*)'
    r'(in_stack_([0-9a-fA-F]+))\s*;'
)

# Simpler version for usage detection (not just declarations)
_IN_STACK_USE_RE = re.compile(r'\bin_stack_([0-9a-fA-F]+)\b')


@dataclass
class InStackMapping:
    """Tek in_stack -> param_N eslesmesi."""
    in_stack_name: str       # "in_stack_00000018"
    offset: int              # 0x18
    param_index: int         # 10 (param_10)
    param_name: str          # "param_10"
    c_type: str              # "undefined8", "int *", "long" vb.


@dataclass
class InStackResult:
    """in_stack reconstruction sonucu."""
    success: bool
    function_name: str
    register_param_count: int       # Signature'daki param sayisi (tipik 5-8)
    in_stack_count: int             # in_stack degisken sayisi
    mappings: list[InStackMapping] = field(default_factory=list)
    renamed_code: str = ""          # Yeniden isimlendirilmis C kodu
    errors: list[str] = field(default_factory=list)


class InStackReconstructor:
    """ARM64 in_stack_XXXXXXXX degiskenlerini param_N formatina donusturur.

    Ghidra ARM64 decompile ciktisinda, fonksiyon 8'den fazla parametre
    aldiginda fazla parametreler in_stack_XXXXXXXX seklinde local variable
    olarak gosterilir. Bu sinif onlari siralar ve param_N olarak
    yeniden isimlendirir.

    Ek olarak, FortranParamDB ile entegre olarak bilinen Fortran fonksiyonlari
    icin parametre isimlerini de uygulayabilir.

    Args:
        fortran_db: Opsiyonel FortranParamDB instance. None ise otomatik olusturulur.
    """

    # Function header regex: "void _funcname_(type param_1, type param_2, ...)"
    _FUNC_SIG_RE = re.compile(
        r'^(?:void|int|long|undefined\d*|uint|double|float|char\s*\*?|bool)\s+'
        r'(\w+)\s*\(([^)]*)\)',
        re.MULTILINE,
    )

    def __init__(self, fortran_db: FortranParamDB | None = None) -> None:
        self.fortran_db = fortran_db or FortranParamDB()

    def detect_in_stack_vars(self, c_code: str) -> list[tuple[str, int, str]]:
        """C kodundaki in_stack_XXXXXXXX variable declaration'larini bul.

        Returns:
            [(in_stack_name, offset, c_type), ...] sirali liste.
        """
        found: list[tuple[str, int, str]] = []
        seen: set[str] = set()

        for match in _IN_STACK_RE.finditer(c_code):
            c_type = match.group(1).strip()
            var_name = match.group(2)
            offset_hex = match.group(3)

            if var_name in seen:
                continue
            seen.add(var_name)

            try:
                offset = int(offset_hex, 16)
            except ValueError:
                continue

            found.append((var_name, offset, c_type))

        # Offset'e gore sirala
        found.sort(key=lambda x: x[1])
        return found

    def count_signature_params(self, c_code: str) -> tuple[str, int]:
        """Fonksiyon signature'indaki parametre sayisini say.

        Returns:
            (function_name, param_count) tuple. Bulunamazsa ("", 0).
        """
        match = self._FUNC_SIG_RE.search(c_code)
        if not match:
            return ("", 0)

        func_name = match.group(1)
        params_str = match.group(2).strip()

        if not params_str or params_str == "void":
            return (func_name, 0)

        # Parametre sayisini say (basit virgul split)
        params = [p.strip() for p in params_str.split(",") if p.strip()]
        return (func_name, len(params))

    def reconstruct(
        self,
        c_code: str,
        func_name: str | None = None,
    ) -> InStackResult:
        """in_stack degiskenlerini param_N olarak yeniden isimlendir.

        Adimlar:
        1. Fonksiyon signature'indan mevcut param sayisini al
        2. in_stack_XXXXXXXX declaration'larini bul ve offset'e gore sirala
        3. Her in_stack'e sirayla param_N ata (N = register_params + 1, +2, ...)
        4. C kodunda tum in_stack referanslarini rename et

        Args:
            c_code: Ghidra decompile ciktisi (tek fonksiyon).
            func_name: Fonksiyon adi (None ise otomatik tespit).

        Returns:
            InStackResult: Reconstruction sonucu.
        """
        errors: list[str] = []

        # 1. Fonksiyon adini ve param sayisini bul
        detected_name, sig_param_count = self.count_signature_params(c_code)
        if func_name is None:
            func_name = detected_name
        if not func_name:
            return InStackResult(
                success=False,
                function_name="",
                register_param_count=0,
                in_stack_count=0,
                errors=["Fonksiyon signature'i bulunamadi"],
            )

        # 2. in_stack degiskenlerini bul
        in_stack_vars = self.detect_in_stack_vars(c_code)
        if not in_stack_vars:
            return InStackResult(
                success=True,
                function_name=func_name,
                register_param_count=sig_param_count,
                in_stack_count=0,
                renamed_code=c_code,
            )

        # 3. Mapping olustur
        mappings: list[InStackMapping] = []
        next_param_idx = sig_param_count + 1

        for var_name, offset, c_type in in_stack_vars:
            param_name = f"param_{next_param_idx}"
            mappings.append(InStackMapping(
                in_stack_name=var_name,
                offset=offset,
                param_index=next_param_idx,
                param_name=param_name,
                c_type=c_type,
            ))
            next_param_idx += 1

        # 4. C kodunda rename et
        renamed = c_code
        for mapping in mappings:
            # Tam kelime siniri ile degistir (yanlislikla baska degisken degismesin)
            pattern = re.compile(r'\b' + re.escape(mapping.in_stack_name) + r'\b')
            renamed = pattern.sub(mapping.param_name, renamed)

        logger.info(
            "InStackReconstructor: %s -- %d in_stack -> param_%d..param_%d",
            func_name, len(mappings),
            sig_param_count + 1, next_param_idx - 1,
        )

        return InStackResult(
            success=True,
            function_name=func_name,
            register_param_count=sig_param_count,
            in_stack_count=len(mappings),
            mappings=mappings,
            renamed_code=renamed,
        )

    def reconstruct_with_names(
        self,
        c_code: str,
        func_name: str | None = None,
        source_param_names: list[str] | None = None,
    ) -> InStackResult:
        """in_stack reconstruction + parametre isim atama (Fortran DB veya kaynak).

        Once reconstruct() ile in_stack -> param_N donusumu yapar.
        Sonra:
        - source_param_names verilmisse: param_1..param_N'e gercek isim atar
        - FortranParamDB'de varsa: bilinen isimleri uygular

        Args:
            c_code: Ghidra decompile ciktisi.
            func_name: Fonksiyon adi (None ise otomatik).
            source_param_names: Kaynak koddan alinan parametre isimleri.

        Returns:
            InStackResult: Tam sonuc.
        """
        # Oncelik 1: in_stack -> param_N
        result = self.reconstruct(c_code, func_name)
        if not result.success:
            return result

        # Parametre isimlerini belirle
        param_names: list[str] | None = None
        if source_param_names:
            param_names = source_param_names
        elif result.function_name:
            param_names = self.fortran_db.get_param_names(result.function_name)

        if not param_names:
            return result

        # param_N -> gercek isim donusumu
        renamed = result.renamed_code
        total_params = result.register_param_count + result.in_stack_count

        for i in range(min(total_params, len(param_names))):
            old_name = f"param_{i + 1}"
            new_name = param_names[i]
            if old_name == new_name:
                continue
            pattern = re.compile(r'\b' + re.escape(old_name) + r'\b')
            renamed = pattern.sub(new_name, renamed)

        result.renamed_code = renamed
        return result


# ---------------------------------------------------------------
# Fortran source parser
# ---------------------------------------------------------------

# SUBROUTINE pattern (case insensitive, continuation line destegi yok)
_SUBROUTINE_RE = re.compile(
    r'^\s*SUBROUTINE\s+(\w+)\s*\(([^)]*)\)',
    re.IGNORECASE | re.MULTILINE,
)

# FUNCTION pattern
_FUNCTION_RE = re.compile(
    r'^\s*(?:(?:INTEGER|REAL|DOUBLE\s+PRECISION|COMPLEX|LOGICAL|CHARACTER)\s+)?'
    r'FUNCTION\s+(\w+)\s*\(([^)]*)\)',
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class FortranSourceEntry:
    """Bir Fortran SUBROUTINE/FUNCTION icin parametre bilgisi."""
    fortran_name: str           # "RESULTS"
    c_symbol: str               # "_results_"
    param_names: list[str]      # ["co", "nkon", "nelem", ...]
    source_file: str = ""       # Kaynak dosya yolu


class FortranSourceParser:
    """Fortran kaynak kodundan SUBROUTINE/FUNCTION parametre isimlerini cikarir.

    Open source Fortran kodlarini (CalculiX, OpenFOAM, Code_Aster vb.)
    parse ederek {c_symbol: [param_names]} tablosu uretir.

    Bu tablo FortranParamDB'ye register edilerek in_stack reconstruction
    sirasinda otomatik isim atama saglar.

    Kullanim:
        parser = FortranSourceParser()
        entries = parser.parse_file(Path("mafillsmas.f"))
        for entry in entries:
            db.register(entry.c_symbol, entry.param_names)
    """

    def __init__(self) -> None:
        self._entries: list[FortranSourceEntry] = []

    def parse_text(self, text: str, source_file: str = "") -> list[FortranSourceEntry]:
        """Fortran kaynak kodu metnini parse et.

        Fixed-form Fortran'da (CalculiX) satir devami 6. sutunda bosluk
        olmayan karakterle belirtilir. Bu fonksiyon once continuation
        satirlarini birlestirip sonra SUBROUTINE/FUNCTION satirlarini parse eder.

        Args:
            text: Fortran kaynak metni.
            source_file: Kaynak dosya yolu (bilgi icin).

        Returns:
            FortranSourceEntry listesi.
        """
        # Fixed-form continuation birlestirme:
        # Satir 6. sutunda bosluk/sifir degilse continuation
        lines = text.split('\n')
        merged_lines: list[str] = []
        for line in lines:
            # Comment satirlarini atla
            if line and line[0] in ('C', 'c', '*', '!'):
                continue
            # Continuation: 6. kolon (index 5) bosluk degil ve satirda en az
            # 6 karakter var ve onceki satir var
            if (len(line) > 5
                    and line[5] not in (' ', '0', '\t')
                    and line[0] == ' '
                    and merged_lines):
                # Onceki satira ekle (7. kolondan itibaren)
                merged_lines[-1] = merged_lines[-1] + line[6:]
            else:
                merged_lines.append(line)

        merged_text = '\n'.join(merged_lines)

        entries: list[FortranSourceEntry] = []

        for pattern in (_SUBROUTINE_RE, _FUNCTION_RE):
            for match in pattern.finditer(merged_text):
                fortran_name = match.group(1)
                params_str = match.group(2).strip()

                if not params_str:
                    param_names = []
                else:
                    param_names = [p.strip().lower() for p in params_str.split(",")]

                c_symbol = f"_{fortran_name.lower()}_"

                entry = FortranSourceEntry(
                    fortran_name=fortran_name.upper(),
                    c_symbol=c_symbol,
                    param_names=param_names,
                    source_file=source_file,
                )
                entries.append(entry)

        return entries

    def parse_file(self, filepath: Path) -> list[FortranSourceEntry]:
        """Fortran dosyasini parse et.

        Args:
            filepath: .f, .f90, .F, .F90 dosya yolu.

        Returns:
            FortranSourceEntry listesi.

        Raises:
            FileNotFoundError: Dosya yoksa.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Fortran dosyasi bulunamadi: {filepath}")

        text = filepath.read_text(encoding="utf-8", errors="replace")
        return self.parse_text(text, source_file=str(filepath))

    def parse_directory(
        self,
        directory: Path,
        extensions: tuple[str, ...] = (".f", ".f90", ".F", ".F90", ".for"),
    ) -> list[FortranSourceEntry]:
        """Dizindeki tum Fortran dosyalarini parse et.

        Args:
            directory: Kaynak kod dizini.
            extensions: Aranacak dosya uzantilari.

        Returns:
            Tum entry'lerin birlesmis listesi.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Dizin bulunamadi: {directory}")

        all_entries: list[FortranSourceEntry] = []
        for ext in extensions:
            for fpath in sorted(directory.rglob(f"*{ext}")):
                try:
                    entries = self.parse_file(fpath)
                    all_entries.extend(entries)
                except Exception as exc:
                    logger.warning("Fortran parse hatasi (%s): %s", fpath, exc)

        logger.info(
            "FortranSourceParser: %s -- %d dosya, %d subroutine/function",
            directory, len(list(directory.rglob("*"))), len(all_entries),
        )
        return all_entries

    def build_param_db(
        self,
        entries: list[FortranSourceEntry] | None = None,
    ) -> dict[str, list[str]]:
        """Entry listesinden {c_symbol: [param_names]} dict'i uret.

        Args:
            entries: FortranSourceEntry listesi. None ise icsel _entries kullanilir.

        Returns:
            {c_symbol: param_names} dict'i.
        """
        if entries is None:
            entries = self._entries
        return {e.c_symbol: e.param_names for e in entries}
