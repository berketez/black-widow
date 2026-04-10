"""API korelasyon veritabani -- bilinen kutuphane fonksiyon cagrilari.

Decompile edilmis binary'lerdeki import tablosu, sembol tablosu veya string
referanslarindan bilinen muhendislik/bilimsel kutuphane cagrilarini tespit eder.

Desteklenen kutuphaneler:
- BLAS level 1/2/3  (daxpy, dgemm, dtrsm, ...)
- LAPACK  (dgetrf, dsyev, dgesvd, ...)
- FFTW  (fftw_plan_*, fftw_execute, ...)
- PETSc  (KSPSolve, MatAssemblyBegin, SNESSolve, ...)
- SuiteSparse  (cholmod_*, umfpack_*, spqr_*)
- Intel MKL  (mkl_*, pardiso_*)
- cuBLAS / cuSOLVER / cuSPARSE  (cublas*, cusolver*)
- SUNDIALS  (CVode*, KINSol, IDA*)
- GSL  (gsl_*)
- ARPACK  (dsaupd_, dseupd_, ...)
- ScaLAPACK  (pdgemm_, pdgetrf_, ...)
- Eigen C++  (mangled names)
- QuantLib  (finance)
- OpenBLAS / ATLAS  (gotoblas_*, ATL_*)
- HDF5  (H5Dread, H5Fopen, ...)
- METIS / ParMETIS  (METIS_PartGraph*, ParMETIS_*)
- Trilinos / Hypre  (Hypre*, Epetra_*)
- MUMPS  (dmumps_c, zmumps_c)
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class APISignature:
    """Bilinen bir kutuphane fonksiyon imzasi."""

    pattern: str        # "_dgemm_" veya regex pattern
    algorithm: str      # "matrix_multiply"
    library: str        # "BLAS"
    category: str       # "linear_algebra"
    confidence: float   # 0.95
    description: str


# ---------------------------------------------------------------------------
# API veritabani  (110+ kayit)
# ---------------------------------------------------------------------------

ENGINEERING_APIS: list[APISignature] = [

    # ========================================================================
    #  BLAS LEVEL 1  (vector-vector)
    # ========================================================================
    APISignature(
        pattern=r"[_]?daxpy[_]?",
        algorithm="axpy",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="y = alpha*x + y (double)",
    ),
    APISignature(
        pattern=r"[_]?saxpy[_]?",
        algorithm="axpy",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="y = alpha*x + y (single)",
    ),
    APISignature(
        pattern=r"[_]?ddot[_]?",
        algorithm="dot_product",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="dot product (double)",
    ),
    APISignature(
        pattern=r"[_]?sdot[_]?",
        algorithm="dot_product",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="dot product (single)",
    ),
    APISignature(
        pattern=r"[_]?dnrm2[_]?",
        algorithm="vector_norm",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="L2 norm (double)",
    ),
    APISignature(
        pattern=r"[_]?snrm2[_]?",
        algorithm="vector_norm",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="L2 norm (single)",
    ),
    APISignature(
        pattern=r"[_]?dscal[_]?",
        algorithm="scalar_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="x = alpha*x (double)",
    ),
    APISignature(
        pattern=r"[_]?sscal[_]?",
        algorithm="scalar_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="x = alpha*x (single)",
    ),
    APISignature(
        pattern=r"[_]?dcopy[_]?",
        algorithm="vector_copy",
        library="BLAS",
        category="linear_algebra",
        confidence=0.90,
        description="y = x (double vector copy)",
    ),
    APISignature(
        pattern=r"[_]?dswap[_]?",
        algorithm="vector_swap",
        library="BLAS",
        category="linear_algebra",
        confidence=0.90,
        description="swap x <-> y (double)",
    ),
    APISignature(
        pattern=r"[_]?idamax[_]?",
        algorithm="max_abs_index",
        library="BLAS",
        category="linear_algebra",
        confidence=0.93,
        description="index of max |x[i]| (double) -- pivoting icin",
    ),
    APISignature(
        pattern=r"[_]?dasum[_]?",
        algorithm="absolute_sum",
        library="BLAS",
        category="linear_algebra",
        confidence=0.93,
        description="sum(|x[i]|) L1 norm (double)",
    ),
    APISignature(
        pattern=r"[_]?drotg?[_]?",
        algorithm="givens_rotation",
        library="BLAS",
        category="linear_algebra",
        confidence=0.94,
        description="Givens rotation setup/apply (double)",
    ),

    # ========================================================================
    #  BLAS LEVEL 2  (matrix-vector)
    # ========================================================================
    APISignature(
        pattern=r"[_]?dgemv[_]?",
        algorithm="matrix_vector_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="y = alpha*A*x + beta*y (double, general matrix)",
    ),
    APISignature(
        pattern=r"[_]?sgemv[_]?",
        algorithm="matrix_vector_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="y = alpha*A*x + beta*y (single, general matrix)",
    ),
    APISignature(
        pattern=r"[_]?dsymv[_]?",
        algorithm="symmetric_matvec",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="y = alpha*A*x + beta*y (double, symmetric A)",
    ),
    APISignature(
        pattern=r"[_]?dtrmv[_]?",
        algorithm="triangular_matvec",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="x = A*x (double, triangular A)",
    ),
    APISignature(
        pattern=r"[_]?dtrsv[_]?",
        algorithm="triangular_solve",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="solve A*x = b (double, triangular A)",
    ),
    APISignature(
        pattern=r"[_]?dger[_]?",
        algorithm="rank1_update",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="A = alpha*x*y^T + A (double, rank-1 update)",
    ),
    APISignature(
        pattern=r"[_]?dsyr[_]?",
        algorithm="symmetric_rank1_update",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="A = alpha*x*x^T + A (double, symmetric rank-1)",
    ),
    APISignature(
        pattern=r"[_]?dsyr2[_]?",
        algorithm="symmetric_rank2_update",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="A = alpha*x*y^T + alpha*y*x^T + A (double, symmetric rank-2)",
    ),
    APISignature(
        pattern=r"[_]?dspmv[_]?",
        algorithm="packed_symmetric_matvec",
        library="BLAS",
        category="linear_algebra",
        confidence=0.94,
        description="y = alpha*A*x + beta*y (double, packed symmetric)",
    ),
    APISignature(
        pattern=r"[_]?dgbmv[_]?",
        algorithm="banded_matvec",
        library="BLAS",
        category="linear_algebra",
        confidence=0.94,
        description="y = alpha*A*x + beta*y (double, banded matrix)",
    ),

    # ========================================================================
    #  BLAS LEVEL 3  (matrix-matrix)
    # ========================================================================
    APISignature(
        pattern=r"[_]?dgemm[_]?",
        algorithm="matrix_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.97,
        description="C = alpha*A*B + beta*C (double, general)",
    ),
    APISignature(
        pattern=r"[_]?sgemm[_]?",
        algorithm="matrix_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.97,
        description="C = alpha*A*B + beta*C (single, general)",
    ),
    APISignature(
        pattern=r"[_]?zgemm[_]?",
        algorithm="matrix_multiply_complex",
        library="BLAS",
        category="linear_algebra",
        confidence=0.97,
        description="C = alpha*A*B + beta*C (double complex)",
    ),
    APISignature(
        pattern=r"[_]?dtrsm[_]?",
        algorithm="triangular_matrix_solve",
        library="BLAS",
        category="linear_algebra",
        confidence=0.97,
        description="solve A*X = alpha*B (double, triangular A, multiple RHS)",
    ),
    APISignature(
        pattern=r"[_]?dsyrk[_]?",
        algorithm="symmetric_rank_k_update",
        library="BLAS",
        category="linear_algebra",
        confidence=0.96,
        description="C = alpha*A*A^T + beta*C (double, symmetric rank-k)",
    ),
    APISignature(
        pattern=r"[_]?dsyr2k[_]?",
        algorithm="symmetric_rank_2k_update",
        library="BLAS",
        category="linear_algebra",
        confidence=0.96,
        description="C = alpha*A*B^T + alpha*B*A^T + beta*C (double)",
    ),
    APISignature(
        pattern=r"[_]?dtrmm[_]?",
        algorithm="triangular_matrix_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.96,
        description="B = alpha*A*B (double, A triangular)",
    ),
    APISignature(
        pattern=r"[_]?dsymm[_]?",
        algorithm="symmetric_matrix_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.96,
        description="C = alpha*A*B + beta*C (double, A or B symmetric)",
    ),

    # ========================================================================
    #  LAPACK  (factorizations, eigensolvers, SVD)
    # ========================================================================
    APISignature(
        pattern=r"[_]?dgetrf[_]?",
        algorithm="lu_factorization",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="PA = LU pivotlu LU faktorlemesi (double, general)",
    ),
    APISignature(
        pattern=r"[_]?dgetrs[_]?",
        algorithm="lu_solve",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="LU sonrasi A*X = B cozumu (double)",
    ),
    APISignature(
        pattern=r"[_]?dgetri[_]?",
        algorithm="matrix_inverse",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="LU bazli matris tersi (double)",
    ),
    APISignature(
        pattern=r"[_]?dgesv[_]?",
        algorithm="linear_solve",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="A*X = B tam cozum (LU + solve, double)",
    ),
    APISignature(
        pattern=r"[_]?dpotrf[_]?",
        algorithm="cholesky_factorization",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="A = L*L^T Cholesky faktorlemesi (double, positive definite)",
    ),
    APISignature(
        pattern=r"[_]?dpotrs[_]?",
        algorithm="cholesky_solve",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="Cholesky sonrasi cozum (double)",
    ),
    APISignature(
        pattern=r"[_]?dsyev[_]?",
        algorithm="eigenvalue_symmetric",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="Simetrik matris eigenvalue/eigenvector (double)",
    ),
    APISignature(
        pattern=r"[_]?dsyevd[_]?",
        algorithm="eigenvalue_symmetric_divconq",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="Simetrik eigenvalue -- divide & conquer (double)",
    ),
    APISignature(
        pattern=r"[_]?dsyevr[_]?",
        algorithm="eigenvalue_symmetric_rrr",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="Simetrik eigenvalue -- MRRR (double, en hizli)",
    ),
    APISignature(
        pattern=r"[_]?dgeev[_]?",
        algorithm="eigenvalue_general",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="Genel matris eigenvalue (double, non-symmetric)",
    ),
    APISignature(
        pattern=r"[_]?dgesvd[_]?",
        algorithm="svd",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="A = U*S*V^T tekil deger ayristirmasi (double)",
    ),
    APISignature(
        pattern=r"[_]?dgesdd[_]?",
        algorithm="svd_divconq",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="SVD divide & conquer (double, daha hizli)",
    ),
    APISignature(
        pattern=r"[_]?dgees[_]?",
        algorithm="schur_decomposition",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Schur faktorlemesi (double)",
    ),
    APISignature(
        pattern=r"[_]?dgeqrf[_]?",
        algorithm="qr_factorization",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="QR faktorlemesi (double, Householder)",
    ),
    APISignature(
        pattern=r"[_]?dorgqr[_]?",
        algorithm="qr_generate_q",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="QR'den Q matrisini uret (double)",
    ),
    APISignature(
        pattern=r"[_]?dgels[_]?",
        algorithm="least_squares",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="En kucuk kareler cozumu QR/LQ ile (double)",
    ),
    APISignature(
        pattern=r"[_]?dgelsd[_]?",
        algorithm="least_squares_svd",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.97,
        description="En kucuk kareler SVD ile (double, rank-deficient)",
    ),
    APISignature(
        pattern=r"[_]?dgbtrf[_]?",
        algorithm="banded_lu",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Banded matrix LU factorization (double)",
    ),
    APISignature(
        pattern=r"[_]?dpbtrf[_]?",
        algorithm="banded_cholesky",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Banded positive definite Cholesky (double)",
    ),
    APISignature(
        pattern=r"[_]?dstev[_]?",
        algorithm="tridiag_eigenvalue",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Tridiagonal symmetric eigenvalue (double)",
    ),
    APISignature(
        pattern=r"[_]?dgttrf[_]?",
        algorithm="tridiag_lu",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Tridiagonal LU (double)",
    ),
    APISignature(
        pattern=r"[_]?dggev[_]?",
        algorithm="generalized_eigenvalue",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Generalized eigenvalue A*x = lambda*B*x (double)",
    ),
    APISignature(
        pattern=r"[_]?dgecon[_]?",
        algorithm="condition_number",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.95,
        description="Condition number estimation (double)",
    ),

    # ========================================================================
    #  FFTW
    # ========================================================================
    APISignature(
        pattern=r"fftw_plan_dft_1d",
        algorithm="fft_1d",
        library="FFTW",
        category="dsp_transform",
        confidence=0.98,
        description="1D FFT plan olusturma (complex-to-complex)",
    ),
    APISignature(
        pattern=r"fftw_plan_dft_2d",
        algorithm="fft_2d",
        library="FFTW",
        category="dsp_transform",
        confidence=0.98,
        description="2D FFT plan olusturma",
    ),
    APISignature(
        pattern=r"fftw_plan_dft_3d",
        algorithm="fft_3d",
        library="FFTW",
        category="dsp_transform",
        confidence=0.98,
        description="3D FFT plan olusturma",
    ),
    APISignature(
        pattern=r"fftw_plan_dft_r2c_[123]d",
        algorithm="fft_real_to_complex",
        library="FFTW",
        category="dsp_transform",
        confidence=0.98,
        description="Real-to-complex FFT (1D/2D/3D)",
    ),
    APISignature(
        pattern=r"fftw_plan_dft_c2r_[123]d",
        algorithm="ifft_complex_to_real",
        library="FFTW",
        category="dsp_transform",
        confidence=0.98,
        description="Complex-to-real IFFT (1D/2D/3D)",
    ),
    APISignature(
        pattern=r"fftw_plan_many_dft",
        algorithm="fft_batched",
        library="FFTW",
        category="dsp_transform",
        confidence=0.97,
        description="Batched FFT (birden fazla transform ayni anda)",
    ),
    APISignature(
        pattern=r"fftw_execute",
        algorithm="fft_execute",
        library="FFTW",
        category="dsp_transform",
        confidence=0.95,
        description="FFTW plan calistirma",
    ),
    APISignature(
        pattern=r"fftw_destroy_plan",
        algorithm="fft_cleanup",
        library="FFTW",
        category="dsp_transform",
        confidence=0.90,
        description="FFTW plan serbest birakma",
    ),
    APISignature(
        pattern=r"fftwf_plan_dft",
        algorithm="fft_single_precision",
        library="FFTW",
        category="dsp_transform",
        confidence=0.97,
        description="Single-precision FFT (fftwf)",
    ),

    # ========================================================================
    #  PETSc  (Portable, Extensible Toolkit for Scientific Computation)
    # ========================================================================
    APISignature(
        pattern=r"KSPCreate",
        algorithm="krylov_solver_setup",
        library="PETSc",
        category="numerical_solver",
        confidence=0.97,
        description="Krylov alt-uzay cozucu olusturma",
    ),
    APISignature(
        pattern=r"KSPSolve",
        algorithm="krylov_solve",
        library="PETSc",
        category="numerical_solver",
        confidence=0.98,
        description="Krylov cozucu calistirma (CG, GMRES, BiCGSTAB, vb.)",
    ),
    APISignature(
        pattern=r"KSPSetType",
        algorithm="krylov_config",
        library="PETSc",
        category="numerical_solver",
        confidence=0.96,
        description="Krylov solver tipi ayarlama",
    ),
    APISignature(
        pattern=r"MatAssemblyBegin",
        algorithm="matrix_assembly",
        library="PETSc",
        category="numerical_solver",
        confidence=0.95,
        description="PETSc sparse matris assembly baslangici",
    ),
    APISignature(
        pattern=r"MatAssemblyEnd",
        algorithm="matrix_assembly",
        library="PETSc",
        category="numerical_solver",
        confidence=0.95,
        description="PETSc sparse matris assembly bitisi",
    ),
    APISignature(
        pattern=r"VecCreate(?:Seq|MPI)?",
        algorithm="vector_setup",
        library="PETSc",
        category="numerical_solver",
        confidence=0.92,
        description="PETSc vektor olusturma",
    ),
    APISignature(
        pattern=r"SNESSolve",
        algorithm="nonlinear_solve",
        library="PETSc",
        category="nonlinear_solver",
        confidence=0.98,
        description="Newton-tipi nonlineer cozucu (SNES)",
    ),
    APISignature(
        pattern=r"TSCreate",
        algorithm="time_stepping",
        library="PETSc",
        category="time_integration",
        confidence=0.96,
        description="PETSc zaman adimi entegratoru",
    ),
    APISignature(
        pattern=r"TSSolve",
        algorithm="time_stepping_solve",
        library="PETSc",
        category="time_integration",
        confidence=0.97,
        description="PETSc zaman entegrasyonu calistirma",
    ),
    APISignature(
        pattern=r"PCSetType",
        algorithm="preconditioner_config",
        library="PETSc",
        category="numerical_solver",
        confidence=0.94,
        description="Preconditiner tipi ayarlama (ILU, Jacobi, MG, vb.)",
    ),
    APISignature(
        pattern=r"MatCreateAIJ",
        algorithm="sparse_matrix_create",
        library="PETSc",
        category="numerical_solver",
        confidence=0.95,
        description="AIJ (CSR) sparse matris olusturma",
    ),
    APISignature(
        pattern=r"DMCreate(?:DA|Plex)",
        algorithm="mesh_management",
        library="PETSc",
        category="finite_element",
        confidence=0.95,
        description="Structured (DMDA) veya unstructured (DMPlex) mesh yonetimi",
    ),

    # ========================================================================
    #  SuiteSparse
    # ========================================================================
    APISignature(
        pattern=r"cholmod_(?:analyze|factorize|solve)",
        algorithm="sparse_cholesky",
        library="SuiteSparse",
        category="linear_algebra",
        confidence=0.97,
        description="CHOLMOD sparse Cholesky cozucu",
    ),
    APISignature(
        pattern=r"cholmod_(?:allocate_sparse|start|finish|free_sparse)",
        algorithm="cholmod_management",
        library="SuiteSparse",
        category="linear_algebra",
        confidence=0.92,
        description="CHOLMOD bellek yonetimi",
    ),
    APISignature(
        pattern=r"umfpack_d[il]_(?:symbolic|numeric|solve|free_symbolic|free_numeric)",
        algorithm="sparse_lu",
        library="SuiteSparse",
        category="linear_algebra",
        confidence=0.97,
        description="UMFPACK sparse LU cozucu (double, int/long)",
    ),
    APISignature(
        pattern=r"SuiteSparseQR",
        algorithm="sparse_qr",
        library="SuiteSparse",
        category="linear_algebra",
        confidence=0.97,
        description="SPQR sparse QR faktorlemesi",
    ),
    APISignature(
        pattern=r"cs_(?:spalloc|lusol|cholsol|qrsol|multiply|add|transpose)",
        algorithm="csparse_operations",
        library="SuiteSparse",
        category="linear_algebra",
        confidence=0.95,
        description="CSparse sparse matris islemleri",
    ),
    APISignature(
        pattern=r"klu_(?:analyze|factor|solve|free_symbolic|free_numeric)",
        algorithm="sparse_lu_circuit",
        library="SuiteSparse",
        category="linear_algebra",
        confidence=0.96,
        description="KLU sparse LU -- devre simulasyonu icin optimize",
    ),

    # ========================================================================
    #  Intel MKL / Pardiso
    # ========================================================================
    APISignature(
        pattern=r"mkl_(?:d|s|z|c)csrmv",
        algorithm="sparse_matvec_mkl",
        library="MKL",
        category="linear_algebra",
        confidence=0.96,
        description="MKL sparse CSR matrix-vector multiply",
    ),
    APISignature(
        pattern=r"mkl_(?:d|s)csrmm",
        algorithm="sparse_matmul_mkl",
        library="MKL",
        category="linear_algebra",
        confidence=0.96,
        description="MKL sparse CSR matrix-matrix multiply",
    ),
    APISignature(
        pattern=r"pardiso[_]?",
        algorithm="pardiso_sparse_solve",
        library="MKL",
        category="linear_algebra",
        confidence=0.97,
        description="PARDISO direkt sparse cozucu (LU/Cholesky/LDLT)",
    ),
    APISignature(
        pattern=r"mkl_dcsrilut",
        algorithm="incomplete_lu",
        library="MKL",
        category="linear_algebra",
        confidence=0.95,
        description="MKL Incomplete LU with threshold (preconditioner)",
    ),
    APISignature(
        pattern=r"LAPACKE_(?:d|s|z|c)\w+",
        algorithm="lapacke_call",
        library="MKL",
        category="linear_algebra",
        confidence=0.95,
        description="LAPACKE C interface (MKL backend)",
    ),
    APISignature(
        pattern=r"cblas_(?:d|s|z|c)\w+",
        algorithm="cblas_call",
        library="MKL",
        category="linear_algebra",
        confidence=0.95,
        description="CBLAS C interface (MKL backend)",
    ),
    APISignature(
        pattern=r"mkl_sparse_(?:d|s)_(?:create_csr|mv|mm|add|export_csr)",
        algorithm="mkl_sparse_inspector_executor",
        library="MKL",
        category="linear_algebra",
        confidence=0.96,
        description="MKL Sparse Inspector-Executor interface",
    ),

    # ========================================================================
    #  cuBLAS / cuSOLVER / cuSPARSE (CUDA GPU)
    # ========================================================================
    APISignature(
        pattern=r"cublas[SDCZ]gemm(?:_v2)?",
        algorithm="gpu_matrix_multiply",
        library="cuBLAS",
        category="gpu_linear_algebra",
        confidence=0.98,
        description="cuBLAS GPU matris carpimi",
    ),
    APISignature(
        pattern=r"cublas[SDCZ]gemv(?:_v2)?",
        algorithm="gpu_matvec",
        library="cuBLAS",
        category="gpu_linear_algebra",
        confidence=0.97,
        description="cuBLAS GPU matris-vektor carpimi",
    ),
    APISignature(
        pattern=r"cublas[SDCZ]trsm(?:_v2)?",
        algorithm="gpu_triangular_solve",
        library="cuBLAS",
        category="gpu_linear_algebra",
        confidence=0.97,
        description="cuBLAS GPU ucgensel cozucu",
    ),
    APISignature(
        pattern=r"cublas(?:Create|Destroy|SetStream)",
        algorithm="cublas_management",
        library="cuBLAS",
        category="gpu_linear_algebra",
        confidence=0.90,
        description="cuBLAS handle yonetimi",
    ),
    APISignature(
        pattern=r"cublas[SDCZ]geam",
        algorithm="gpu_matrix_add",
        library="cuBLAS",
        category="gpu_linear_algebra",
        confidence=0.96,
        description="cuBLAS GPU matris toplama/transpose",
    ),
    APISignature(
        pattern=r"cusolverDn[SDCZ]getrf",
        algorithm="gpu_lu_factorization",
        library="cuSOLVER",
        category="gpu_linear_algebra",
        confidence=0.97,
        description="cuSOLVER GPU LU faktorlemesi",
    ),
    APISignature(
        pattern=r"cusolverDn[SDCZ]potrf",
        algorithm="gpu_cholesky",
        library="cuSOLVER",
        category="gpu_linear_algebra",
        confidence=0.97,
        description="cuSOLVER GPU Cholesky faktorlemesi",
    ),
    APISignature(
        pattern=r"cusolverDn[SDCZ]gesvd",
        algorithm="gpu_svd",
        library="cuSOLVER",
        category="gpu_linear_algebra",
        confidence=0.97,
        description="cuSOLVER GPU SVD",
    ),
    APISignature(
        pattern=r"cusolverDn[SDCZ]syevd",
        algorithm="gpu_eigenvalue",
        library="cuSOLVER",
        category="gpu_linear_algebra",
        confidence=0.97,
        description="cuSOLVER GPU simetrik eigenvalue",
    ),
    APISignature(
        pattern=r"cusparse(?:Create|Destroy|SetStream)",
        algorithm="cusparse_management",
        library="cuSPARSE",
        category="gpu_linear_algebra",
        confidence=0.90,
        description="cuSPARSE handle yonetimi",
    ),
    APISignature(
        pattern=r"cusparse[SDCZ]?(?:SpMV|SpMM|csrmv|csrmm)",
        algorithm="gpu_sparse_matvec",
        library="cuSPARSE",
        category="gpu_linear_algebra",
        confidence=0.96,
        description="cuSPARSE GPU sparse matris operasyonu",
    ),
    APISignature(
        pattern=r"cusolverSp[SDCZ]csrlsvlu",
        algorithm="gpu_sparse_lu_solve",
        library="cuSOLVER",
        category="gpu_linear_algebra",
        confidence=0.96,
        description="cuSOLVER sparse LU cozucu (GPU)",
    ),

    # ========================================================================
    #  SUNDIALS  (ODE/DAE/Nonlinear solvers)
    # ========================================================================
    APISignature(
        pattern=r"CVodeCreate",
        algorithm="ode_solver_setup",
        library="SUNDIALS",
        category="time_integration",
        confidence=0.97,
        description="CVODE ODE cozucu (Adams/BDF) olusturma",
    ),
    APISignature(
        pattern=r"CVode\b",
        algorithm="ode_solve",
        library="SUNDIALS",
        category="time_integration",
        confidence=0.97,
        description="CVODE zaman adimi ilerleme",
    ),
    APISignature(
        pattern=r"CVodeSetLinearSolver",
        algorithm="cvode_linear_solver",
        library="SUNDIALS",
        category="time_integration",
        confidence=0.95,
        description="CVODE lineer cozucu ayarlama",
    ),
    APISignature(
        pattern=r"ARKStepCreate",
        algorithm="ark_ode_solver",
        library="SUNDIALS",
        category="time_integration",
        confidence=0.96,
        description="ARKode additive Runge-Kutta cozucu",
    ),
    APISignature(
        pattern=r"IDACreate",
        algorithm="dae_solver_setup",
        library="SUNDIALS",
        category="time_integration",
        confidence=0.97,
        description="IDA DAE cozucu olusturma",
    ),
    APISignature(
        pattern=r"IDASolve",
        algorithm="dae_solve",
        library="SUNDIALS",
        category="time_integration",
        confidence=0.97,
        description="IDA DAE cozucu ilerleme",
    ),
    APISignature(
        pattern=r"IDACalcIC",
        algorithm="dae_initial_conditions",
        library="SUNDIALS",
        category="time_integration",
        confidence=0.96,
        description="IDA tutarli baslangic kosulu hesabi",
    ),
    APISignature(
        pattern=r"KINSol",
        algorithm="nonlinear_solve_kinsol",
        library="SUNDIALS",
        category="nonlinear_solver",
        confidence=0.97,
        description="KINSOL nonlineer cozucu (Newton, Picard, fixed-point)",
    ),
    APISignature(
        pattern=r"KINCreate",
        algorithm="kinsol_setup",
        library="SUNDIALS",
        category="nonlinear_solver",
        confidence=0.95,
        description="KINSOL olusturma",
    ),
    APISignature(
        pattern=r"N_VNew_(?:Serial|Parallel|OpenMP|Cuda|Hip)",
        algorithm="sundials_vector",
        library="SUNDIALS",
        category="time_integration",
        confidence=0.93,
        description="SUNDIALS N_Vector olusturma",
    ),

    # ========================================================================
    #  GSL  (GNU Scientific Library)
    # ========================================================================
    APISignature(
        pattern=r"gsl_integration_qag[sp]?",
        algorithm="adaptive_integration",
        library="GSL",
        category="numerical_calculus",
        confidence=0.97,
        description="GSL adaptif Gauss-Kronrod sayisal integral",
    ),
    APISignature(
        pattern=r"gsl_integration_qng",
        algorithm="nonadaptive_integration",
        library="GSL",
        category="numerical_calculus",
        confidence=0.97,
        description="GSL non-adaptif Gauss-Kronrod integral",
    ),
    APISignature(
        pattern=r"gsl_linalg_(?:LU|QR|cholesky|SV)_(?:decomp|solve|invert)",
        algorithm="gsl_linear_algebra",
        library="GSL",
        category="linear_algebra",
        confidence=0.96,
        description="GSL lineer cebir cozuculeri",
    ),
    APISignature(
        pattern=r"gsl_eigen_(?:symm|nonsymm|herm|gensymm)(?:v)?_(?:alloc|free|workspace)",
        algorithm="gsl_eigenvalue",
        library="GSL",
        category="linear_algebra",
        confidence=0.96,
        description="GSL eigenvalue cozucu",
    ),
    APISignature(
        pattern=r"gsl_multifit_nlinear_(?:alloc|init|iterate|driver)",
        algorithm="nonlinear_least_squares",
        library="GSL",
        category="optimization",
        confidence=0.96,
        description="GSL nonlineer en kucuk kareler (Levenberg-Marquardt)",
    ),
    APISignature(
        pattern=r"gsl_odeiv2_(?:step_alloc|evolve_apply|driver_alloc)",
        algorithm="gsl_ode_solver",
        library="GSL",
        category="time_integration",
        confidence=0.96,
        description="GSL ODE cozucu (RK4, RKF45, vb.)",
    ),
    APISignature(
        pattern=r"gsl_rng_(?:alloc|uniform|gaussian)",
        algorithm="gsl_random",
        library="GSL",
        category="stochastic",
        confidence=0.92,
        description="GSL random sayi ureteci",
    ),
    APISignature(
        pattern=r"gsl_fft_(?:complex|real)_(?:wavetable|workspace|transform|radix2)",
        algorithm="gsl_fft",
        library="GSL",
        category="dsp_transform",
        confidence=0.96,
        description="GSL FFT islemleri",
    ),
    APISignature(
        pattern=r"gsl_spline_(?:alloc|init|eval|free)",
        algorithm="spline_interpolation",
        library="GSL",
        category="interpolation",
        confidence=0.95,
        description="GSL cubic spline interpolasyonu",
    ),
    APISignature(
        pattern=r"gsl_min_fminimizer_(?:alloc|set|iterate|minimum)",
        algorithm="gsl_minimization",
        library="GSL",
        category="optimization",
        confidence=0.95,
        description="GSL 1D minimization (Brent, golden section)",
    ),
    APISignature(
        pattern=r"gsl_multimin_fdfminimizer_(?:alloc|set|iterate)",
        algorithm="gsl_multidim_minimization",
        library="GSL",
        category="optimization",
        confidence=0.96,
        description="GSL cok boyutlu minimizasyon (CG, BFGS, steepest descent)",
    ),

    # ========================================================================
    #  ARPACK  (eigenvalue -- large sparse)
    # ========================================================================
    APISignature(
        pattern=r"[_]?dsaupd[_]?",
        algorithm="arpack_symmetric_eigenvalue",
        library="ARPACK",
        category="linear_algebra",
        confidence=0.97,
        description="ARPACK simetrik eigenvalue (Lanczos, buyuk seyrek matris)",
    ),
    APISignature(
        pattern=r"[_]?dseupd[_]?",
        algorithm="arpack_symmetric_eigenvector",
        library="ARPACK",
        category="linear_algebra",
        confidence=0.97,
        description="ARPACK simetrik eigenvector cikarimi",
    ),
    APISignature(
        pattern=r"[_]?dnaupd[_]?",
        algorithm="arpack_nonsymmetric_eigenvalue",
        library="ARPACK",
        category="linear_algebra",
        confidence=0.97,
        description="ARPACK non-simetrik eigenvalue (Arnoldi)",
    ),
    APISignature(
        pattern=r"[_]?dneupd[_]?",
        algorithm="arpack_nonsymmetric_eigenvector",
        library="ARPACK",
        category="linear_algebra",
        confidence=0.97,
        description="ARPACK non-simetrik eigenvector cikarimi",
    ),

    # ========================================================================
    #  ScaLAPACK  (distributed memory)
    # ========================================================================
    APISignature(
        pattern=r"[_]?pdgemm[_]?",
        algorithm="distributed_matrix_multiply",
        library="ScaLAPACK",
        category="distributed_linear_algebra",
        confidence=0.97,
        description="Dagitik matris carpimi (double)",
    ),
    APISignature(
        pattern=r"[_]?pdgetrf[_]?",
        algorithm="distributed_lu",
        library="ScaLAPACK",
        category="distributed_linear_algebra",
        confidence=0.97,
        description="Dagitik LU faktorlemesi (double)",
    ),
    APISignature(
        pattern=r"[_]?pdpotrf[_]?",
        algorithm="distributed_cholesky",
        library="ScaLAPACK",
        category="distributed_linear_algebra",
        confidence=0.97,
        description="Dagitik Cholesky (double)",
    ),
    APISignature(
        pattern=r"[_]?pdsyev[_]?",
        algorithm="distributed_eigenvalue",
        library="ScaLAPACK",
        category="distributed_linear_algebra",
        confidence=0.97,
        description="Dagitik simetrik eigenvalue (double)",
    ),
    APISignature(
        pattern=r"[_]?pdgesvd[_]?",
        algorithm="distributed_svd",
        library="ScaLAPACK",
        category="distributed_linear_algebra",
        confidence=0.97,
        description="Dagitik SVD (double)",
    ),
    APISignature(
        pattern=r"(?:blacs_gridinit|blacs_gridexit|descinit)[_]?",
        algorithm="scalapack_grid",
        library="ScaLAPACK",
        category="distributed_linear_algebra",
        confidence=0.93,
        description="BLACS islemci grid yonetimi",
    ),

    # ========================================================================
    #  Eigen C++  (mangled names)
    # ========================================================================
    APISignature(
        pattern=r"_ZN5Eigen\w*(?:Matrix|Vector|SparseMatrix|Map|Block|Array)",
        algorithm="eigen_container",
        library="Eigen",
        category="linear_algebra",
        confidence=0.92,
        description="Eigen matris/vektor constructor (mangled C++ name)",
    ),
    APISignature(
        pattern=r"_ZN5Eigen\w*(?:ColPivHouseholderQR|FullPivLU|LDLT|LLT|JacobiSVD|"
                r"SelfAdjointEigenSolver|CompleteOrthogonalDecomposition)",
        algorithm="eigen_decomposition",
        library="Eigen",
        category="linear_algebra",
        confidence=0.95,
        description="Eigen matrix decomposition (mangled)",
    ),
    APISignature(
        pattern=r"_ZN5Eigen\w*(?:ConjugateGradient|BiCGSTAB|SparseLU|SparseQR|"
                r"SimplicialLDLT|SimplicialLLT|CholmodSupernodal)",
        algorithm="eigen_sparse_solver",
        library="Eigen",
        category="linear_algebra",
        confidence=0.95,
        description="Eigen sparse solver (mangled)",
    ),

    # ========================================================================
    #  QuantLib  (finance)
    # ========================================================================
    APISignature(
        pattern=r"QuantLib::BlackScholes(?:Process|Formula|Calculator)",
        algorithm="black_scholes",
        library="QuantLib",
        category="finance",
        confidence=0.98,
        description="Black-Scholes opsiyon fiyatlama",
    ),
    APISignature(
        pattern=r"QuantLib::(?:Analytic)?EuropeanEngine",
        algorithm="european_option",
        library="QuantLib",
        category="finance",
        confidence=0.97,
        description="Avrupa tipi opsiyon fiyatlama motoru",
    ),
    APISignature(
        pattern=r"QuantLib::(?:MC|MonteCarlo)\w*Engine",
        algorithm="monte_carlo_pricing",
        library="QuantLib",
        category="finance",
        confidence=0.97,
        description="Monte Carlo opsiyon fiyatlama",
    ),
    APISignature(
        pattern=r"QuantLib::(?:HullWhite|Vasicek|CoxIngersollRoss)",
        algorithm="interest_rate_model",
        library="QuantLib",
        category="finance",
        confidence=0.96,
        description="Faiz orani modeli (Hull-White, Vasicek, CIR)",
    ),
    APISignature(
        pattern=r"QuantLib::(?:FD|FiniteDifference)\w*Engine",
        algorithm="fd_option_pricing",
        library="QuantLib",
        category="finance",
        confidence=0.96,
        description="Sonlu farklar ile opsiyon fiyatlama",
    ),
    APISignature(
        pattern=r"QuantLib::YieldTermStructure",
        algorithm="yield_curve",
        library="QuantLib",
        category="finance",
        confidence=0.94,
        description="Verim egrisi modelleme",
    ),

    # ========================================================================
    #  OpenBLAS / ATLAS / GotoBLAS
    # ========================================================================
    APISignature(
        pattern=r"gotoblas_(?:init|set_num_threads)",
        algorithm="openblas_init",
        library="OpenBLAS",
        category="linear_algebra",
        confidence=0.93,
        description="OpenBLAS/GotoBLAS baslatma",
    ),
    APISignature(
        pattern=r"openblas_(?:set_num_threads|get_config|get_num_threads)",
        algorithm="openblas_config",
        library="OpenBLAS",
        category="linear_algebra",
        confidence=0.93,
        description="OpenBLAS yapilandirma",
    ),
    APISignature(
        pattern=r"ATL_[dscz]\w+",
        algorithm="atlas_operation",
        library="ATLAS",
        category="linear_algebra",
        confidence=0.93,
        description="ATLAS optimized BLAS/LAPACK cagrisi",
    ),

    # ========================================================================
    #  HDF5  (veri I/O -- bilimsel veri formati)
    # ========================================================================
    APISignature(
        pattern=r"H5Fopen",
        algorithm="hdf5_file_open",
        library="HDF5",
        category="scientific_io",
        confidence=0.95,
        description="HDF5 dosya acma",
    ),
    APISignature(
        pattern=r"H5Dread",
        algorithm="hdf5_dataset_read",
        library="HDF5",
        category="scientific_io",
        confidence=0.95,
        description="HDF5 dataset okuma",
    ),
    APISignature(
        pattern=r"H5Dwrite",
        algorithm="hdf5_dataset_write",
        library="HDF5",
        category="scientific_io",
        confidence=0.95,
        description="HDF5 dataset yazma",
    ),
    APISignature(
        pattern=r"H5Dcreate[12]?",
        algorithm="hdf5_dataset_create",
        library="HDF5",
        category="scientific_io",
        confidence=0.94,
        description="HDF5 dataset olusturma",
    ),
    APISignature(
        pattern=r"H5Screate_simple",
        algorithm="hdf5_dataspace",
        library="HDF5",
        category="scientific_io",
        confidence=0.92,
        description="HDF5 dataspace olusturma",
    ),

    # ========================================================================
    #  METIS / ParMETIS  (graph partitioning)
    # ========================================================================
    APISignature(
        pattern=r"METIS_PartGraph(?:Recursive|Kway)",
        algorithm="graph_partitioning",
        library="METIS",
        category="graph_algorithm",
        confidence=0.97,
        description="METIS graph partitioning (FEA mesh decomposition icin)",
    ),
    APISignature(
        pattern=r"METIS_NodeND",
        algorithm="nested_dissection_ordering",
        library="METIS",
        category="graph_algorithm",
        confidence=0.96,
        description="METIS nested dissection siralama (sparse solver fill-in minimize)",
    ),
    APISignature(
        pattern=r"ParMETIS_V3_PartKway",
        algorithm="parallel_graph_partitioning",
        library="ParMETIS",
        category="graph_algorithm",
        confidence=0.97,
        description="ParMETIS paralel graph partitioning",
    ),

    # ========================================================================
    #  Trilinos / Hypre  (large-scale solvers)
    # ========================================================================
    APISignature(
        pattern=r"HYPRE_(?:BoomerAMG|ParCSR|IJ|Struct)(?:Setup|Solve|Create)",
        algorithm="hypre_solver",
        library="Hypre",
        category="numerical_solver",
        confidence=0.96,
        description="Hypre AMG/Krylov cozucu (buyuk olcekli paralel)",
    ),
    APISignature(
        pattern=r"Epetra_(?:CrsMatrix|MultiVector|Map|Comm)",
        algorithm="trilinos_epetra",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.94,
        description="Trilinos Epetra veri yapilari",
    ),
    APISignature(
        pattern=r"Tpetra::(?:CrsMatrix|MultiVector|Map)",
        algorithm="trilinos_tpetra",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.94,
        description="Trilinos Tpetra (next-gen, template-based)",
    ),
    APISignature(
        pattern=r"AztecOO_StatusTest|AztecOO::Iterate",
        algorithm="trilinos_aztec_solver",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.95,
        description="Trilinos AztecOO iteratif cozucu",
    ),

    # ========================================================================
    #  MUMPS  (MUltifrontal Massively Parallel Sparse direct Solver)
    # ========================================================================
    APISignature(
        pattern=r"[dszc]mumps_c",
        algorithm="mumps_direct_solve",
        library="MUMPS",
        category="linear_algebra",
        confidence=0.97,
        description="MUMPS multifrontal sparse direkt cozucu",
    ),

    # ========================================================================
    #  MPI  (parallelization indicator)
    # ========================================================================
    APISignature(
        pattern=r"MPI_(?:Init|Finalize|Comm_rank|Comm_size|Send|Recv|"
                r"Allreduce|Bcast|Scatter|Gather|Barrier|Waitall)",
        algorithm="mpi_parallel",
        library="MPI",
        category="parallel_computing",
        confidence=0.85,
        description="MPI paralel hesaplama altyapisi",
    ),

    # ========================================================================
    #  OpenMP  (threading indicator)
    # ========================================================================
    APISignature(
        pattern=r"(?:GOMP|omp)_(?:parallel|get_num_threads|set_num_threads|"
                r"get_thread_num|barrier|critical|atomic)",
        algorithm="openmp_parallel",
        library="OpenMP",
        category="parallel_computing",
        confidence=0.88,
        description="OpenMP thread paralelligi",
    ),

    # ========================================================================
    #  SPOOLES  (direct sparse solver -- CalculiX default)
    # ========================================================================
    APISignature(
        pattern=r"FrontMtx_factorInpMtx",
        algorithm="spooles_factorization",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.97,
        description="SPOOLES multifrontal sparse faktorlemesi",
    ),
    APISignature(
        pattern=r"FrontMtx_solve",
        algorithm="spooles_solve",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.97,
        description="SPOOLES multifrontal sparse cozucu",
    ),
    APISignature(
        pattern=r"FrontMtx_(?:new|init|free)",
        algorithm="spooles_front_management",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.94,
        description="SPOOLES FrontMtx olusturma/silme",
    ),
    APISignature(
        pattern=r"InpMtx_(?:inputTriple|inputRow|inputColumn|changeCoordType|"
                r"new|init|free)",
        algorithm="spooles_input_matrix",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.96,
        description="SPOOLES input matris (triple/row/column) yonetimi",
    ),
    APISignature(
        pattern=r"ETree_(?:initFromGraphWithPerms|new|free|nfront|root)",
        algorithm="spooles_elimination_tree",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.95,
        description="SPOOLES elimination tree (faktorleme icin siralama)",
    ),
    APISignature(
        pattern=r"IVL_(?:new|init|free|setList)",
        algorithm="spooles_ivl",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.90,
        description="SPOOLES integer vector list (adjacency, symbolic factor)",
    ),
    APISignature(
        pattern=r"Graph_(?:new|init|free|fillFromInpMtx)",
        algorithm="spooles_graph",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.91,
        description="SPOOLES graph (matris yapisal pattern'i)",
    ),
    APISignature(
        pattern=r"DenseMtx_(?:new|init|free|entries|zero)",
        algorithm="spooles_dense_matrix",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.92,
        description="SPOOLES dense matris (RHS veya cozum vektoru)",
    ),
    APISignature(
        pattern=r"SubMtxManager_(?:new|init|free)",
        algorithm="spooles_submtx_manager",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.90,
        description="SPOOLES SubMtx bellek yonetimi",
    ),
    APISignature(
        pattern=r"ChvManager_(?:new|init|free)",
        algorithm="spooles_chv_manager",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.90,
        description="SPOOLES Chv (chevron) bellek yonetimi",
    ),
    APISignature(
        pattern=r"Chv_(?:new|init|free|maxabs|assembleChv)",
        algorithm="spooles_chevron",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.91,
        description="SPOOLES chevron (frontal matris alt yapisi)",
    ),
    APISignature(
        pattern=r"BridgeMPI_(?:new|init|factorSetup|factor|solve)",
        algorithm="spooles_mpi_bridge",
        library="SPOOLES",
        category="linear_algebra",
        confidence=0.95,
        description="SPOOLES MPI paralel arayuzu (CalculiX MPI)",
    ),

    # ========================================================================
    #  PaStiX  (Parallel Sparse direcT Solver)
    # ========================================================================
    APISignature(
        pattern=r"pastix_task_init",
        algorithm="pastix_init",
        library="PaStiX",
        category="linear_algebra",
        confidence=0.97,
        description="PaStiX solver baslatma",
    ),
    APISignature(
        pattern=r"pastix_task_analyze",
        algorithm="pastix_analyze",
        library="PaStiX",
        category="linear_algebra",
        confidence=0.97,
        description="PaStiX symbolic factorization / ordering",
    ),
    APISignature(
        pattern=r"pastix_task_numfact",
        algorithm="pastix_factorize",
        library="PaStiX",
        category="linear_algebra",
        confidence=0.97,
        description="PaStiX numerik faktorleme (LU/LLT/LDLT)",
    ),
    APISignature(
        pattern=r"pastix_task_solve",
        algorithm="pastix_solve",
        library="PaStiX",
        category="linear_algebra",
        confidence=0.97,
        description="PaStiX cozum asamasi (forward/backward sub)",
    ),
    APISignature(
        pattern=r"pastix_task_refine",
        algorithm="pastix_refine",
        library="PaStiX",
        category="linear_algebra",
        confidence=0.96,
        description="PaStiX iteratif iyilestirme (iterative refinement)",
    ),
    APISignature(
        pattern=r"pastix(?:Init|Finalize|SetSchurUnknownList)",
        algorithm="pastix_management",
        library="PaStiX",
        category="linear_algebra",
        confidence=0.93,
        description="PaStiX genel yonetim fonksiyonlari",
    ),

    # ========================================================================
    #  SuperLU  (sparse direct solver)
    # ========================================================================
    APISignature(
        pattern=r"[_]?dgstrf[_]?",
        algorithm="superlu_factorize",
        library="SuperLU",
        category="linear_algebra",
        confidence=0.97,
        description="SuperLU sparse LU faktorlemesi (double)",
    ),
    APISignature(
        pattern=r"[_]?dgstrs[_]?",
        algorithm="superlu_solve",
        library="SuperLU",
        category="linear_algebra",
        confidence=0.97,
        description="SuperLU sparse triangular solve (double)",
    ),
    APISignature(
        pattern=r"[_]?dgssvx[_]?",
        algorithm="superlu_expert_solve",
        library="SuperLU",
        category="linear_algebra",
        confidence=0.97,
        description="SuperLU expert driver: factor + solve + equilibrate + refine (double)",
    ),
    APISignature(
        pattern=r"dCreate_CompCol_Matrix",
        algorithm="superlu_create_csc",
        library="SuperLU",
        category="linear_algebra",
        confidence=0.96,
        description="SuperLU compressed column matris olusturma",
    ),
    APISignature(
        pattern=r"dCreate_Dense_Matrix",
        algorithm="superlu_create_dense",
        library="SuperLU",
        category="linear_algebra",
        confidence=0.95,
        description="SuperLU dense matris olusturma (RHS)",
    ),
    APISignature(
        pattern=r"(?:d|s|z|c)gssv[_]?",
        algorithm="superlu_simple_solve",
        library="SuperLU",
        category="linear_algebra",
        confidence=0.96,
        description="SuperLU simple driver: factor + solve",
    ),
    APISignature(
        pattern=r"Destroy_(?:CompCol|Dense|SuperNode)_Matrix",
        algorithm="superlu_cleanup",
        library="SuperLU",
        category="linear_algebra",
        confidence=0.91,
        description="SuperLU matris bellegi serbest birakma",
    ),
    APISignature(
        pattern=r"sp_ienv[_]?",
        algorithm="superlu_config",
        library="SuperLU",
        category="linear_algebra",
        confidence=0.90,
        description="SuperLU yapilandirma parametresi sorgulama",
    ),
    APISignature(
        pattern=r"dgstrf_dist|pdgstrf",
        algorithm="superlu_dist_factorize",
        library="SuperLU_DIST",
        category="distributed_linear_algebra",
        confidence=0.96,
        description="SuperLU_DIST dagitik sparse LU (double)",
    ),

    # ========================================================================
    #  MUMPS  (extended entries)
    # ========================================================================
    APISignature(
        pattern=r"DMUMPS_INIT",
        algorithm="mumps_init",
        library="MUMPS",
        category="linear_algebra",
        confidence=0.97,
        description="MUMPS double precision baslatma (JOB=-1)",
    ),
    APISignature(
        pattern=r"DMUMPS_ANALYZE",
        algorithm="mumps_analyze",
        library="MUMPS",
        category="linear_algebra",
        confidence=0.97,
        description="MUMPS symbolic analysis (JOB=1)",
    ),
    APISignature(
        pattern=r"DMUMPS_FACTORIZE",
        algorithm="mumps_factorize",
        library="MUMPS",
        category="linear_algebra",
        confidence=0.97,
        description="MUMPS numerik faktorleme (JOB=2)",
    ),
    APISignature(
        pattern=r"DMUMPS_SOLVE",
        algorithm="mumps_solve",
        library="MUMPS",
        category="linear_algebra",
        confidence=0.97,
        description="MUMPS cozum (JOB=3)",
    ),
    APISignature(
        pattern=r"[sz]mumps_c",
        algorithm="mumps_direct_solve_other",
        library="MUMPS",
        category="linear_algebra",
        confidence=0.97,
        description="MUMPS single/complex sparse direkt cozucu",
    ),
    APISignature(
        pattern=r"mumps_(?:interleave_par|get_mapping)",
        algorithm="mumps_utility",
        library="MUMPS",
        category="linear_algebra",
        confidence=0.90,
        description="MUMPS yardimci fonksiyonlari",
    ),

    # ========================================================================
    #  Trilinos  (extended entries)
    # ========================================================================
    APISignature(
        pattern=r"Epetra_CrsMatrix",
        algorithm="trilinos_crs_matrix",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.95,
        description="Trilinos Epetra CRS sparse matris",
    ),
    APISignature(
        pattern=r"AztecOO(?:::)?Iterate",
        algorithm="trilinos_aztec_iterate",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.96,
        description="Trilinos AztecOO iteratif cozucu iterasyon",
    ),
    APISignature(
        pattern=r"Ifpack_(?:IC|ICT|ILU|ILUT|Amesos|Chebyshev|PointRelaxation)",
        algorithm="trilinos_ifpack_preconditioner",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.95,
        description="Trilinos Ifpack preconditioner (IC, ILU, ILUT, Amesos, vb.)",
    ),
    APISignature(
        pattern=r"ML_(?:Epetra|Create|Set_Amatrix|Aggregate|Solve)",
        algorithm="trilinos_ml_amg",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.95,
        description="Trilinos ML algebraik multigrid (AMG) preconditioner",
    ),
    APISignature(
        pattern=r"Amesos_(?:BaseSolver|Klu|Umfpack|Mumps|Pardiso|Superlu)",
        algorithm="trilinos_amesos_direct",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.96,
        description="Trilinos Amesos direkt cozucu arayuzu",
    ),
    APISignature(
        pattern=r"Belos_(?:BlockCG|BlockGmres|PseudoBlockCG|TFQMR)",
        algorithm="trilinos_belos_solver",
        library="Trilinos",
        category="numerical_solver",
        confidence=0.95,
        description="Trilinos Belos iteratif cozucu",
    ),
    APISignature(
        pattern=r"NOX::(?:Solver|StatusTest|Direction)",
        algorithm="trilinos_nox_nonlinear",
        library="Trilinos",
        category="nonlinear_solver",
        confidence=0.95,
        description="Trilinos NOX nonlineer cozucu",
    ),

    # ========================================================================
    #  FEniCS / DOLFIN  (Python FE framework, C++ backend)
    # ========================================================================
    APISignature(
        pattern=r"dolfin::(?:assemble|assemble_system)",
        algorithm="fenics_assemble",
        library="FEniCS",
        category="finite_element",
        confidence=0.96,
        description="FEniCS/DOLFIN variasyonel form assembly",
    ),
    APISignature(
        pattern=r"dolfin::solve",
        algorithm="fenics_solve",
        library="FEniCS",
        category="finite_element",
        confidence=0.94,
        description="FEniCS/DOLFIN lineer/nonlineer cozucu",
    ),
    APISignature(
        pattern=r"dolfin::DirichletBC",
        algorithm="fenics_bc",
        library="FEniCS",
        category="finite_element",
        confidence=0.95,
        description="FEniCS Dirichlet sinir kosulu",
    ),
    APISignature(
        pattern=r"dolfin::FunctionSpace",
        algorithm="fenics_function_space",
        library="FEniCS",
        category="finite_element",
        confidence=0.94,
        description="FEniCS fonksiyon uzayi (CG, DG, RT, vb.)",
    ),
    APISignature(
        pattern=r"dolfin::(?:Mesh|UnitSquareMesh|UnitCubeMesh|RectangleMesh)",
        algorithm="fenics_mesh",
        library="FEniCS",
        category="finite_element",
        confidence=0.93,
        description="FEniCS mesh olusturma/yukleme",
    ),
    APISignature(
        pattern=r"dolfin::(?:LinearVariationalSolver|NonlinearVariationalSolver)",
        algorithm="fenics_variational_solver",
        library="FEniCS",
        category="finite_element",
        confidence=0.96,
        description="FEniCS variasyonel cozucu (lineer/nonlineer)",
    ),
    APISignature(
        pattern=r"dolfin::(?:TrialFunction|TestFunction|Function)",
        algorithm="fenics_function",
        library="FEniCS",
        category="finite_element",
        confidence=0.92,
        description="FEniCS trial/test/solution fonksiyonu",
    ),

    # ========================================================================
    #  deal.II  (C++ FEM library)
    # ========================================================================
    APISignature(
        pattern=r"dealii::SparseMatrix",
        algorithm="dealii_sparse_matrix",
        library="deal.II",
        category="finite_element",
        confidence=0.95,
        description="deal.II sparse matris",
    ),
    APISignature(
        pattern=r"dealii::(?:ConstraintMatrix|AffineConstraints)",
        algorithm="dealii_constraints",
        library="deal.II",
        category="finite_element",
        confidence=0.95,
        description="deal.II constraint handling (hanging nodes, BCs)",
    ),
    APISignature(
        pattern=r"dealii::DoFHandler",
        algorithm="dealii_dof_handler",
        library="deal.II",
        category="finite_element",
        confidence=0.95,
        description="deal.II DOF yonetimi (mesh -> dof mapping)",
    ),
    APISignature(
        pattern=r"dealii::FE_Q",
        algorithm="dealii_fe_q",
        library="deal.II",
        category="finite_element",
        confidence=0.94,
        description="deal.II Lagrange finite element (continuous)",
    ),
    APISignature(
        pattern=r"dealii::(?:Triangulation|GridGenerator)",
        algorithm="dealii_mesh",
        library="deal.II",
        category="finite_element",
        confidence=0.94,
        description="deal.II mesh/grid olusturma ve yonetimi",
    ),
    APISignature(
        pattern=r"dealii::SolverCG",
        algorithm="dealii_solver_cg",
        library="deal.II",
        category="numerical_solver",
        confidence=0.95,
        description="deal.II Conjugate Gradient cozucu",
    ),
    APISignature(
        pattern=r"dealii::(?:SolverGMRES|SolverBicgstab|SolverMinRes)",
        algorithm="dealii_krylov_solver",
        library="deal.II",
        category="numerical_solver",
        confidence=0.95,
        description="deal.II Krylov alt-uzay cozuculeri (GMRES, BiCGSTAB, MinRes)",
    ),
    APISignature(
        pattern=r"dealii::(?:PreconditionSSOR|PreconditionJacobi|PreconditionSOR)",
        algorithm="dealii_preconditioner",
        library="deal.II",
        category="numerical_solver",
        confidence=0.94,
        description="deal.II preconditioner (SSOR, Jacobi, SOR)",
    ),
    APISignature(
        pattern=r"dealii::DataOut",
        algorithm="dealii_output",
        library="deal.II",
        category="scientific_io",
        confidence=0.92,
        description="deal.II sonuc cikti (VTK, VTU, vb.)",
    ),

    # ========================================================================
    #  OpenMP  (extended -- scientific computing patterns)
    # ========================================================================
    APISignature(
        pattern=r"omp_get_thread_num",
        algorithm="openmp_thread_id",
        library="OpenMP",
        category="parallel_computing",
        confidence=0.90,
        description="OpenMP thread ID sorgulama",
    ),
    APISignature(
        pattern=r"omp_get_num_threads",
        algorithm="openmp_num_threads",
        library="OpenMP",
        category="parallel_computing",
        confidence=0.90,
        description="OpenMP aktif thread sayisi",
    ),
    APISignature(
        pattern=r"omp_set_num_threads",
        algorithm="openmp_set_threads",
        library="OpenMP",
        category="parallel_computing",
        confidence=0.90,
        description="OpenMP thread sayisi ayarlama",
    ),
    APISignature(
        pattern=r"omp_(?:init_lock|set_lock|unset_lock|destroy_lock|test_lock)",
        algorithm="openmp_lock",
        library="OpenMP",
        category="parallel_computing",
        confidence=0.90,
        description="OpenMP mutex lock islemleri",
    ),
    APISignature(
        pattern=r"omp_get_wtime",
        algorithm="openmp_timer",
        library="OpenMP",
        category="parallel_computing",
        confidence=0.88,
        description="OpenMP wall-clock zamanlayici",
    ),

    # ========================================================================
    #  MPI  (extended entries for scientific computing)
    # ========================================================================
    APISignature(
        pattern=r"MPI_Allreduce",
        algorithm="mpi_allreduce",
        library="MPI",
        category="parallel_computing",
        confidence=0.92,
        description="MPI global reduction (sum, max, min, vb.) -- tum islemcilere dagitim",
    ),
    APISignature(
        pattern=r"MPI_Bcast",
        algorithm="mpi_broadcast",
        library="MPI",
        category="parallel_computing",
        confidence=0.90,
        description="MPI broadcast (bir islemciden hepsine veri)",
    ),
    APISignature(
        pattern=r"MPI_Scatter",
        algorithm="mpi_scatter",
        library="MPI",
        category="parallel_computing",
        confidence=0.90,
        description="MPI scatter (veriyi parcalayip dagitma)",
    ),
    APISignature(
        pattern=r"MPI_Gather",
        algorithm="mpi_gather",
        library="MPI",
        category="parallel_computing",
        confidence=0.90,
        description="MPI gather (parcali veriyi toplama)",
    ),
    APISignature(
        pattern=r"MPI_Allgather",
        algorithm="mpi_allgather",
        library="MPI",
        category="parallel_computing",
        confidence=0.90,
        description="MPI allgather (tum parcalari tum islemcilere)",
    ),
    APISignature(
        pattern=r"MPI_(?:Isend|Irecv|Wait|Waitall|Test)",
        algorithm="mpi_nonblocking",
        library="MPI",
        category="parallel_computing",
        confidence=0.90,
        description="MPI non-blocking iletisim (async send/recv)",
    ),
    APISignature(
        pattern=r"MPI_(?:Cart_create|Cart_coords|Cart_shift)",
        algorithm="mpi_cartesian_topology",
        library="MPI",
        category="parallel_computing",
        confidence=0.92,
        description="MPI Cartesian topology (structured grid decomposition)",
    ),
    APISignature(
        pattern=r"MPI_Type_(?:create_subarray|commit|free|contiguous|vector)",
        algorithm="mpi_derived_datatype",
        library="MPI",
        category="parallel_computing",
        confidence=0.91,
        description="MPI derived datatype (subarray, strided, vb.)",
    ),
    APISignature(
        pattern=r"MPI_(?:File_open|File_write|File_read|File_close)",
        algorithm="mpi_io",
        library="MPI",
        category="parallel_computing",
        confidence=0.92,
        description="MPI-IO paralel dosya I/O",
    ),

    # ========================================================================
    #  HDF5  (extended entries)
    # ========================================================================
    APISignature(
        pattern=r"H5Fcreate",
        algorithm="hdf5_file_create",
        library="HDF5",
        category="scientific_io",
        confidence=0.95,
        description="HDF5 dosya olusturma",
    ),
    APISignature(
        pattern=r"H5Fclose",
        algorithm="hdf5_file_close",
        library="HDF5",
        category="scientific_io",
        confidence=0.92,
        description="HDF5 dosya kapatma",
    ),
    APISignature(
        pattern=r"H5Sselect_hyperslab",
        algorithm="hdf5_hyperslab",
        library="HDF5",
        category="scientific_io",
        confidence=0.95,
        description="HDF5 hyperslab secimi (parcali veri okuma/yazma)",
    ),
    APISignature(
        pattern=r"H5Gcreate[12]?",
        algorithm="hdf5_group_create",
        library="HDF5",
        category="scientific_io",
        confidence=0.93,
        description="HDF5 grup olusturma",
    ),
    APISignature(
        pattern=r"H5Awrite",
        algorithm="hdf5_attribute_write",
        library="HDF5",
        category="scientific_io",
        confidence=0.93,
        description="HDF5 attribute yazma (metadata)",
    ),
    APISignature(
        pattern=r"H5Pcreate",
        algorithm="hdf5_property_list",
        library="HDF5",
        category="scientific_io",
        confidence=0.91,
        description="HDF5 property list olusturma (compression, chunking, vb.)",
    ),
    APISignature(
        pattern=r"H5Pset_chunk",
        algorithm="hdf5_chunking",
        library="HDF5",
        category="scientific_io",
        confidence=0.93,
        description="HDF5 chunked storage ayarlama",
    ),
    APISignature(
        pattern=r"H5Pset_deflate",
        algorithm="hdf5_compression",
        library="HDF5",
        category="scientific_io",
        confidence=0.92,
        description="HDF5 gzip compression ayarlama",
    ),

    # ========================================================================
    #  CGNS  (CFD General Notation System)
    # ========================================================================
    APISignature(
        pattern=r"cg_open",
        algorithm="cgns_open",
        library="CGNS",
        category="scientific_io",
        confidence=0.95,
        description="CGNS dosya acma",
    ),
    APISignature(
        pattern=r"cg_zone_write",
        algorithm="cgns_zone_write",
        library="CGNS",
        category="scientific_io",
        confidence=0.96,
        description="CGNS zone (mesh blogu) yazma",
    ),
    APISignature(
        pattern=r"cg_sol_write",
        algorithm="cgns_solution_write",
        library="CGNS",
        category="scientific_io",
        confidence=0.96,
        description="CGNS flow solution yazma",
    ),
    APISignature(
        pattern=r"cg_coord_write",
        algorithm="cgns_coord_write",
        library="CGNS",
        category="scientific_io",
        confidence=0.96,
        description="CGNS koordinat (mesh node) yazma",
    ),
    APISignature(
        pattern=r"cg_field_write",
        algorithm="cgns_field_write",
        library="CGNS",
        category="scientific_io",
        confidence=0.96,
        description="CGNS akim alani degiskeni yazma",
    ),
    APISignature(
        pattern=r"cg_(?:section_write|elements_write)",
        algorithm="cgns_elements_write",
        library="CGNS",
        category="scientific_io",
        confidence=0.95,
        description="CGNS element baglantilik (connectivity) yazma",
    ),
    APISignature(
        pattern=r"cg_(?:boco_write|bc_write)",
        algorithm="cgns_bc_write",
        library="CGNS",
        category="scientific_io",
        confidence=0.95,
        description="CGNS sinir kosulu yazma",
    ),
    APISignature(
        pattern=r"cg_close",
        algorithm="cgns_close",
        library="CGNS",
        category="scientific_io",
        confidence=0.92,
        description="CGNS dosya kapatma",
    ),
    APISignature(
        pattern=r"cg_base_write",
        algorithm="cgns_base_write",
        library="CGNS",
        category="scientific_io",
        confidence=0.95,
        description="CGNS base node yazma (boyut bilgisi)",
    ),

    # ========================================================================
    #  VTK  (Visualization Toolkit -- scientific visualization)
    # ========================================================================
    APISignature(
        pattern=r"vtkUnstructuredGrid",
        algorithm="vtk_unstructured_grid",
        library="VTK",
        category="scientific_io",
        confidence=0.94,
        description="VTK yapilandirmasiz grid (FEA/CFD mesh)",
    ),
    APISignature(
        pattern=r"vtkXML(?:Unstructured|Structured|Rectilinear|PolyData)(?:Writer|Reader)",
        algorithm="vtk_xml_io",
        library="VTK",
        category="scientific_io",
        confidence=0.95,
        description="VTK XML dosya okuma/yazma (VTU, VTS, VTR, VTP)",
    ),
    APISignature(
        pattern=r"vtkStructuredGrid",
        algorithm="vtk_structured_grid",
        library="VTK",
        category="scientific_io",
        confidence=0.94,
        description="VTK yapilandirilmis grid (structured mesh)",
    ),
    APISignature(
        pattern=r"vtkPoints",
        algorithm="vtk_points",
        library="VTK",
        category="scientific_io",
        confidence=0.90,
        description="VTK nokta (vertex) container",
    ),
    APISignature(
        pattern=r"vtkDoubleArray",
        algorithm="vtk_double_array",
        library="VTK",
        category="scientific_io",
        confidence=0.88,
        description="VTK double precision veri dizisi",
    ),
    APISignature(
        pattern=r"vtkCellArray",
        algorithm="vtk_cell_array",
        library="VTK",
        category="scientific_io",
        confidence=0.90,
        description="VTK hucre (element) baglantilik dizisi",
    ),
    APISignature(
        pattern=r"vtkPolyData",
        algorithm="vtk_polydata",
        library="VTK",
        category="scientific_io",
        confidence=0.93,
        description="VTK polygonal veri (yuzey mesh, cizgi, nokta)",
    ),

    # ========================================================================
    #  More LAPACK  (dgels, dgeqrf, dgesdd, dsytrd, dstebz)
    # ========================================================================
    APISignature(
        pattern=r"[_]?dsytrd[_]?",
        algorithm="symmetric_tridiag_reduction",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Simetrik matris -> tridiagonal indirgeme (Householder)",
    ),
    APISignature(
        pattern=r"[_]?dstebz[_]?",
        algorithm="tridiag_eigenvalue_bisection",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Tridiagonal eigenvalue bisection ile (belirli aralik/indeks)",
    ),
    APISignature(
        pattern=r"[_]?dstein[_]?",
        algorithm="tridiag_eigenvector_inverse_iteration",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Tridiagonal eigenvector inverse iteration ile",
    ),
    APISignature(
        pattern=r"[_]?dormqr[_]?",
        algorithm="apply_q_from_qr",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.95,
        description="QR'den Q matrisini uygulama (multiply by Q, double)",
    ),
    APISignature(
        pattern=r"[_]?dgelss[_]?",
        algorithm="least_squares_svd_full",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="En kucuk kareler SVD ile (double, tum tekil degerler)",
    ),
    APISignature(
        pattern=r"[_]?dgebal[_]?",
        algorithm="matrix_balance",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.94,
        description="Matris dengeleme (eigenvalue hesabi oncesi)",
    ),
    APISignature(
        pattern=r"[_]?dhseqr[_]?",
        algorithm="hessenberg_eigenvalue",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Hessenberg matris eigenvalue (QR algorithm)",
    ),
    APISignature(
        pattern=r"[_]?dlacpy[_]?",
        algorithm="matrix_copy",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.90,
        description="Matris kopyalama (upper/lower/full)",
    ),
    APISignature(
        pattern=r"[_]?dlaset[_]?",
        algorithm="matrix_set",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.90,
        description="Matris sifirlama / birim matris ayarlama",
    ),
    APISignature(
        pattern=r"[_]?dlansy[_]?",
        algorithm="symmetric_matrix_norm",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.93,
        description="Simetrik matris norm hesabi (1, inf, Frobenius)",
    ),
    APISignature(
        pattern=r"[_]?dpotri[_]?",
        algorithm="cholesky_inverse",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Cholesky bazli matris tersi (double, positive definite)",
    ),
    APISignature(
        pattern=r"[_]?dsygv[_]?",
        algorithm="generalized_symmetric_eigenvalue",
        library="LAPACK",
        category="linear_algebra",
        confidence=0.96,
        description="Generalized symmetric eigenvalue A*x = lambda*B*x (Cholesky + syev)",
    ),

    # ========================================================================
    #  More BLAS  (dtrmv, dtpmv, dsymm, dsyrk, dsyr2k -- deduplicate check)
    # ========================================================================
    APISignature(
        pattern=r"[_]?dtpmv[_]?",
        algorithm="packed_triangular_matvec",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="x = A*x (double, packed triangular A)",
    ),
    APISignature(
        pattern=r"[_]?dtpsv[_]?",
        algorithm="packed_triangular_solve",
        library="BLAS",
        category="linear_algebra",
        confidence=0.95,
        description="solve A*x = b (double, packed triangular A)",
    ),
    APISignature(
        pattern=r"[_]?dspr[_]?",
        algorithm="packed_symmetric_rank1",
        library="BLAS",
        category="linear_algebra",
        confidence=0.94,
        description="A = alpha*x*x^T + A (double, packed symmetric rank-1)",
    ),
    APISignature(
        pattern=r"[_]?dspr2[_]?",
        algorithm="packed_symmetric_rank2",
        library="BLAS",
        category="linear_algebra",
        confidence=0.94,
        description="A = alpha*x*y^T + alpha*y*x^T + A (double, packed symmetric rank-2)",
    ),
    APISignature(
        pattern=r"[_]?zhemm[_]?",
        algorithm="hermitian_matrix_multiply",
        library="BLAS",
        category="linear_algebra",
        confidence=0.96,
        description="C = alpha*A*B + beta*C (complex, A Hermitian)",
    ),
    APISignature(
        pattern=r"[_]?zherk[_]?",
        algorithm="hermitian_rank_k_update",
        library="BLAS",
        category="linear_algebra",
        confidence=0.96,
        description="C = alpha*A*A^H + beta*C (complex, Hermitian rank-k)",
    ),
    APISignature(
        pattern=r"[_]?ztrsm[_]?",
        algorithm="complex_triangular_matrix_solve",
        library="BLAS",
        category="linear_algebra",
        confidence=0.97,
        description="solve A*X = alpha*B (complex, triangular A)",
    ),

    # ========================================================================
    #  CalculiX-specific  (internal routines found in CalculiX source)
    # ========================================================================
    APISignature(
        pattern=r"(?:e_c3d|e_c3d_th|e_c3d_cs|e_c3d_rhs)[_]?",
        algorithm="calculix_element_routine",
        library="CalculiX",
        category="finite_element",
        confidence=0.98,
        description="CalculiX 3D element stiffness/thermal/RHS rutini",
    ),
    APISignature(
        pattern=r"(?:mafill|mafilldm|mafillsm|mafillp)[_]?",
        algorithm="calculix_matrix_fill",
        library="CalculiX",
        category="finite_element",
        confidence=0.98,
        description="CalculiX global matris doldurma (stiffness, mass, pressure)",
    ),
    # TIGHTENED (2026-03-25): "results" matches common English word.
    # Now requires underscore context or specific CalculiX function names.
    APISignature(
        pattern=r"(?:resultsini|calcresidual|_results_|results_)",
        algorithm="calculix_results",
        library="CalculiX",
        category="finite_element",
        confidence=0.75,
        description="CalculiX sonuc hesaplama (stress, strain, vb.)",
    ),
    APISignature(
        pattern=r"(?:nonlingeo|linstatic|arpack|complexfreq|steadystate)[_]?",
        algorithm="calculix_analysis_type",
        library="CalculiX",
        category="finite_element",
        confidence=0.98,
        description="CalculiX analiz tipi rutini (nonlinear, static, frequency)",
    ),
    APISignature(
        pattern=r"(?:cascade|gentiedmpc|gencontelem|genmpc)[_]?",
        algorithm="calculix_constraint",
        library="CalculiX",
        category="finite_element",
        confidence=0.96,
        description="CalculiX constraint/contact/MPC olusturma",
    ),
    APISignature(
        pattern=r"(?:preiter|prespooles|prepardiso)[_]?",
        algorithm="calculix_solver_prep",
        library="CalculiX",
        category="finite_element",
        confidence=0.95,
        description="CalculiX solver hazirlama (SPOOLES/PARDISO oncesi)",
    ),
    APISignature(
        pattern=r"(?:radflowload|radmatrix)[_]?",
        algorithm="calculix_radiation",
        library="CalculiX",
        category="finite_element",
        confidence=0.94,
        description="CalculiX radyasyon isi transferi",
    ),
    APISignature(
        pattern=r"(?:calinput|keystart|iniparser)[_]?",
        algorithm="calculix_input_parser",
        library="CalculiX",
        category="finite_element",
        confidence=0.93,
        description="CalculiX input dosya parser (*STEP, *MATERIAL, vb.)",
    ),

    # ========================================================================
    #  NetCDF  (scientific data I/O)
    # ========================================================================
    APISignature(
        pattern=r"nc_(?:create|open|close)",
        algorithm="netcdf_file",
        library="NetCDF",
        category="scientific_io",
        confidence=0.94,
        description="NetCDF dosya olusturma/acma/kapatma",
    ),
    APISignature(
        pattern=r"nc_(?:def_dim|def_var|put_var|get_var)",
        algorithm="netcdf_data",
        library="NetCDF",
        category="scientific_io",
        confidence=0.95,
        description="NetCDF boyut/degisken tanimlama ve veri okuma/yazma",
    ),
    APISignature(
        pattern=r"nc_put_att",
        algorithm="netcdf_attribute",
        library="NetCDF",
        category="scientific_io",
        confidence=0.93,
        description="NetCDF attribute (metadata) yazma",
    ),

    # ========================================================================
    #  SCOTCH  (graph/mesh partitioning -- alternative to METIS)
    # ========================================================================
    APISignature(
        pattern=r"SCOTCH_(?:graphOrder|graphPart|meshOrder)",
        algorithm="scotch_partitioning",
        library="SCOTCH",
        category="graph_algorithm",
        confidence=0.96,
        description="SCOTCH graph/mesh partitioning ve ordering",
    ),
    APISignature(
        pattern=r"SCOTCH_(?:graphInit|graphBuild|graphLoad|graphFree)",
        algorithm="scotch_graph_management",
        library="SCOTCH",
        category="graph_algorithm",
        confidence=0.93,
        description="SCOTCH graph olusturma/yukleme/silme",
    ),

    # ========================================================================
    #  CUDA  (general GPU patterns for scientific computing)
    # ========================================================================
    APISignature(
        pattern=r"cudaMalloc(?:Managed|Host)?",
        algorithm="cuda_memory_alloc",
        library="CUDA",
        category="gpu_computing",
        confidence=0.90,
        description="CUDA GPU bellek ayirma",
    ),
    APISignature(
        pattern=r"cudaMemcpy(?:Async)?",
        algorithm="cuda_memory_transfer",
        library="CUDA",
        category="gpu_computing",
        confidence=0.90,
        description="CUDA host-device bellek transferi",
    ),
    APISignature(
        pattern=r"cudaDeviceSynchronize",
        algorithm="cuda_sync",
        library="CUDA",
        category="gpu_computing",
        confidence=0.88,
        description="CUDA device senkronizasyon",
    ),
    APISignature(
        pattern=r"cudaStreamCreate(?:WithFlags)?",
        algorithm="cuda_stream",
        library="CUDA",
        category="gpu_computing",
        confidence=0.88,
        description="CUDA stream olusturma (async execution)",
    ),
]


# ---------------------------------------------------------------------------
# Tum pattern'leri birlestirip tek bir regex ile tarayan combined pattern
# ---------------------------------------------------------------------------

def _add_word_boundary(pattern: str) -> str:
    r"""Add word boundary assertions to an API pattern.

    Prevents substring matches like "dscal" matching inside "ScanQuotedScalar".
    Uses \b (word boundary) which works correctly with IGNORECASE.

    For patterns starting with [_]? or ending with [_]?, the \b is placed
    outside the optional underscore to ensure proper boundary detection.
    """
    # If the pattern already has explicit word boundaries, leave it alone
    if pattern.startswith(r"\b") or pattern.startswith("(?:^"):
        return pattern
    # Add \b before and after the pattern
    return rf"\b(?:{pattern})\b"


def _build_combined_regex(apis: list[APISignature]) -> re.Pattern[str]:
    """Tum API pattern'lerini | ile birlestirip tek regex derler.

    Bu sayede bir fonksiyon listesi uzerinde O(n) yerine O(1) tek gecis ile
    eslestirme yapilabilir.  Her pattern gruplama icindedir -- eslesen grubun
    indeksinden hangi API'ye denk geldigini bulabiliriz.

    IMPORTANT (2026-03-25): Word boundaries (\b) added to each pattern to
    prevent substring matches (e.g. "dscal" inside "ScanQuotedScalar").
    """
    # Her pattern'i named group yapamayiz (isim cakismasi olur),
    # ama numarali gruplarla eslestirme yapabiliriz.
    parts: list[str] = []
    for api in apis:
        # Her API pattern'ini word-boundary-wrapped non-capturing group icine al
        parts.append(f"(?:{_add_word_boundary(api.pattern)})")
    combined = "|".join(parts)
    return re.compile(combined, re.IGNORECASE)


API_COMBINED_REGEX: re.Pattern[str] = _build_combined_regex(ENGINEERING_APIS)
