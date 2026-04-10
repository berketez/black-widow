#!/usr/bin/env python3
"""Expand CFG fingerprint templates with general-purpose algorithm patterns.

This script:
1. Updates existing templates that have zeroed features 16-23 with proper estimates.
2. Adds ~120 new general-purpose algorithm templates covering:
   - Sorting variants
   - Search variants
   - Data structure operations (linked list, binary tree, heap, queue, etc.)
   - String operations
   - Memory management
   - Error handling / common patterns
   - I/O patterns
   - Concurrency patterns
   - Bit manipulation
   - Math utilities
   - Parsing patterns
   - Validation / checksum

Feature vector (24-dim) reference:
    0:  block_count (normalized log)
    1:  edge_count (normalized log)
    2:  loop_count (normalized)
    3:  max_loop_depth (normalized)
    4:  cyclomatic_complexity (normalized log)
    5:  diamond_count / block_count
    6:  back_edge_count / edge_count
    7:  dominator_tree_depth (normalized)
    8:  entry_block_out_degree
    9:  exit_block_in_degree
    10: avg_block_size (instruction count, normalized)
    11: max_block_size (normalized)
    12: conditional_edge_ratio
    13: fall_through_edge_ratio
    14: self_loop_count
    15: linear_chain_ratio
    16: call_depth (CALL/BL/BLR count / 10.0)
    17: arithmetic_intensity (total_instr / edges / 20)
    18: constant_usage_ratio (reserved, 0.0)
    19: switch_case_ratio
    20: memory_access_pattern (avg_block_size * loops / 500)
    21: recursive_flag (0.0 or 1.0)
    22: simd_indicator (reserved, 0.0)
    23: avg_operand_complexity (total_instr / blocks / 30)
"""

import json
import sys
from pathlib import Path


TEMPLATE_PATH = Path(__file__).parent.parent / "karadul" / "reconstruction" / "computation" / "templates" / "known_algorithms.json"


# -----------------------------------------------------------------------
# Feature 16-23 updates for existing templates that have zeros
# -----------------------------------------------------------------------
# Format: name -> [f16, f17, f18, f19, f20, f21, f22, f23]
# f16: call_depth, f17: arithmetic_intensity, f18: reserved(0),
# f19: switch_case_ratio, f20: memory_access_pattern,
# f21: recursive_flag, f22: reserved(0), f23: avg_operand_complexity

EXISTING_UPDATES = {
    # Sorting -- no calls, low arithmetic, medium memory access, not recursive
    "bubble_sort":     [0.0, 0.15, 0.0, 0.0, 0.25, 0.0, 0.0, 0.18],
    "insertion_sort":  [0.0, 0.15, 0.0, 0.0, 0.25, 0.0, 0.0, 0.18],
    "selection_sort":  [0.0, 0.15, 0.0, 0.0, 0.25, 0.0, 0.0, 0.18],
    "quicksort":       [0.1, 0.12, 0.0, 0.0, 0.20, 1.0, 0.0, 0.15],  # recursive
    "mergesort":       [0.2, 0.12, 0.0, 0.0, 0.30, 1.0, 0.0, 0.18],  # recursive, malloc
    "heapsort":        [0.0, 0.15, 0.0, 0.0, 0.30, 0.0, 0.0, 0.20],
    "radix_sort":      [0.1, 0.10, 0.0, 0.0, 0.40, 0.0, 0.0, 0.15],
    "counting_sort":   [0.1, 0.10, 0.0, 0.0, 0.35, 0.0, 0.0, 0.15],
    "shell_sort":      [0.0, 0.15, 0.0, 0.0, 0.30, 0.0, 0.0, 0.18],
    "tim_sort_merge":  [0.2, 0.12, 0.0, 0.0, 0.35, 0.0, 0.0, 0.18],
    "introsort_partition": [0.1, 0.12, 0.0, 0.0, 0.25, 1.0, 0.0, 0.15],
    "partial_sort":    [0.1, 0.12, 0.0, 0.0, 0.25, 0.0, 0.0, 0.18],

    # Search
    "binary_search":   [0.0, 0.12, 0.0, 0.0, 0.15, 0.0, 0.0, 0.15],
    "linear_search":   [0.0, 0.10, 0.0, 0.0, 0.20, 0.0, 0.0, 0.12],
    "hash_lookup":     [0.1, 0.10, 0.0, 0.0, 0.25, 0.0, 0.0, 0.15],

    # Crypto -- higher arithmetic, medium calls
    "aes_round":       [0.0, 0.55, 0.0, 0.0, 0.15, 0.0, 0.0, 0.42],
    "sha256_transform": [0.0, 0.60, 0.0, 0.0, 0.20, 0.0, 0.0, 0.45],
    "md5_transform":   [0.0, 0.58, 0.0, 0.0, 0.20, 0.0, 0.0, 0.42],
    "chacha20_block":  [0.0, 0.55, 0.0, 0.0, 0.10, 0.0, 0.0, 0.45],
    "aes_key_schedule": [0.0, 0.50, 0.0, 0.0, 0.15, 0.0, 0.0, 0.40],
    "sha512_transform": [0.0, 0.62, 0.0, 0.0, 0.22, 0.0, 0.0, 0.48],
    "sha3_keccak_f":   [0.0, 0.58, 0.0, 0.0, 0.18, 0.0, 0.0, 0.45],
    "rsa_modexp":      [0.1, 0.55, 0.0, 0.0, 0.15, 0.0, 0.0, 0.45],
    "ecdsa_sign":      [0.2, 0.52, 0.0, 0.0, 0.15, 0.0, 0.0, 0.42],
    "poly1305_blocks": [0.0, 0.50, 0.0, 0.0, 0.15, 0.0, 0.0, 0.42],
    "gcm_ghash":       [0.0, 0.52, 0.0, 0.0, 0.18, 0.0, 0.0, 0.40],
    "des_feistel":     [0.0, 0.55, 0.0, 0.0, 0.12, 0.0, 0.0, 0.42],
    "blowfish_encrypt": [0.0, 0.52, 0.0, 0.0, 0.15, 0.0, 0.0, 0.40],
    "rc4_prga":        [0.0, 0.35, 0.0, 0.0, 0.25, 0.0, 0.0, 0.30],

    # Numerical -- high arithmetic, medium calls for some
    "matrix_multiply": [0.0, 0.50, 0.0, 0.0, 0.55, 0.0, 0.0, 0.40],
    "lu_decomposition": [0.0, 0.48, 0.0, 0.0, 0.50, 0.0, 0.0, 0.40],
    "cholesky":        [0.0, 0.50, 0.0, 0.0, 0.45, 0.0, 0.0, 0.42],
    "gauss_quadrature": [0.1, 0.45, 0.0, 0.0, 0.35, 0.0, 0.0, 0.38],
    "newton_raphson":  [0.1, 0.40, 0.0, 0.0, 0.20, 0.0, 0.0, 0.35],
    "jacobi_iteration": [0.0, 0.35, 0.0, 0.0, 0.50, 0.0, 0.0, 0.30],
    "gauss_seidel":    [0.0, 0.35, 0.0, 0.0, 0.50, 0.0, 0.0, 0.30],
    "conjugate_gradient": [0.2, 0.38, 0.0, 0.0, 0.55, 0.0, 0.0, 0.32],
    "svd_householder": [0.1, 0.48, 0.0, 0.0, 0.45, 0.0, 0.0, 0.40],
    "qr_givens":       [0.05, 0.45, 0.0, 0.0, 0.40, 0.0, 0.0, 0.38],
    "thomas_algorithm": [0.0, 0.40, 0.0, 0.0, 0.45, 0.0, 0.0, 0.35],
    "bisection_method": [0.1, 0.25, 0.0, 0.0, 0.10, 0.0, 0.0, 0.22],
    "secant_method":   [0.1, 0.30, 0.0, 0.0, 0.10, 0.0, 0.0, 0.25],
    "fixed_point_iteration": [0.1, 0.30, 0.0, 0.0, 0.10, 0.0, 0.0, 0.25],
    "power_method":    [0.1, 0.40, 0.0, 0.0, 0.40, 0.0, 0.0, 0.35],
    "inverse_iteration": [0.2, 0.42, 0.0, 0.0, 0.42, 0.0, 0.0, 0.36],
    "lanczos_step":    [0.2, 0.40, 0.0, 0.0, 0.50, 0.0, 0.0, 0.35],
    "arnoldi_step":    [0.2, 0.40, 0.0, 0.0, 0.48, 0.0, 0.0, 0.35],
    "gmres_step":      [0.2, 0.38, 0.0, 0.0, 0.50, 0.0, 0.0, 0.35],
    "multigrid_vcycle": [0.3, 0.35, 0.0, 0.0, 0.55, 1.0, 0.0, 0.32],  # recursive
    "gauss_seidel_step": [0.0, 0.35, 0.0, 0.0, 0.50, 0.0, 0.0, 0.30],
    "sor_step":        [0.0, 0.35, 0.0, 0.0, 0.50, 0.0, 0.0, 0.30],
    "incomplete_lu":   [0.0, 0.42, 0.0, 0.0, 0.50, 0.0, 0.0, 0.38],

    # DSP
    "fft_butterfly":   [0.0, 0.48, 0.0, 0.0, 0.25, 0.0, 0.0, 0.40],
    "fir_filter":      [0.0, 0.42, 0.0, 0.0, 0.35, 0.0, 0.0, 0.35],
    "convolution":     [0.0, 0.45, 0.0, 0.0, 0.40, 0.0, 0.0, 0.38],
    "dft_naive":       [0.0, 0.50, 0.0, 0.0, 0.35, 0.0, 0.0, 0.42],
    "inverse_fft":     [0.0, 0.48, 0.0, 0.0, 0.25, 0.0, 0.0, 0.40],
    "autocorrelation": [0.0, 0.45, 0.0, 0.0, 0.35, 0.0, 0.0, 0.38],
    "cross_correlation": [0.0, 0.45, 0.0, 0.0, 0.35, 0.0, 0.0, 0.38],
    "window_function_apply": [0.0, 0.35, 0.0, 0.0, 0.20, 0.0, 0.0, 0.30],

    # Graph
    "dfs":             [0.1, 0.10, 0.0, 0.0, 0.30, 1.0, 0.0, 0.15],  # recursive
    "bfs":             [0.1, 0.10, 0.0, 0.0, 0.30, 0.0, 0.0, 0.15],
    "dijkstra":        [0.1, 0.15, 0.0, 0.0, 0.35, 0.0, 0.0, 0.20],
    "bellman_ford":    [0.0, 0.15, 0.0, 0.0, 0.35, 0.0, 0.0, 0.18],
    "floyd_warshall":  [0.0, 0.25, 0.0, 0.0, 0.55, 0.0, 0.0, 0.25],
    "kruskal_mst":     [0.2, 0.10, 0.0, 0.0, 0.30, 0.0, 0.0, 0.15],
    "tarjan_scc":      [0.1, 0.10, 0.0, 0.0, 0.30, 1.0, 0.0, 0.15],
    "a_star_search":   [0.2, 0.18, 0.0, 0.0, 0.35, 0.0, 0.0, 0.22],

    # Data structure
    "rbtree_insert":   [0.1, 0.10, 0.0, 0.05, 0.20, 0.0, 0.0, 0.15],
    "avl_rotate":      [0.0, 0.08, 0.0, 0.0, 0.15, 0.0, 0.0, 0.12],
    "linked_list_reverse": [0.0, 0.08, 0.0, 0.0, 0.20, 0.0, 0.0, 0.12],
    "stack_push_pop":  [0.0, 0.08, 0.0, 0.0, 0.15, 0.0, 0.0, 0.10],

    # String
    "strcmp_loop":     [0.0, 0.10, 0.0, 0.0, 0.15, 0.0, 0.0, 0.12],
    "memcpy_loop":    [0.0, 0.08, 0.0, 0.0, 0.30, 0.0, 0.0, 0.10],
    "strlen_loop":    [0.0, 0.10, 0.0, 0.0, 0.15, 0.0, 0.0, 0.10],
    "memmove_loop":   [0.0, 0.08, 0.0, 0.0, 0.30, 0.0, 0.0, 0.10],
    "memset_loop":    [0.0, 0.06, 0.0, 0.0, 0.25, 0.0, 0.0, 0.08],
    "strstr_naive":   [0.0, 0.12, 0.0, 0.0, 0.20, 0.0, 0.0, 0.15],
    "atoi_parse":     [0.0, 0.15, 0.0, 0.0, 0.10, 0.0, 0.0, 0.18],
    "base64_encode":  [0.0, 0.15, 0.0, 0.0, 0.20, 0.0, 0.0, 0.18],

    # Finance
    "black_scholes_step": [0.2, 0.48, 0.0, 0.0, 0.10, 0.0, 0.0, 0.40],
    "monte_carlo_step": [0.2, 0.35, 0.0, 0.0, 0.15, 0.0, 0.0, 0.30],
    "binomial_tree_step": [0.1, 0.30, 0.0, 0.0, 0.30, 0.0, 0.0, 0.28],
    "geometric_brownian_motion": [0.1, 0.40, 0.0, 0.0, 0.10, 0.0, 0.0, 0.35],
    "vasicek_step":    [0.1, 0.38, 0.0, 0.0, 0.10, 0.0, 0.0, 0.32],
    "cir_step":        [0.1, 0.38, 0.0, 0.0, 0.10, 0.0, 0.0, 0.32],
    "heston_vol_step": [0.1, 0.42, 0.0, 0.0, 0.10, 0.0, 0.0, 0.35],
    "barrier_option_check": [0.1, 0.25, 0.0, 0.0, 0.10, 0.0, 0.0, 0.22],
    "american_put_exercise": [0.1, 0.30, 0.0, 0.0, 0.15, 0.0, 0.0, 0.25],
    "yield_curve_bootstrap": [0.2, 0.35, 0.0, 0.0, 0.20, 0.0, 0.0, 0.30],
    "credit_default_swap": [0.2, 0.35, 0.0, 0.0, 0.15, 0.0, 0.0, 0.30],

    # Control flow
    "state_machine":    [0.1, 0.08, 0.0, 0.30, 0.10, 0.0, 0.0, 0.12],
    "event_loop":       [0.3, 0.08, 0.0, 0.15, 0.10, 0.0, 0.0, 0.12],
    "producer_consumer": [0.2, 0.08, 0.0, 0.05, 0.15, 0.0, 0.0, 0.10],

    # ML
    "softmax_forward":  [0.0, 0.35, 0.0, 0.0, 0.25, 0.0, 0.0, 0.30],
    "relu_backward":    [0.0, 0.20, 0.0, 0.0, 0.20, 0.0, 0.0, 0.18],
    "batch_norm_forward": [0.0, 0.38, 0.0, 0.0, 0.30, 0.0, 0.0, 0.32],
    "attention_score":  [0.1, 0.45, 0.0, 0.0, 0.35, 0.0, 0.0, 0.38],
    "embedding_lookup": [0.0, 0.10, 0.0, 0.0, 0.30, 0.0, 0.0, 0.12],
    "loss_cross_entropy": [0.0, 0.35, 0.0, 0.0, 0.25, 0.0, 0.0, 0.30],
    "adam_update":      [0.0, 0.40, 0.0, 0.0, 0.35, 0.0, 0.0, 0.35],
    "dropout_forward":  [0.1, 0.15, 0.0, 0.0, 0.20, 0.0, 0.0, 0.15],

    # Compression
    "huffman_encode":   [0.1, 0.15, 0.0, 0.0, 0.25, 0.0, 0.0, 0.18],
    "lz77_match":       [0.0, 0.15, 0.0, 0.0, 0.35, 0.0, 0.0, 0.18],
    "deflate_block":    [0.2, 0.20, 0.0, 0.10, 0.30, 0.0, 0.0, 0.22],
    "run_length_encode": [0.0, 0.12, 0.0, 0.0, 0.25, 0.0, 0.0, 0.15],
    "dictionary_lookup": [0.0, 0.10, 0.0, 0.0, 0.25, 0.0, 0.0, 0.15],

    # Linear algebra
    "dot_product":      [0.0, 0.45, 0.0, 0.0, 0.30, 0.0, 0.0, 0.35],
    "vector_add":       [0.0, 0.35, 0.0, 0.0, 0.30, 0.0, 0.0, 0.28],
    "vector_scale":     [0.0, 0.35, 0.0, 0.0, 0.25, 0.0, 0.0, 0.28],
    "matrix_transpose": [0.0, 0.15, 0.0, 0.0, 0.45, 0.0, 0.0, 0.18],
    "matrix_vector_multiply": [0.0, 0.45, 0.0, 0.0, 0.45, 0.0, 0.0, 0.38],
    "outer_product":    [0.0, 0.40, 0.0, 0.0, 0.40, 0.0, 0.0, 0.35],
    "trace_computation": [0.0, 0.35, 0.0, 0.0, 0.20, 0.0, 0.0, 0.28],
    "determinant_cofactor": [0.1, 0.38, 0.0, 0.0, 0.35, 1.0, 0.0, 0.32],

    # FEA
    "shape_function_eval": [0.0, 0.45, 0.0, 0.0, 0.20, 0.0, 0.0, 0.38],
    "stiffness_assembly": [0.1, 0.40, 0.0, 0.0, 0.55, 0.0, 0.0, 0.35],
    "load_vector_assembly": [0.1, 0.38, 0.0, 0.0, 0.50, 0.0, 0.0, 0.32],
    "boundary_condition_apply": [0.0, 0.25, 0.0, 0.05, 0.35, 0.0, 0.0, 0.22],
    "element_jacobian": [0.0, 0.48, 0.0, 0.0, 0.25, 0.0, 0.0, 0.40],
    "strain_displacement": [0.0, 0.45, 0.0, 0.0, 0.25, 0.0, 0.0, 0.38],
    "stress_update":    [0.0, 0.42, 0.0, 0.05, 0.20, 0.0, 0.0, 0.35],
    "plasticity_return_map": [0.1, 0.42, 0.0, 0.05, 0.15, 0.0, 0.0, 0.38],
    "contact_detection": [0.2, 0.25, 0.0, 0.05, 0.40, 0.0, 0.0, 0.25],
    "mesh_refinement":  [0.3, 0.15, 0.0, 0.05, 0.40, 1.0, 0.0, 0.18],

    # CFD
    "roe_flux":         [0.0, 0.48, 0.0, 0.05, 0.20, 0.0, 0.0, 0.40],
    "hll_flux":         [0.0, 0.45, 0.0, 0.05, 0.18, 0.0, 0.0, 0.38],
    "muscl_reconstruction": [0.0, 0.42, 0.0, 0.05, 0.25, 0.0, 0.0, 0.35],
    "runge_kutta_time_step": [0.2, 0.45, 0.0, 0.0, 0.30, 0.0, 0.0, 0.38],
    "pressure_correction": [0.2, 0.38, 0.0, 0.0, 0.45, 0.0, 0.0, 0.32],
    "velocity_update":  [0.0, 0.35, 0.0, 0.0, 0.40, 0.0, 0.0, 0.30],
    "turbulence_source": [0.1, 0.40, 0.0, 0.05, 0.30, 0.0, 0.0, 0.35],
    "boundary_layer_wall": [0.1, 0.35, 0.0, 0.05, 0.25, 0.0, 0.0, 0.30],

    # System
    "malloc_freelist":  [0.1, 0.08, 0.0, 0.05, 0.25, 0.0, 0.0, 0.12],
    "spinlock_acquire": [0.0, 0.05, 0.0, 0.0, 0.05, 0.0, 0.0, 0.08],
    "mutex_lock_wait":  [0.1, 0.05, 0.0, 0.05, 0.05, 0.0, 0.0, 0.08],
    "ring_buffer_enqueue": [0.0, 0.08, 0.0, 0.0, 0.15, 0.0, 0.0, 0.10],
    "hash_table_insert": [0.1, 0.10, 0.0, 0.0, 0.25, 0.0, 0.0, 0.15],
}


# -----------------------------------------------------------------------
# New templates
# -----------------------------------------------------------------------
# Each entry: (name, category, 24-dim fingerprint, structure_hash, description,
#              expected_params, expected_return)

NEW_TEMPLATES = [
    # ===================================================================
    # SORTING VARIANTS
    # ===================================================================
    {
        "name": "quicksort_hoare",
        "category": "sorting",
        # Hoare partition: slightly more blocks/edges than Lomuto, same recursion
        "fingerprint": [
            0.48, 0.58, 0.3, 0.2, 0.52, 0.28, 0.05, 0.45,
            0.4, 0.3, 0.18, 0.30, 0.42, 0.28, 0.0, 0.25,
            0.1, 0.12, 0.0, 0.0, 0.20, 1.0, 0.0, 0.15
        ],
        "structure_hash": "wl_qsort_hoare_0001",
        "description": "Quicksort with Hoare partition scheme (two-pointer)",
        "expected_params": {"arr": "void*", "low": "int", "high": "int"},
        "expected_return": "void",
    },
    {
        "name": "quicksort_3way",
        "category": "sorting",
        # 3-way partition: more branches, handles duplicates
        "fingerprint": [
            0.52, 0.62, 0.3, 0.2, 0.55, 0.30, 0.05, 0.48,
            0.4, 0.3, 0.18, 0.30, 0.45, 0.28, 0.0, 0.22,
            0.1, 0.12, 0.0, 0.0, 0.22, 1.0, 0.0, 0.15
        ],
        "structure_hash": "wl_qsort_3way_0001",
        "description": "Dutch national flag 3-way quicksort for duplicate keys",
        "expected_params": {"arr": "void*", "low": "int", "high": "int"},
        "expected_return": "void",
    },
    {
        "name": "quicksort_iterative",
        "category": "sorting",
        # Uses explicit stack instead of recursion
        "fingerprint": [
            0.42, 0.52, 0.3, 0.4, 0.45, 0.22, 0.08, 0.40,
            0.4, 0.3, 0.18, 0.32, 0.38, 0.32, 0.0, 0.28,
            0.1, 0.12, 0.0, 0.0, 0.22, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_qsort_iter_0001",
        "description": "Iterative quicksort using explicit stack",
        "expected_params": {"arr": "void*", "n": "int"},
        "expected_return": "void",
    },
    {
        "name": "mergesort_iterative",
        "category": "sorting",
        # Bottom-up merge sort, no recursion, nested loops
        "fingerprint": [
            0.38, 0.46, 0.3, 0.6, 0.42, 0.20, 0.08, 0.35,
            0.4, 0.25, 0.20, 0.35, 0.35, 0.35, 0.0, 0.30,
            0.1, 0.12, 0.0, 0.0, 0.35, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_msort_iter_0001",
        "description": "Bottom-up iterative merge sort",
        "expected_params": {"arr": "void*", "n": "int"},
        "expected_return": "void",
    },
    {
        "name": "insertion_sort_binary",
        "category": "sorting",
        # Binary insertion sort: uses binary search for insert position
        "fingerprint": [
            0.30, 0.35, 0.2, 0.4, 0.28, 0.18, 0.10, 0.28,
            0.4, 0.2, 0.20, 0.28, 0.38, 0.32, 0.0, 0.35,
            0.0, 0.15, 0.0, 0.0, 0.28, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_bisort_0001",
        "description": "Insertion sort using binary search for insert position",
        "expected_params": {"arr": "void*", "n": "int"},
        "expected_return": "void",
    },
    {
        "name": "heapsort_bottom_up",
        "category": "sorting",
        # Bottom-up heapsort: sift-down without comparisons going up
        "fingerprint": [
            0.42, 0.50, 0.3, 0.4, 0.44, 0.22, 0.10, 0.38,
            0.4, 0.2, 0.18, 0.32, 0.38, 0.32, 0.0, 0.30,
            0.0, 0.15, 0.0, 0.0, 0.32, 0.0, 0.0, 0.20
        ],
        "structure_hash": "wl_buhsort_0001",
        "description": "Bottom-up heapsort (Floyd's improvement)",
        "expected_params": {"arr": "void*", "n": "int"},
        "expected_return": "void",
    },

    # ===================================================================
    # SEARCH VARIANTS
    # ===================================================================
    {
        "name": "binary_search_lower_bound",
        "category": "search",
        # Similar to binary search, slightly different branching
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.10, 0.10, 0.15,
            0.4, 0.2, 0.15, 0.20, 0.40, 0.30, 0.0, 0.40,
            0.0, 0.12, 0.0, 0.0, 0.12, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_bsearch_lb_0001",
        "description": "Binary search for lower bound (first >= target)",
        "expected_params": {"arr": "void*", "n": "int", "target": "int"},
        "expected_return": "int",
    },
    {
        "name": "binary_search_upper_bound",
        "category": "search",
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.10, 0.10, 0.15,
            0.4, 0.2, 0.15, 0.20, 0.40, 0.30, 0.0, 0.40,
            0.0, 0.12, 0.0, 0.0, 0.12, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_bsearch_ub_0001",
        "description": "Binary search for upper bound (first > target)",
        "expected_params": {"arr": "void*", "n": "int", "target": "int"},
        "expected_return": "int",
    },
    {
        "name": "interpolation_search",
        "category": "search",
        # More arithmetic (interpolation calc), similar structure to binary search
        "fingerprint": [
            0.18, 0.22, 0.1, 0.2, 0.15, 0.12, 0.10, 0.18,
            0.4, 0.2, 0.20, 0.25, 0.38, 0.30, 0.0, 0.35,
            0.0, 0.20, 0.0, 0.0, 0.15, 0.0, 0.0, 0.22
        ],
        "structure_hash": "wl_isearch_0001",
        "description": "Interpolation search for uniformly distributed data",
        "expected_params": {"arr": "void*", "n": "int", "target": "int"},
        "expected_return": "int",
    },
    {
        "name": "hash_table_resize",
        "category": "search",
        # Rehash: loop over old table, reinsert into new, calls hash+insert
        "fingerprint": [
            0.35, 0.42, 0.2, 0.4, 0.35, 0.18, 0.05, 0.30,
            0.4, 0.2, 0.15, 0.25, 0.30, 0.35, 0.0, 0.30,
            0.3, 0.10, 0.0, 0.0, 0.35, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_ht_resize_0001",
        "description": "Hash table resize/rehash -- allocate new, reinsert all",
        "expected_params": {"table": "void*"},
        "expected_return": "int",
    },
    {
        "name": "hash_table_delete",
        "category": "search",
        # hash -> walk chain -> unlink node
        "fingerprint": [
            0.22, 0.28, 0.1, 0.2, 0.22, 0.15, 0.05, 0.22,
            0.4, 0.2, 0.15, 0.22, 0.35, 0.35, 0.0, 0.30,
            0.1, 0.10, 0.0, 0.0, 0.22, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_ht_delete_0001",
        "description": "Hash table delete -- hash, find, unlink from chain",
        "expected_params": {"table": "void*", "key": "void*"},
        "expected_return": "int",
    },
    {
        "name": "hash_table_open_addressing",
        "category": "search",
        # Linear/quadratic probing loop
        "fingerprint": [
            0.20, 0.25, 0.1, 0.2, 0.20, 0.12, 0.08, 0.20,
            0.4, 0.2, 0.18, 0.25, 0.35, 0.32, 0.0, 0.35,
            0.05, 0.12, 0.0, 0.0, 0.20, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_ht_oa_0001",
        "description": "Hash table with open addressing (linear/quadratic probing)",
        "expected_params": {"table": "void*", "key": "void*"},
        "expected_return": "void*",
    },

    # ===================================================================
    # DATA STRUCTURE OPERATIONS
    # ===================================================================
    {
        "name": "linked_list_insert",
        "category": "data_structure",
        # Small: malloc + pointer update
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.45,
            0.1, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_ll_insert_0001",
        "description": "Singly linked list insert (head/tail/sorted)",
        "expected_params": {"head": "void**", "data": "void*"},
        "expected_return": "void",
    },
    {
        "name": "linked_list_delete",
        "category": "data_structure",
        # Walk list, find prev, unlink, free
        "fingerprint": [
            0.18, 0.22, 0.1, 0.2, 0.15, 0.12, 0.05, 0.15,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.35, 0.0, 0.35,
            0.1, 0.08, 0.0, 0.0, 0.15, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_ll_delete_0001",
        "description": "Singly linked list delete by value",
        "expected_params": {"head": "void**", "key": "void*"},
        "expected_return": "int",
    },
    {
        "name": "linked_list_search",
        "category": "data_structure",
        # Simple traversal with comparison
        "fingerprint": [
            0.12, 0.15, 0.1, 0.2, 0.10, 0.08, 0.08, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.35, 0.35, 0.0, 0.40,
            0.0, 0.08, 0.0, 0.0, 0.15, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_ll_search_0001",
        "description": "Singly linked list linear search",
        "expected_params": {"head": "void*", "key": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "doubly_linked_list_insert",
        "category": "data_structure",
        # Similar to singly but with prev pointer update
        "fingerprint": [
            0.15, 0.18, 0.0, 0.0, 0.12, 0.10, 0.0, 0.12,
            0.4, 0.2, 0.15, 0.22, 0.28, 0.42, 0.0, 0.42,
            0.1, 0.08, 0.0, 0.0, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_dll_insert_0001",
        "description": "Doubly linked list insert with prev/next update",
        "expected_params": {"head": "void**", "data": "void*"},
        "expected_return": "void",
    },
    {
        "name": "doubly_linked_list_delete",
        "category": "data_structure",
        # Unlink: update prev->next and next->prev, free
        "fingerprint": [
            0.15, 0.18, 0.0, 0.0, 0.12, 0.10, 0.0, 0.12,
            0.4, 0.2, 0.15, 0.22, 0.30, 0.40, 0.0, 0.40,
            0.1, 0.08, 0.0, 0.0, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_dll_delete_0001",
        "description": "Doubly linked list delete -- O(1) unlink",
        "expected_params": {"node": "void*"},
        "expected_return": "void",
    },
    {
        "name": "binary_tree_insert",
        "category": "data_structure",
        # Recursive or iterative walk left/right, then alloc+attach
        "fingerprint": [
            0.18, 0.22, 0.1, 0.2, 0.15, 0.12, 0.05, 0.18,
            0.4, 0.2, 0.12, 0.20, 0.40, 0.30, 0.0, 0.35,
            0.1, 0.08, 0.0, 0.0, 0.15, 1.0, 0.0, 0.12
        ],
        "structure_hash": "wl_bst_insert_0001",
        "description": "Binary search tree insert (recursive)",
        "expected_params": {"root": "void**", "key": "int"},
        "expected_return": "void*",
    },
    {
        "name": "binary_tree_search",
        "category": "data_structure",
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.10, 0.08, 0.15,
            0.4, 0.2, 0.10, 0.18, 0.42, 0.30, 0.0, 0.38,
            0.0, 0.08, 0.0, 0.0, 0.12, 1.0, 0.0, 0.10
        ],
        "structure_hash": "wl_bst_search_0001",
        "description": "Binary search tree lookup (recursive)",
        "expected_params": {"root": "void*", "key": "int"},
        "expected_return": "void*",
    },
    {
        "name": "binary_tree_delete",
        "category": "data_structure",
        # More complex: find, handle 3 cases (leaf, one child, two children)
        "fingerprint": [
            0.32, 0.40, 0.1, 0.2, 0.32, 0.20, 0.05, 0.28,
            0.4, 0.3, 0.15, 0.22, 0.40, 0.30, 0.0, 0.28,
            0.2, 0.10, 0.0, 0.05, 0.18, 1.0, 0.0, 0.15
        ],
        "structure_hash": "wl_bst_delete_0001",
        "description": "Binary search tree delete with 3-case handling",
        "expected_params": {"root": "void**", "key": "int"},
        "expected_return": "void*",
    },
    {
        "name": "binary_tree_inorder",
        "category": "data_structure",
        # Simple recursive traversal: left, visit, right
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.12,
            0.4, 0.2, 0.10, 0.15, 0.30, 0.40, 0.0, 0.40,
            0.2, 0.06, 0.0, 0.0, 0.05, 1.0, 0.0, 0.08
        ],
        "structure_hash": "wl_bst_inorder_0001",
        "description": "Binary tree in-order traversal (recursive)",
        "expected_params": {"root": "void*", "callback": "void*"},
        "expected_return": "void",
    },
    {
        "name": "binary_tree_preorder",
        "category": "data_structure",
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.12,
            0.4, 0.2, 0.10, 0.15, 0.30, 0.40, 0.0, 0.40,
            0.2, 0.06, 0.0, 0.0, 0.05, 1.0, 0.0, 0.08
        ],
        "structure_hash": "wl_bst_preorder_0001",
        "description": "Binary tree pre-order traversal (recursive)",
        "expected_params": {"root": "void*", "callback": "void*"},
        "expected_return": "void",
    },
    {
        "name": "rbtree_delete",
        "category": "data_structure",
        # Complex: find + transplant + fixup (many cases)
        "fingerprint": [
            0.55, 0.68, 0.2, 0.2, 0.58, 0.28, 0.03, 0.48,
            0.4, 0.3, 0.15, 0.25, 0.42, 0.28, 0.0, 0.22,
            0.2, 0.10, 0.0, 0.08, 0.20, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_rbt_del_0001",
        "description": "Red-black tree delete with fixup cases",
        "expected_params": {"tree": "void*", "node": "void*"},
        "expected_return": "void",
    },
    {
        "name": "rbtree_fixup",
        "category": "data_structure",
        # Loop with case analysis (uncle red/black, left/right)
        "fingerprint": [
            0.35, 0.45, 0.1, 0.2, 0.38, 0.22, 0.05, 0.32,
            0.4, 0.2, 0.12, 0.20, 0.45, 0.25, 0.0, 0.25,
            0.1, 0.08, 0.0, 0.10, 0.15, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_rbt_fix_0001",
        "description": "Red-black tree insertion fixup (rotate + recolor)",
        "expected_params": {"tree": "void*", "node": "void*"},
        "expected_return": "void",
    },
    {
        "name": "rbtree_rotate",
        "category": "data_structure",
        # Small: 4-5 pointer updates
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.05, 0.0, 0.10,
            0.4, 0.2, 0.15, 0.22, 0.25, 0.45, 0.0, 0.50,
            0.0, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_rbt_rot_0001",
        "description": "Red-black tree left/right rotation",
        "expected_params": {"tree": "void*", "node": "void*"},
        "expected_return": "void",
    },
    {
        "name": "avl_insert",
        "category": "data_structure",
        # BST insert + height update + rebalance
        "fingerprint": [
            0.35, 0.42, 0.1, 0.2, 0.35, 0.20, 0.05, 0.30,
            0.4, 0.2, 0.12, 0.22, 0.42, 0.28, 0.0, 0.28,
            0.1, 0.10, 0.0, 0.05, 0.18, 1.0, 0.0, 0.15
        ],
        "structure_hash": "wl_avl_ins_0001",
        "description": "AVL tree insert with height update and rebalance",
        "expected_params": {"root": "void**", "key": "int"},
        "expected_return": "void*",
    },
    {
        "name": "avl_delete",
        "category": "data_structure",
        "fingerprint": [
            0.42, 0.52, 0.1, 0.2, 0.42, 0.25, 0.05, 0.35,
            0.4, 0.3, 0.12, 0.22, 0.42, 0.28, 0.0, 0.25,
            0.2, 0.10, 0.0, 0.05, 0.18, 1.0, 0.0, 0.15
        ],
        "structure_hash": "wl_avl_del_0001",
        "description": "AVL tree delete with rebalance",
        "expected_params": {"root": "void**", "key": "int"},
        "expected_return": "void*",
    },
    {
        "name": "avl_rebalance",
        "category": "data_structure",
        "fingerprint": [
            0.25, 0.32, 0.0, 0.0, 0.25, 0.18, 0.0, 0.22,
            0.4, 0.2, 0.12, 0.20, 0.42, 0.28, 0.0, 0.30,
            0.0, 0.08, 0.0, 0.05, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_avl_rebal_0001",
        "description": "AVL tree rebalance (4 rotation cases)",
        "expected_params": {"node": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "heap_insert",
        "category": "data_structure",
        # Append + sift-up loop
        "fingerprint": [
            0.12, 0.15, 0.1, 0.2, 0.10, 0.08, 0.08, 0.12,
            0.4, 0.2, 0.12, 0.18, 0.35, 0.35, 0.0, 0.40,
            0.0, 0.10, 0.0, 0.0, 0.12, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_heap_ins_0001",
        "description": "Binary heap insert with sift-up",
        "expected_params": {"heap": "void*", "key": "int"},
        "expected_return": "void",
    },
    {
        "name": "heap_extract_min",
        "category": "data_structure",
        # Swap root with last + sift-down
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.10, 0.08, 0.15,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.32, 0.0, 0.35,
            0.0, 0.10, 0.0, 0.0, 0.15, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_heap_ext_0001",
        "description": "Binary heap extract-min with sift-down",
        "expected_params": {"heap": "void*"},
        "expected_return": "int",
    },
    {
        "name": "heap_sift_up",
        "category": "data_structure",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.10, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.35, 0.35, 0.0, 0.45,
            0.0, 0.10, 0.0, 0.0, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_heap_up_0001",
        "description": "Heap sift-up (bubble up after insert)",
        "expected_params": {"heap": "void*", "idx": "int"},
        "expected_return": "void",
    },
    {
        "name": "heap_sift_down",
        "category": "data_structure",
        "fingerprint": [
            0.12, 0.15, 0.1, 0.2, 0.10, 0.08, 0.10, 0.12,
            0.4, 0.2, 0.12, 0.18, 0.38, 0.32, 0.0, 0.40,
            0.0, 0.10, 0.0, 0.0, 0.12, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_heap_down_0001",
        "description": "Heap sift-down (heapify after extract)",
        "expected_params": {"heap": "void*", "idx": "int"},
        "expected_return": "void",
    },
    {
        "name": "priority_queue_push",
        "category": "data_structure",
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.08, 0.08, 0.15,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.35, 0.0, 0.38,
            0.1, 0.10, 0.0, 0.0, 0.15, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_pq_push_0001",
        "description": "Priority queue push (heap insert wrapper)",
        "expected_params": {"pq": "void*", "priority": "int", "data": "void*"},
        "expected_return": "void",
    },
    {
        "name": "priority_queue_pop",
        "category": "data_structure",
        "fingerprint": [
            0.18, 0.22, 0.1, 0.2, 0.15, 0.10, 0.08, 0.18,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.32, 0.0, 0.35,
            0.1, 0.10, 0.0, 0.0, 0.15, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_pq_pop_0001",
        "description": "Priority queue pop (heap extract wrapper)",
        "expected_params": {"pq": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "deque_push_front",
        "category": "data_structure",
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.28, 0.42, 0.0, 0.48,
            0.0, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_deq_pf_0001",
        "description": "Double-ended queue push front (circular buffer)",
        "expected_params": {"deque": "void*", "data": "void*"},
        "expected_return": "void",
    },
    {
        "name": "deque_push_back",
        "category": "data_structure",
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.28, 0.42, 0.0, 0.48,
            0.0, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_deq_pb_0001",
        "description": "Double-ended queue push back (circular buffer)",
        "expected_params": {"deque": "void*", "data": "void*"},
        "expected_return": "void",
    },
    {
        "name": "deque_pop_front",
        "category": "data_structure",
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.48,
            0.0, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_deq_popf_0001",
        "description": "Double-ended queue pop front",
        "expected_params": {"deque": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "queue_enqueue",
        "category": "data_structure",
        "fingerprint": [
            0.10, 0.12, 0.0, 0.0, 0.08, 0.05, 0.0, 0.08,
            0.4, 0.2, 0.12, 0.18, 0.25, 0.45, 0.0, 0.50,
            0.0, 0.08, 0.0, 0.0, 0.06, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_q_enq_0001",
        "description": "Queue enqueue (linked list or circular buffer)",
        "expected_params": {"queue": "void*", "data": "void*"},
        "expected_return": "void",
    },
    {
        "name": "queue_dequeue",
        "category": "data_structure",
        "fingerprint": [
            0.10, 0.12, 0.0, 0.0, 0.08, 0.05, 0.0, 0.08,
            0.4, 0.2, 0.12, 0.18, 0.28, 0.42, 0.0, 0.50,
            0.1, 0.08, 0.0, 0.0, 0.06, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_q_deq_0001",
        "description": "Queue dequeue with empty check",
        "expected_params": {"queue": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "stack_peek",
        "category": "data_structure",
        "fingerprint": [
            0.08, 0.10, 0.0, 0.0, 0.05, 0.03, 0.0, 0.05,
            0.4, 0.2, 0.10, 0.15, 0.25, 0.48, 0.0, 0.55,
            0.0, 0.06, 0.0, 0.0, 0.05, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_stk_peek_0001",
        "description": "Stack peek (check empty + return top)",
        "expected_params": {"stack": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "circular_buffer_write",
        "category": "data_structure",
        # Modular index, full check, write
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.45,
            0.0, 0.10, 0.0, 0.0, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_cbuf_w_0001",
        "description": "Circular buffer write with wraparound",
        "expected_params": {"buf": "void*", "data": "void*"},
        "expected_return": "int",
    },
    {
        "name": "circular_buffer_read",
        "category": "data_structure",
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.45,
            0.0, 0.10, 0.0, 0.0, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_cbuf_r_0001",
        "description": "Circular buffer read with wraparound",
        "expected_params": {"buf": "void*", "out": "void*"},
        "expected_return": "int",
    },

    # ===================================================================
    # STRING OPERATIONS
    # ===================================================================
    {
        "name": "strncmp_loop",
        "category": "string",
        # Like strcmp but with length check
        "fingerprint": [
            0.12, 0.15, 0.1, 0.2, 0.10, 0.08, 0.10, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.38, 0.32, 0.0, 0.40,
            0.0, 0.10, 0.0, 0.0, 0.15, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_strncmp_0001",
        "description": "String comparison with length limit",
        "expected_params": {"s1": "char*", "s2": "char*", "n": "size_t"},
        "expected_return": "int",
    },
    {
        "name": "strchr_loop",
        "category": "string",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.10, 0.08,
            0.4, 0.2, 0.10, 0.15, 0.35, 0.35, 0.0, 0.45,
            0.0, 0.10, 0.0, 0.0, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_strchr_0001",
        "description": "Find first occurrence of character in string",
        "expected_params": {"s": "char*", "c": "int"},
        "expected_return": "char*",
    },
    {
        "name": "strrchr_loop",
        "category": "string",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.10, 0.08,
            0.4, 0.2, 0.10, 0.15, 0.35, 0.35, 0.0, 0.42,
            0.0, 0.10, 0.0, 0.0, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_strrchr_0001",
        "description": "Find last occurrence of character in string",
        "expected_params": {"s": "char*", "c": "int"},
        "expected_return": "char*",
    },
    {
        "name": "strcpy_loop",
        "category": "string",
        "fingerprint": [
            0.08, 0.10, 0.1, 0.2, 0.06, 0.03, 0.10, 0.06,
            0.4, 0.2, 0.08, 0.12, 0.30, 0.40, 0.0, 0.50,
            0.0, 0.08, 0.0, 0.0, 0.15, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_strcpy_0001",
        "description": "Copy string until null terminator",
        "expected_params": {"dst": "char*", "src": "char*"},
        "expected_return": "char*",
    },
    {
        "name": "strncpy_loop",
        "category": "string",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.10, 0.08,
            0.4, 0.2, 0.08, 0.12, 0.35, 0.35, 0.0, 0.45,
            0.0, 0.08, 0.0, 0.0, 0.15, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_strncpy_0001",
        "description": "Copy string with length limit",
        "expected_params": {"dst": "char*", "src": "char*", "n": "size_t"},
        "expected_return": "char*",
    },
    {
        "name": "strcat_loop",
        "category": "string",
        # strlen to find end, then copy
        "fingerprint": [
            0.12, 0.15, 0.2, 0.2, 0.10, 0.08, 0.08, 0.10,
            0.4, 0.2, 0.10, 0.15, 0.32, 0.38, 0.0, 0.42,
            0.0, 0.08, 0.0, 0.0, 0.18, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_strcat_0001",
        "description": "Concatenate strings (find end + copy)",
        "expected_params": {"dst": "char*", "src": "char*"},
        "expected_return": "char*",
    },
    {
        "name": "string_hash_djb2",
        "category": "string",
        # Simple loop: hash = hash * 33 + c
        "fingerprint": [
            0.08, 0.10, 0.1, 0.2, 0.06, 0.03, 0.10, 0.06,
            0.4, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.50,
            0.0, 0.18, 0.0, 0.0, 0.12, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_djb2_0001",
        "description": "DJB2 string hash (hash * 33 + c)",
        "expected_params": {"str": "char*"},
        "expected_return": "uint32_t",
    },
    {
        "name": "string_hash_fnv1a",
        "category": "string",
        # Loop: hash ^= c; hash *= FNV_prime
        "fingerprint": [
            0.08, 0.10, 0.1, 0.2, 0.06, 0.03, 0.10, 0.06,
            0.4, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.50,
            0.0, 0.18, 0.0, 0.0, 0.12, 0.0, 0.0, 0.20
        ],
        "structure_hash": "wl_fnv1a_0001",
        "description": "FNV-1a string hash (xor-then-multiply)",
        "expected_params": {"str": "char*"},
        "expected_return": "uint32_t",
    },
    {
        "name": "string_hash_murmur",
        "category": "string",
        # More complex: block processing + tail + finalization
        "fingerprint": [
            0.22, 0.28, 0.1, 0.2, 0.22, 0.15, 0.05, 0.20,
            0.4, 0.2, 0.18, 0.28, 0.32, 0.35, 0.0, 0.35,
            0.0, 0.30, 0.0, 0.05, 0.25, 0.0, 0.0, 0.28
        ],
        "structure_hash": "wl_murmur_0001",
        "description": "MurmurHash3 (block-based with finalization)",
        "expected_params": {"data": "void*", "len": "int", "seed": "uint32_t"},
        "expected_return": "uint32_t",
    },
    {
        "name": "string_reverse",
        "category": "string",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.08, 0.08,
            0.4, 0.2, 0.10, 0.15, 0.30, 0.40, 0.0, 0.45,
            0.0, 0.08, 0.0, 0.0, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_strrev_0001",
        "description": "In-place string reverse (two-pointer swap)",
        "expected_params": {"str": "char*"},
        "expected_return": "void",
    },
    {
        "name": "sprintf_format",
        "category": "string",
        # Complex: loop with format char switch (%d, %s, %f, etc.)
        "fingerprint": [
            0.55, 0.68, 0.2, 0.2, 0.58, 0.25, 0.05, 0.45,
            0.4, 0.2, 0.15, 0.25, 0.38, 0.28, 0.0, 0.22,
            0.3, 0.12, 0.0, 0.25, 0.20, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_sprintf_0001",
        "description": "sprintf-like format string processing",
        "expected_params": {"buf": "char*", "fmt": "char*"},
        "expected_return": "int",
    },
    {
        "name": "sscanf_parse",
        "category": "string",
        "fingerprint": [
            0.52, 0.65, 0.2, 0.2, 0.55, 0.25, 0.05, 0.42,
            0.4, 0.2, 0.15, 0.25, 0.40, 0.28, 0.0, 0.22,
            0.2, 0.12, 0.0, 0.25, 0.18, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_sscanf_0001",
        "description": "sscanf-like format string parsing",
        "expected_params": {"str": "char*", "fmt": "char*"},
        "expected_return": "int",
    },
    {
        "name": "utf8_decode",
        "category": "string",
        # Multi-branch: 1-4 byte sequences, validation
        "fingerprint": [
            0.28, 0.35, 0.1, 0.2, 0.28, 0.18, 0.05, 0.25,
            0.4, 0.2, 0.15, 0.22, 0.42, 0.28, 0.0, 0.28,
            0.0, 0.15, 0.0, 0.15, 0.15, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_utf8dec_0001",
        "description": "UTF-8 multi-byte character decoder",
        "expected_params": {"src": "char*", "codepoint": "uint32_t*"},
        "expected_return": "int",
    },
    {
        "name": "utf8_encode",
        "category": "string",
        "fingerprint": [
            0.22, 0.28, 0.0, 0.0, 0.22, 0.15, 0.0, 0.20,
            0.4, 0.2, 0.15, 0.22, 0.42, 0.28, 0.0, 0.30,
            0.0, 0.15, 0.0, 0.12, 0.10, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_utf8enc_0001",
        "description": "UTF-8 codepoint to byte sequence encoder",
        "expected_params": {"codepoint": "uint32_t", "dst": "char*"},
        "expected_return": "int",
    },
    {
        "name": "regex_match_simple",
        "category": "string",
        # Backtracking: recursive or loop with retry
        "fingerprint": [
            0.45, 0.55, 0.2, 0.4, 0.48, 0.22, 0.08, 0.38,
            0.4, 0.3, 0.12, 0.20, 0.42, 0.28, 0.0, 0.22,
            0.1, 0.10, 0.0, 0.10, 0.20, 1.0, 0.0, 0.15
        ],
        "structure_hash": "wl_regex_0001",
        "description": "Simple regex matcher with backtracking",
        "expected_params": {"pattern": "char*", "text": "char*"},
        "expected_return": "int",
    },

    # ===================================================================
    # MEMORY MANAGEMENT
    # ===================================================================
    {
        "name": "free_coalesce",
        "category": "memory",
        # Check adjacent blocks, merge if free, update freelist
        "fingerprint": [
            0.28, 0.35, 0.1, 0.2, 0.28, 0.18, 0.05, 0.25,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.32, 0.0, 0.30,
            0.1, 0.08, 0.0, 0.05, 0.20, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_free_coal_0001",
        "description": "Free with adjacent block coalescing",
        "expected_params": {"ptr": "void*"},
        "expected_return": "void",
    },
    {
        "name": "realloc_pattern",
        "category": "memory",
        # Check size, try extend in-place, else malloc+copy+free
        "fingerprint": [
            0.25, 0.32, 0.0, 0.0, 0.25, 0.18, 0.0, 0.22,
            0.4, 0.3, 0.15, 0.22, 0.35, 0.32, 0.0, 0.30,
            0.2, 0.08, 0.0, 0.05, 0.18, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_realloc_0001",
        "description": "Realloc: try extend, else malloc+memcpy+free",
        "expected_params": {"ptr": "void*", "new_size": "size_t"},
        "expected_return": "void*",
    },
    {
        "name": "memory_pool_alloc",
        "category": "memory",
        # Fast: check free list, pop, or allocate from pool
        "fingerprint": [
            0.15, 0.18, 0.0, 0.0, 0.12, 0.10, 0.0, 0.12,
            0.4, 0.2, 0.12, 0.18, 0.32, 0.38, 0.0, 0.40,
            0.0, 0.08, 0.0, 0.0, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_pool_alloc_0001",
        "description": "Memory pool fixed-size allocation (freelist pop)",
        "expected_params": {"pool": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "memory_pool_free",
        "category": "memory",
        "fingerprint": [
            0.10, 0.12, 0.0, 0.0, 0.08, 0.05, 0.0, 0.08,
            0.4, 0.2, 0.10, 0.15, 0.28, 0.42, 0.0, 0.50,
            0.0, 0.06, 0.0, 0.0, 0.06, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_pool_free_0001",
        "description": "Memory pool free (push to freelist)",
        "expected_params": {"pool": "void*", "ptr": "void*"},
        "expected_return": "void",
    },
    {
        "name": "arena_alloc",
        "category": "memory",
        # Bump allocator: align, check capacity, bump pointer
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.20, 0.30, 0.40, 0.0, 0.45,
            0.0, 0.10, 0.0, 0.0, 0.08, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_arena_alloc_0001",
        "description": "Arena allocator (bump pointer with alignment)",
        "expected_params": {"arena": "void*", "size": "size_t"},
        "expected_return": "void*",
    },
    {
        "name": "arena_reset",
        "category": "memory",
        "fingerprint": [
            0.08, 0.10, 0.0, 0.0, 0.05, 0.03, 0.0, 0.05,
            0.4, 0.2, 0.08, 0.12, 0.20, 0.50, 0.0, 0.55,
            0.0, 0.06, 0.0, 0.0, 0.05, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_arena_reset_0001",
        "description": "Arena reset (set offset to 0, no individual free)",
        "expected_params": {"arena": "void*"},
        "expected_return": "void",
    },
    {
        "name": "slab_alloc",
        "category": "memory",
        # Per-size-class cache with partial/full/empty slab lists
        "fingerprint": [
            0.28, 0.35, 0.1, 0.2, 0.28, 0.18, 0.05, 0.25,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.32, 0.0, 0.30,
            0.1, 0.08, 0.0, 0.05, 0.18, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_slab_alloc_0001",
        "description": "Slab allocator: per-size-class object cache",
        "expected_params": {"cache": "void*", "size": "size_t"},
        "expected_return": "void*",
    },
    {
        "name": "slab_free",
        "category": "memory",
        "fingerprint": [
            0.22, 0.28, 0.0, 0.0, 0.22, 0.15, 0.0, 0.20,
            0.4, 0.2, 0.12, 0.18, 0.32, 0.35, 0.0, 0.35,
            0.1, 0.06, 0.0, 0.05, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_slab_free_0001",
        "description": "Slab allocator free: return object to cache",
        "expected_params": {"cache": "void*", "ptr": "void*"},
        "expected_return": "void",
    },

    # ===================================================================
    # ERROR HANDLING & COMMON PATTERNS
    # ===================================================================
    {
        "name": "error_check_cleanup",
        "category": "control_flow",
        # Sequential: call -> check -> goto cleanup or return
        "fingerprint": [
            0.25, 0.32, 0.0, 0.0, 0.25, 0.18, 0.0, 0.22,
            0.4, 0.4, 0.12, 0.20, 0.38, 0.32, 0.0, 0.30,
            0.3, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_errclean_0001",
        "description": "Error check chain with goto-cleanup pattern",
        "expected_params": {},
        "expected_return": "int",
    },
    {
        "name": "error_propagation_chain",
        "category": "control_flow",
        # Multiple sequential checks, early return on error
        "fingerprint": [
            0.30, 0.38, 0.0, 0.0, 0.30, 0.20, 0.0, 0.25,
            0.4, 0.4, 0.12, 0.18, 0.42, 0.28, 0.0, 0.28,
            0.3, 0.08, 0.0, 0.0, 0.05, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_errprop_0001",
        "description": "Sequential error propagation (if err != 0 return err)",
        "expected_params": {},
        "expected_return": "int",
    },
    {
        "name": "callback_dispatch",
        "category": "control_flow",
        # Load function pointer + indirect call
        "fingerprint": [
            0.15, 0.18, 0.0, 0.0, 0.12, 0.10, 0.0, 0.12,
            0.4, 0.2, 0.15, 0.22, 0.30, 0.40, 0.0, 0.38,
            0.2, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_cbdispatch_0001",
        "description": "Callback dispatch through function pointer",
        "expected_params": {"callback": "void*", "data": "void*"},
        "expected_return": "int",
    },
    {
        "name": "callback_vtable_dispatch",
        "category": "control_flow",
        # Load vtable, index, call -- typical C++ virtual dispatch in C
        "fingerprint": [
            0.18, 0.22, 0.0, 0.0, 0.15, 0.12, 0.0, 0.15,
            0.4, 0.2, 0.15, 0.22, 0.28, 0.42, 0.0, 0.35,
            0.2, 0.08, 0.0, 0.0, 0.10, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_vtable_0001",
        "description": "Virtual table dispatch (load vtable + indexed call)",
        "expected_params": {"obj": "void*", "method_idx": "int"},
        "expected_return": "void*",
    },
    {
        "name": "function_pointer_table",
        "category": "control_flow",
        # Switch-like: index into table + call
        "fingerprint": [
            0.22, 0.28, 0.0, 0.0, 0.22, 0.15, 0.0, 0.20,
            0.6, 0.2, 0.15, 0.22, 0.30, 0.35, 0.0, 0.30,
            0.2, 0.08, 0.0, 0.15, 0.08, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_fptable_0001",
        "description": "Function pointer table dispatch (jump table)",
        "expected_params": {"table": "void**", "idx": "int"},
        "expected_return": "void*",
    },
    {
        "name": "observer_notify",
        "category": "control_flow",
        # Loop over listener list, call each
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.08, 0.08, 0.12,
            0.4, 0.2, 0.10, 0.15, 0.30, 0.38, 0.0, 0.38,
            0.3, 0.06, 0.0, 0.0, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_notify_0001",
        "description": "Observer pattern: notify all registered callbacks",
        "expected_params": {"observers": "void*", "event": "void*"},
        "expected_return": "void",
    },
    {
        "name": "observer_register",
        "category": "control_flow",
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.28, 0.42, 0.0, 0.42,
            0.1, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_obsreg_0001",
        "description": "Observer pattern: register callback",
        "expected_params": {"observers": "void*", "callback": "void*"},
        "expected_return": "int",
    },
    {
        "name": "factory_create",
        "category": "control_flow",
        # switch on type -> allocate + initialize specific subtype
        "fingerprint": [
            0.30, 0.38, 0.0, 0.0, 0.30, 0.20, 0.0, 0.25,
            0.6, 0.2, 0.15, 0.22, 0.35, 0.30, 0.0, 0.25,
            0.3, 0.08, 0.0, 0.25, 0.10, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_factory_0001",
        "description": "Factory pattern: switch on type, allocate specific struct",
        "expected_params": {"type": "int"},
        "expected_return": "void*",
    },
    {
        "name": "singleton_get_instance",
        "category": "control_flow",
        # Check if initialized, if not init, return instance
        "fingerprint": [
            0.10, 0.12, 0.0, 0.0, 0.08, 0.05, 0.0, 0.08,
            0.4, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.45,
            0.1, 0.06, 0.0, 0.0, 0.06, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_singleton_0001",
        "description": "Singleton get_instance (lazy init check)",
        "expected_params": {},
        "expected_return": "void*",
    },
    {
        "name": "ref_count_inc",
        "category": "control_flow",
        # Very small: atomic increment or load+store
        "fingerprint": [
            0.06, 0.08, 0.0, 0.0, 0.04, 0.02, 0.0, 0.04,
            0.2, 0.2, 0.08, 0.12, 0.20, 0.50, 0.0, 0.55,
            0.0, 0.10, 0.0, 0.0, 0.05, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_refcnt_inc_0001",
        "description": "Reference count increment (retain)",
        "expected_params": {"obj": "void*"},
        "expected_return": "void",
    },
    {
        "name": "ref_count_dec_free",
        "category": "control_flow",
        # Decrement + check zero + free if zero
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.10, 0.18, 0.32, 0.38, 0.0, 0.40,
            0.1, 0.08, 0.0, 0.0, 0.08, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_refcnt_dec_0001",
        "description": "Reference count decrement + conditional free (release)",
        "expected_params": {"obj": "void*"},
        "expected_return": "void",
    },
    {
        "name": "lazy_init",
        "category": "control_flow",
        "fingerprint": [
            0.12, 0.15, 0.0, 0.0, 0.10, 0.08, 0.0, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.32, 0.38, 0.0, 0.42,
            0.1, 0.06, 0.0, 0.0, 0.06, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_lazyinit_0001",
        "description": "Lazy initialization (check-then-init pattern)",
        "expected_params": {"obj": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "double_check_lock",
        "category": "control_flow",
        # Check -> lock -> check again -> init -> unlock
        "fingerprint": [
            0.18, 0.22, 0.0, 0.0, 0.15, 0.12, 0.0, 0.15,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.35, 0.0, 0.35,
            0.2, 0.06, 0.0, 0.0, 0.06, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_dblcheck_0001",
        "description": "Double-checked locking (DCLP) for thread-safe init",
        "expected_params": {"obj": "void*"},
        "expected_return": "void*",
    },

    # ===================================================================
    # I/O PATTERNS
    # ===================================================================
    {
        "name": "file_read_loop",
        "category": "io",
        # Loop: read chunk -> process -> check EOF
        "fingerprint": [
            0.18, 0.22, 0.1, 0.2, 0.15, 0.10, 0.08, 0.15,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.35, 0.0, 0.35,
            0.2, 0.08, 0.0, 0.0, 0.22, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_fread_0001",
        "description": "File read loop (read chunk + check EOF/error)",
        "expected_params": {"fd": "int", "buf": "void*", "size": "size_t"},
        "expected_return": "ssize_t",
    },
    {
        "name": "file_write_loop",
        "category": "io",
        "fingerprint": [
            0.18, 0.22, 0.1, 0.2, 0.15, 0.10, 0.08, 0.15,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.35, 0.0, 0.35,
            0.2, 0.08, 0.0, 0.0, 0.20, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_fwrite_0001",
        "description": "File write loop (write chunk + handle partial writes)",
        "expected_params": {"fd": "int", "buf": "void*", "size": "size_t"},
        "expected_return": "ssize_t",
    },
    {
        "name": "buffered_read",
        "category": "io",
        # Check buffer, refill if needed, copy from buffer
        "fingerprint": [
            0.22, 0.28, 0.1, 0.2, 0.22, 0.15, 0.05, 0.20,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.32, 0.0, 0.32,
            0.2, 0.08, 0.0, 0.0, 0.25, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_bufread_0001",
        "description": "Buffered read (check buffer -> refill -> copy)",
        "expected_params": {"stream": "void*", "buf": "void*", "n": "size_t"},
        "expected_return": "size_t",
    },
    {
        "name": "buffered_write",
        "category": "io",
        "fingerprint": [
            0.22, 0.28, 0.1, 0.2, 0.22, 0.15, 0.05, 0.20,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.32, 0.0, 0.32,
            0.2, 0.08, 0.0, 0.0, 0.22, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_bufwrite_0001",
        "description": "Buffered write (fill buffer -> flush when full)",
        "expected_params": {"stream": "void*", "buf": "void*", "n": "size_t"},
        "expected_return": "size_t",
    },
    {
        "name": "socket_read_loop",
        "category": "io",
        # recv in loop, handle partial reads, check disconnect
        "fingerprint": [
            0.22, 0.28, 0.1, 0.2, 0.22, 0.15, 0.08, 0.20,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.32, 0.0, 0.30,
            0.2, 0.08, 0.0, 0.0, 0.18, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_sockread_0001",
        "description": "Socket read loop (recv + partial read handling)",
        "expected_params": {"sock": "int", "buf": "void*", "len": "size_t"},
        "expected_return": "ssize_t",
    },
    {
        "name": "socket_accept_loop",
        "category": "io",
        # accept -> fork/dispatch -> continue
        "fingerprint": [
            0.20, 0.25, 0.1, 0.2, 0.20, 0.12, 0.08, 0.18,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.35, 0.0, 0.32,
            0.3, 0.06, 0.0, 0.0, 0.10, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_sockaccept_0001",
        "description": "Socket accept loop (listen -> accept -> handle)",
        "expected_params": {"sock": "int"},
        "expected_return": "void",
    },
    {
        "name": "poll_event_loop",
        "category": "io",
        # poll + iterate events + dispatch
        "fingerprint": [
            0.30, 0.38, 0.2, 0.4, 0.30, 0.18, 0.08, 0.25,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.30, 0.0, 0.28,
            0.3, 0.06, 0.0, 0.10, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_poll_0001",
        "description": "poll()-based event loop with fd dispatch",
        "expected_params": {"fds": "void*", "nfds": "int"},
        "expected_return": "void",
    },
    {
        "name": "select_event_loop",
        "category": "io",
        "fingerprint": [
            0.30, 0.38, 0.2, 0.4, 0.30, 0.18, 0.08, 0.25,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.30, 0.0, 0.28,
            0.3, 0.06, 0.0, 0.10, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_select_0001",
        "description": "select()-based event loop with fd_set check",
        "expected_params": {"maxfd": "int"},
        "expected_return": "void",
    },
    {
        "name": "epoll_event_loop",
        "category": "io",
        # epoll_wait + iterate events + dispatch
        "fingerprint": [
            0.32, 0.40, 0.2, 0.4, 0.32, 0.20, 0.08, 0.28,
            0.4, 0.2, 0.12, 0.22, 0.38, 0.30, 0.0, 0.28,
            0.3, 0.06, 0.0, 0.10, 0.15, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_epoll_0001",
        "description": "epoll-based event loop (Linux high-perf I/O)",
        "expected_params": {"epfd": "int"},
        "expected_return": "void",
    },

    # ===================================================================
    # CONCURRENCY
    # ===================================================================
    {
        "name": "thread_pool_dispatch",
        "category": "concurrency",
        # Lock queue -> push task -> signal worker -> unlock
        "fingerprint": [
            0.22, 0.28, 0.0, 0.0, 0.22, 0.15, 0.0, 0.20,
            0.4, 0.2, 0.12, 0.20, 0.32, 0.35, 0.0, 0.32,
            0.3, 0.06, 0.0, 0.0, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_tpool_disp_0001",
        "description": "Thread pool task submission (lock + enqueue + signal)",
        "expected_params": {"pool": "void*", "func": "void*", "arg": "void*"},
        "expected_return": "int",
    },
    {
        "name": "thread_pool_worker",
        "category": "concurrency",
        # Loop: lock -> wait condition -> dequeue -> unlock -> execute
        "fingerprint": [
            0.25, 0.32, 0.1, 0.2, 0.25, 0.15, 0.08, 0.22,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.32, 0.0, 0.30,
            0.3, 0.06, 0.0, 0.0, 0.10, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_tpool_work_0001",
        "description": "Thread pool worker loop (wait -> dequeue -> execute)",
        "expected_params": {"pool": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "mutex_trylock",
        "category": "concurrency",
        # Try CAS, return success/fail
        "fingerprint": [
            0.08, 0.10, 0.0, 0.0, 0.06, 0.03, 0.0, 0.06,
            0.4, 0.2, 0.08, 0.12, 0.30, 0.40, 0.0, 0.48,
            0.1, 0.06, 0.0, 0.0, 0.05, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_mtrylock_0001",
        "description": "Mutex try-lock (non-blocking CAS attempt)",
        "expected_params": {"mutex": "void*"},
        "expected_return": "int",
    },
    {
        "name": "rwlock_read",
        "category": "concurrency",
        # Spin/wait until no writers, increment reader count
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.08, 0.08, 0.12,
            0.4, 0.2, 0.10, 0.15, 0.35, 0.35, 0.0, 0.38,
            0.1, 0.06, 0.0, 0.0, 0.06, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_rwlock_r_0001",
        "description": "Reader-writer lock: acquire read (shared)",
        "expected_params": {"rwlock": "void*"},
        "expected_return": "void",
    },
    {
        "name": "rwlock_write",
        "category": "concurrency",
        # Wait until no readers AND no writers
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.08, 0.08, 0.12,
            0.4, 0.2, 0.10, 0.15, 0.35, 0.35, 0.0, 0.38,
            0.1, 0.06, 0.0, 0.0, 0.06, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_rwlock_w_0001",
        "description": "Reader-writer lock: acquire write (exclusive)",
        "expected_params": {"rwlock": "void*"},
        "expected_return": "void",
    },
    {
        "name": "condition_wait_signal",
        "category": "concurrency",
        # while(!predicate) cond_wait; ... cond_signal
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.08, 0.08, 0.12,
            0.4, 0.2, 0.10, 0.15, 0.35, 0.35, 0.0, 0.38,
            0.2, 0.06, 0.0, 0.0, 0.06, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_condwait_0001",
        "description": "Condition variable wait/signal pattern",
        "expected_params": {"cond": "void*", "mutex": "void*"},
        "expected_return": "void",
    },
    {
        "name": "semaphore_wait_post",
        "category": "concurrency",
        "fingerprint": [
            0.12, 0.15, 0.1, 0.2, 0.10, 0.05, 0.08, 0.10,
            0.4, 0.2, 0.10, 0.15, 0.32, 0.38, 0.0, 0.40,
            0.1, 0.06, 0.0, 0.0, 0.05, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_semwait_0001",
        "description": "Semaphore wait (decrement) / post (increment)",
        "expected_params": {"sem": "void*"},
        "expected_return": "int",
    },
    {
        "name": "atomic_cas_loop",
        "category": "concurrency",
        # Tight loop: load -> compute -> CAS -> retry if fail
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.10, 0.08,
            0.4, 0.2, 0.10, 0.15, 0.35, 0.35, 0.0, 0.42,
            0.0, 0.12, 0.0, 0.0, 0.05, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_casloop_0001",
        "description": "Atomic compare-and-swap retry loop (lock-free)",
        "expected_params": {"ptr": "void*", "expected": "int", "desired": "int"},
        "expected_return": "int",
    },
    {
        "name": "lock_free_queue_push",
        "category": "concurrency",
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.08, 0.10, 0.12,
            0.4, 0.2, 0.12, 0.18, 0.35, 0.35, 0.0, 0.38,
            0.1, 0.08, 0.0, 0.0, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_lfq_push_0001",
        "description": "Lock-free queue push (CAS on tail pointer)",
        "expected_params": {"queue": "void*", "data": "void*"},
        "expected_return": "void",
    },
    {
        "name": "lock_free_queue_pop",
        "category": "concurrency",
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.08, 0.10, 0.12,
            0.4, 0.2, 0.12, 0.18, 0.35, 0.35, 0.0, 0.38,
            0.1, 0.08, 0.0, 0.0, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_lfq_pop_0001",
        "description": "Lock-free queue pop (CAS on head pointer)",
        "expected_params": {"queue": "void*"},
        "expected_return": "void*",
    },

    # ===================================================================
    # BIT MANIPULATION
    # ===================================================================
    {
        "name": "popcount_loop",
        "category": "bitwise",
        # Loop: n &= (n-1), count++
        "fingerprint": [
            0.08, 0.10, 0.1, 0.2, 0.06, 0.03, 0.10, 0.06,
            0.2, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.48,
            0.0, 0.18, 0.0, 0.0, 0.06, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_popcnt_0001",
        "description": "Population count (count set bits via n&=(n-1) loop)",
        "expected_params": {"n": "uint32_t"},
        "expected_return": "int",
    },
    {
        "name": "bit_reverse",
        "category": "bitwise",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.08, 0.08,
            0.2, 0.2, 0.15, 0.20, 0.28, 0.42, 0.0, 0.45,
            0.0, 0.22, 0.0, 0.0, 0.05, 0.0, 0.0, 0.22
        ],
        "structure_hash": "wl_bitrev_0001",
        "description": "Bit reversal (shift-and-or loop or lookup table)",
        "expected_params": {"n": "uint32_t"},
        "expected_return": "uint32_t",
    },
    {
        "name": "next_power_of_two",
        "category": "bitwise",
        # Sequence of or-shift: v |= v >> 1; v |= v >> 2; ... v++
        "fingerprint": [
            0.08, 0.10, 0.0, 0.0, 0.06, 0.02, 0.0, 0.06,
            0.2, 0.2, 0.15, 0.22, 0.20, 0.50, 0.0, 0.52,
            0.0, 0.22, 0.0, 0.0, 0.03, 0.0, 0.0, 0.22
        ],
        "structure_hash": "wl_npow2_0001",
        "description": "Round up to next power of two (shift-or chain)",
        "expected_params": {"n": "uint32_t"},
        "expected_return": "uint32_t",
    },
    {
        "name": "leading_zeros",
        "category": "bitwise",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.08, 0.08,
            0.2, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.45,
            0.0, 0.18, 0.0, 0.0, 0.05, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_clz_0001",
        "description": "Count leading zeros (binary search or loop)",
        "expected_params": {"n": "uint32_t"},
        "expected_return": "int",
    },
    {
        "name": "trailing_zeros",
        "category": "bitwise",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.08, 0.08,
            0.2, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.45,
            0.0, 0.18, 0.0, 0.0, 0.05, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_ctz_0001",
        "description": "Count trailing zeros",
        "expected_params": {"n": "uint32_t"},
        "expected_return": "int",
    },
    {
        "name": "bitfield_extract",
        "category": "bitwise",
        "fingerprint": [
            0.06, 0.08, 0.0, 0.0, 0.04, 0.02, 0.0, 0.04,
            0.2, 0.2, 0.12, 0.18, 0.20, 0.50, 0.0, 0.55,
            0.0, 0.20, 0.0, 0.0, 0.03, 0.0, 0.0, 0.20
        ],
        "structure_hash": "wl_bfext_0001",
        "description": "Extract bitfield (shift + mask)",
        "expected_params": {"value": "uint32_t", "offset": "int", "width": "int"},
        "expected_return": "uint32_t",
    },
    {
        "name": "bitfield_insert",
        "category": "bitwise",
        "fingerprint": [
            0.08, 0.10, 0.0, 0.0, 0.06, 0.03, 0.0, 0.06,
            0.2, 0.2, 0.12, 0.18, 0.22, 0.48, 0.0, 0.52,
            0.0, 0.20, 0.0, 0.0, 0.03, 0.0, 0.0, 0.20
        ],
        "structure_hash": "wl_bfins_0001",
        "description": "Insert bitfield (clear + shift + or)",
        "expected_params": {"dest": "uint32_t*", "value": "uint32_t", "offset": "int", "width": "int"},
        "expected_return": "void",
    },

    # ===================================================================
    # MATH UTILITIES
    # ===================================================================
    {
        "name": "integer_sqrt",
        "category": "math",
        # Newton's method or binary search for sqrt(n)
        "fingerprint": [
            0.12, 0.15, 0.1, 0.2, 0.10, 0.08, 0.08, 0.10,
            0.2, 0.2, 0.15, 0.22, 0.35, 0.35, 0.0, 0.40,
            0.0, 0.22, 0.0, 0.0, 0.08, 0.0, 0.0, 0.22
        ],
        "structure_hash": "wl_isqrt_0001",
        "description": "Integer square root (Newton's method or binary search)",
        "expected_params": {"n": "uint64_t"},
        "expected_return": "uint32_t",
    },
    {
        "name": "integer_log2",
        "category": "math",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.08, 0.08,
            0.2, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.45,
            0.0, 0.18, 0.0, 0.0, 0.05, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_ilog2_0001",
        "description": "Integer log2 (bit position of highest set bit)",
        "expected_params": {"n": "uint32_t"},
        "expected_return": "int",
    },
    {
        "name": "gcd_euclidean",
        "category": "math",
        # Loop: while b != 0: a,b = b, a%b
        "fingerprint": [
            0.08, 0.10, 0.1, 0.2, 0.06, 0.03, 0.10, 0.06,
            0.2, 0.2, 0.15, 0.20, 0.35, 0.35, 0.0, 0.45,
            0.0, 0.22, 0.0, 0.0, 0.06, 0.0, 0.0, 0.22
        ],
        "structure_hash": "wl_gcd_0001",
        "description": "Greatest common divisor (Euclidean algorithm)",
        "expected_params": {"a": "int", "b": "int"},
        "expected_return": "int",
    },
    {
        "name": "lcm_pattern",
        "category": "math",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.08, 0.08,
            0.2, 0.2, 0.15, 0.20, 0.32, 0.38, 0.0, 0.42,
            0.1, 0.22, 0.0, 0.0, 0.06, 0.0, 0.0, 0.22
        ],
        "structure_hash": "wl_lcm_0001",
        "description": "Least common multiple via GCD",
        "expected_params": {"a": "int", "b": "int"},
        "expected_return": "int",
    },
    {
        "name": "modular_exponentiation",
        "category": "math",
        # Loop: square and multiply, similar to RSA
        "fingerprint": [
            0.15, 0.18, 0.1, 0.2, 0.12, 0.08, 0.08, 0.12,
            0.2, 0.2, 0.18, 0.25, 0.35, 0.35, 0.0, 0.38,
            0.0, 0.30, 0.0, 0.0, 0.10, 0.0, 0.0, 0.28
        ],
        "structure_hash": "wl_modexp_0001",
        "description": "Modular exponentiation (square-and-multiply)",
        "expected_params": {"base": "uint64_t", "exp": "uint64_t", "mod": "uint64_t"},
        "expected_return": "uint64_t",
    },
    {
        "name": "prime_sieve",
        "category": "math",
        # Sieve of Eratosthenes: nested loops, bit array
        "fingerprint": [
            0.22, 0.28, 0.2, 0.4, 0.22, 0.12, 0.08, 0.20,
            0.4, 0.2, 0.12, 0.20, 0.32, 0.35, 0.0, 0.35,
            0.1, 0.12, 0.0, 0.0, 0.35, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_sieve_0001",
        "description": "Sieve of Eratosthenes for prime generation",
        "expected_params": {"limit": "int", "primes": "int*"},
        "expected_return": "int",
    },
    {
        "name": "abs_diff",
        "category": "math",
        "fingerprint": [
            0.06, 0.08, 0.0, 0.0, 0.04, 0.02, 0.0, 0.04,
            0.2, 0.2, 0.12, 0.18, 0.30, 0.40, 0.0, 0.52,
            0.0, 0.18, 0.0, 0.0, 0.03, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_absdiff_0001",
        "description": "Absolute difference (branchless or conditional)",
        "expected_params": {"a": "int", "b": "int"},
        "expected_return": "int",
    },
    {
        "name": "clamp_value",
        "category": "math",
        "fingerprint": [
            0.08, 0.10, 0.0, 0.0, 0.06, 0.03, 0.0, 0.06,
            0.2, 0.2, 0.12, 0.18, 0.35, 0.35, 0.0, 0.48,
            0.0, 0.15, 0.0, 0.0, 0.03, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_clamp_0001",
        "description": "Clamp value to [min, max] range",
        "expected_params": {"val": "int", "min": "int", "max": "int"},
        "expected_return": "int",
    },
    {
        "name": "saturate_add",
        "category": "math",
        "fingerprint": [
            0.08, 0.10, 0.0, 0.0, 0.06, 0.03, 0.0, 0.06,
            0.2, 0.2, 0.12, 0.18, 0.32, 0.38, 0.0, 0.48,
            0.0, 0.18, 0.0, 0.0, 0.03, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_satadd_0001",
        "description": "Saturating addition (clamp on overflow)",
        "expected_params": {"a": "int", "b": "int"},
        "expected_return": "int",
    },

    # ===================================================================
    # PARSING
    # ===================================================================
    {
        "name": "tokenizer_loop",
        "category": "parsing",
        # Loop: skip whitespace -> extract token -> classify
        "fingerprint": [
            0.30, 0.38, 0.2, 0.4, 0.30, 0.18, 0.08, 0.25,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.30, 0.0, 0.28,
            0.1, 0.10, 0.0, 0.10, 0.18, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_tokenize_0001",
        "description": "Lexer/tokenizer loop (skip ws -> extract -> classify)",
        "expected_params": {"input": "char*", "tokens": "void*"},
        "expected_return": "int",
    },
    {
        "name": "recursive_descent_parse",
        "category": "parsing",
        # Many mutual recursive calls, switch on token type
        "fingerprint": [
            0.45, 0.55, 0.1, 0.2, 0.48, 0.22, 0.03, 0.42,
            0.4, 0.3, 0.12, 0.20, 0.38, 0.28, 0.0, 0.25,
            0.4, 0.08, 0.0, 0.15, 0.08, 1.0, 0.0, 0.12
        ],
        "structure_hash": "wl_rdparse_0001",
        "description": "Recursive descent parser (mutual recursion on grammar)",
        "expected_params": {"parser": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "json_parse_value",
        "category": "parsing",
        # Switch on first char: {, [, ", digit, true/false/null
        "fingerprint": [
            0.38, 0.48, 0.1, 0.2, 0.40, 0.22, 0.03, 0.35,
            0.6, 0.2, 0.12, 0.20, 0.40, 0.28, 0.0, 0.25,
            0.3, 0.08, 0.0, 0.20, 0.10, 1.0, 0.0, 0.12
        ],
        "structure_hash": "wl_jsonparse_0001",
        "description": "JSON value parser (switch on type: obj/arr/str/num/bool/null)",
        "expected_params": {"parser": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "xml_parse_tag",
        "category": "parsing",
        "fingerprint": [
            0.35, 0.45, 0.1, 0.2, 0.38, 0.20, 0.05, 0.32,
            0.4, 0.2, 0.12, 0.20, 0.40, 0.28, 0.0, 0.25,
            0.3, 0.08, 0.0, 0.15, 0.12, 1.0, 0.0, 0.12
        ],
        "structure_hash": "wl_xmlparse_0001",
        "description": "XML tag parser (open/close/self-closing detection)",
        "expected_params": {"parser": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "command_line_parse",
        "category": "parsing",
        # Loop over argv, switch on flag prefix (- or --)
        "fingerprint": [
            0.32, 0.40, 0.1, 0.2, 0.32, 0.18, 0.05, 0.28,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.30, 0.0, 0.28,
            0.2, 0.08, 0.0, 0.15, 0.10, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_argparse_0001",
        "description": "Command line argument parser (getopt-style)",
        "expected_params": {"argc": "int", "argv": "char**"},
        "expected_return": "int",
    },
    {
        "name": "ini_file_parse",
        "category": "parsing",
        # Loop lines: check [section], key=value, comments
        "fingerprint": [
            0.28, 0.35, 0.1, 0.2, 0.28, 0.15, 0.08, 0.25,
            0.4, 0.2, 0.12, 0.20, 0.38, 0.30, 0.0, 0.28,
            0.2, 0.08, 0.0, 0.12, 0.15, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_iniparse_0001",
        "description": "INI file parser ([section] + key=value)",
        "expected_params": {"filename": "char*", "config": "void*"},
        "expected_return": "int",
    },

    # ===================================================================
    # VALIDATION / CHECKSUM
    # ===================================================================
    {
        "name": "bounds_check",
        "category": "validation",
        # Very small: compare index against bounds, branch
        "fingerprint": [
            0.08, 0.10, 0.0, 0.0, 0.06, 0.03, 0.0, 0.06,
            0.4, 0.2, 0.10, 0.15, 0.35, 0.35, 0.0, 0.48,
            0.0, 0.10, 0.0, 0.0, 0.03, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_bounds_0001",
        "description": "Array bounds check (index < size)",
        "expected_params": {"index": "size_t", "size": "size_t"},
        "expected_return": "int",
    },
    {
        "name": "null_check_chain",
        "category": "validation",
        # Sequential: if(!p) return ERR; if(!p->x) return ERR; ...
        "fingerprint": [
            0.15, 0.18, 0.0, 0.0, 0.12, 0.10, 0.0, 0.12,
            0.4, 0.3, 0.10, 0.15, 0.40, 0.30, 0.0, 0.35,
            0.0, 0.06, 0.0, 0.0, 0.05, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_nullchk_0001",
        "description": "Chain of null pointer checks with early return",
        "expected_params": {"ptr": "void*"},
        "expected_return": "int",
    },
    {
        "name": "crc32_compute",
        "category": "validation",
        # Loop: table lookup per byte, XOR accumulate
        "fingerprint": [
            0.12, 0.15, 0.1, 0.2, 0.10, 0.05, 0.10, 0.10,
            0.4, 0.2, 0.15, 0.22, 0.30, 0.40, 0.0, 0.42,
            0.0, 0.18, 0.0, 0.0, 0.18, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_crc32_0001",
        "description": "CRC32 computation (table-driven byte loop)",
        "expected_params": {"data": "void*", "len": "size_t"},
        "expected_return": "uint32_t",
    },
    {
        "name": "checksum_adler32",
        "category": "validation",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.10, 0.08,
            0.4, 0.2, 0.15, 0.20, 0.30, 0.40, 0.0, 0.42,
            0.0, 0.18, 0.0, 0.0, 0.15, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_adler32_0001",
        "description": "Adler-32 checksum (running sum A + B*65521)",
        "expected_params": {"data": "void*", "len": "size_t"},
        "expected_return": "uint32_t",
    },
    {
        "name": "luhn_check",
        "category": "validation",
        # Loop digits from right, double every other, sum
        "fingerprint": [
            0.12, 0.15, 0.1, 0.2, 0.10, 0.08, 0.08, 0.10,
            0.4, 0.2, 0.12, 0.18, 0.32, 0.38, 0.0, 0.40,
            0.0, 0.15, 0.0, 0.0, 0.10, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_luhn_0001",
        "description": "Luhn algorithm (credit card / ID number validation)",
        "expected_params": {"digits": "char*"},
        "expected_return": "int",
    },

    # ===================================================================
    # ADDITIONAL COMMON PATTERNS (sqlite3, libc, misc)
    # ===================================================================
    {
        "name": "btree_page_search",
        "category": "data_structure",
        # B-tree: binary search within page keys, follow child pointer
        "fingerprint": [
            0.35, 0.42, 0.2, 0.4, 0.35, 0.20, 0.08, 0.30,
            0.4, 0.2, 0.15, 0.22, 0.40, 0.30, 0.0, 0.28,
            0.1, 0.12, 0.0, 0.0, 0.25, 0.0, 0.0, 0.18
        ],
        "structure_hash": "wl_btree_search_0001",
        "description": "B-tree page search (binary search keys, follow child)",
        "expected_params": {"page": "void*", "key": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "btree_page_split",
        "category": "data_structure",
        "fingerprint": [
            0.42, 0.52, 0.1, 0.2, 0.42, 0.22, 0.05, 0.35,
            0.4, 0.3, 0.15, 0.22, 0.35, 0.30, 0.0, 0.28,
            0.2, 0.10, 0.0, 0.0, 0.30, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_btree_split_0001",
        "description": "B-tree page split (allocate new page, redistribute keys)",
        "expected_params": {"page": "void*"},
        "expected_return": "int",
    },
    {
        "name": "btree_page_insert",
        "category": "data_structure",
        "fingerprint": [
            0.38, 0.48, 0.1, 0.2, 0.38, 0.22, 0.05, 0.32,
            0.4, 0.3, 0.15, 0.22, 0.38, 0.30, 0.0, 0.28,
            0.2, 0.10, 0.0, 0.0, 0.28, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_btree_insert_0001",
        "description": "B-tree page insert (find slot, shift, insert key)",
        "expected_params": {"page": "void*", "key": "void*", "value": "void*"},
        "expected_return": "int",
    },
    {
        "name": "lru_cache_get",
        "category": "data_structure",
        # Hash lookup + move-to-front in doubly-linked list
        "fingerprint": [
            0.22, 0.28, 0.1, 0.2, 0.22, 0.15, 0.05, 0.20,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.32, 0.0, 0.30,
            0.1, 0.08, 0.0, 0.0, 0.18, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_lru_get_0001",
        "description": "LRU cache get (hash lookup + move to front)",
        "expected_params": {"cache": "void*", "key": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "lru_cache_put",
        "category": "data_structure",
        # Insert or update + evict LRU if full
        "fingerprint": [
            0.28, 0.35, 0.1, 0.2, 0.28, 0.18, 0.05, 0.25,
            0.4, 0.2, 0.12, 0.20, 0.35, 0.32, 0.0, 0.28,
            0.2, 0.08, 0.0, 0.0, 0.20, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_lru_put_0001",
        "description": "LRU cache put (insert/update + evict oldest if full)",
        "expected_params": {"cache": "void*", "key": "void*", "value": "void*"},
        "expected_return": "int",
    },
    {
        "name": "varint_decode",
        "category": "encoding",
        # Loop: read byte, check high bit, accumulate value
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.10, 0.08,
            0.4, 0.2, 0.12, 0.18, 0.35, 0.35, 0.0, 0.42,
            0.0, 0.15, 0.0, 0.0, 0.10, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_varint_dec_0001",
        "description": "Variable-length integer decode (protobuf/sqlite style)",
        "expected_params": {"buf": "uint8_t*", "value": "uint64_t*"},
        "expected_return": "int",
    },
    {
        "name": "varint_encode",
        "category": "encoding",
        "fingerprint": [
            0.10, 0.12, 0.1, 0.2, 0.08, 0.05, 0.10, 0.08,
            0.4, 0.2, 0.12, 0.18, 0.32, 0.38, 0.0, 0.42,
            0.0, 0.15, 0.0, 0.0, 0.08, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_varint_enc_0001",
        "description": "Variable-length integer encode",
        "expected_params": {"value": "uint64_t", "buf": "uint8_t*"},
        "expected_return": "int",
    },
    {
        "name": "page_cache_fetch",
        "category": "data_structure",
        # Hash lookup, miss -> read from disk, insert into cache
        "fingerprint": [
            0.30, 0.38, 0.1, 0.2, 0.30, 0.18, 0.05, 0.28,
            0.4, 0.3, 0.12, 0.20, 0.35, 0.32, 0.0, 0.28,
            0.3, 0.08, 0.0, 0.05, 0.22, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_pcache_0001",
        "description": "Page cache fetch (hash lookup, miss -> disk read)",
        "expected_params": {"cache": "void*", "page_no": "int"},
        "expected_return": "void*",
    },
    {
        "name": "journal_write",
        "category": "io",
        # WAL/journal: serialize header + write page + sync
        "fingerprint": [
            0.25, 0.32, 0.1, 0.2, 0.25, 0.15, 0.05, 0.22,
            0.4, 0.2, 0.12, 0.20, 0.32, 0.35, 0.0, 0.30,
            0.3, 0.08, 0.0, 0.0, 0.22, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_journal_w_0001",
        "description": "Write-ahead log (journal) page write",
        "expected_params": {"journal": "void*", "page": "void*", "page_no": "int"},
        "expected_return": "int",
    },
    {
        "name": "comparison_function",
        "category": "control_flow",
        # Generic comparator: cast + compare fields
        "fingerprint": [
            0.10, 0.12, 0.0, 0.0, 0.08, 0.05, 0.0, 0.08,
            0.4, 0.2, 0.12, 0.18, 0.35, 0.35, 0.0, 0.45,
            0.0, 0.12, 0.0, 0.0, 0.05, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_cmpfn_0001",
        "description": "Generic comparison function (for qsort/bsearch callback)",
        "expected_params": {"a": "void*", "b": "void*"},
        "expected_return": "int",
    },
    {
        "name": "type_dispatch_switch",
        "category": "control_flow",
        # Large switch: 10+ cases based on type tag
        "fingerprint": [
            0.45, 0.55, 0.1, 0.2, 0.48, 0.22, 0.03, 0.40,
            0.8, 0.2, 0.12, 0.20, 0.42, 0.25, 0.0, 0.20,
            0.2, 0.08, 0.0, 0.35, 0.08, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_typedisp_0001",
        "description": "Type dispatch switch (large switch on type tag)",
        "expected_params": {"obj": "void*"},
        "expected_return": "int",
    },
    {
        "name": "cleanup_destructor",
        "category": "control_flow",
        # Sequential: free field1, free field2, ..., free struct
        "fingerprint": [
            0.18, 0.22, 0.0, 0.0, 0.15, 0.10, 0.0, 0.15,
            0.4, 0.2, 0.10, 0.15, 0.25, 0.42, 0.0, 0.38,
            0.4, 0.06, 0.0, 0.0, 0.08, 0.0, 0.0, 0.08
        ],
        "structure_hash": "wl_destructor_0001",
        "description": "Cleanup destructor (sequential free of struct fields)",
        "expected_params": {"obj": "void*"},
        "expected_return": "void",
    },
    {
        "name": "init_constructor",
        "category": "control_flow",
        # Allocate + zero + set defaults
        "fingerprint": [
            0.18, 0.22, 0.0, 0.0, 0.15, 0.10, 0.0, 0.15,
            0.4, 0.2, 0.12, 0.20, 0.25, 0.42, 0.0, 0.38,
            0.3, 0.08, 0.0, 0.0, 0.10, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_constructor_0001",
        "description": "Object constructor (allocate + zero + initialize fields)",
        "expected_params": {},
        "expected_return": "void*",
    },
    {
        "name": "array_grow",
        "category": "data_structure",
        # Dynamic array: check capacity, realloc if needed, append
        "fingerprint": [
            0.15, 0.18, 0.0, 0.0, 0.12, 0.10, 0.0, 0.12,
            0.4, 0.2, 0.12, 0.20, 0.32, 0.38, 0.0, 0.38,
            0.1, 0.08, 0.0, 0.0, 0.12, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_arrgrow_0001",
        "description": "Dynamic array grow (check capacity, realloc, append)",
        "expected_params": {"arr": "void*", "elem": "void*"},
        "expected_return": "int",
    },
    {
        "name": "array_binary_search",
        "category": "data_structure",
        # Sorted array binary search with comparator callback
        "fingerprint": [
            0.18, 0.22, 0.1, 0.2, 0.15, 0.10, 0.08, 0.15,
            0.4, 0.2, 0.12, 0.20, 0.40, 0.30, 0.0, 0.35,
            0.1, 0.10, 0.0, 0.0, 0.15, 0.0, 0.0, 0.15
        ],
        "structure_hash": "wl_arrbsearch_0001",
        "description": "Sorted array binary search with comparator",
        "expected_params": {"arr": "void*", "n": "int", "key": "void*", "cmp": "void*"},
        "expected_return": "void*",
    },
    {
        "name": "trie_insert",
        "category": "data_structure",
        # Walk/create nodes per character
        "fingerprint": [
            0.22, 0.28, 0.1, 0.2, 0.22, 0.15, 0.05, 0.20,
            0.4, 0.2, 0.12, 0.18, 0.35, 0.32, 0.0, 0.30,
            0.1, 0.08, 0.0, 0.0, 0.18, 0.0, 0.0, 0.12
        ],
        "structure_hash": "wl_trie_ins_0001",
        "description": "Trie insert (walk/create nodes per character)",
        "expected_params": {"root": "void*", "key": "char*"},
        "expected_return": "void",
    },
    {
        "name": "trie_search",
        "category": "data_structure",
        # Walk nodes per character, check is_end
        "fingerprint": [
            0.18, 0.22, 0.1, 0.2, 0.15, 0.10, 0.08, 0.15,
            0.4, 0.2, 0.10, 0.18, 0.38, 0.32, 0.0, 0.35,
            0.0, 0.08, 0.0, 0.0, 0.15, 0.0, 0.0, 0.10
        ],
        "structure_hash": "wl_trie_search_0001",
        "description": "Trie search (walk nodes, check is_end flag)",
        "expected_params": {"root": "void*", "key": "char*"},
        "expected_return": "int",
    },
    {
        "name": "hash_combine",
        "category": "data_structure",
        # Combine two hash values: seed ^= hash + 0x9e3779b9 + (seed << 6) + ...
        "fingerprint": [
            0.06, 0.08, 0.0, 0.0, 0.04, 0.02, 0.0, 0.04,
            0.2, 0.2, 0.15, 0.22, 0.20, 0.50, 0.0, 0.55,
            0.0, 0.25, 0.0, 0.0, 0.03, 0.0, 0.0, 0.25
        ],
        "structure_hash": "wl_hashcomb_0001",
        "description": "Hash combine (boost-style seed mixing)",
        "expected_params": {"seed": "uint32_t*", "value": "uint32_t"},
        "expected_return": "void",
    },
]


def main():
    """Load, update, expand, and save templates."""
    if not TEMPLATE_PATH.exists():
        print(f"ERROR: Template file not found: {TEMPLATE_PATH}", file=sys.stderr)
        sys.exit(1)

    # Load existing
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        templates = json.load(f)

    print(f"Loaded {len(templates)} existing templates")

    # Phase 1: Update features 16-23 for existing templates
    updated_count = 0
    for t in templates:
        name = t["name"]
        if name in EXISTING_UPDATES:
            fp = t["fingerprint"]
            new_vals = EXISTING_UPDATES[name]
            # Only update if current values are all zeros
            if all(v == 0.0 for v in fp[16:24]):
                for i, v in enumerate(new_vals):
                    fp[16 + i] = v
                updated_count += 1

    print(f"Updated features 16-23 for {updated_count} existing templates")

    # Phase 2: Add new templates
    existing_names = {t["name"] for t in templates}
    added_count = 0
    skipped = []
    for nt in NEW_TEMPLATES:
        if nt["name"] in existing_names:
            skipped.append(nt["name"])
            continue
        # Validate fingerprint length
        fp = nt["fingerprint"]
        if len(fp) != 24:
            print(f"WARNING: {nt['name']} has {len(fp)}-dim fingerprint, skipping",
                  file=sys.stderr)
            continue
        templates.append(nt)
        existing_names.add(nt["name"])
        added_count += 1

    if skipped:
        print(f"Skipped {len(skipped)} already-existing: {skipped}")

    print(f"Added {added_count} new templates")
    print(f"Total templates: {len(templates)}")

    # Count categories
    cats: dict[str, int] = {}
    for t in templates:
        c = t["category"]
        cats[c] = cats.get(c, 0) + 1
    print("\nCategory breakdown:")
    for c, n in sorted(cats.items()):
        print(f"  {c}: {n}")

    # Save
    with open(TEMPLATE_PATH, "w", encoding="utf-8") as f:
        json.dump(templates, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\nSaved to {TEMPLATE_PATH}")


if __name__ == "__main__":
    main()
