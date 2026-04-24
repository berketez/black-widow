"""Deep Call Chain Tracer -- traces all code paths from target functions.

Karadul v1.2.3 Module 4.  Given a target function, builds a depth-first
execution tree annotated with algorithm detections, domain labels,
composition stages, and dispatch types at each node.

v1.2.3 Performance fixes:
  - Per-trace timeout (_TRACE_TIMEOUT = 60s)
  - Auto-trace total timeout (_AUTO_TIMEOUT = 120s)
  - Max nodes per trace (_MAX_NODES_PER_TRACE = 500)
  - Max callees per node (_MAX_CALLEES_PER_NODE = 20)
  - visited set is now GLOBAL (not backtracked) -- prevents combinatorial
    explosion on large call graphs (67K+ edges).

Example output for ``GPStartVPNTunnel``::

    GPStartVPNTunnel (0x1000)
    +-- setup_tls [CRYPTO: tls_handshake] (0x2000)
    |   +-- generate_key [CRYPTO: key_gen] (0x3000)
    |   +-- verify_cert [CRYPTO: x509_verify] (0x3100)
    +-- connect_vpn [NETWORK: tcp_connect] (0x4000)
        +-- encrypt_tunnel [CRYPTO: aes_encrypt] (0x5000)

Kullanim:
    from karadul.reconstruction.engineering.deep_tracer import (
        DeepCallChainTracer,
    )
    tracer = DeepCallChainTracer(max_depth=8)
    result = tracer.trace("GPStartVPNTunnel", call_graph)
    print(tracer.render_ascii(result))
"""
from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# v1.2.3 Performance limits -- prevent combinatorial explosion on large graphs
# ---------------------------------------------------------------------------
_TRACE_TIMEOUT: float = 300.0      # Max seconds for a single trace() call
_AUTO_TIMEOUT: float = 600.0       # Max seconds for trace_auto() (all targets combined)
_MAX_NODES_PER_TRACE: int = 5000   # Max nodes expanded in a single trace tree
_MAX_CALLEES_PER_NODE: int = 100   # Max callees expanded per node (truncates adj list)


# ---------------------------------------------------------------------------
# Skip sets -- runtime/utility functions not worth expanding
# ---------------------------------------------------------------------------

SKIP_FUNCTIONS: frozenset[str] = frozenset({
    # -- Obj-C runtime -------------------------------------------------------
    "_objc_msgSend", "_objc_msgSendSuper2", "_objc_msgSendSuper",
    "_objc_retain", "_objc_release", "_objc_autorelease",
    "_objc_retainAutoreleasedReturnValue",
    "_objc_retainAutoreleaseReturnValue",
    "_objc_unsafeClaimAutoreleasedReturnValue",
    "_objc_opt_class", "_objc_opt_isKindOfClass",
    "_objc_opt_respondsToSelector", "_objc_opt_new",
    "_objc_alloc", "_objc_alloc_init",
    "_objc_storeStrong", "_objc_storeWeak",
    "_objc_destroyWeak", "_objc_loadWeakRetained",
    "_objc_copyWeak", "_objc_moveWeak",
    "_objc_autoreleasePoolPush", "_objc_autoreleasePoolPop",
    "_objc_enumerationMutation",
    "_objc_exception_throw", "_objc_terminate",
    "_objc_sync_enter", "_objc_sync_exit",
    "_objc_begin_catch", "_objc_end_catch",
    "_objc_setAssociatedObject", "_objc_getAssociatedObject",
    "_objc_setProperty", "_objc_getProperty",
    "_objc_setProperty_atomic", "_objc_setProperty_nonatomic",
    "_objc_setProperty_nonatomic_copy",
    "_objc_constructInstance", "_objc_destructInstance",
    "_objc_opt_self",
    "_objc_autoreleaseReturnValue",
    "_objc_retainAutorelease",
    "_objc_initWeak",
    "___objc_personality_v0",

    # -- GCD / libdispatch ---------------------------------------------------
    "_dispatch_async", "_dispatch_sync",
    "_dispatch_async_f", "_dispatch_sync_f",
    "_dispatch_barrier_async", "_dispatch_barrier_sync",
    "_dispatch_group_create", "_dispatch_group_enter",
    "_dispatch_group_leave", "_dispatch_group_wait",
    "_dispatch_group_notify",
    "_dispatch_queue_create", "_dispatch_get_global_queue",
    "_dispatch_get_main_queue",
    "_dispatch_semaphore_create", "_dispatch_semaphore_signal",
    "_dispatch_semaphore_wait",
    "_dispatch_time", "_dispatch_once",
    "_dispatch_data_create", "_dispatch_release",
    "_dispatch_retain",

    # -- CoreFoundation ------------------------------------------------------
    "_CFRelease", "_CFRetain", "_CFAutorelease",
    "_CFBridgingRelease", "_CFBridgingRetain",
    "_CFStringCreateWithCString",
    "_CFDictionaryGetValue", "_CFDictionarySetValue",
    "_CFArrayGetCount", "_CFArrayGetValueAtIndex",
    "_CFRunLoopGetCurrent", "_CFRunLoopRun",
    "_CFPreferencesGetAppBooleanValue",

    # -- Foundation / NSObject -----------------------------------------------
    "_NSLog", "_NSLogv",
    "__NSConcreteStackBlock", "__NSConcreteGlobalBlock",
    "_NSSearchPathForDirectoriesInDomains",
    "_NSStringFromClass",
    "_NSTemporaryDirectory",
    "_NSHomeDirectory",

    # -- Block runtime -------------------------------------------------------
    "__Block_object_dispose", "__Block_object_copy",
    "___block_descriptor",

    # -- C stdlib / memory ---------------------------------------------------
    "_malloc", "_calloc", "_realloc", "_free",
    "_reallocf", "_valloc",
    "_memcpy", "_memmove", "_memset", "_memcmp", "_memchr",
    "_bzero", "_bcopy",
    "_strlen", "_strcmp", "_strncmp", "_strcpy", "_strncpy",
    "_strcat", "_strncat", "_strstr", "_strchr", "_strrchr",
    "_strtol", "_strtoul", "_strtod", "_strtof",
    "_atoi", "_atol", "_atof",
    "_sprintf", "_snprintf", "_sscanf",
    "_printf", "_fprintf", "_vprintf", "_vfprintf",
    "_puts", "_putchar", "_getchar",
    "_fopen", "_fclose", "_fread", "_fwrite",
    "_fseek", "_ftell", "_fflush", "_feof", "_ferror",
    "_open", "_close", "_read", "_write",
    "_lseek", "_stat", "_fstat",
    "_usleep", "_sleep", "_nanosleep",
    "_abort", "_exit", "__exit",
    "_getenv", "_setenv", "_unsetenv",
    "_assert", "___assert_rtn",

    # -- C++ runtime ---------------------------------------------------------
    "___cxa_throw", "___cxa_rethrow",
    "___cxa_begin_catch", "___cxa_end_catch",
    "___cxa_allocate_exception", "___cxa_free_exception",
    "___cxa_guard_acquire", "___cxa_guard_release",
    "___cxa_guard_abort",
    "___cxa_atexit", "___cxa_finalize",
    "___gxx_personality_v0",
    "___clang_call_terminate",
    "_operator_new", "_operator_delete",
    "__Znwm", "__ZdlPv",           # operator new / delete mangled
    "__Znam", "__ZdaPv",           # operator new[] / delete[] mangled

    # -- Stack protection / security -----------------------------------------
    "___stack_chk_fail", "___stack_chk_guard",
    "___memcpy_chk", "___memset_chk",
    "___strcpy_chk", "___strncpy_chk",
    "___strncat_chk", "___snprintf_chk",
    "___sprintf_chk",

    # -- Thread / sync -------------------------------------------------------
    "_pthread_mutex_lock", "_pthread_mutex_unlock",
    "_pthread_mutex_init", "_pthread_mutex_destroy",
    "_pthread_rwlock_rdlock", "_pthread_rwlock_wrlock",
    "_pthread_rwlock_unlock",
    "_pthread_create", "_pthread_join", "_pthread_detach",
    "_pthread_self", "_pthread_equal",
    "_pthread_once",
    "_os_unfair_lock_lock", "_os_unfair_lock_unlock",

    # -- Error handling / logging --------------------------------------------
    "_perror", "_strerror",
    "_os_log_create", "_os_log_impl",
    "__os_log_impl", "__os_log_default",

    # -- Math (basic) --------------------------------------------------------
    "_sqrt", "_sqrtf", "_pow", "_powf",
    "_exp", "_expf", "_log", "_logf", "_log10", "_log2",
    "_sin", "_sinf", "_cos", "_cosf", "_tan", "_tanf",
    "_asin", "_acos", "_atan", "_atan2",
    "_fabs", "_fabsf", "_ceil", "_floor", "_round",
    "_fmin", "_fmax", "_fmod",

    # -- Ghidra artifacts / thunks -------------------------------------------
    "_entry", "__libc_start_main", "___libc_csu_init",
    "___libc_csu_fini",
    "__stub_helper",
    "_FUN_", "thunk_FUN_",  # Generic Ghidra unnamed functions
})

# Additional prefix patterns to skip (checked with startswith)
_SKIP_PREFIXES: tuple[str, ...] = (
    "_OBJC_CLASS_$_",
    "_OBJC_METACLASS_$_",
    "__stub_",
    "thunk_FUN_",
    "_FUN_",
    "___block_literal_",
    "switch_",
    "_got.",
)

# ---------------------------------------------------------------------------
# Domain inference from function name keywords
# ---------------------------------------------------------------------------

_DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "crypto": [
        "ssl", "tls", "aes", "rsa", "ecdsa", "sha", "md5", "hmac",
        "encrypt", "decrypt", "cipher", "cert", "x509", "pkcs",
        "sign", "verify", "key", "crypto", "hash", "digest",
    ],
    "network": [
        "socket", "connect", "bind", "listen", "accept", "send",
        "recv", "dns", "http", "url", "tcp", "udp", "ip",
        "vpn", "tunnel", "proxy", "network",
    ],
    "structural": [
        "stiffness", "element", "node", "mesh", "assembly",
        "solve", "newton", "residual", "convergence", "stress",
        "strain", "force", "displacement", "matrix",
    ],
    "fluid": [
        "velocity", "pressure", "flux", "gradient", "turbulent",
        "viscosity", "navier", "stokes", "euler",
    ],
    "ui": [
        "view", "window", "button", "label", "controller",
        "panel", "dialog", "menu", "toolbar", "statusbar",
        "NSView", "NSWindow", "UIView", "UIViewController",
    ],
    "config": [
        "config", "preference", "setting", "property",
        "load", "save", "default", "init",
    ],
    "gcd": [
        "dispatch", "queue", "group", "semaphore", "block",
    ],
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TraceNode:
    """A single node in the deep call trace tree."""

    function_name: str
    address: str = ""
    depth: int = 0
    children: list[TraceNode] = field(default_factory=list)
    algorithms: list[str] = field(default_factory=list)
    domain: str = ""
    dispatch_type: str | None = None  # "direct", "objc_dispatch", "vtable", None
    call_count: int = 1               # Times called from parent
    is_pruned: bool = False
    prune_reason: str | None = None   # "max_depth", "repeated", "skip", "no_algo"
    composition_stage: str | None = None  # e.g. "TLS Pipeline: stage 2 (key_exchange)"
    domain_tags: list[str] = field(default_factory=list)  # multiple domain tags

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "address": self.address,
            "depth": self.depth,
            "algorithms": self.algorithms,
            "domain": self.domain,
            "domain_tags": self.domain_tags,
            "dispatch_type": self.dispatch_type,
            "call_count": self.call_count,
            "is_pruned": self.is_pruned,
            "prune_reason": self.prune_reason,
            "composition_stage": self.composition_stage,
            "children": [c.to_dict() for c in self.children],
        }

    @property
    def descendant_count(self) -> int:
        """Total number of descendants (recursive)."""
        count = len(self.children)
        for child in self.children:
            count += child.descendant_count
        return count


@dataclass
class TraceResult:
    """Complete trace result for a single target function."""

    success: bool
    root: TraceNode | None
    total_nodes: int = 0
    max_depth_reached: int = 0
    algorithms_found: list[str] = field(default_factory=list)
    domains_found: list[str] = field(default_factory=list)
    trace_duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "target_function": self.root.function_name if self.root else "",
            "total_nodes": self.total_nodes,
            "max_depth_reached": self.max_depth_reached,
            "algorithms_found": self.algorithms_found,
            "domains_found": self.domains_found,
            "trace_duration_seconds": round(self.trace_duration_seconds, 4),
            "errors": self.errors,
            "root": self.root.to_dict() if self.root else None,
        }


# ---------------------------------------------------------------------------
# DeepCallChainTracer
# ---------------------------------------------------------------------------

class DeepCallChainTracer:
    """Traces deep call chains from target functions, building annotated
    execution trees.

    Each node in the tree carries:
      - Algorithm detections at that function
      - Domain label (crypto, network, structural, etc.)
      - Dispatch type (direct, objc_dispatch, vtable)
      - Children (callees, recursively expanded)

    Pruning strategies prevent exponential blowup:
      1. Skip known runtime/utility functions (SKIP_FUNCTIONS)
      2. Don't re-expand a subtree already visited (cycle break)
      3. Cap at max_depth
      4. Below a configurable depth, only expand algo-bearing functions
    """

    def __init__(
        self,
        config: Any | None = None,
        max_depth: int = 8,
        algo_priority_depth: int = 5,
        max_targets: int = 3,
    ) -> None:
        """
        Parameters
        ----------
        config : Config, optional
            Karadul configuration object.
        max_depth : int
            Maximum tree depth (default 8, was 10 in v1.2.2).
        algo_priority_depth : int
            Below this depth, only expand functions that have algorithm
            detections (default 5, was 6 in v1.2.2).
        max_targets : int
            Default top_n for trace_auto (default 3, was 5 in v1.2.2).
        """
        self._config = config
        self._max_depth = max_depth
        self._algo_priority_depth = algo_priority_depth
        self._max_targets = max_targets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def trace(
        self,
        target_function: str,
        call_graph: dict,
        algorithms: list | None = None,
        dispatch_result: dict | None = None,
        functions_json: Path | None = None,
    ) -> TraceResult:
        """Trace all code paths from a target function.

        Parameters
        ----------
        target_function : str
            Function name to trace from.
        call_graph : dict
            Ghidra call graph (or augmented call graph).
        algorithms : list, optional
            AlgorithmMatch objects or dicts.
        dispatch_result : dict, optional
            Virtual dispatch resolution data.
        functions_json : Path, optional
            Path to ``ghidra_functions.json`` for extra metadata.

        Returns
        -------
        TraceResult
        """
        t0 = time.monotonic()
        errors: list[str] = []
        deadline = t0 + _TRACE_TIMEOUT

        try:
            # Build indexes
            adjacency = self._build_adjacency(call_graph)
            func_addr_map = self._build_func_addr_map(call_graph, functions_json)
            algo_map = self._build_algo_map(algorithms)

            # Virtual edge dispatch type map
            dispatch_map = self._build_dispatch_map(call_graph)

            logger.debug(
                "Trace %s: %d functions, %d total edges in adjacency",
                target_function,
                len(adjacency),
                sum(len(v) for v in adjacency.values()),
            )

            # Check target exists
            if target_function not in adjacency and target_function not in func_addr_map:
                # Try case-insensitive lookup
                target_lower = target_function.lower()
                matched = None
                for name in adjacency:
                    if name.lower() == target_lower:
                        matched = name
                        break
                if not matched:
                    for name in func_addr_map:
                        if name.lower() == target_lower:
                            matched = name
                            break
                if matched:
                    target_function = matched
                else:
                    return TraceResult(
                        success=False,
                        root=None,
                        errors=[
                            f"Target function '{target_function}' not found "
                            f"in call graph ({len(adjacency)} functions indexed)."
                        ],
                        trace_duration_seconds=time.monotonic() - t0,
                    )

            # Build the tree (with timeout + node limit)
            visited: set[str] = set()
            node_count = [0]  # mutable counter for _build_tree
            root = self._build_tree(
                func_name=target_function,
                adjacency=adjacency,
                algo_map=algo_map,
                func_addr_map=func_addr_map,
                dispatch_map=dispatch_map,
                depth=0,
                visited=visited,
                deadline=deadline,
                node_count=node_count,
            )
            if node_count[0] >= _MAX_NODES_PER_TRACE:
                errors.append(
                    f"Node limit reached ({_MAX_NODES_PER_TRACE}), tree truncated"
                )
            if time.monotonic() >= deadline:
                errors.append(
                    f"Timeout reached ({_TRACE_TIMEOUT}s), tree truncated"
                )

            # v1.2: Annotate with composition stage information
            composition_map = self._build_composition_map(dispatch_result)
            if composition_map:
                self._annotate_algorithms(root, algo_map, composition_map)

            # Gather stats
            all_algos: set[str] = set()
            all_domains: set[str] = set()
            total_nodes = 0
            max_depth_seen = 0

            def _walk(node: TraceNode) -> None:
                nonlocal total_nodes, max_depth_seen
                total_nodes += 1
                max_depth_seen = max(max_depth_seen, node.depth)
                for algo in node.algorithms:
                    all_algos.add(algo)
                if node.domain:
                    all_domains.add(node.domain)
                for child in node.children:
                    _walk(child)

            _walk(root)

        except Exception as exc:
            logger.error("Trace failed for %s: %s", target_function, exc, exc_info=True)
            return TraceResult(
                success=False,
                root=None,
                errors=[str(exc)],
                trace_duration_seconds=time.monotonic() - t0,
            )

        return TraceResult(
            success=True,
            root=root,
            total_nodes=total_nodes,
            max_depth_reached=max_depth_seen,
            algorithms_found=sorted(all_algos),
            domains_found=sorted(all_domains),
            trace_duration_seconds=time.monotonic() - t0,
            errors=errors,
        )

    def trace_auto(
        self,
        call_graph: dict,
        algorithms: list | None = None,
        dispatch_result: Any | None = None,
        functions_json: Path | None = None,
        top_n: int = 5,
    ) -> list[TraceResult]:
        """Auto-select top N interesting target functions and trace each.

        Selection criteria (weighted scoring):
          1. Entry points (no callers, or called from main/start)
          2. High algorithm density in their subtree
          3. Many callees (complex orchestrator functions)
          4. Match known "interesting" patterns (GPStart*, main, etc.)

        Parameters
        ----------
        call_graph : dict
            Ghidra call graph.
        algorithms : list, optional
            Algorithm detections.
        dispatch_result : dict, optional
            Virtual dispatch resolution data.
        functions_json : Path, optional
            Path to ghidra_functions.json.
        top_n : int
            Number of targets to trace (default 5).

        Returns
        -------
        list[TraceResult]
        """
        auto_t0 = time.monotonic()
        auto_deadline = auto_t0 + _AUTO_TIMEOUT

        targets = self._select_targets(
            call_graph, algorithms, top_n,
            dispatch_result=dispatch_result,
        )
        results: list[TraceResult] = []

        for target in targets:
            # Check auto-trace total timeout
            if time.monotonic() >= auto_deadline:
                logger.warning(
                    "trace_auto timeout (%.0fs) reached after %d/%d targets",
                    _AUTO_TIMEOUT, len(results), len(targets),
                )
                break

            result = self.trace(
                target_function=target,
                call_graph=call_graph,
                algorithms=algorithms,
                dispatch_result=dispatch_result,
                functions_json=functions_json,
            )
            results.append(result)

        logger.info(
            "trace_auto completed: %d targets in %.1fs",
            len(results), time.monotonic() - auto_t0,
        )
        return results

    # ------------------------------------------------------------------
    # Tree construction
    # ------------------------------------------------------------------

    def _build_tree(
        self,
        func_name: str,
        adjacency: dict[str, list[str]],
        algo_map: dict[str, list[str]],
        func_addr_map: dict[str, str],
        dispatch_map: dict[tuple[str, str], str],
        depth: int,
        visited: set[str],
        parent_name: str = "",
        deadline: float = 0.0,
        node_count: list[int] | None = None,
    ) -> TraceNode:
        """Build trace tree recursively via DFS.

        v1.2.3 changes:
          - ``visited`` is now GLOBAL (no backtrack/discard). This prevents
            the same function from being expanded in multiple branches,
            eliminating combinatorial explosion on large graphs.
          - ``deadline`` param: if ``time.monotonic() >= deadline``, stop.
          - ``node_count`` param: mutable [int] counter, stops at
            ``_MAX_NODES_PER_TRACE``.
          - Callee list truncated to ``_MAX_CALLEES_PER_NODE``.

        Parameters
        ----------
        func_name : str
            Current function name.
        adjacency : dict
            Function -> list of callee names.
        algo_map : dict
            Function -> list of algorithm names.
        func_addr_map : dict
            Function -> address.
        dispatch_map : dict
            (caller, callee) -> dispatch type.
        depth : int
            Current depth.
        visited : set
            Already-visited function names (global, NOT backtracked).
        parent_name : str
            Caller's name (for dispatch type lookup).
        deadline : float
            Monotonic clock deadline. 0 = no limit.
        node_count : list[int], optional
            Mutable counter [current_count]. Stops at _MAX_NODES_PER_TRACE.

        Returns
        -------
        TraceNode
        """
        if node_count is None:
            node_count = [0]

        address = func_addr_map.get(func_name, "")
        algorithms = algo_map.get(func_name, [])
        domain = self._infer_domain(func_name, algorithms)
        disp_type = dispatch_map.get((parent_name, func_name))

        node = TraceNode(
            function_name=func_name,
            address=address,
            depth=depth,
            algorithms=list(algorithms),
            domain=domain,
            dispatch_type=disp_type,
        )

        node_count[0] += 1

        # -- Pruning checks --

        # 0. Timeout / node limit
        if deadline and time.monotonic() >= deadline:
            node.is_pruned = True
            node.prune_reason = "timeout"
            return node

        if node_count[0] >= _MAX_NODES_PER_TRACE:
            node.is_pruned = True
            node.prune_reason = "node_limit"
            return node

        # 1. Max depth
        if depth >= self._max_depth:
            node.is_pruned = True
            node.prune_reason = "max_depth"
            return node

        # 2. Already visited (GLOBAL -- no backtrack in v1.2.3)
        if func_name in visited:
            node.is_pruned = True
            node.prune_reason = "repeated"
            return node

        # 3. Skip known runtime functions
        if self._should_skip(func_name):
            node.is_pruned = True
            node.prune_reason = "skip"
            return node

        # 4. Below algo_priority_depth, skip non-algo functions
        if depth >= self._algo_priority_depth and not algorithms:
            node.is_pruned = True
            node.prune_reason = "no_algo"
            return node

        # Mark visited BEFORE recursing (prevents infinite loops)
        # v1.2.3: NO discard -- visited is global to prevent combinatorial explosion
        visited.add(func_name)

        # Get callees -- truncate to _MAX_CALLEES_PER_NODE
        callees = adjacency.get(func_name, [])

        # Sort callees: algo-bearing ones first, then by name
        def _callee_sort_key(callee: str) -> tuple[int, str]:
            has_algo = 0 if callee in algo_map else 1
            return (has_algo, callee)

        callees_sorted = sorted(callees, key=_callee_sort_key)[:_MAX_CALLEES_PER_NODE]

        if len(callees) > _MAX_CALLEES_PER_NODE:
            logger.debug(
                "%s: truncated %d callees to %d",
                func_name, len(callees), _MAX_CALLEES_PER_NODE,
            )

        # Expand callees
        for callee in callees_sorted:
            if self._should_skip(callee):
                continue

            # Early exit if we hit limits during expansion
            if node_count[0] >= _MAX_NODES_PER_TRACE:
                break
            if deadline and time.monotonic() >= deadline:
                break

            child = self._build_tree(
                func_name=callee,
                adjacency=adjacency,
                algo_map=algo_map,
                func_addr_map=func_addr_map,
                dispatch_map=dispatch_map,
                depth=depth + 1,
                visited=visited,
                parent_name=func_name,
                deadline=deadline,
                node_count=node_count,
            )
            node.children.append(child)

        # v1.2.3: visited is NOT discarded -- global dedup prevents explosion

        return node

    def _should_skip(self, func_name: str) -> bool:
        """Check if a function should be skipped (runtime/utility)."""
        if func_name in SKIP_FUNCTIONS:
            return True
        for prefix in _SKIP_PREFIXES:
            if func_name.startswith(prefix):
                return True
        # Skip unnamed Ghidra functions (FUN_XXXXXXXX pattern)
        if func_name.startswith("FUN_") and len(func_name) == 12:
            return True
        return False

    # ------------------------------------------------------------------
    # Target selection
    # ------------------------------------------------------------------

    def _select_targets(
        self,
        call_graph: dict,
        algorithms: list | None,
        top_n: int,
        dispatch_result: dict | None = None,
    ) -> list[str]:
        """Auto-select the most interesting target functions.

        Scoring (v1.2 enhanced):
            score = callee_count * (1 + n_algorithms) * entry_bonus
                    * pattern_bonus * dispatch_bonus * composition_bonus

        v1.2 additions:
          - Functions with many resolved dispatch edges get a bonus
          - Composition entry points (first stage of a composition) get a bonus
          - Functions that are dispatch resolution targets get a small bonus
        """
        adjacency = self._build_adjacency(call_graph)
        algo_map = self._build_algo_map(algorithms)

        # Build reverse adjacency for caller counting
        reverse_adj: dict[str, int] = defaultdict(int)
        for caller, callees in adjacency.items():
            for callee in callees:
                reverse_adj[callee] += 1

        # v1.2: Dispatch edge counts per function
        dispatch_edge_count: dict[str, int] = defaultdict(int)
        dispatch_targets: set[str] = set()
        if dispatch_result:
            # dispatch_result DispatchResolutionResult objesi veya dict olabilir
            sites = getattr(dispatch_result, "dispatch_sites", None)
            if sites is None and isinstance(dispatch_result, dict):
                sites = dispatch_result.get("dispatch_sites", [])
            for site in (sites or []):
                if isinstance(site, dict):
                    caller = site.get("caller_name", "")
                    resolved = site.get("resolved_targets", [])
                else:
                    # DispatchSite dataclass objesi
                    caller = getattr(site, "caller_func", "")
                    resolved = getattr(site, "resolved_targets", [])
                if caller:
                    dispatch_edge_count[caller] += len(resolved)
                    for t in resolved:
                        tname = t.get("name", "") if isinstance(t, dict) else str(t)
                        if tname:
                            dispatch_targets.add(tname)

        # v1.2: Composition entry points
        composition_entries: set[str] = set()
        if dispatch_result:
            # DispatchResolutionResult'da compositions attribute'u yok
            # to_dict() ile dict'e cevirip bakmak gerekir, veya dogrudan atla
            comps: list = []
            if isinstance(dispatch_result, dict):
                comps = dispatch_result.get("compositions", [])
            elif hasattr(dispatch_result, "compositions"):
                comps = dispatch_result.compositions
            for comp in comps:
                if isinstance(comp, dict):
                    stages = comp.get("stages", [])
                else:
                    stages = getattr(comp, "stages", [])
                if stages:
                    first = stages[0]
                    entry = first.get("function_name", "") if isinstance(first, dict) else getattr(first, "function_name", "")
                    if entry:
                        composition_entries.add(entry)

        # Interesting name patterns
        interesting_patterns = [
            "start", "init", "main", "run", "execute",
            "setup", "launch", "begin", "process",
            "handle", "perform", "solve", "compute",
            "nonlingeo", "arpack", "calculix",
        ]

        scores: dict[str, float] = {}

        for func_name, callees in adjacency.items():
            if self._should_skip(func_name):
                continue

            callee_count = len(callees)
            if callee_count == 0:
                continue  # Leaf functions are not interesting as targets

            n_algos = len(algo_map.get(func_name, []))
            caller_count = reverse_adj.get(func_name, 0)

            # Base score: callee count * algorithm presence
            score = callee_count * (1.0 + n_algos * 2.0)

            # Entry point bonus: functions with few callers
            if caller_count == 0:
                score *= 3.0  # Root function
            elif caller_count <= 2:
                score *= 1.5

            # Pattern bonus: matches known interesting patterns
            fn_lower = func_name.lower()
            for pat in interesting_patterns:
                if pat in fn_lower:
                    score *= 1.5
                    break

            # v1.2: Dispatch resolution bonus -- functions that resolve many
            # virtual dispatch sites are likely orchestrators
            n_dispatch = dispatch_edge_count.get(func_name, 0)
            if n_dispatch >= 5:
                score *= 2.0
            elif n_dispatch >= 2:
                score *= 1.5
            elif n_dispatch >= 1:
                score *= 1.2

            # v1.2: Composition entry point bonus
            if func_name in composition_entries:
                score *= 2.5

            # v1.2: Dispatch target bonus (resolved method implementations)
            if func_name in dispatch_targets:
                score *= 1.3

            # Penalty for very short names (likely auto-generated)
            if len(func_name) < 4:
                score *= 0.3

            # Penalty for Obj-C runtime/generic names
            if func_name.startswith("_objc_") or func_name.startswith("_CF"):
                score *= 0.1

            scores[func_name] = score

        # Sort by score descending, take top_n
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        targets = [name for name, _ in ranked[:top_n]]

        if targets:
            logger.info(
                "Auto-selected %d trace targets: %s",
                len(targets),
                ", ".join(f"{t}({scores[t]:.0f})" for t in targets[:5]),
            )

        return targets

    # ------------------------------------------------------------------
    # Rendering: ASCII tree
    # ------------------------------------------------------------------

    def render_ascii(self, result: TraceResult) -> str:
        """Render trace result as an ASCII art tree.

        Parameters
        ----------
        result : TraceResult
            Output from ``trace()``.

        Returns
        -------
        str
            ASCII tree representation.
        """
        if not result.root:
            return "(empty trace)"

        lines: list[str] = []
        self._render_node_ascii(result.root, lines, prefix="", is_last=True, is_root=True)
        return "\n".join(lines)

    def _render_node_ascii(
        self,
        node: TraceNode,
        lines: list[str],
        prefix: str,
        is_last: bool,
        is_root: bool = False,
    ) -> None:
        """Recursively render a node and its children as unicode box-drawing tree.

        Output format::

            main (0x1000)
            ├── setup_tls [CRYPTO: tls_handshake] (0x2000)
            │   ├── generate_key [CRYPTO: key_gen] (0x3000)
            │   └── verify_cert [CRYPTO: x509_verify] (0x3100)
            └── connect_vpn [NETWORK: tcp_connect] (0x4000)
                └── encrypt_tunnel [CRYPTO: aes_encrypt] (0x5000)
        """
        # Build the line for this node
        if is_root:
            connector = ""
            child_prefix = ""
        else:
            connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
            child_prefix = prefix + ("    " if is_last else "\u2502   ")

        # Node label: function_name + optional address
        label = node.function_name
        if node.address:
            label += f" ({node.address})"

        # Annotation brackets
        annotations: list[str] = []

        # Domain + algorithm annotation in [DOMAIN: algo] format
        if node.algorithms:
            algo_str = ", ".join(node.algorithms[:3])
            if len(node.algorithms) > 3:
                algo_str += f" +{len(node.algorithms) - 3}"
            if node.domain:
                annotations.append(f"[{node.domain.upper()}: {algo_str}]")
            else:
                annotations.append(f"[{algo_str}]")
        elif node.domain:
            annotations.append(f"[{node.domain.upper()}]")

        # Dispatch type (non-direct)
        if node.dispatch_type and node.dispatch_type != "direct":
            annotations.append(f"<{node.dispatch_type}>")

        # Composition stage
        if node.composition_stage:
            annotations.append(f"{{{node.composition_stage}}}")

        # Pruning indicator
        if node.is_pruned and node.prune_reason:
            annotations.append(f"... [{node.prune_reason}]")

        if annotations:
            label += " " + " ".join(annotations)

        lines.append(f"{prefix}{connector}{label}")

        # Render children
        visible_children = node.children
        for i, child in enumerate(visible_children):
            is_child_last = (i == len(visible_children) - 1)
            self._render_node_ascii(
                child, lines,
                prefix=child_prefix if not is_root else "",
                is_last=is_child_last,
            )

    # ------------------------------------------------------------------
    # Rendering: Mermaid flowchart
    # ------------------------------------------------------------------

    def render_mermaid(self, result: TraceResult) -> str:
        """Render trace result as a Mermaid flowchart.

        Parameters
        ----------
        result : TraceResult

        Returns
        -------
        str
            Mermaid diagram source.
        """
        if not result.root:
            return "graph TD\n    empty[No trace data]"

        lines: list[str] = ["graph TD"]
        node_ids: dict[str, str] = {}
        counter = [0]

        def _get_id(name: str, depth: int) -> str:
            key = f"{name}_{depth}"
            if key not in node_ids:
                counter[0] += 1
                node_ids[key] = f"N{counter[0]}"
            return node_ids[key]

        def _safe_label(text: str) -> str:
            """Escape characters that Mermaid interprets as syntax."""
            return text.replace('"', "'").replace("[", "(").replace("]", ")")

        def _walk(node: TraceNode, parent_id: str | None) -> None:
            nid = _get_id(node.function_name, node.depth)

            # Node label
            label = _safe_label(node.function_name)
            if node.algorithms:
                algo_str = _safe_label(", ".join(node.algorithms[:2]))
                label += f"\\n[{algo_str}]"
            if node.domain:
                label += f"\\n({node.domain})"
            if node.composition_stage:
                label += f"\\n*{_safe_label(node.composition_stage)}*"

            # Node shape based on characteristics
            if node.composition_stage:
                # Hexagon for composition stage nodes
                lines.append(f'    {nid}{{{{{label}}}}}')
            elif node.algorithms:
                lines.append(f"    {nid}[/{label}\\]")  # Trapezoid for algo nodes
            elif node.is_pruned:
                lines.append(f"    {nid}({label})")   # Rounded for pruned
            else:
                lines.append(f"    {nid}[{label}]")   # Rectangle default

            # Edge from parent
            if parent_id:
                edge_label = ""
                if node.dispatch_type and node.dispatch_type != "direct":
                    edge_label = f"|{node.dispatch_type}|"
                lines.append(f"    {parent_id} -->{edge_label} {nid}")

            # Limit children shown in Mermaid (too many becomes unreadable)
            children_to_show = node.children[:8]
            for child in children_to_show:
                _walk(child, nid)

            if len(node.children) > 8:
                more_id = f"MORE_{nid}"
                lines.append(f"    {more_id}[... +{len(node.children) - 8} more]")
                lines.append(f"    {nid} --> {more_id}")

        _walk(result.root, None)

        # Style algo nodes -- pink/magenta
        algo_node_ids = [
            _get_id(n.function_name, n.depth)
            for n in self._walk_nodes(result.root)
            if n.algorithms
        ]
        if algo_node_ids:
            lines.append(
                f"    style {','.join(algo_node_ids[:20])} fill:#f9f,stroke:#333"
            )

        # Style composition nodes -- green
        comp_node_ids = [
            _get_id(n.function_name, n.depth)
            for n in self._walk_nodes(result.root)
            if n.composition_stage
        ]
        if comp_node_ids:
            lines.append(
                f"    style {','.join(comp_node_ids[:20])} fill:#9f9,stroke:#333"
            )

        return "\n".join(lines)

    def _walk_nodes(self, node: TraceNode) -> list[TraceNode]:
        """Flatten tree into a list of all nodes."""
        result = [node]
        for child in node.children:
            result.extend(self._walk_nodes(child))
        return result

    # ------------------------------------------------------------------
    # Rendering: full Markdown report
    # ------------------------------------------------------------------

    def generate_report(self, results: list[TraceResult]) -> str:
        """Generate a full Markdown report for multiple trace results.

        Parameters
        ----------
        results : list[TraceResult]
            Output from ``trace()`` or ``trace_auto()``.

        Returns
        -------
        str
            Markdown report.
        """
        lines: list[str] = []
        lines.append("# Deep Call Chain Trace Report")
        lines.append("")

        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        lines.append(f"**Traces:** {len(successful)} successful, {len(failed)} failed")
        lines.append("")

        # Summary table
        if successful:
            lines.append("## Summary")
            lines.append("")
            lines.append(
                "| # | Target | Nodes | Depth | Algorithms | Domains | Time |"
            )
            lines.append(
                "|---|--------|-------|-------|-----------|---------|------|"
            )
            for i, r in enumerate(successful, 1):
                target = r.root.function_name if r.root else "?"
                lines.append(
                    f"| {i} | {target} | {r.total_nodes} | "
                    f"{r.max_depth_reached} | "
                    f"{len(r.algorithms_found)} | "
                    f"{', '.join(r.domains_found[:3])} | "
                    f"{r.trace_duration_seconds:.3f}s |"
                )
            lines.append("")

        # Detailed traces
        for i, r in enumerate(successful, 1):
            target = r.root.function_name if r.root else "?"
            lines.append(f"## {i}. {target}")
            lines.append("")
            lines.append(f"- **Total nodes:** {r.total_nodes}")
            lines.append(f"- **Max depth:** {r.max_depth_reached}")
            lines.append(f"- **Algorithms:** {', '.join(r.algorithms_found) or 'none'}")
            lines.append(f"- **Domains:** {', '.join(r.domains_found) or 'none'}")
            lines.append(f"- **Trace time:** {r.trace_duration_seconds:.3f}s")
            lines.append("")

            # ASCII tree
            lines.append("### Call Tree")
            lines.append("")
            lines.append("```")
            ascii_tree = self.render_ascii(r)
            # Limit to first 100 lines for readability
            tree_lines = ascii_tree.split("\n")
            if len(tree_lines) > 500:
                lines.extend(tree_lines[:500])
                lines.append(f"... ({len(tree_lines) - 500} more lines)")
            else:
                lines.append(ascii_tree)
            lines.append("```")
            lines.append("")

            # Mermaid diagram (only for smaller trees)
            if r.total_nodes <= 50:
                lines.append("### Flow Diagram")
                lines.append("")
                lines.append("```mermaid")
                lines.append(self.render_mermaid(r))
                lines.append("```")
                lines.append("")

            # Algorithm details
            if r.algorithms_found:
                lines.append("### Algorithms Found")
                lines.append("")
                for algo in r.algorithms_found:
                    lines.append(f"- {algo}")
                lines.append("")

        # Failed traces
        if failed:
            lines.append("## Failed Traces")
            lines.append("")
            for r in failed:
                target = r.root.function_name if r.root else "unknown"
                for err in r.errors:
                    lines.append(f"- **{target}:** {err}")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Annotation helpers
    # ------------------------------------------------------------------

    def _annotate_algorithms(
        self,
        node: TraceNode,
        algo_map: dict[str, list[str]],
        composition_map: dict[str, str] | None = None,
    ) -> None:
        """Annotate a node (and all descendants) with algorithm detections
        and composition stage information.

        Parameters
        ----------
        node : TraceNode
            Root node to annotate.
        algo_map : dict
            function_name -> list of algorithm names.
        composition_map : dict, optional
            function_name -> composition stage description
            (e.g. "TLS Pipeline: stage 2 (key_exchange)").
        """
        node.algorithms = algo_map.get(node.function_name, [])
        if composition_map:
            node.composition_stage = composition_map.get(node.function_name)
        # Refresh domain with updated algo info
        node.domain = self._infer_domain(node.function_name, node.algorithms)
        # Multi-domain tags
        node.domain_tags = self._infer_all_domains(node.function_name, node.algorithms)
        for child in node.children:
            self._annotate_algorithms(child, algo_map, composition_map)

    def _infer_domain(
        self,
        func_name: str,
        algorithms: list[str],
    ) -> str:
        """Infer the domain of a function from its name and algorithms."""
        fn_lower = func_name.lower()

        # First check algorithms
        for algo in algorithms:
            algo_lower = algo.lower()
            for domain, keywords in _DOMAIN_KEYWORDS.items():
                if any(kw in algo_lower for kw in keywords):
                    return domain

        # Then check function name
        best_domain = ""
        best_score = 0
        for domain, keywords in _DOMAIN_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in fn_lower)
            if score > best_score:
                best_score = score
                best_domain = domain

        return best_domain

    def _infer_all_domains(
        self,
        func_name: str,
        algorithms: list[str],
    ) -> list[str]:
        """Infer ALL matching domains (not just the best one).

        Returns a sorted list of domain tags with non-zero keyword matches.
        Useful for functions that straddle multiple domains (e.g., a crypto
        function that also does network I/O).
        """
        fn_lower = func_name.lower()
        domains: set[str] = set()

        # Check algorithms first
        for algo in algorithms:
            algo_lower = algo.lower()
            for domain, keywords in _DOMAIN_KEYWORDS.items():
                if any(kw in algo_lower for kw in keywords):
                    domains.add(domain)

        # Then check function name
        for domain, keywords in _DOMAIN_KEYWORDS.items():
            if any(kw in fn_lower for kw in keywords):
                domains.add(domain)

        return sorted(domains)

    def _build_composition_map(
        self,
        dispatch_result: dict | None,
    ) -> dict[str, str]:
        """Build function_name -> composition_stage description mapping.

        Reads composition data from dispatch_result (if it contains
        compositions from the AlgorithmCompositionAnalyzer output).

        Returns
        -------
        dict
            function_name -> "CompositionName: stage N (stage_label)"
        """
        mapping: dict[str, str] = {}
        if not dispatch_result:
            return mapping

        # dispatch_result may carry compositions from pipeline
        # dispatch_result: dict veya DispatchResolutionResult olabilir
        if isinstance(dispatch_result, dict):
            compositions = dispatch_result.get("compositions", [])
        else:
            compositions = getattr(dispatch_result, "compositions", []) or []

        for comp in compositions:
            if isinstance(comp, dict):
                comp_name = comp.get("name", "Composition")
                stages = comp.get("stages", [])
            else:
                comp_name = getattr(comp, "name", "Composition")
                stages = getattr(comp, "stages", [])
            for i, stage in enumerate(stages):
                if isinstance(stage, dict):
                    func_name = stage.get("function_name", "")
                    label = stage.get("label", stage.get("name", ""))
                else:
                    func_name = getattr(stage, "function_name", "")
                    label = getattr(stage, "label", getattr(stage, "name", ""))
                if func_name:
                    mapping[func_name] = f"{comp_name}: stage {i + 1} ({label})"
        return mapping

    # ------------------------------------------------------------------
    # Index builders
    # ------------------------------------------------------------------

    def _build_adjacency(
        self,
        call_graph: dict,
    ) -> dict[str, list[str]]:
        """Build adjacency list from call graph.

        Merges original edges and virtual edges (if present).
        """
        adjacency: dict[str, list[str]] = defaultdict(list)

        nodes = call_graph.get("nodes", {})
        for addr, info in nodes.items():
            caller = info.get("name", "")
            if not caller:
                continue
            for callee_info in info.get("callees", []):
                callee_name = callee_info.get("name", "")
                if callee_name:
                    adjacency[caller].append(callee_name)

        # Virtual edges from augmented graph
        for vedge in call_graph.get("virtual_edges", []):
            from_name = vedge.get("from_name", "")
            to_name = vedge.get("to_name", "")
            if from_name and to_name:
                adjacency[from_name].append(to_name)

        # Deduplicate (preserving order)
        return {k: list(dict.fromkeys(v)) for k, v in adjacency.items()}

    def _build_func_addr_map(
        self,
        call_graph: dict,
        functions_json: Path | None = None,
    ) -> dict[str, str]:
        """Build function name -> address mapping."""
        mapping: dict[str, str] = {}

        nodes = call_graph.get("nodes", {})
        for addr, info in nodes.items():
            name = info.get("name", "")
            if name:
                mapping[name] = info.get("address", addr)

        # Supplement from functions_json
        if functions_json and functions_json.exists():
            try:
                with open(functions_json) as f:
                    fdata = json.load(f)
                for func in fdata.get("functions", []):
                    name = func.get("name", "")
                    addr = func.get("address", "")
                    if name and addr and name not in mapping:
                        mapping[name] = addr
            except Exception as exc:
                logger.warning("Failed to load functions_json: %s", exc)

        return mapping

    def _build_algo_map(
        self,
        algorithms: list | None,
    ) -> dict[str, list[str]]:
        """Build function_name -> list of algorithm names."""
        mapping: dict[str, list[str]] = defaultdict(list)
        if not algorithms:
            return dict(mapping)

        for a in algorithms:
            if isinstance(a, dict):
                fname = a.get("function_name", "")
                aname = a.get("name", "")
            elif hasattr(a, "function_name"):
                fname = a.function_name
                aname = a.name
            else:
                continue

            if fname and aname:
                if aname not in mapping[fname]:
                    mapping[fname].append(aname)

        return dict(mapping)

    def _build_dispatch_map(
        self,
        call_graph: dict,
    ) -> dict[tuple[str, str], str]:
        """Build (caller, callee) -> dispatch_type mapping from virtual edges."""
        mapping: dict[tuple[str, str], str] = {}

        # Original edges are "direct"
        nodes = call_graph.get("nodes", {})
        for addr, info in nodes.items():
            caller = info.get("name", "")
            if not caller:
                continue
            for callee_info in info.get("callees", []):
                callee = callee_info.get("name", "")
                if callee:
                    mapping[(caller, callee)] = "direct"

        # Virtual edges carry their type
        for vedge in call_graph.get("virtual_edges", []):
            from_name = vedge.get("from_name", "")
            to_name = vedge.get("to_name", "")
            vtype = vedge.get("type", "objc_dispatch")
            if from_name and to_name:
                mapping[(from_name, to_name)] = vtype

        return mapping
