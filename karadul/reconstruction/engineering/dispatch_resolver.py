"""VirtualDispatchResolver -- Obj-C dynamic dispatch resolution for Karadul v1.1.5.

Resolves `objc_msgSend` / `objc_msgSendSuper` / C++ vtable dispatch calls to their
actual method implementations, transforming dead-end call graph edges into real
connections.

BEFORE: caller -> _objc_msgSend  (dead end, ~2170 such edges in GlobalProtect)
AFTER:  caller -> -[NEVPNManager connection]  (real target with confidence)

4-phase pipeline:
  Phase 1: Scan all decompiled C files for dispatch sites
  Phase 2: Build selector-to-implementation map from Ghidra function metadata
  Phase 3: Resolve each dispatch site using type propagation + selector lookup
  Phase 4: Augment the call graph with resolved edges
"""

from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class MethodImpl:
    """A concrete Obj-C method implementation found in the binary."""
    class_name: str
    selector: str
    kind: str           # "-" for instance, "+" for class method
    address: str
    func_name: str      # Full Ghidra function name


@dataclass
class DispatchSite:
    """A single dynamic dispatch call site found in decompiled code."""
    caller_func: str            # Function containing the dispatch
    caller_addr: str            # Address of the caller function
    source_file: str            # Decompiled .c file path
    line_number: int            # Line in decompiled code
    variant: str                # "objc_msgSend", "objc_msgSendSuper", "vtable"
    receiver_expr: str          # The receiver expression text
    receiver_type: str | None   # Resolved class name, if known
    selector: str | None        # The selector string (None for vtable)
    vtable_offset: str | None   # Hex offset for vtable dispatch
    resolved_targets: list[str] = field(default_factory=list)
    confidence: float = 0.0
    resolution_method: str = "unresolved"


@dataclass
class DispatchResolutionResult:
    """Overall result of the dispatch resolution pipeline."""
    success: bool
    total_dispatch_sites: int
    resolved_count: int         # Single target resolved
    candidate_count: int        # Multiple candidates (narrowed down)
    unresolved_count: int
    external_count: int         # Framework methods (no local impl)
    resolution_rate: float      # resolved / total
    augmented_edges: list[dict] = field(default_factory=list)
    removed_edges: list[dict] = field(default_factory=list)
    dispatch_sites: list[DispatchSite] = field(default_factory=list)
    class_hierarchy: dict = field(default_factory=dict)
    selector_map_size: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "total_dispatch_sites": self.total_dispatch_sites,
            "resolved_count": self.resolved_count,
            "candidate_count": self.candidate_count,
            "unresolved_count": self.unresolved_count,
            "external_count": self.external_count,
            "resolution_rate": round(self.resolution_rate, 4),
            "augmented_edges_count": len(self.augmented_edges),
            "removed_edges_count": len(self.removed_edges),
            "selector_map_size": self.selector_map_size,
            "errors": self.errors,
        }


@dataclass
class _FileHeader:
    """Parsed header from a decompiled .c file."""
    func_name: str
    address: str
    class_name: str | None      # Extracted from C++ namespace or bracket notation
    method_name: str | None     # Extracted selector
    kind: str | None            # "-" or "+" or None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class DispatchResolverConfig:
    """Tunable parameters for the resolver."""
    max_workers: int = 8
    min_confidence: float = 0.3
    enable_type_propagation: bool = True
    enable_vtable_resolution: bool = True
    # Known framework classes that won't have local implementations
    framework_prefixes: tuple[str, ...] = (
        "NS", "UI", "CG", "CA", "CF", "NE", "SK", "WK", "AV",
        "CL", "MK", "SC", "IO", "OS", "Sec", "LAContext",
    )


# ---------------------------------------------------------------------------
# Regex patterns for dispatch site scanning
# ---------------------------------------------------------------------------

# Pattern A: Direct selector -- _objc_msgSend(receiver, "selector", ...)
_RE_MSGSEND_DIRECT = re.compile(
    r'_?objc_msgSend\s*\(\s*([^,]+?)\s*,\s*"([^"]+)"',
)

# Pattern B: Class method via _OBJC_CLASS___ClassName
_RE_MSGSEND_CLASS_REF = re.compile(
    r'_?objc_msgSend\s*\(\s*&_OBJC_CLASS___(\w+)\s*,\s*"([^"]+)"',
)

# Pattern C: Class method via objc::class_t::ClassName
_RE_MSGSEND_CLASS_T = re.compile(
    r'_?objc_msgSend\s*\(\s*&objc::class_t::(\w+)\s*,\s*"([^"]+)"',
)

# Pattern D: Super dispatch -- _objc_msgSendSuper2(&local, "selector")
_RE_MSGSEND_SUPER = re.compile(
    r'_?objc_msgSendSuper\d*\s*\(\s*[^,]+\s*,\s*"([^"]+)"',
)

# Pattern E: C++ vtable dispatch
_RE_VTABLE = re.compile(
    r'\(\*\s*\(\s*(?:code|void)\s*\*+\s*\)\s*\(\s*\*\s*\(\s*long\s*\*\s*\)\s*'
    r'(\w+)\s*\+\s*(0x[0-9a-fA-F]+)\s*\)\s*\)',
)

# Pattern for alloc/init type propagation
_RE_ALLOC_INIT_CLASS = re.compile(
    r'_?objc_alloc_init\s*\(\s*&(?:_OBJC_CLASS___(\w+)|objc::class_t::(\w+))\s*\)',
)
_RE_ALLOC_CLASS = re.compile(
    r'_?objc_alloc\s*\(\s*&(?:_OBJC_CLASS___(\w+)|objc::class_t::(\w+))\s*\)',
)

# Pattern for function header: C++ namespace::method or bracket notation
_RE_HEADER_NAMESPACE = re.compile(
    r'^\s*(?:\w[\w\s\*]*\s+)?(\w+)::([\w:~]+)\s*\(',
    re.MULTILINE,
)
_RE_HEADER_BRACKET = re.compile(
    r'^//\s*Function:\s*([+-])\[(\w[\w()]*)\s+([\w:]+)\]',
    re.MULTILINE,
)
_RE_HEADER_FUNC_NAME = re.compile(
    r'^//\s*Function:\s*(.+)$', re.MULTILINE,
)
_RE_HEADER_ADDRESS = re.compile(
    r'^//\s*Address:\s*([0-9a-fA-Fx]+)', re.MULTILINE,
)

# Pattern for extracting class from _OBJC_CLASS___ receiver in general
_RE_RECEIVER_CLASS = re.compile(
    r'&_OBJC_CLASS___(\w+)|&objc::class_t::(\w+)',
)

# ---------------------------------------------------------------------------
# Function name parsing patterns (from Ghidra metadata)
# ---------------------------------------------------------------------------

# -[ClassName selectorName:param:] or +[ClassName sel:]
_RE_BRACKET_METHOD = re.compile(
    r'^([+-])\[(\w[\w()]*)\s+([\w:]+)\]$',
)

# ---------------------------------------------------------------------------
# Obj-C class hierarchy patterns (from strings / symbols)
# ---------------------------------------------------------------------------

# _OBJC_CLASS_$_ClassName in strings_json or symbol tables
_RE_OBJC_CLASS_SYMBOL = re.compile(
    r'_OBJC_CLASS_\$_(\w+)',
)

# _OBJC_METACLASS_$_ClassName
_RE_OBJC_METACLASS_SYMBOL = re.compile(
    r'_OBJC_METACLASS_\$_(\w+)',
)

# class_getSuperclass(ClassName) or [ClassName superclass] in decompiled code
_RE_GET_SUPERCLASS = re.compile(
    r'class_getSuperclass\s*\(\s*&?_?OBJC_CLASS___(\w+)',
)

# objc_opt_class / object_getClass calls referencing a class
_RE_OBJC_OPT_CLASS = re.compile(
    r'objc_opt_class\s*\(\s*&?_?OBJC_CLASS___(\w+)',
)

# Superclass assignment pattern in Ghidra decompiled code:
# _OBJC_CLASS___SubClass._superclass = &_OBJC_CLASS___ParentClass
_RE_SUPERCLASS_ASSIGN = re.compile(
    r'_OBJC_CLASS___(\w+)\._?super(?:class)?\s*=\s*&?_?OBJC_CLASS___(\w+)',
)

# Obj-C class_ro_t or class64_t superclass references in decompiled structs:
# { &_OBJC_CLASS___ParentClass, &_OBJC_METACLASS___ChildClass, ... }
_RE_SUPERCLASS_STRUCT_REF = re.compile(
    r'&_OBJC_CLASS___(\w+)\s*,\s*&_OBJC_METACLASS___(\w+)',
)

# ---------------------------------------------------------------------------
# C++ RTTI patterns (for vtable resolution)
# ---------------------------------------------------------------------------

# _ZTV prefix: vtable for ClassName (mangled)
_RE_RTTI_VTABLE = re.compile(
    r'_ZTV[IN]?(\d+)(\w+)',
)

# _ZTI prefix: typeinfo for ClassName (mangled)
_RE_RTTI_TYPEINFO = re.compile(
    r'_ZTI[IN]?(\d+)(\w+)',
)

# _ZN prefix: mangled C++ method name  _ZN<len>ClassName<len>MethodNameE...
_RE_CPP_MANGLED = re.compile(
    r'_ZN(\d+)(\w+?)(\d+)(\w+)E',
)


# ---------------------------------------------------------------------------
# VirtualDispatchResolver
# ---------------------------------------------------------------------------

class VirtualDispatchResolver:
    """Resolves Obj-C dynamic dispatch to concrete implementations.

    Usage:
        resolver = VirtualDispatchResolver()
        result = resolver.resolve(
            decompiled_dir=Path("...decompiled/"),
            functions_json=Path("...ghidra_functions.json"),
            call_graph_json=Path("...ghidra_call_graph.json"),
        )
        print(f"Resolved {result.resolved_count}/{result.total_dispatch_sites}")
    """

    def __init__(self, config: DispatchResolverConfig | None = None):
        self.config = config or DispatchResolverConfig()
        self._selector_map: dict[str, list[MethodImpl]] = {}
        self._class_hierarchy: dict[str, dict[str, Any]] = {}
        self._func_address_map: dict[str, str] = {}   # name -> address
        self._func_name_map: dict[str, str] = {}       # address -> name
        self._vtable_map: dict[str, str] = {}           # class -> vtable addr
        self._rtti_hierarchy: dict[str, str] = {}       # child -> parent (C++)

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def resolve(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        call_graph_json: Path,
        strings_json: Path | None = None,
        output_dir: Path | None = None,
    ) -> DispatchResolutionResult:
        """Full dispatch resolution pipeline."""
        errors: list[str] = []

        # Phase 1+2 can run in parallel since they're independent
        logger.info("Phase 2: Building selector map from %s", functions_json)
        self._build_selector_map(functions_json)
        self._build_class_hierarchy(functions_json, strings_json, decompiled_dir)

        logger.info(
            "Selector map: %d selectors, %d implementations",
            len(self._selector_map),
            sum(len(v) for v in self._selector_map.values()),
        )
        logger.info("Class hierarchy: %d classes", len(self._class_hierarchy))

        logger.info("Phase 1: Scanning dispatch sites in %s", decompiled_dir)
        sites = self._scan_dispatch_sites(decompiled_dir)
        logger.info("Found %d dispatch sites", len(sites))

        logger.info("Phase 3: Resolving dispatch sites")
        resolved_sites = self._resolve_sites(sites)

        # Tally results
        resolved = sum(1 for s in resolved_sites if len(s.resolved_targets) == 1)
        candidates = sum(1 for s in resolved_sites if len(s.resolved_targets) > 1)
        external = sum(
            1 for s in resolved_sites
            if s.resolution_method == "framework_external"
        )
        unresolved = sum(
            1 for s in resolved_sites
            if len(s.resolved_targets) == 0
            and s.resolution_method != "framework_external"
        )

        logger.info("Phase 4: Augmenting call graph")
        augmented_edges, removed_edges = self._augment_call_graph(
            call_graph_json, resolved_sites,
        )

        total = len(resolved_sites)
        rate = (resolved + candidates) / total if total > 0 else 0.0

        result = DispatchResolutionResult(
            success=len(errors) == 0,
            total_dispatch_sites=total,
            resolved_count=resolved,
            candidate_count=candidates,
            unresolved_count=unresolved,
            external_count=external,
            resolution_rate=rate,
            augmented_edges=augmented_edges,
            removed_edges=removed_edges,
            dispatch_sites=resolved_sites,
            class_hierarchy=self._class_hierarchy,
            selector_map_size=len(self._selector_map),
            errors=errors,
        )

        # Write outputs
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            self._write_outputs(output_dir, result, call_graph_json)

        report = self._generate_report(result)
        logger.info("\n%s", report)

        return result

    # -------------------------------------------------------------------
    # Phase 1: Scan dispatch sites
    # -------------------------------------------------------------------

    def _scan_dispatch_sites(self, decompiled_dir: Path) -> list[DispatchSite]:
        """Scan all decompiled C files for dispatch patterns."""
        c_files = sorted(decompiled_dir.glob("*.c"))
        if not c_files:
            logger.warning("No .c files found in %s", decompiled_dir)
            return []

        all_sites: list[DispatchSite] = []

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
            futures = {
                pool.submit(self._scan_single_file, f): f for f in c_files
            }
            for future in as_completed(futures):
                fpath = futures[future]
                try:
                    sites = future.result()
                    all_sites.extend(sites)
                except Exception as exc:
                    logger.warning("Error scanning %s: %s", fpath.name, exc)

        return all_sites

    def _scan_single_file(self, filepath: Path) -> list[DispatchSite]:
        """Extract all dispatch sites from a single decompiled C file."""
        try:
            code = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug("Cannot read %s: %s", filepath, e)
            return []

        header = self._parse_file_header(code)
        sites: list[DispatchSite] = []
        lines = code.split("\n")

        for line_no, line in enumerate(lines, start=1):
            # Skip comment-only lines and disassembly
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue

            # --- Pattern B: _OBJC_CLASS___ClassName (most specific, check first)
            for m in _RE_MSGSEND_CLASS_REF.finditer(line):
                sites.append(DispatchSite(
                    caller_func=header.func_name,
                    caller_addr=header.address,
                    source_file=str(filepath),
                    line_number=line_no,
                    variant="objc_msgSend",
                    receiver_expr=m.group(0),
                    receiver_type=m.group(1),
                    selector=m.group(2),
                    vtable_offset=None,
                ))

            # --- Pattern C: objc::class_t::ClassName
            for m in _RE_MSGSEND_CLASS_T.finditer(line):
                # Avoid double-counting if Pattern B also matched this line
                sel = m.group(2)
                cls = m.group(1)
                if any(s.selector == sel and s.receiver_type == cls
                       and s.line_number == line_no for s in sites):
                    continue
                sites.append(DispatchSite(
                    caller_func=header.func_name,
                    caller_addr=header.address,
                    source_file=str(filepath),
                    line_number=line_no,
                    variant="objc_msgSend",
                    receiver_expr=m.group(0),
                    receiver_type=cls,
                    selector=sel,
                    vtable_offset=None,
                ))

            # --- Pattern D: Super dispatch
            for m in _RE_MSGSEND_SUPER.finditer(line):
                # Super calls: the receiver class is the *parent* of the
                # function's class. We note the selector; resolution will
                # figure out the superclass.
                sites.append(DispatchSite(
                    caller_func=header.func_name,
                    caller_addr=header.address,
                    source_file=str(filepath),
                    line_number=line_no,
                    variant="objc_msgSendSuper",
                    receiver_expr=m.group(0),
                    receiver_type=None,  # resolved later from class hierarchy
                    selector=m.group(1),
                    vtable_offset=None,
                ))

            # --- Pattern A: Generic _objc_msgSend(receiver, "selector")
            # This is broad, so run it AFTER B/C to avoid duplication
            for m in _RE_MSGSEND_DIRECT.finditer(line):
                sel = m.group(2)
                recv = m.group(1).strip()
                # Skip if already captured by B or C patterns on same line
                if any(s.selector == sel and s.line_number == line_no
                       and s.variant == "objc_msgSend" for s in sites):
                    continue
                # Try to extract class from receiver expression
                recv_type = self._extract_receiver_type(recv, header)
                sites.append(DispatchSite(
                    caller_func=header.func_name,
                    caller_addr=header.address,
                    source_file=str(filepath),
                    line_number=line_no,
                    variant="objc_msgSend",
                    receiver_expr=recv,
                    receiver_type=recv_type,
                    selector=sel,
                    vtable_offset=None,
                ))

            # --- Pattern E: C++ vtable dispatch
            if self.config.enable_vtable_resolution:
                for m in _RE_VTABLE.finditer(line):
                    sites.append(DispatchSite(
                        caller_func=header.func_name,
                        caller_addr=header.address,
                        source_file=str(filepath),
                        line_number=line_no,
                        variant="vtable",
                        receiver_expr=m.group(1),
                        receiver_type=None,
                        selector=None,
                        vtable_offset=m.group(2),
                    ))

        return sites

    def _parse_file_header(self, code: str) -> _FileHeader:
        """Parse the header comment block from a decompiled C file."""
        # Extract function name from header comment
        func_name = "unknown"
        address = "0"

        m_name = _RE_HEADER_FUNC_NAME.search(code[:1000])
        if m_name:
            func_name = m_name.group(1).strip()

        m_addr = _RE_HEADER_ADDRESS.search(code[:1000])
        if m_addr:
            address = m_addr.group(1).strip()

        # Try bracket notation: -[Class method]
        m_bracket = _RE_HEADER_BRACKET.search(code[:1000])
        if m_bracket:
            return _FileHeader(
                func_name=func_name,
                address=address,
                class_name=m_bracket.group(2),
                method_name=m_bracket.group(3),
                kind=m_bracket.group(1),
            )

        # Try C++ namespace: ClassName::method(...)
        # Look in the function signature area (after the header comments)
        m_ns = _RE_HEADER_NAMESPACE.search(code[:2000])
        if m_ns:
            return _FileHeader(
                func_name=func_name,
                address=address,
                class_name=m_ns.group(1),
                method_name=m_ns.group(2),
                kind="-",  # assume instance method
            )

        return _FileHeader(
            func_name=func_name,
            address=address,
            class_name=None,
            method_name=None,
            kind=None,
        )

    def _extract_receiver_type(
        self, receiver_expr: str, header: _FileHeader,
    ) -> str | None:
        """Try to determine the receiver's class from the expression."""
        # Case 1: &_OBJC_CLASS___ClassName or &objc::class_t::Name
        m = _RE_RECEIVER_CLASS.search(receiver_expr)
        if m:
            return m.group(1) or m.group(2)

        # Case 2: param_1 in an ObjC method means self -> header class
        if receiver_expr.strip() in ("param_1", "self") and header.class_name:
            return header.class_name

        # Case 3: IVar2 from alloc/init pattern -- needs context, handled
        # in Phase 3 type propagation
        return None

    # -------------------------------------------------------------------
    # Phase 2: Build selector map + class hierarchy
    # -------------------------------------------------------------------

    def _build_selector_map(self, functions_json: Path) -> None:
        """Build selector -> [MethodImpl] map from Ghidra function data."""
        with open(functions_json, "r") as f:
            data = json.load(f)

        self._selector_map.clear()
        self._func_address_map.clear()
        self._func_name_map.clear()

        for fn in data.get("functions", []):
            name = fn["name"]
            addr = fn.get("address", "0")
            self._func_address_map[name] = addr
            self._func_name_map[addr] = name

            # Try bracket notation: -[Class selector:]
            m = _RE_BRACKET_METHOD.match(name)
            if m:
                kind, cls, sel = m.group(1), m.group(2), m.group(3)
                impl = MethodImpl(
                    class_name=cls, selector=sel, kind=kind,
                    address=addr, func_name=name,
                )
                self._selector_map.setdefault(sel, []).append(impl)
                continue

            # For plain selector names (the majority in GlobalProtect),
            # we treat the function name itself as the selector.
            # E.g. "initWithWindowNibName:" -> selector = "initWithWindowNibName:"
            # These don't have class info from the name alone, but we can
            # use the decompiled file header's namespace to recover it.
            # We index them so unique selectors can still be resolved.
            if not name.startswith("_") and not name.startswith("FUN_"):
                # Could be a selector-style name
                impl = MethodImpl(
                    class_name="",  # unknown from name alone
                    selector=name,
                    kind="-",
                    address=addr,
                    func_name=name,
                )
                self._selector_map.setdefault(name, []).append(impl)

    def _build_class_hierarchy(
        self,
        functions_json: Path,
        strings_json: Path | None = None,
        decompiled_dir: Path | None = None,
    ) -> None:
        """Build a class hierarchy from function metadata + runtime info.

        Reconstructs the Obj-C / C++ class hierarchy from multiple sources:
        1. Bracket-notation method names: -[ClassName method]
        2. _OBJC_CLASS_$_ / _OBJC_METACLASS_$_ symbols from strings_json
        3. Superclass assignment patterns in decompiled C files
        4. class_getSuperclass() calls in decompiled code
        5. C++ RTTI symbols (_ZTV, _ZTI, _ZN) from functions_json
        """
        with open(functions_json, "r") as f:
            data = json.load(f)

        self._class_hierarchy.clear()

        # --- Source 1: Bracket notation from function names ---
        for fn in data.get("functions", []):
            name = fn["name"]

            m = _RE_BRACKET_METHOD.match(name)
            if m:
                cls = m.group(2)
                sel = m.group(3)
                kind = m.group(1)
                entry = self._class_hierarchy.setdefault(cls, {
                    "methods": [], "superclass": None, "source": "bracket",
                })
                entry["methods"].append({
                    "selector": sel, "kind": kind,
                    "address": fn.get("address", "0"),
                })

        # --- Source 5: C++ RTTI from function/symbol names ---
        # (__init__'te annote edildi; re-entry'de sifirla.)
        self._vtable_map = {}
        self._rtti_hierarchy = {}

        for fn in data.get("functions", []):
            name = fn["name"]
            addr = fn.get("address", "0")

            # _ZTV: vtable symbol -> extract class name
            if name.startswith("_ZTV"):
                cls = self._demangle_rtti_name(name[4:])
                if cls:
                    self._vtable_map[cls] = addr
                    self._class_hierarchy.setdefault(cls, {
                        "methods": [], "superclass": None, "source": "vtable",
                    })

            # _ZTI: typeinfo symbol -> extract class name
            elif name.startswith("_ZTI"):
                cls = self._demangle_rtti_name(name[4:])
                if cls:
                    self._class_hierarchy.setdefault(cls, {
                        "methods": [], "superclass": None, "source": "typeinfo",
                    })

            # _ZN: mangled C++ method -> class::method
            elif name.startswith("_ZN"):
                parsed = self._parse_mangled_method(name)
                if parsed:
                    cls, method = parsed
                    entry = self._class_hierarchy.setdefault(cls, {
                        "methods": [], "superclass": None, "source": "mangled",
                    })
                    existing_sels = {m["selector"] for m in entry["methods"]}
                    if method not in existing_sels:
                        entry["methods"].append({
                            "selector": method, "kind": "-",
                            "address": addr,
                        })

        # --- Source 2: strings_json for _OBJC_CLASS_$_ symbols ---
        if strings_json is not None:
            self._extract_hierarchy_from_strings(strings_json)

        # --- Source 3 & 4: Decompiled C files for superclass patterns ---
        if decompiled_dir is not None:
            self._extract_hierarchy_from_decompiled(decompiled_dir)

        # Also add classes discovered from decompiled headers' namespaces
        # (this happens lazily during Phase 3 scanning, enriching the
        # hierarchy as we encounter new classes)

        logger.info(
            "Class hierarchy built: %d classes, %d with superclass, %d vtables",
            len(self._class_hierarchy),
            sum(1 for v in self._class_hierarchy.values() if v.get("superclass")),
            len(self._vtable_map),
        )

    def _enrich_hierarchy_from_header(
        self, class_name: str, method_name: str, kind: str, address: str,
    ) -> None:
        """Add a class/method to the hierarchy from decompiled file headers."""
        if not class_name:
            return
        entry = self._class_hierarchy.setdefault(class_name, {
            "methods": [], "superclass": None, "source": "namespace",
        })
        # Avoid duplicates
        existing_sels = {m["selector"] for m in entry["methods"]}
        if method_name and method_name not in existing_sels:
            entry["methods"].append({
                "selector": method_name, "kind": kind or "-",
                "address": address,
            })

    # -------------------------------------------------------------------
    # Hierarchy extraction helpers
    # -------------------------------------------------------------------

    def _extract_hierarchy_from_strings(self, strings_json: Path) -> None:
        """Extract Obj-C class hierarchy from Ghidra strings export.

        Looks for _OBJC_CLASS_$_ and _OBJC_METACLASS_$_ symbols which
        indicate classes present in the binary.  Also searches for
        paired class/metaclass entries that hint at parent-child
        relationships (metaclass of child often references parent class
        in adjacent data).
        """
        try:
            with open(strings_json, "r") as f:
                strings_data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Cannot read strings_json %s: %s", strings_json, e)
            return

        # strings_data may be a list of dicts with "value"/"string" keys,
        # or a flat list of strings, or a dict with "strings" key
        raw_strings: list[str] = []
        if isinstance(strings_data, list):
            for item in strings_data:
                if isinstance(item, str):
                    raw_strings.append(item)
                elif isinstance(item, dict):
                    raw_strings.append(
                        item.get("value", item.get("string", str(item)))
                    )
        elif isinstance(strings_data, dict):
            for item in strings_data.get("strings", strings_data.get("data", [])):
                if isinstance(item, str):
                    raw_strings.append(item)
                elif isinstance(item, dict):
                    raw_strings.append(
                        item.get("value", item.get("string", str(item)))
                    )

        # Collect all class names from _OBJC_CLASS_$_ symbols
        objc_classes: set[str] = set()
        for s in raw_strings:
            for m in _RE_OBJC_CLASS_SYMBOL.finditer(s):
                cls = m.group(1)
                objc_classes.add(cls)
                self._class_hierarchy.setdefault(cls, {
                    "methods": [], "superclass": None, "source": "strings",
                })
            # Also track metaclass symbols
            for m in _RE_OBJC_METACLASS_SYMBOL.finditer(s):
                cls = m.group(1)
                objc_classes.add(cls)
                self._class_hierarchy.setdefault(cls, {
                    "methods": [], "superclass": None, "source": "strings",
                })

            # Look for superclass assignment patterns in string data
            for m in _RE_SUPERCLASS_ASSIGN.finditer(s):
                child_cls, parent_cls = m.group(1), m.group(2)
                entry = self._class_hierarchy.setdefault(child_cls, {
                    "methods": [], "superclass": None, "source": "strings",
                })
                if entry["superclass"] is None:
                    entry["superclass"] = parent_cls
                    logger.debug(
                        "Superclass from strings: %s -> %s", child_cls, parent_cls,
                    )

            # Struct reference pattern: &_OBJC_CLASS___Parent, &_OBJC_METACLASS___Child
            for m in _RE_SUPERCLASS_STRUCT_REF.finditer(s):
                parent_cls, child_cls = m.group(1), m.group(2)
                entry = self._class_hierarchy.setdefault(child_cls, {
                    "methods": [], "superclass": None, "source": "strings",
                })
                if entry["superclass"] is None:
                    entry["superclass"] = parent_cls

        logger.info(
            "Strings: found %d Obj-C classes from symbols", len(objc_classes),
        )

    def _extract_hierarchy_from_decompiled(self, decompiled_dir: Path) -> None:
        """Scan decompiled C files for superclass relationship patterns.

        Looks for:
        - class_getSuperclass(&_OBJC_CLASS___ClassName)
        - _OBJC_CLASS___Child._superclass = &_OBJC_CLASS___Parent
        - Common Obj-C init patterns that reveal inheritance
        """
        c_files = sorted(decompiled_dir.glob("*.c"))
        if not c_files:
            return

        relationships_found = 0

        for filepath in c_files:
            try:
                # Read a generous portion for class hierarchy info
                code = filepath.read_text(
                    encoding="utf-8", errors="replace",
                )
            except OSError:
                continue

            # Pattern: _OBJC_CLASS___Child._superclass = &_OBJC_CLASS___Parent
            for m in _RE_SUPERCLASS_ASSIGN.finditer(code):
                child_cls, parent_cls = m.group(1), m.group(2)
                entry = self._class_hierarchy.setdefault(child_cls, {
                    "methods": [], "superclass": None, "source": "decompiled",
                })
                if entry["superclass"] is None:
                    entry["superclass"] = parent_cls
                    relationships_found += 1
                    logger.debug(
                        "Superclass from decompiled: %s -> %s",
                        child_cls, parent_cls,
                    )

            # Pattern: &_OBJC_CLASS___Parent, &_OBJC_METACLASS___Child
            for m in _RE_SUPERCLASS_STRUCT_REF.finditer(code):
                parent_cls, child_cls = m.group(1), m.group(2)
                entry = self._class_hierarchy.setdefault(child_cls, {
                    "methods": [], "superclass": None, "source": "decompiled",
                })
                if entry["superclass"] is None:
                    entry["superclass"] = parent_cls
                    relationships_found += 1

            # Pattern: objc_msgSendSuper2 in a -[Child init] function,
            # where the file header reveals the class.  The super struct
            # typically references the parent class.
            header = self._parse_file_header(code[:2000])
            if header.class_name and header.kind:
                # Look for super-struct patterns that reveal parent
                # Common: local_super.class = &_OBJC_CLASS___ParentClass
                for sup_m in re.finditer(
                    r'(?:super|local_\w+)\.(?:receiver|isa|class)\s*=\s*'
                    r'&?_?OBJC_CLASS___(\w+)',
                    code,
                ):
                    parent_cls = sup_m.group(1)
                    if parent_cls != header.class_name:
                        entry = self._class_hierarchy.setdefault(
                            header.class_name, {
                                "methods": [],
                                "superclass": None,
                                "source": "decompiled",
                            },
                        )
                        if entry["superclass"] is None:
                            entry["superclass"] = parent_cls
                            relationships_found += 1
                            logger.debug(
                                "Superclass from super-struct: %s -> %s",
                                header.class_name, parent_cls,
                            )

        logger.info(
            "Decompiled scan: found %d superclass relationships",
            relationships_found,
        )

    @staticmethod
    def _demangle_rtti_name(mangled_suffix: str) -> str | None:
        """Basic demangling of RTTI name suffix.

        Handles simple cases like: N<len>ClassName  or  <len>ClassName
        e.g. "14GPVPNProtocol" -> "GPVPNProtocol"
        e.g. "N2GP11VPNProtocolE" -> "GP::VPNProtocol" (nested)

        For complex nested names, returns the innermost class.
        """
        if not mangled_suffix:
            return None

        # Simple case: <length><name>
        m = re.match(r'^(\d+)(\w+)', mangled_suffix)
        if m:
            length = int(m.group(1))
            name = m.group(2)
            if length <= len(name):
                return name[:length]

        # Nested namespace: N<len1>name1<len2>name2...E
        if mangled_suffix.startswith("N") or mangled_suffix.startswith("I"):
            parts = []
            pos = 1  # skip N or I
            rest = mangled_suffix[pos:]
            while rest and rest[0] != "E":
                m_part = re.match(r'(\d+)(\w+)', rest)
                if not m_part:
                    break
                length = int(m_part.group(1))
                name = m_part.group(2)[:length]
                parts.append(name)
                pos = len(str(length)) + length
                rest = rest[pos:]
            if parts:
                return parts[-1]  # return innermost class name

        return None

    @staticmethod
    def _parse_mangled_method(mangled: str) -> tuple[str, str] | None:
        """Parse a C++ mangled method name to (class_name, method_name).

        Handles _ZN<len>ClassName<len>MethodNameE...
        """
        m = _RE_CPP_MANGLED.match(mangled)
        if m:
            cls_len = int(m.group(1))
            cls_plus_rest = m.group(2)
            if cls_len <= len(cls_plus_rest):
                cls = cls_plus_rest[:cls_len]
                rest = cls_plus_rest[cls_len:]
                # Method name follows
                m2 = re.match(r'(\d+)(\w+)', rest)
                if m2:
                    meth_len = int(m2.group(1))
                    meth_name = m2.group(2)[:meth_len]
                    return (cls, meth_name)

        # Fallback: try simple 2-component parse
        # _ZN<len1>Class<len2>MethodE<signature>
        if mangled.startswith("_ZN"):
            rest = mangled[3:]
            m1 = re.match(r'(\d+)', rest)
            if m1:
                l1 = int(m1.group(1))
                start = len(m1.group(1))
                if start + l1 <= len(rest):
                    cls = rest[start:start + l1]
                    rest2 = rest[start + l1:]
                    m2 = re.match(r'(\d+)', rest2)
                    if m2:
                        l2 = int(m2.group(1))
                        mstart = len(m2.group(1))
                        if mstart + l2 <= len(rest2):
                            meth = rest2[mstart:mstart + l2]
                            return (cls, meth)
        return None

    # -------------------------------------------------------------------
    # Phase 3: Resolve dispatch sites
    # -------------------------------------------------------------------

    def _resolve_sites(
        self, sites: list[DispatchSite],
    ) -> list[DispatchSite]:
        """Resolve each dispatch site to concrete target(s)."""
        # First pass: enrich class hierarchy from file headers
        seen_files: dict[str, _FileHeader] = {}
        for site in sites:
            if site.source_file not in seen_files:
                try:
                    code = Path(site.source_file).read_text(
                        encoding="utf-8", errors="replace",
                    )[:2000]
                    header = self._parse_file_header(code)
                    seen_files[site.source_file] = header
                    if header.class_name and header.method_name:
                        self._enrich_hierarchy_from_header(
                            header.class_name, header.method_name,
                            header.kind or "-", header.address,
                        )
                        # Also add this method to the selector map with
                        # class info
                        sel = header.method_name
                        impls = self._selector_map.get(sel, [])
                        has_class = any(
                            im.class_name == header.class_name for im in impls
                        )
                        if not has_class and header.class_name:
                            self._selector_map.setdefault(sel, []).append(
                                MethodImpl(
                                    class_name=header.class_name,
                                    selector=sel,
                                    kind=header.kind or "-",
                                    address=header.address,
                                    func_name=f"{header.kind or '-'}[{header.class_name} {sel}]",
                                )
                            )
                except OSError:
                    pass

        # Type propagation: build per-file variable type maps
        file_type_maps: dict[str, dict[str, str]] = {}
        if self.config.enable_type_propagation:
            for fpath_str, header in seen_files.items():
                try:
                    code = Path(fpath_str).read_text(
                        encoding="utf-8", errors="replace",
                    )
                    file_type_maps[fpath_str] = self._propagate_types(
                        code, header,
                    )
                except OSError:
                    pass

        # Resolve each site
        for site in sites:
            if site.variant == "vtable":
                self._resolve_vtable_site(
                    site, seen_files.get(site.source_file),
                )
                continue

            if site.selector is None:
                site.resolution_method = "no_selector"
                site.confidence = 0.0
                continue

            self._resolve_single_site(
                site, seen_files.get(site.source_file),
                file_type_maps.get(site.source_file, {}),
            )

        return sites

    def _resolve_vtable_site(
        self,
        site: DispatchSite,
        header: _FileHeader | None,
    ) -> None:
        """Resolve a C++ vtable dispatch site using RTTI info.

        Strategy:
        1. If the receiver variable has a known class (from header or
           type context), look up that class in the vtable map.
        2. Use the vtable offset to estimate which method slot is being
           called (offset / pointer_size = slot index).
        3. Match the slot index against known methods of the class.
        4. If no exact match, report as vtable_partial with candidates.
        """
        receiver = site.receiver_expr.strip()
        vtable_offset = site.vtable_offset

        # Try to determine the class of the receiver
        receiver_class: str | None = None

        # Check if receiver matches a known class variable pattern
        # e.g. "this" or "param_1" in a C++ method -> header class
        if receiver in ("this", "param_1", "self") and header and header.class_name:
            receiver_class = header.class_name
        elif header and header.class_name:
            # In a C++ method, vtable dispatch on local often means self
            receiver_class = header.class_name

        if receiver_class and receiver_class in self._vtable_map:
            # We know the class has a vtable. Look up methods.
            entry = self._class_hierarchy.get(receiver_class, {})
            methods = entry.get("methods", [])

            if vtable_offset and methods:
                # Estimate slot index (8 bytes per pointer on 64-bit)
                try:
                    offset_val = int(vtable_offset, 16)
                    # First 2 slots are typically RTTI offset + RTTI pointer
                    slot_index = (offset_val // 8) - 2
                    if 0 <= slot_index < len(methods):
                        method = methods[slot_index]
                        target_name = f"{receiver_class}::{method['selector']}"
                        # Check if this function exists in our address map
                        addr = self._func_address_map.get(target_name)
                        if addr is None:
                            # Try bracket notation
                            target_name_bracket = (
                                f"-[{receiver_class} {method['selector']}]"
                            )
                            addr = self._func_address_map.get(target_name_bracket)
                            if addr:
                                target_name = target_name_bracket
                        site.resolved_targets = [target_name]
                        site.receiver_type = receiver_class
                        site.confidence = 0.60
                        site.resolution_method = "vtable_rtti_slot"
                        return
                except (ValueError, IndexError):
                    pass

            # We know the class but can't pinpoint the slot -- return
            # all methods as candidates
            if methods:
                site.resolved_targets = [
                    f"{receiver_class}::{m['selector']}" for m in methods[:5]
                ]
                site.receiver_type = receiver_class
                site.confidence = 0.45
                site.resolution_method = "vtable_rtti_candidates"
                return

        # If receiver class is known from RTTI hierarchy but not vtable_map,
        # check if any known C++ class matches
        if receiver_class and receiver_class in self._class_hierarchy:
            entry = self._class_hierarchy[receiver_class]
            methods = entry.get("methods", [])
            if methods:
                site.resolved_targets = [
                    f"{receiver_class}::{m['selector']}" for m in methods[:5]
                ]
                site.receiver_type = receiver_class
                site.confidence = 0.40
                site.resolution_method = "vtable_class_methods"
                return

        # Check if any vtable class has methods that could match based
        # on the decompiled context (last resort)
        if hasattr(self, '_vtable_map') and self._vtable_map:
            # At minimum, we know vtable classes exist in the binary
            site.resolution_method = "vtable_no_receiver_type"
            site.confidence = 0.15
            return

        # Truly unresolved vtable
        site.resolution_method = "vtable_unresolved"
        site.confidence = 0.1

    def _resolve_single_site(
        self,
        site: DispatchSite,
        header: _FileHeader | None,
        type_map: dict[str, str],
    ) -> None:
        """Resolve a single dispatch site."""
        sel = site.selector
        assert sel is not None

        impls = self._selector_map.get(sel, [])

        # --- Strategy 1: Known class from receiver expression
        if site.receiver_type:
            cls = site.receiver_type
            # Check if this is a class method to a known class
            class_impls = [
                im for im in impls if im.class_name == cls
            ]
            if class_impls:
                site.resolved_targets = [im.func_name for im in class_impls]
                site.confidence = 0.95
                site.resolution_method = "class_method_direct"
                return

            # The class might be a framework class without local impl
            if self._is_framework_class(cls):
                site.resolved_targets = [f"+[{cls} {sel}]" if site.variant == "objc_msgSend"
                                         and self._looks_like_class_method(sel)
                                         else f"-[{cls} {sel}]"]
                site.confidence = 0.85
                site.resolution_method = "framework_external"
                return

            # Class known but no matching impl -- could be inherited
            for parent_cls in self._walk_superclasses(cls):
                parent_impls = [im for im in impls if im.class_name == parent_cls]
                if parent_impls:
                    site.resolved_targets = [im.func_name for im in parent_impls]
                    site.confidence = 0.75
                    site.resolution_method = "inherited_method"
                    return

        # --- Strategy 2: Type propagation from variable tracking
        if site.receiver_expr.strip() in type_map:
            inferred_cls = type_map[site.receiver_expr.strip()]
            class_impls = [im for im in impls if im.class_name == inferred_cls]
            if class_impls:
                site.resolved_targets = [im.func_name for im in class_impls]
                site.confidence = 0.80
                site.resolution_method = "type_propagation"
                return
            # Class known from type propagation but no local impl -> external
            if self._is_framework_class(inferred_cls):
                kind = "+" if self._looks_like_class_method(sel) else "-"
                site.receiver_type = inferred_cls
                site.resolved_targets = [f"{kind}[{inferred_cls} {sel}]"]
                site.confidence = 0.75
                site.resolution_method = "type_propagation_external"
                return

        # --- Strategy 3: self in ObjC method -> receiver is the method's class
        if (site.receiver_expr.strip() in ("param_1", "self", "IVar2")
                and header and header.class_name):
            cls = header.class_name
            class_impls = [im for im in impls if im.class_name == cls]
            if class_impls:
                site.resolved_targets = [im.func_name for im in class_impls]
                site.confidence = 0.80
                site.resolution_method = "self_class"
                return
            # Self class but no local impl
            if self._is_framework_class(cls):
                kind = "+" if self._looks_like_class_method(sel) else "-"
                site.receiver_type = cls
                site.resolved_targets = [f"{kind}[{cls} {sel}]"]
                site.confidence = 0.70
                site.resolution_method = "self_class_external"
                return

        # --- Strategy 4: Super dispatch → parent class
        if site.variant == "objc_msgSendSuper" and header and header.class_name:
            for parent_cls in self._walk_superclasses(header.class_name):
                parent_impls = [im for im in impls if im.class_name == parent_cls]
                if parent_impls:
                    site.resolved_targets = [im.func_name for im in parent_impls]
                    site.confidence = 0.70
                    site.resolution_method = "super_dispatch"
                    return
            # No local superclass impl -- likely framework super
            site.resolved_targets = [f"-[?super {sel}]"]
            site.confidence = 0.40
            site.resolution_method = "super_external"
            return

        # --- Strategy 5: Unique selector (only one implementor in binary)
        if len(impls) == 1:
            site.resolved_targets = [impls[0].func_name]
            site.confidence = 0.70
            site.resolution_method = "unique_selector"
            return

        # --- Strategy 6: Candidate set (multiple implementors)
        if len(impls) > 1:
            # Filter by kind: if the receiver looks like a class ref,
            # prefer class methods
            if self._looks_like_class_receiver(site.receiver_expr):
                class_methods = [im for im in impls if im.kind == "+"]
                if class_methods:
                    site.resolved_targets = [im.func_name for im in class_methods]
                    site.confidence = 0.50
                    site.resolution_method = "candidate_set_class"
                    return

            site.resolved_targets = [im.func_name for im in impls]
            site.confidence = 0.40
            site.resolution_method = "candidate_set"
            return

        # --- Strategy 7: Framework method (selector not found locally)
        # Check if the selector name matches common framework patterns
        if self._looks_like_framework_selector(sel):
            # Try to infer the class from context
            cls_guess = site.receiver_type or "?"
            kind = "+" if self._looks_like_class_method(sel) else "-"
            site.resolved_targets = [f"{kind}[{cls_guess} {sel}]"]
            site.confidence = 0.50
            site.resolution_method = "framework_external"
            return

        # Truly unresolved
        site.resolved_targets = []
        site.confidence = 0.0
        site.resolution_method = "unresolved"

    def _propagate_types(
        self, func_code: str, header: _FileHeader,
    ) -> dict[str, str]:
        """Basic intra-procedural type propagation.

        Returns mapping of variable_name -> class_name.
        """
        type_map: dict[str, str] = {}

        # Rule 0: Function signature parameter types
        # e.g. "void GPStartVPNTunnel(NEVPNManager *param_1, NSDictionary *param_2)"
        # Also handles: "ID PanMSAgentSystemExtensions::init_system_ext_app_(ID param_1, ...)"
        sig_match = re.search(
            r'^\w[\w\s\*]*\s+\w[\w:~]*\s*\(([^)]+)\)',
            func_code, re.MULTILINE,
        )
        if sig_match:
            params_str = sig_match.group(1)
            for param_m in re.finditer(
                r'(\w+)\s*\*\s*(param_\d+)', params_str,
            ):
                param_type = param_m.group(1)
                param_name = param_m.group(2)
                # Skip generic types like ID, SEL, void, undefined*
                if param_type not in ("ID", "SEL", "void", "undefined",
                                       "undefined8", "long", "char", "int",
                                       "ulong", "uint", "bool", "typedef"):
                    type_map[param_name] = param_type

        # Rule 0b: Local variable declarations with class types
        # e.g. "NEVPNManager *pNVar8;"
        # CONSERVATIVE: only trust declarations where the variable name
        # suggests a typed pointer (pXVar, IVar, etc.) -- not generic
        # uVar/lVar which Ghidra often reassigns.
        _GENERIC_VARS = re.compile(r'^[ul]Var\d+$')
        _SKIP_TYPES = {
            "ID", "SEL", "void", "undefined", "undefined8",
            "long", "char", "int", "ulong", "uint", "bool", "code",
            "dispatch_queue_t", "dispatch_group_t", "dispatch_time_t",
            "class_t", "cfstringStruct",
        }
        for decl_m in re.finditer(
            r'^\s+(\w+)\s*\*\s*(\w+)\s*;', func_code, re.MULTILINE,
        ):
            decl_type = decl_m.group(1)
            decl_name = decl_m.group(2)
            if decl_type in _SKIP_TYPES:
                continue
            # Only trust typed var names (pXVar, IVar, param) not generic
            if _GENERIC_VARS.match(decl_name):
                continue
            type_map[decl_name] = decl_type

        # Rule 1: param_1 = self in ObjC method (overrides Rule 0 if applicable)
        if header.class_name:
            type_map["param_1"] = header.class_name

        # Rule 1b: Cast-based type propagation
        # e.g. "pNVar8 = (NEVPNManager *)_objc_retain(uVar4);"
        for cast_m in re.finditer(
            r'(\w+)\s*=\s*\(\s*(\w+)\s*\*\s*\)\s*_objc_retain',
            func_code,
        ):
            var_name = cast_m.group(1)
            cast_type = cast_m.group(2)
            if cast_type not in ("void", "undefined", "long", "char"):
                type_map.setdefault(var_name, cast_type)

        # Rule 2: alloc/init patterns
        # uVar = _objc_alloc_init(&_OBJC_CLASS___Foo)  ->  uVar is Foo
        for m in _RE_ALLOC_INIT_CLASS.finditer(func_code):
            cls = m.group(1) or m.group(2)
            # Find the variable assignment: "varName = _objc_alloc_init..."
            line_start = func_code.rfind("\n", 0, m.start()) + 1
            prefix = func_code[line_start:m.start()].strip()
            # Pattern: "varName = " at end
            assign_match = re.search(r'(\w+)\s*=\s*$', prefix)
            if assign_match:
                type_map[assign_match.group(1)] = cls

        # Rule 2b: objc_alloc followed by init message
        for m in _RE_ALLOC_CLASS.finditer(func_code):
            cls = m.group(1) or m.group(2)
            line_start = func_code.rfind("\n", 0, m.start()) + 1
            prefix = func_code[line_start:m.start()].strip()
            assign_match = re.search(r'(\w+)\s*=\s*$', prefix)
            if assign_match:
                type_map[assign_match.group(1)] = cls

        # Rule 3: retainAutoreleasedReturnValue IMMEDIATELY after class method
        # Pattern: class method call on line N, retain on line N+1
        # Reset if any other code intervenes.
        lines = func_code.split("\n")
        last_class_target: str | None = None
        for line in lines:
            stripped = line.strip()
            # Skip empty/comment lines
            if not stripped or stripped.startswith("//"):
                continue

            if "_objc_retainAutoreleasedReturnValue" in line and last_class_target:
                assign_match = re.search(r'(\w+)\s*=\s*_objc_retain', line)
                if assign_match:
                    type_map.setdefault(assign_match.group(1), last_class_target)
                last_class_target = None
                continue

            # Check for class reference patterns
            m_ref = _RE_MSGSEND_CLASS_REF.search(line)
            m_ct = _RE_MSGSEND_CLASS_T.search(line)
            if m_ref:
                last_class_target = m_ref.group(1)
            elif m_ct:
                last_class_target = m_ct.group(1)
            else:
                # Any other code resets the chain
                last_class_target = None

        return type_map

    # -------------------------------------------------------------------
    # Phase 4: Augment call graph
    # -------------------------------------------------------------------

    def _augment_call_graph(
        self,
        call_graph_json: Path,
        resolved_sites: list[DispatchSite],
    ) -> tuple[list[dict], list[dict]]:
        """Build new edges and removed edges for the call graph.

        Returns (augmented_edges, removed_edges).
        """
        with open(call_graph_json, "r") as f:
            cg = json.load(f)

        # Group resolved sites by caller address
        caller_targets: dict[str, list[DispatchSite]] = {}
        for site in resolved_sites:
            if site.resolved_targets and site.confidence >= self.config.min_confidence:
                caller_targets.setdefault(site.caller_addr, []).append(site)

        augmented_edges: list[dict] = []
        removed_edges: list[dict] = []

        # Dispatch function addresses
        dispatch_addrs: set[str] = set()
        for addr, node in cg.get("nodes", {}).items():
            if node.get("name", "") in (
                "_objc_msgSend", "_objc_msgSendSuper2",
                "_objc_msgSend_stret", "_objc_msgSendSuper2_stret",
            ):
                dispatch_addrs.add(addr)

        for caller_addr, sites_for_caller in caller_targets.items():
            node = cg.get("nodes", {}).get(caller_addr)
            if node is None:
                continue

            # Record removed edges (caller -> _objc_msgSend)
            for callee in node.get("callees", []):
                if callee.get("address") in dispatch_addrs:
                    removed_edges.append({
                        "source": node["name"],
                        "source_addr": caller_addr,
                        "target": callee["name"],
                        "target_addr": callee["address"],
                        "edge_type": "removed_dispatch",
                    })

            # Add new edges
            for site in sites_for_caller:
                for target_name in site.resolved_targets:
                    # Look up target address
                    target_addr = self._func_address_map.get(target_name, "external")
                    augmented_edges.append({
                        # Canonical format (used by downstream consumers)
                        "from": caller_addr,
                        "to": target_addr,
                        "type": "virtual_dispatch",
                        "confidence": round(site.confidence, 4),
                        # Detailed fields for analysis/debugging
                        "source": site.caller_func,
                        "source_addr": caller_addr,
                        "target": target_name,
                        "target_addr": target_addr,
                        "selector": site.selector,
                        "receiver_type": site.receiver_type,
                        "resolution_method": site.resolution_method,
                        "edge_type": "resolved_dispatch",
                    })

        return augmented_edges, removed_edges

    # -------------------------------------------------------------------
    # Output & reporting
    # -------------------------------------------------------------------

    def _write_outputs(
        self,
        output_dir: Path,
        result: DispatchResolutionResult,
        original_cg_path: Path,
    ) -> None:
        """Write augmented call graph and dispatch report to files."""
        # Write augmented call graph
        with open(original_cg_path, "r") as f:
            cg = json.load(f)

        # Add dispatch resolution metadata
        cg["dispatch_resolution"] = {
            "total_sites": result.total_dispatch_sites,
            "resolved": result.resolved_count,
            "candidates": result.candidate_count,
            "external": result.external_count,
            "unresolved": result.unresolved_count,
            "resolution_rate": round(result.resolution_rate, 4),
        }
        cg["augmented_edges"] = result.augmented_edges
        cg["removed_dispatch_edges"] = result.removed_edges

        augmented_path = output_dir / "augmented_call_graph.json"
        with open(augmented_path, "w") as f:
            json.dump(cg, f, indent=2)
        logger.info("Wrote augmented call graph to %s", augmented_path)

        # Write detailed dispatch sites
        sites_data = []
        for site in result.dispatch_sites:
            sites_data.append({
                "caller_func": site.caller_func,
                "caller_addr": site.caller_addr,
                "source_file": Path(site.source_file).name,
                "line_number": site.line_number,
                "variant": site.variant,
                "receiver_type": site.receiver_type,
                "selector": site.selector,
                "resolved_targets": site.resolved_targets,
                "confidence": round(site.confidence, 3),
                "resolution_method": site.resolution_method,
            })

        sites_path = output_dir / "dispatch_sites.json"
        with open(sites_path, "w") as f:
            json.dump({
                "total": len(sites_data),
                "sites": sites_data,
            }, f, indent=2)
        logger.info("Wrote %d dispatch sites to %s", len(sites_data), sites_path)

        # Write human-readable report
        report_path = output_dir / "dispatch_report.txt"
        report_path.write_text(self._generate_report(result))
        logger.info("Wrote report to %s", report_path)

    def _generate_report(self, result: DispatchResolutionResult) -> str:
        """Generate human-readable resolution report."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("  Virtual Dispatch Resolution Report")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Total dispatch sites found:  {result.total_dispatch_sites}")
        lines.append(f"Resolved (single target):    {result.resolved_count}")
        lines.append(f"Candidates (multiple):       {result.candidate_count}")
        lines.append(f"External (framework):        {result.external_count}")
        lines.append(f"Unresolved:                  {result.unresolved_count}")
        lines.append(f"Resolution rate:             {result.resolution_rate:.1%}")
        lines.append(f"Selector map size:           {result.selector_map_size}")
        lines.append(f"Classes in hierarchy:        {len(result.class_hierarchy)}")
        lines.append(f"New edges added:             {len(result.augmented_edges)}")
        lines.append(f"Dispatch edges removed:      {len(result.removed_edges)}")
        lines.append("")

        # Resolution method breakdown
        method_counts: dict[str, int] = {}
        for site in result.dispatch_sites:
            method_counts[site.resolution_method] = (
                method_counts.get(site.resolution_method, 0) + 1
            )
        lines.append("Resolution Method Breakdown:")
        lines.append("-" * 40)
        for method, count in sorted(
            method_counts.items(), key=lambda x: -x[1],
        ):
            pct = count / max(result.total_dispatch_sites, 1) * 100
            lines.append(f"  {method:30s}  {count:5d}  ({pct:5.1f}%)")
        lines.append("")

        # Variant breakdown
        variant_counts: dict[str, int] = {}
        for site in result.dispatch_sites:
            variant_counts[site.variant] = (
                variant_counts.get(site.variant, 0) + 1
            )
        lines.append("Dispatch Variant Breakdown:")
        lines.append("-" * 40)
        for variant, count in sorted(
            variant_counts.items(), key=lambda x: -x[1],
        ):
            lines.append(f"  {variant:30s}  {count:5d}")
        lines.append("")

        # Top unresolved selectors
        unresolved_sels: dict[str, int] = {}
        for site in result.dispatch_sites:
            if site.resolution_method == "unresolved" and site.selector:
                unresolved_sels[site.selector] = (
                    unresolved_sels.get(site.selector, 0) + 1
                )
        if unresolved_sels:
            lines.append("Top 20 Unresolved Selectors:")
            lines.append("-" * 40)
            for sel, count in sorted(
                unresolved_sels.items(), key=lambda x: -x[1],
            )[:20]:
                lines.append(f"  {sel:40s}  {count:3d}")
            lines.append("")

        # Sample resolved dispatches
        resolved_samples = [
            s for s in result.dispatch_sites
            if len(s.resolved_targets) == 1
            and s.resolution_method not in ("framework_external",)
        ][:15]
        if resolved_samples:
            lines.append("Sample Resolved Dispatches:")
            lines.append("-" * 70)
            for site in resolved_samples:
                lines.append(
                    f"  {site.caller_func} L{site.line_number}: "
                    f"{site.selector} -> {site.resolved_targets[0]}  "
                    f"[{site.resolution_method}, {site.confidence:.0%}]"
                )
            lines.append("")

        if result.errors:
            lines.append("Errors:")
            lines.append("-" * 40)
            for err in result.errors:
                lines.append(f"  {err}")

        lines.append("=" * 70)
        return "\n".join(lines)

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _is_framework_class(self, class_name: str) -> bool:
        """Check if a class name belongs to a system framework."""
        for prefix in self.config.framework_prefixes:
            if class_name.startswith(prefix):
                return True
        return False

    def _walk_superclasses(self, class_name: str) -> list[str]:
        """Walk the class hierarchy upward, returning superclass chain."""
        chain: list[str] = []
        visited: set[str] = {class_name}
        current = class_name
        while True:
            entry = self._class_hierarchy.get(current)
            if entry is None or entry.get("superclass") is None:
                break
            parent = entry["superclass"]
            if parent in visited:
                break  # avoid cycles
            visited.add(parent)
            chain.append(parent)
            current = parent
        return chain

    @staticmethod
    def _looks_like_class_method(selector: str) -> bool:
        """Heuristic: class methods are typically factory methods."""
        class_method_prefixes = (
            "alloc", "new", "shared", "default", "class",
            "arrayWith", "dictionaryWith", "stringWith",
            "numberWith", "dateWith", "errorWith",
            "imageNamed:", "mainBundle", "defaultCenter",
            "defaultManager",
        )
        for prefix in class_method_prefixes:
            if selector.startswith(prefix):
                return True
        return False

    @staticmethod
    def _looks_like_class_receiver(receiver_expr: str) -> bool:
        """Check if receiver expression looks like a class reference."""
        return (
            "&_OBJC_CLASS___" in receiver_expr
            or "&objc::class_t::" in receiver_expr
        )

    @staticmethod
    def _looks_like_framework_selector(selector: str) -> bool:
        """Heuristic: common Cocoa/UIKit selectors."""
        # Most selectors are framework if they match common patterns
        framework_selectors = {
            "init", "dealloc", "retain", "release", "autorelease",
            "description", "hash", "isEqual:", "copy", "mutableCopy",
            "class", "superclass", "respondsToSelector:",
            "performSelector:", "performSelector:withObject:",
            "count", "objectAtIndex:", "objectForKey:",
            "addObject:", "removeObject:", "setObject:forKey:",
            "stringValue", "intValue", "floatValue", "doubleValue",
            "length", "UTF8String",
            "frame", "bounds", "setFrame:", "setBounds:",
            "setHidden:", "isHidden",
            "setEnabled:", "isEnabled",
            "setTitle:", "title",
            "setStringValue:", "stringValue",
            "setImage:", "image",
            "setFont:", "font",
            "setTarget:", "target",
            "setAction:", "action",
            "delegate", "setDelegate:",
            "window", "view", "subviews",
            "addSubview:", "removeFromSuperview",
        }
        # Exact match
        if selector in framework_selectors:
            return True
        # Pattern match: setX:, isX, xWith...
        if selector.startswith("set") and selector.endswith(":"):
            return True
        if selector.startswith("is") and selector[2:3].isupper():
            return True
        return False
