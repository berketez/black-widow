"""C Project Builder -- decompile edilmis binary'den organize IDE projesi uret.

Call graph + API analizi ile fonksiyonlari subsystem'lere ayirir,
kucuk fonksiyonlari birlestirir, CMake/Makefile/clangd dosyalari uretir.

Cikti yapisi:
  project/
    README.md
    CMakeLists.txt / Makefile / compile_commands.json
    .vscode/ .clangd
    include/          -- types.h + subsystem header'lari
    src/
      main.c          -- entry point fonksiyonlari
      subsystem_XXX/  -- API-based gruplama
      misc/           -- thunks_and_stubs.c + utility_functions.c
    analysis/
      call_graph.dot / algorithms.md / xref_index.md / subsystem_map.md
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Subsystem siniflandirma kurallari
# ---------------------------------------------------------------------------

# API fonksiyon adlari -> subsystem eslesmesi
# Bir fonksiyonun callee'leri bu pattern'lere gore taranir.
_SUBSYSTEM_RULES: list[tuple[str, list[str]]] = [
    ("network", [
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "getaddrinfo", "gethostbyname", "htons", "inet_addr", "select",
        "poll", "epoll_create", "epoll_ctl", "sendto", "recvfrom",
        "setsockopt", "getsockopt", "shutdown",
    ]),
    ("crypto", [
        "SSL_", "EVP_", "CC", "SecKey", "MD5", "SHA", "AES_",
        "RSA_", "HMAC_", "RAND_bytes", "CCCrypt",
    ]),
    ("file_io", [
        "fopen", "fread", "fwrite", "fclose", "fgets", "fputs", "fprintf",
        "open", "read", "write", "close", "stat", "access", "lstat",
        "opendir", "readdir", "closedir", "mkdir", "unlink", "rename",
        "fseek", "ftell", "rewind", "fstat",
    ]),
    ("concurrency", [
        "pthread_", "dispatch_", "NSOperation", "os_unfair_lock",
        "sem_wait", "sem_post", "sem_init",
    ]),
    ("memory", [
        "malloc", "free", "realloc", "calloc", "mmap", "munmap",
        "mprotect", "vm_allocate", "vm_deallocate",
    ]),
    ("process", [
        "fork", "exec", "execve", "execvp", "kill", "waitpid",
        "posix_spawn", "system", "popen", "pclose", "pipe",
        "signal", "sigaction", "_exit",
    ]),
    ("objc_runtime", [
        "objc_msgSend", "objc_getClass", "objc_retain", "objc_release",
        "objc_alloc", "objc_allocWithZone",
        "_swift_", "swift_", "_Block_copy", "_Block_release",
    ]),
    ("ui", [
        "NSView", "UIView", "NSWindow", "UIWindow", "NSButton", "UIButton",
        "Controller", "NSApp", "UIApplication",
    ]),
]

# Prefix-match icin derlenmis lookup: (prefix, subsystem) sirali listesi
_PREFIX_RULES: list[tuple[str, str]] = []
_EXACT_RULES: dict[str, str] = {}


def _build_lookup() -> None:
    """Subsystem lookup tablolarini derle (modul yuklenince bir kez calisir)."""
    for subsystem, apis in _SUBSYSTEM_RULES:
        for api in apis:
            if api.endswith("_"):
                _PREFIX_RULES.append((api, subsystem))
            else:
                _EXACT_RULES[api] = subsystem
    # Uzun prefix'ler once eslesmeli (SSL_ vs S)
    _PREFIX_RULES.sort(key=lambda x: -len(x[0]))


_build_lookup()

# ---------------------------------------------------------------------------
# Entry point tespiti
# ---------------------------------------------------------------------------

_ENTRY_NAMES = frozenset({
    "main", "_main", "entry", "_entry", "start", "_start",
    "WinMain", "DllMain", "module_init", "_mod_init_func",
})

# Ghidra thunk fonksiyon pattern'i
_THUNK_RE = re.compile(r"^thunk_", re.IGNORECASE)

# Ghidra auto-generated FUN_ pattern
_FUN_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")

# Dosya adi sanitization icin guvenli olmayan karakterler
_UNSAFE_FILENAME_RE = re.compile(r'[^a-zA-Z0-9_\-.]')

# ---------------------------------------------------------------------------
# Sonuc dataclass
# ---------------------------------------------------------------------------


@dataclass
class CProjectBuildResult:
    success: bool
    files_written: int = 0
    subsystems_found: int = 0
    functions_merged: int = 0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Ana builder sinifi
# ---------------------------------------------------------------------------


class CProjectBuilder:
    """Decompile edilmis C dosyalarindan organize IDE projesi olusturur."""

    # Tek dosyada max satir — asarsa bol
    MAX_LINES_PER_FILE = 5000
    # Bu satir sayisindan kucuk fonksiyonlar "kucuk" sayilir
    SMALL_FUNC_THRESHOLD = 10

    def __init__(self, config) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        source_dir: Path,
        output_dir: Path,
        workspace=None,
        algorithm_results=None,
    ) -> CProjectBuildResult:
        """Organize C projesi olustur.

        Args:
            source_dir: Decompile edilmis *.c dosyalarinin bulundugu dizin.
            output_dir: Proje cikti dizini.
            workspace: Karadul Workspace nesnesi (opsiyonel, call graph icin).
            algorithm_results: Algoritma tespit sonuclari (opsiyonel).

        Returns:
            CProjectBuildResult
        """
        errors: list[str] = []
        files_written = 0
        functions_merged = 0

        output_dir.mkdir(parents=True, exist_ok=True)

        # -- C dosyalarini topla -------------------------------------------
        c_files = sorted(source_dir.rglob("*.c"))
        if not c_files:
            return CProjectBuildResult(success=False, errors=["C dosyasi bulunamadi"])

        # Her dosyanin icerigi ve satir sayisi
        file_contents: dict[str, str] = {}   # stem -> content
        file_lines: dict[str, int] = {}      # stem -> line count
        for cf in c_files:
            content = cf.read_text(errors="replace")
            stem = cf.stem
            file_contents[stem] = content
            file_lines[stem] = content.count("\n") + 1

        # -- Call graph yukle -----------------------------------------------
        call_graph = self._load_call_graph(workspace)
        nodes: dict[str, dict] = call_graph.get("nodes", {}) if call_graph else {}
        edges: list[dict] = call_graph.get("edges", []) if call_graph else []
        program_name = call_graph.get("program", "unknown") if call_graph else "unknown"

        # -- Subsystem siniflandirma ----------------------------------------
        # func_name -> subsystem
        func_subsystem: dict[str, str] = {}
        for addr, node in nodes.items():
            name = node.get("name", "")
            callees = node.get("callees", [])
            subsys = self._classify_subsystem(name, callees)
            func_subsystem[name] = subsys

        # Dosya stem'lerini de siniflandir (call graph'ta olmayanlari dahil)
        for stem in file_contents:
            if stem not in func_subsystem:
                func_subsystem[stem] = "misc"

        # -- Community-based fallback (misc fonksiyonlar icin) ---------------
        if call_graph:
            community_map = self._detect_communities(call_graph)
            for fname, subsys in list(func_subsystem.items()):
                if subsys == "misc" and fname in community_map:
                    func_subsystem[fname] = community_map[fname]

        # -- Entry point'leri ayir ------------------------------------------
        entry_stems: list[str] = []
        for stem in file_contents:
            if stem in _ENTRY_NAMES or stem.lower() in {"main", "_main", "entry"}:
                entry_stems.append(stem)
            elif nodes:
                # Call graph'ta hic caller'i olmayan ve adi bilinen
                for addr, node in nodes.items():
                    if node.get("name") == stem and node.get("caller_count", 0) == 0:
                        if stem not in _ENTRY_NAMES and not _FUN_RE.match(stem):
                            # Potansiyel entry, ama sadece ismi uygunsa
                            pass

        # -- Kucuk fonksiyon tespiti ----------------------------------------
        small_funcs: dict[str, list[str]] = defaultdict(list)  # subsystem -> [stem, ...]
        normal_funcs: dict[str, list[str]] = defaultdict(list)  # subsystem -> [stem, ...]

        for stem, content in file_contents.items():
            if stem in entry_stems:
                continue  # entry point'ler ayri
            lines = file_lines[stem]
            subsys = func_subsystem.get(stem, "misc")
            is_thunk = bool(_THUNK_RE.match(stem))
            if is_thunk or lines < self.SMALL_FUNC_THRESHOLD:
                small_funcs[subsys].append(stem)
            else:
                normal_funcs[subsys].append(stem)

        # -- Dizin yapisi olustur -------------------------------------------
        src_dir = output_dir / "src"
        include_dir = output_dir / "include"
        analysis_dir = output_dir / "analysis"
        vscode_dir = output_dir / ".vscode"

        for d in [src_dir, include_dir, analysis_dir, vscode_dir]:
            d.mkdir(parents=True, exist_ok=True)

        active_subsystems: set[str] = set()
        for subsys in set(list(normal_funcs.keys()) + list(small_funcs.keys())):
            if normal_funcs.get(subsys) or small_funcs.get(subsys):
                active_subsystems.add(subsys)

        # -- 1. Entry point dosyasi -----------------------------------------
        if entry_stems:
            main_parts = []
            for stem in entry_stems:
                main_parts.append(f"// === {stem} ===\n")
                main_parts.append(file_contents[stem])
                main_parts.append("\n")
            (src_dir / "main.c").write_text("".join(main_parts))
            files_written += 1

        # -- 2. Subsystem dizinleri ve dosyalari ----------------------------
        for subsys in sorted(active_subsystems):
            subsys_dir = src_dir / f"subsystem_{subsys}"
            subsys_dir.mkdir(exist_ok=True)

            # Normal (buyuk) fonksiyonlar
            normal = normal_funcs.get(subsys, [])
            if normal:
                written = self._write_grouped_files(
                    subsys_dir, normal, file_contents, subsys
                )
                files_written += written

            # Kucuk fonksiyonlar (thunk + stub) -> tek dosyada birlestirilir
            smalls = small_funcs.get(subsys, [])
            if smalls:
                merged_content = self._merge_small_functions(smalls, file_contents)
                functions_merged += len(smalls)
                # thunks_and_stubs.c yazimi (500 satir limitine dikkat)
                merged_files = self._split_if_large(
                    merged_content, "thunks_and_stubs", subsys_dir
                )
                files_written += merged_files

        # -- 3. types.h ------------------------------------------------------
        types_content = self._build_types_h(source_dir, workspace)
        (include_dir / "types.h").write_text(types_content)
        files_written += 1

        # -- 4. Subsystem header'lari ----------------------------------------
        for subsys in sorted(active_subsystems):
            header = self._build_subsystem_header(
                subsys, normal_funcs.get(subsys, []) + small_funcs.get(subsys, []),
                nodes,
            )
            (include_dir / f"subsystem_{subsys}.h").write_text(header)
            files_written += 1

        # -- 5. IDE dosyalari -------------------------------------------------
        all_c_sources = self._collect_source_paths(src_dir, output_dir)

        cmake = self._build_cmake(program_name, all_c_sources)
        (output_dir / "CMakeLists.txt").write_text(cmake)
        files_written += 1

        makefile = self._build_makefile(program_name, all_c_sources)
        (output_dir / "Makefile").write_text(makefile)
        files_written += 1

        compile_cmds = self._build_compile_commands(all_c_sources, output_dir)
        (output_dir / "compile_commands.json").write_text(compile_cmds)
        files_written += 1

        vscode_settings = self._build_vscode_settings()
        (vscode_dir / "settings.json").write_text(vscode_settings)
        files_written += 1

        cpp_props = self._build_cpp_properties(output_dir)
        (vscode_dir / "c_cpp_properties.json").write_text(cpp_props)
        files_written += 1

        clangd = self._build_clangd_config()
        (output_dir / ".clangd").write_text(clangd)
        files_written += 1

        # -- 6. Analysis dosyalari -------------------------------------------
        # call_graph.dot
        if call_graph:
            try:
                dot = self._build_call_graph_dot(nodes, edges)
                (analysis_dir / "call_graph.dot").write_text(dot)
                files_written += 1
            except Exception as exc:
                errors.append(f"Call graph DOT hatasi: {exc}")

        # algorithms.md
        if algorithm_results and hasattr(algorithm_results, "algorithms"):
            algos_md = self._build_algorithm_report(algorithm_results)
            (analysis_dir / "algorithms.md").write_text(algos_md)
            files_written += 1

        # xref_index.md
        if nodes:
            xref = self._build_xref_index(nodes)
            (analysis_dir / "xref_index.md").write_text(xref)
            files_written += 1

        # subsystem_map.md
        if func_subsystem:
            smap = self._build_subsystem_map(func_subsystem, active_subsystems)
            (analysis_dir / "subsystem_map.md").write_text(smap)
            files_written += 1

        # -- 7. README.md ----------------------------------------------------
        readme = self._build_readme(
            program_name=program_name,
            c_files_count=len(c_files),
            subsystems=sorted(active_subsystems),
            functions_merged=functions_merged,
            algorithm_results=algorithm_results,
        )
        (output_dir / "README.md").write_text(readme)
        files_written += 1

        logger.info(
            "C project built: %d dosya, %d subsystem, %d merged -> %s",
            files_written, len(active_subsystems), functions_merged, output_dir,
        )

        return CProjectBuildResult(
            success=files_written > 0,
            files_written=files_written,
            subsystems_found=len(active_subsystems),
            functions_merged=functions_merged,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Yardimci: edge endpoint ve dosya adi sanitization
    # ------------------------------------------------------------------

    @staticmethod
    def _get_edge_endpoints(edge: dict) -> tuple[str, str]:
        """Edge dict'inden kaynak ve hedef fonksiyon adlarini cek.

        Farkli kaynaklarda (Ghidra, IDA, vb.) edge key'leri degisebilir:
        from_name / source / from  ve  to_name / target / to.
        Bu metod hepsini tek noktadan handle eder.
        """
        src = edge.get("from_name", edge.get("source", edge.get("from", "")))
        dst = edge.get("to_name", edge.get("target", edge.get("to", "")))
        return src, dst

    @staticmethod
    def _sanitize_stem(stem: str) -> str:
        """Dosya adi icin guvenli karakter setine donustur.

        Go binary'lerde fonksiyon adlari '/' icerebilir (orn: runtime/internal/sys).
        Bu, workspace disina yazima (path traversal) yol acabilir.
        """
        safe = _UNSAFE_FILENAME_RE.sub('_', stem)
        safe = safe.strip('_.')
        return safe or 'unnamed'

    # ------------------------------------------------------------------
    # Call graph yukleme
    # ------------------------------------------------------------------

    def _load_call_graph(self, workspace) -> dict | None:
        """Call graph JSON'u workspace'ten yukle. Iki olasi konumu dener."""
        if not workspace:
            return None
        static_dir = workspace.get_stage_dir("static")
        candidates = [
            static_dir / "ghidra_call_graph.json",
            static_dir / "ghidra_output" / "call_graph.json",
        ]
        for path in candidates:
            if path.exists():
                try:
                    return json.loads(path.read_text())
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("Call graph okuma hatasi %s: %s", path, exc)
        return None

    # ------------------------------------------------------------------
    # Subsystem siniflandirma
    # ------------------------------------------------------------------

    def _classify_subsystem(self, func_name: str, callees: list[dict]) -> str:
        """Bir fonksiyonu callee API'lerine bakarak subsystem'e ata."""
        subsystem_scores: dict[str, int] = defaultdict(int)

        callee_names = [c.get("name", "") for c in callees]
        all_names = callee_names + [func_name]

        for name in all_names:
            # Basi _ ile baslayan external API'ler: _malloc -> malloc
            clean = name.lstrip("_")

            # Exact match
            if clean in _EXACT_RULES:
                subsystem_scores[_EXACT_RULES[clean]] += 2
                continue

            # Prefix match
            matched = False
            for prefix, subsys in _PREFIX_RULES:
                if clean.startswith(prefix) or name.startswith(prefix):
                    subsystem_scores[subsys] += 2
                    matched = True
                    break

            if not matched and name.startswith("_"):
                # _swift_retain gibi — original name ile prefix dene
                for prefix, subsys in _PREFIX_RULES:
                    if name[1:].startswith(prefix) or name.startswith("_" + prefix):
                        subsystem_scores[subsys] += 2
                        break

        if not subsystem_scores:
            return "misc"

        best = max(subsystem_scores, key=subsystem_scores.get)  # type: ignore[arg-type]
        return best

    # ------------------------------------------------------------------
    # Community detection (label propagation)
    # ------------------------------------------------------------------

    def _detect_communities(self, call_graph: dict) -> dict[str, str]:
        """Call graph'tan label propagation ile community tespit et.

        Undirected adjacency list olusturulur, her node kendi label'iyla
        baslar, iteratif olarak komsu cogunlugunun label'ini alir.
        3'ten az uyeli community'ler filtrelenir.

        Returns:
            {func_name: "group_N"} eslesmesi. Community'ye atanamayanlar
            sonucta yer almaz.
        """
        from collections import Counter

        edges = call_graph.get("edges", [])
        if not edges:
            return {}

        # Adjacency list (undirected)
        adj: dict[str, set[str]] = defaultdict(set)
        for edge in edges:
            src, dst = self._get_edge_endpoints(edge)
            if src and dst and src != dst:
                adj[src].add(dst)
                adj[dst].add(src)

        if not adj:
            return {}

        # Her node kendi label'iyla baslar
        labels = {node: node for node in adj}

        # Iteratif: her node komsu cogunlugunun label'ini alir
        for _ in range(20):
            changed = False
            for node in sorted(adj):
                neighbor_labels = Counter(
                    labels.get(n, n) for n in adj[node] if n in labels
                )
                if neighbor_labels:
                    majority = neighbor_labels.most_common(1)[0][0]
                    if labels[node] != majority:
                        labels[node] = majority
                        changed = True
            if not changed:
                break

        # Label -> community ismi
        community_members: dict[str, list[str]] = defaultdict(list)
        for node, label in labels.items():
            community_members[label].append(node)

        # Kucuk community'leri (< 3 uye) filtrele
        result: dict[str, str] = {}
        group_id = 0
        for label, members in sorted(community_members.items(), key=lambda x: -len(x[1])):
            if len(members) >= 3:
                group_name = "group_%d" % group_id
                for m in members:
                    result[m] = group_name
                group_id += 1

        return result

    # ------------------------------------------------------------------
    # Dosya yazma yardimcilari
    # ------------------------------------------------------------------

    def _write_grouped_files(
        self, dest_dir: Path, stems: list[str],
        file_contents: dict[str, str], subsystem: str,
    ) -> int:
        """Normal fonksiyonlari dosyalara yaz. 500 satir limiti uygula."""
        written = 0
        # Her fonksiyonu kendi dosyasina yaz
        # Ayni subsystem'deki fonksiyonlari semantik gruplara ayirmak icin
        # basit strateji: fonksiyon basina dosya, 500 satiri gesenler bolunur
        for stem in stems:
            content = file_contents.get(stem, "")
            safe_stem = self._sanitize_stem(stem)
            line_count = content.count("\n") + 1
            if line_count <= self.MAX_LINES_PER_FILE:
                (dest_dir / f"{safe_stem}.c").write_text(content)
                written += 1
            else:
                written += self._split_if_large(content, safe_stem, dest_dir)
        return written

    def _merge_small_functions(
        self, stems: list[str], file_contents: dict[str, str],
    ) -> str:
        """Kucuk fonksiyonlari tek string'de birlestirilmis content olarak dondur."""
        parts = [
            "// ==========================================================\n"
            "// Thunks, stubs and small wrapper functions (auto-merged)\n"
            "// ==========================================================\n\n"
        ]
        for stem in sorted(stems):
            content = file_contents.get(stem, "")
            parts.append(f"// --- {stem} ---\n")
            parts.append(content.rstrip())
            parts.append("\n\n")
        return "".join(parts)

    def _split_if_large(self, content: str, base_name: str, dest_dir: Path) -> int:
        """Icerik 500 satiri asarsa bolunmis dosyalar yaz. Dosya sayisini dondurur."""
        base_name = self._sanitize_stem(base_name)
        lines = content.split("\n")
        if len(lines) <= self.MAX_LINES_PER_FILE:
            (dest_dir / f"{base_name}.c").write_text(content)
            return 1

        # Fonksiyon sinirlarindan bolmeye calis (} ile biten satirlar)
        chunks: list[list[str]] = []
        current_chunk: list[str] = []
        for line in lines:
            current_chunk.append(line)
            if len(current_chunk) >= self.MAX_LINES_PER_FILE:
                # Fonksiyon sinirina denk gelmeye calis
                # Son 20 satir icinde } ile biten satir ara
                split_idx = len(current_chunk)
                for i in range(len(current_chunk) - 1, max(0, len(current_chunk) - 20) - 1, -1):
                    if current_chunk[i].strip() == "}":
                        split_idx = i + 1
                        break
                chunks.append(current_chunk[:split_idx])
                current_chunk = current_chunk[split_idx:]

        if current_chunk:
            chunks.append(current_chunk)

        written = 0
        for idx, chunk in enumerate(chunks):
            suffix = f"_part{idx + 1}" if len(chunks) > 1 else ""
            fname = f"{base_name}{suffix}.c"
            (dest_dir / fname).write_text("\n".join(chunk))
            written += 1
        return written

    # ------------------------------------------------------------------
    # types.h
    # ------------------------------------------------------------------

    def _build_types_h(self, source_dir: Path, workspace) -> str:
        """types.h uret — mevcut + Ghidra undefined typedef'leri."""
        lines = [
            "#ifndef _TYPES_H_",
            "#define _TYPES_H_",
            "",
            "#include <stdint.h>",
            "#include <stddef.h>",
            "#include <stdbool.h>",
            "",
            "// ---- Ghidra undefined type definitions ----",
            "typedef uint8_t   undefined1;",
            "typedef uint16_t  undefined2;",
            "typedef uint32_t  undefined4;",
            "typedef uint64_t  undefined8;",
            "typedef void*     undefined;",
            "typedef void    (*code)(void);",
            "",
            "// ---- Ghidra pointer-sized types ----",
            "typedef intptr_t  addr;",
            "typedef uintptr_t uaddr;",
            "",
        ]

        # Mevcut types.h varsa icerigini ekle
        existing_types_h = None
        if workspace:
            typed_dir = workspace.get_stage_dir("reconstructed") / "typed"
            candidate = typed_dir / "types.h"
            if candidate.exists():
                existing_types_h = candidate
        if not existing_types_h and source_dir.parent.exists():
            candidate = source_dir.parent / "typed" / "types.h"
            if candidate.exists():
                existing_types_h = candidate

        if existing_types_h:
            lines.append("// ---- Recovered types from analysis ----")
            content = existing_types_h.read_text(errors="replace")
            # Header guard'lari kaldir, cakisma olmasin
            content = re.sub(r"#ifndef\s+\w+\s*\n#define\s+\w+\s*\n", "", content)
            content = re.sub(r"#endif\s*/\*.*?\*/\s*$", "", content, flags=re.MULTILINE)
            content = re.sub(r"#include\s+<std\w+\.h>", "", content)
            lines.append(content.strip())
            lines.append("")

        lines.append("#endif // _TYPES_H_")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Subsystem header'lari
    # ------------------------------------------------------------------

    def _build_subsystem_header(
        self, subsystem: str, func_stems: list[str],
        nodes: dict[str, dict],
    ) -> str:
        """Subsystem icin forward declaration header'i."""
        guard = f"_SUBSYSTEM_{subsystem.upper()}_H_"
        lines = [
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
            '#include "types.h"',
            "",
            f"// Forward declarations for subsystem: {subsystem}",
            "",
        ]

        # Call graph'tan fonksiyon imzalarini cikar
        declared: set[str] = set()
        for addr, node in nodes.items():
            name = node.get("name", "")
            if name in func_stems and name not in declared:
                lines.append(f"void {name}(void);  // @{node.get('address', '?')}")
                declared.add(name)

        # Call graph'ta olmayan stem'ler
        for stem in sorted(func_stems):
            if stem not in declared:
                lines.append(f"void {stem}(void);")

        lines.extend(["", f"#endif // {guard}", ""])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # IDE dosyalari
    # ------------------------------------------------------------------

    def _collect_source_paths(self, src_dir: Path, project_root: Path) -> list[str]:
        """src/ altindaki tum .c dosyalarinin relative path'lerini topla."""
        paths = []
        for f in sorted(src_dir.rglob("*.c")):
            paths.append(str(f.relative_to(project_root)))
        return paths

    def _build_cmake(self, program_name: str, sources: list[str]) -> str:
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", program_name)
        lines = [
            "cmake_minimum_required(VERSION 3.16)",
            f'project({safe_name} C)',
            "",
            "set(CMAKE_C_STANDARD 11)",
            "set(CMAKE_EXPORT_COMPILE_COMMANDS ON)",
            "",
            f"# Include directories",
            "include_directories(include)",
            "",
            "# Source files",
            "file(GLOB_RECURSE SOURCES src/*.c)",
            "",
            f"add_executable({safe_name} ${{SOURCES}})",
            "",
            "# Warnings (relaxed — decompiled code triggers many)",
            f"target_compile_options({safe_name} PRIVATE -w)",
            "",
        ]
        return "\n".join(lines)

    def _build_makefile(self, program_name: str, sources: list[str]) -> str:
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", program_name)
        lines = [
            f"TARGET = {safe_name}",
            "CC = cc",
            "CFLAGS = -std=c11 -w -Iinclude",
            "",
            "SOURCES = $(shell find src -name '*.c')",
            "OBJECTS = $(SOURCES:.c=.o)",
            "",
            "$(TARGET): $(OBJECTS)",
            "\t$(CC) $(CFLAGS) -o $@ $^",
            "",
            "%.o: %.c",
            "\t$(CC) $(CFLAGS) -c -o $@ $<",
            "",
            "clean:",
            "\trm -f $(OBJECTS) $(TARGET)",
            "",
            ".PHONY: clean",
            "",
        ]
        return "\n".join(lines)

    def _build_compile_commands(self, sources: list[str], project_root: Path) -> str:
        entries = []
        root_str = str(project_root)
        for src in sources:
            entries.append({
                "directory": root_str,
                "command": f"cc -std=c11 -w -Iinclude -c {src}",
                "file": src,
            })
        return json.dumps(entries, indent=2) + "\n"

    def _build_vscode_settings(self) -> str:
        settings = {
            "files.associations": {"*.c": "c", "*.h": "c"},
            "C_Cpp.default.cStandard": "c11",
            "editor.formatOnSave": False,
            "clangd.path": "clangd",
            "clangd.arguments": ["--compile-commands-dir=${workspaceFolder}"],
        }
        return json.dumps(settings, indent=2) + "\n"

    def _build_cpp_properties(self, project_root: Path) -> str:
        props = {
            "configurations": [{
                "name": "Mac",
                "includePath": ["${workspaceFolder}/include"],
                "defines": [],
                "compilerPath": "/usr/bin/cc",
                "cStandard": "c11",
                "intelliSenseMode": "macos-clang-arm64",
            }],
            "version": 4,
        }
        return json.dumps(props, indent=2) + "\n"

    def _build_clangd_config(self) -> str:
        return (
            "CompileFlags:\n"
            "  Add:\n"
            "    - -std=c11\n"
            "    - -w\n"
            "    - -Iinclude\n"
            "  Compiler: clang\n"
            "\n"
            "Diagnostics:\n"
            "  Suppress: '*'\n"
        )

    # ------------------------------------------------------------------
    # Analysis dosyalari
    # ------------------------------------------------------------------

    def _build_call_graph_dot(self, nodes: dict[str, dict], edges: list[dict]) -> str:
        """Call graph'tan Graphviz DOT dosyasi uret."""
        lines = [
            "digraph call_graph {",
            "  rankdir=LR;",
            '  node [shape=box, fontsize=10, style=filled, fillcolor="#f0f0f0"];',
            '  edge [color="#666666"];',
        ]

        # Node'lar (max 500)
        count = 0
        for addr, node in nodes.items():
            if count >= 500:
                break
            name = node.get("name", "unknown")
            address = node.get("address", addr)
            safe = name.replace('"', '\\"')
            label = f"{safe}\\n0x{address}"
            lines.append(f'  "{safe}" [label="{label}"];')
            count += 1

        # Edge'ler (max 2000)
        for edge in edges[:2000]:
            src, dst = self._get_edge_endpoints(edge)
            src = src.replace('"', '\\"')
            dst = dst.replace('"', '\\"')
            if src and dst:
                lines.append(f'  "{src}" -> "{dst}";')

        lines.append("}")
        return "\n".join(lines)

    def _build_algorithm_report(self, algo_result) -> str:
        """confidence > 0.6 olan algoritmalarin raporunu uret."""
        lines = ["# Detected Algorithms\n"]

        by_cat: dict[str, list] = {}
        for algo in algo_result.algorithms:
            if algo.confidence < 0.6:
                continue
            by_cat.setdefault(algo.category, []).append(algo)

        if not by_cat:
            lines.append("_No algorithms detected with confidence > 60%._\n")
            return "\n".join(lines)

        for cat, algos in sorted(by_cat.items()):
            lines.append(f"## {cat.replace('_', ' ').title()}\n")
            for algo in sorted(algos, key=lambda a: -a.confidence):
                conf_pct = f"{algo.confidence * 100:.0f}%"
                lines.append(f"### {algo.name} ({conf_pct})")
                lines.append(f"- **Function:** `{algo.function_name}`")
                lines.append(f"- **Detection:** {algo.detection_method}")
                if hasattr(algo, "evidence") and algo.evidence:
                    lines.append("- **Evidence:**")
                    for ev in algo.evidence:
                        lines.append(f"  - {ev}")
                lines.append("")

        return "\n".join(lines)

    def _build_xref_index(self, nodes: dict[str, dict]) -> str:
        """Fonksiyon cross-reference tablosu."""
        lines = [
            "# Cross-Reference Index\n",
            "| Function | Address | Callers | Callees |",
            "|----------|---------|---------|---------|",
        ]

        for addr in sorted(nodes.keys()):
            node = nodes[addr]
            name = node.get("name", "?")
            address = node.get("address", addr)
            caller_count = node.get("caller_count", 0)
            callee_count = node.get("callee_count", 0)
            callers = ", ".join(
                c.get("name", "?") for c in node.get("callers", [])[:5]
            )
            if caller_count > 5:
                callers += f" (+{caller_count - 5})"
            callees = ", ".join(
                c.get("name", "?") for c in node.get("callees", [])[:5]
            )
            if callee_count > 5:
                callees += f" (+{callee_count - 5})"
            lines.append(
                f"| `{name}` | 0x{address} | {callers or '-'} | {callees or '-'} |"
            )

        lines.append(f"\n_Total: {len(nodes)} functions._\n")
        return "\n".join(lines)

    def _build_subsystem_map(
        self, func_subsystem: dict[str, str], active_subsystems: set[str],
    ) -> str:
        """Subsystem <-> fonksiyon esleme raporu."""
        lines = ["# Subsystem Map\n"]

        # Subsystem basina fonksiyonlar
        by_subsys: dict[str, list[str]] = defaultdict(list)
        for func, subsys in func_subsystem.items():
            by_subsys[subsys].append(func)

        for subsys in sorted(active_subsystems):
            funcs = sorted(by_subsys.get(subsys, []))
            lines.append(f"## {subsys} ({len(funcs)} functions)\n")
            for f in funcs[:50]:
                lines.append(f"- `{f}`")
            if len(funcs) > 50:
                lines.append(f"- _... and {len(funcs) - 50} more_")
            lines.append("")

        # Ozet tablosu
        lines.append("## Summary\n")
        lines.append("| Subsystem | Count |")
        lines.append("|-----------|-------|")
        for subsys in sorted(active_subsystems):
            count = len(by_subsys.get(subsys, []))
            lines.append(f"| {subsys} | {count} |")
        lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # README
    # ------------------------------------------------------------------

    def _build_readme(
        self,
        program_name: str,
        c_files_count: int,
        subsystems: list[str],
        functions_merged: int,
        algorithm_results=None,
    ) -> str:
        lines = [
            f"# {program_name} -- Reverse Engineered Project",
            "",
            "Auto-generated by **Karadul** reverse engineering pipeline.",
            "Decompiled source organized for IDE browsing and analysis.",
            "",
            "## Statistics",
            "",
            f"- **Decompiled functions:** {c_files_count}",
            f"- **Subsystems detected:** {len(subsystems)}",
            f"- **Small functions merged:** {functions_merged}",
        ]

        if algorithm_results and hasattr(algorithm_results, "algorithms"):
            high_conf = sum(1 for a in algorithm_results.algorithms if a.confidence >= 0.6)
            lines.append(f"- **Algorithms detected:** {high_conf} (confidence >= 60%)")

        lines.extend([
            "",
            "## Subsystems",
            "",
        ])
        for s in subsystems:
            lines.append(f"- `{s}`")

        lines.extend([
            "",
            "## Directory Structure",
            "",
            "```",
            "include/          -- Type definitions and subsystem headers",
            "src/",
            "  main.c          -- Entry point functions",
            "  subsystem_*/    -- Grouped by API usage (network, crypto, ...)",
            "  misc/           -- Uncategorized + merged thunks",
            "analysis/",
            "  call_graph.dot  -- Graphviz call graph",
            "  algorithms.md   -- Detected algorithm patterns",
            "  xref_index.md   -- Function cross-reference table",
            "  subsystem_map.md-- Subsystem <-> function mapping",
            "```",
            "",
            "## IDE Setup",
            "",
            "- **VSCode:** Open folder, clangd extension auto-configures",
            "- **CLion:** Open CMakeLists.txt as project",
            "- **Other:** `compile_commands.json` provides clangd integration",
            "",
            "## Warning",
            "",
            "This is **auto-decompiled** code. Variable names, types and comments",
            "are heuristically generated and may not match the original source.",
            "",
        ])
        return "\n".join(lines)
