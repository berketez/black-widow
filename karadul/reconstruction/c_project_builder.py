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
      main.c                 -- entry point fonksiyonlari (varsa)
      subsystem_<ad>/        -- API kuralı ya da çağrı grafı topluluğu
        <fonksiyon>.c        -- dosya başına bir fonksiyon
        thunks_and_stubs.c   -- kısa fonksiyonlar tek dosyada
    analysis/
      call_graph.dot / algorithms.md / xref_index.md / subsystem_map.md

Değişmezler (2026-11-10 çıktı sağlamlığı denetimi, kusur 2 ve 14):
  * Girdideki her fonksiyon (kaynak dosya) çıktıda tam bir kez yer alır.
    Dosya adları harf duyarsız dosya sisteminde de çakışmaz. Kurucu bunu
    sonunda defterinden ve diskten denetler; ihlali `errors` listesine yazar
    ve `success=False` döner.
  * Yerleşim (alt sistem dizini, dosya adı) yalnız girdinin içeriğine
    bağlıdır; girdi sırasına ve PYTHONHASHSEED'e bağlı değildir.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import zlib
from collections import Counter, defaultdict
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

# Eşit puanda alt sistem seçimi: kural tablosundaki sıra (girdi sırası değil).
_SUBSYSTEM_ORDER: dict[str, int] = {
    name: idx for idx, (name, _apis) in enumerate(_SUBSYSTEM_RULES)
}

# ---------------------------------------------------------------------------
# Entry point tespiti
# ---------------------------------------------------------------------------

_ENTRY_NAMES = frozenset({
    "main", "_main", "entry", "_entry", "start", "_start",
    "WinMain", "DllMain", "module_init", "_mod_init_func",
})

# Ghidra thunk fonksiyon pattern'i
_THUNK_RE = re.compile(r"^thunk_", re.IGNORECASE)

# Dosya adi sanitization icin guvenli olmayan karakterler
_UNSAFE_FILENAME_RE = re.compile(r'[^a-zA-Z0-9_\-.]')

# Art arda noktalar ("..") dosya adında kalmaz.
_DOT_RUN_RE = re.compile(r'\.{2,}')

# Kaynak dosya başlığındaki adres satırı (ghidra/headless.py yazar). Çakışan
# dosya adlarını ayırt eden ek buradan alınır.
_ADDRESS_HEADER_RE = re.compile(r"^// Address:\s+(\S+)\s*$", re.MULTILINE)

# Dosya adı gövdesinin (uzantısız) en çok uzunluğu. Dosya sistemi sınırı 255
# bayt; adres eki, sıra eki ve `.c` için pay kalır. ghidra/headless.py
# fonksiyon adını aynı uzunlukta keser.
_MAX_FILE_STEM_LEN = 200

# Kurucunun kendi yazdığı kaynak dosyaları; fonksiyon dosyaları bu adları alamaz.
_ENTRY_FILE_STEM = "main"
_MERGED_FILE_STEM = "thunks_and_stubs"
_RESERVED_FILE_STEM_RE = re.compile(
    r"^(?:%s|%s(?:_part\d+)?)$" % (_ENTRY_FILE_STEM, _MERGED_FILE_STEM)
)
# Birleşik dosyanın (ve her parçasının) başlığı.
_MERGED_BANNER = (
    "// ==========================================================\n"
    "// Thunks, stubs and small wrapper functions (auto-merged)\n"
    "// ==========================================================\n\n"
)

# Adres eki bundan uzunsa (beklenmeyen başlık) özet eki kullanılır.
_MAX_ADDRESS_SUFFIX_LEN = 32
# Başlıkta adres yoksa kullanılan özet ekinin (sha1, onaltılık) uzunluğu.
_HASH_SUFFIX_LEN = 8

# Hata iletisinde örnek olarak adı yazılan fonksiyon sayısı.
_ERROR_EXAMPLE_LIMIT = 5

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
    # Değişmez denetimi: girdideki fonksiyon (kaynak dosya) sayısı; çıktıda
    # tam bir kez yer alan, hiç yer almayan ve birden çok yer alan sayıları.
    functions_total: int = 0
    functions_placed: int = 0
    functions_missing: int = 0
    functions_duplicated: int = 0


class _BuildLedger:
    """Bir kurulumda yazılan dosyaların ve fonksiyon yerleşiminin defteri.

    Yollar harf katlanmış (casefold) anahtarla tutulur: yalnız harf
    büyüklüğüyle ayrılan iki ad aynı dosya sayılır. Böylece güvence,
    kurulumun yapıldığı dosya sisteminin harf duyarlılığına bağlı kalmaz.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        # casefold(göreli yol) -> diske yazılan göreli yol
        self.files: dict[str, str] = {}
        # casefold(göreli yol) -> o yola her yazışta konan birimler
        self.file_units: dict[str, list[tuple[str, ...]]] = defaultdict(list)
        # birim anahtarı -> yazıldığı göreli yollar
        self.placements: dict[str, list[str]] = defaultdict(list)

    def write(self, path: Path, text: str, units: tuple[str, ...] = ()) -> None:
        """Dosyayı yaz; `units` bu dosyaya konan fonksiyonların anahtarlarıdır."""
        rel = path.relative_to(self.root).as_posix()
        key = rel.casefold()
        path.write_text(text)
        self.files[key] = rel
        if units:
            self.file_units[key].append(units)
            for unit in units:
                self.placements[unit].append(rel)

    @property
    def files_written(self) -> int:
        """Diskteki ayrı dosya sayısı (aynı yola iki yazış bir sayılır)."""
        return len(self.files)


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
        functions_merged = 0

        output_dir.mkdir(parents=True, exist_ok=True)
        ledger = _BuildLedger(output_dir)

        # -- C dosyalarini topla -------------------------------------------
        c_files = sorted(source_dir.rglob("*.c"))
        if not c_files:
            return CProjectBuildResult(success=False, errors=["C dosyasi bulunamadi"])

        # Her kaynak dosya bir birimdir (bir fonksiyon). Sözlükler birim
        # anahtarıyla tutulur: anahtar dosya gövdesidir (stem); aynı gövde alt
        # dizinlerde yinelenirse göreli yol anahtar olur, hiçbir dosya ötekini ezmez.
        file_contents: dict[str, str] = {}   # birim anahtarı -> content
        file_lines: dict[str, int] = {}      # birim anahtarı -> line count
        for cf, stem in self._unit_keys(c_files, source_dir):
            content = cf.read_text(errors="replace")
            file_contents[stem] = content
            file_lines[stem] = content.count("\n") + 1

        # -- Call graph yukle -----------------------------------------------
        call_graph = self._load_call_graph(workspace)
        nodes: dict[str, dict] = call_graph.get("nodes", {}) if call_graph else {}
        edges: list[dict] = call_graph.get("edges", []) if call_graph else []
        program_name = call_graph.get("program", "unknown") if call_graph else "unknown"

        # -- Subsystem siniflandirma ----------------------------------------
        # func_name -> subsystem. Düğümler anahtar (adres) sırasıyla dolaşılır:
        # aynı adı taşıyan birden çok düğümde sonuç girdi sırasına bağlı kalmaz.
        func_subsystem: dict[str, str] = {}
        for _addr, node in sorted(nodes.items(), key=lambda item: item[0]):
            name = node.get("name", "")
            callees = node.get("callees", [])
            subsys = self._classify_subsystem(name, callees)
            func_subsystem[name] = subsys

        # Dosya stem'lerini de siniflandir (call graph'ta olmayanlari dahil)
        for stem in file_contents:
            if self._unit_name(stem) not in func_subsystem:
                func_subsystem[self._unit_name(stem)] = "misc"

        # -- Community-based fallback (misc fonksiyonlar icin) ---------------
        if call_graph:
            community_map = self._detect_communities(call_graph)
            for fname, subsys in list(func_subsystem.items()):
                if subsys == "misc" and fname in community_map:
                    func_subsystem[fname] = community_map[fname]

        # -- Entry point'leri ayir ------------------------------------------
        entry_stems: list[str] = []
        for stem in file_contents:
            name = self._unit_name(stem)
            if name in _ENTRY_NAMES or name.lower() in {"main", "_main", "entry"}:
                entry_stems.append(stem)

        # -- Kucuk fonksiyon tespiti ----------------------------------------
        small_funcs: dict[str, list[str]] = defaultdict(list)  # subsystem -> [stem, ...]
        normal_funcs: dict[str, list[str]] = defaultdict(list)  # subsystem -> [stem, ...]

        for stem, content in file_contents.items():
            if stem in entry_stems:
                continue  # entry point'ler ayri
            lines = file_lines[stem]
            name = self._unit_name(stem)
            subsys = func_subsystem.get(name, "misc")
            is_thunk = bool(_THUNK_RE.match(name))
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
            ledger.write(
                src_dir / f"{_ENTRY_FILE_STEM}.c", "".join(main_parts),
                tuple(entry_stems),
            )

        # -- 2. Subsystem dizinleri ve dosyalari ----------------------------
        # Dosya adları proje genelinde ve harf duyarsız olarak benzersiz atanır.
        file_stems = self._assign_file_stems(
            [stem for stems in normal_funcs.values() for stem in stems],
            file_contents,
        )
        for subsys in sorted(active_subsystems):
            subsys_dir = src_dir / f"subsystem_{subsys}"
            subsys_dir.mkdir(exist_ok=True)

            # Normal (buyuk) fonksiyonlar: dosya başına bir fonksiyon. Fonksiyon
            # bölünmez; uzun fonksiyon da tek dosyaya yazılır.
            for stem in normal_funcs.get(subsys, []):
                ledger.write(
                    subsys_dir / f"{file_stems[stem]}.c", file_contents[stem],
                    (stem,),
                )

            # Kucuk fonksiyonlar (thunk + stub) -> tek dosyada birlestirilir
            smalls = small_funcs.get(subsys, [])
            if smalls:
                functions_merged += len(smalls)
                self._write_merged_files(subsys_dir, smalls, file_contents, ledger)

        # -- 3. types.h ------------------------------------------------------
        types_content = self._build_types_h(source_dir, workspace)
        ledger.write(include_dir / "types.h", types_content)

        # -- 4. Subsystem header'lari ----------------------------------------
        for subsys in sorted(active_subsystems):
            header = self._build_subsystem_header(
                subsys,
                [
                    self._unit_name(stem)
                    for stem in normal_funcs.get(subsys, []) + small_funcs.get(subsys, [])
                ],
                nodes,
            )
            ledger.write(include_dir / f"subsystem_{subsys}.h", header)

        # -- 5. IDE dosyalari -------------------------------------------------
        all_c_sources = self._collect_source_paths(src_dir, output_dir)

        cmake = self._build_cmake(program_name, all_c_sources)
        ledger.write(output_dir / "CMakeLists.txt", cmake)

        makefile = self._build_makefile(program_name, all_c_sources)
        ledger.write(output_dir / "Makefile", makefile)

        compile_cmds = self._build_compile_commands(all_c_sources, output_dir)
        ledger.write(output_dir / "compile_commands.json", compile_cmds)

        vscode_settings = self._build_vscode_settings()
        ledger.write(vscode_dir / "settings.json", vscode_settings)

        cpp_props = self._build_cpp_properties(output_dir)
        ledger.write(vscode_dir / "c_cpp_properties.json", cpp_props)

        clangd = self._build_clangd_config()
        ledger.write(output_dir / ".clangd", clangd)

        # -- 6. Analysis dosyalari -------------------------------------------
        # call_graph.dot
        if call_graph:
            try:
                dot = self._build_call_graph_dot(nodes, edges)
                ledger.write(analysis_dir / "call_graph.dot", dot)
            except Exception as exc:
                errors.append(f"Call graph DOT hatasi: {exc}")

        # algorithms.md
        if algorithm_results and hasattr(algorithm_results, "algorithms"):
            algos_md = self._build_algorithm_report(algorithm_results)
            ledger.write(analysis_dir / "algorithms.md", algos_md)

        # xref_index.md
        if nodes:
            xref = self._build_xref_index(nodes)
            ledger.write(analysis_dir / "xref_index.md", xref)

        # subsystem_map.md
        if func_subsystem:
            smap = self._build_subsystem_map(func_subsystem, active_subsystems)
            ledger.write(analysis_dir / "subsystem_map.md", smap)

        # -- 7. README.md ----------------------------------------------------
        readme = self._build_readme(
            program_name=program_name,
            c_files_count=len(c_files),
            subsystems=sorted(active_subsystems),
            functions_merged=functions_merged,
            algorithm_results=algorithm_results,
        )
        ledger.write(output_dir / "README.md", readme)

        # -- 8. Değişmez denetimi --------------------------------------------
        # Girdideki her fonksiyon çıktıda tam bir kez yer almalı. İhlal sessiz
        # kalmaz: hata listesine yazılır ve kurulum başarısız sayılır.
        missing, duplicated, invariant_errors = self._check_placement(
            file_contents, ledger, src_dir,
        )
        for message in invariant_errors:
            logger.error("C project build: %s", message)
        errors.extend(invariant_errors)

        files_written = ledger.files_written
        logger.info(
            "C project built: %d dosya, %d subsystem, %d merged -> %s",
            files_written, len(active_subsystems), functions_merged, output_dir,
        )

        return CProjectBuildResult(
            success=files_written > 0 and not invariant_errors,
            files_written=files_written,
            subsystems_found=len(active_subsystems),
            functions_merged=functions_merged,
            errors=errors,
            functions_total=len(file_contents),
            functions_placed=len(file_contents) - len(missing) - len(duplicated),
            functions_missing=len(missing),
            functions_duplicated=len(duplicated),
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

        Baştaki ve sondaki `_` korunur: `_exit` ile `exit` ayrı fonksiyonlardır
        ve ayrı dosya adı almalıdır (eski kod `_` karakterlerini de siliyor,
        ikisini aynı dosyaya yazıyordu). Yalnız noktalar kırpılır (gizli dosya,
        `..`). Sonuç tek başına benzersizlik güvencesi vermez; onu
        `_assign_file_stems` sağlar.
        """
        safe = _UNSAFE_FILENAME_RE.sub('_', stem)
        safe = _DOT_RUN_RE.sub('.', safe).strip('.')
        if not any(ch.isalnum() for ch in safe):
            return 'unnamed'
        return safe

    # ------------------------------------------------------------------
    # Birim anahtarları ve çakışmasız dosya adları
    # ------------------------------------------------------------------

    @staticmethod
    def _unit_keys(c_files: list[Path], source_dir: Path) -> list[tuple[Path, str]]:
        """Her kaynak dosyaya benzersiz bir birim anahtarı ver.

        Anahtar dosya gövdesidir. Aynı gövde birden çok dizinde varsa en üst
        dizindeki gövdeyi, ötekiler göreli yolu (uzantısız) anahtar alır.
        Göreli yol `/` içerir, gövde içermez; anahtarlar çakışamaz.
        """
        stem_count = Counter(cf.stem for cf in c_files)
        keyed: list[tuple[Path, str]] = []
        for cf in c_files:
            if stem_count[cf.stem] == 1 or cf.parent == source_dir:
                key = cf.stem
            else:
                key = cf.relative_to(source_dir).with_suffix("").as_posix()
            keyed.append((cf, key))
        return keyed

    @staticmethod
    def _unit_name(key: str) -> str:
        """Birim anahtarından fonksiyon adını (dosya gövdesini) çıkar."""
        return key.rsplit("/", 1)[-1]

    @staticmethod
    def _disambiguator(key: str, content: str) -> str:
        """Çakışan dosya adını ayırt eden belirlenimci ek.

        Kaynak başlığındaki adres; başlık yoksa birim anahtarının özeti.
        """
        match = _ADDRESS_HEADER_RE.search(content)
        if match:
            address = _UNSAFE_FILENAME_RE.sub('_', match.group(1)).strip('._')
            if 0 < len(address) <= _MAX_ADDRESS_SUFFIX_LEN:
                return address
        digest = hashlib.sha1(key.encode("utf-8", "surrogatepass")).hexdigest()
        return digest[:_HASH_SUFFIX_LEN]

    def _assign_file_stems(
        self, keys: list[str], file_contents: dict[str, str],
    ) -> dict[str, str]:
        """Her birime proje genelinde benzersiz bir dosya adı gövdesi ata.

        Benzersizlik harf duyarsızdır (macOS ve Windows dosya sistemleri) ve
        kurucunun kendi dosya adlarını (`main`, `thunks_and_stubs`) dışlar.

        1. Adı temizlenince değişmeyen birimler, anahtar sırasıyla kendi
           adlarını alır.
        2. Kalanlar (adı değişen, kesilen ya da adı alınmış olanlar) temizlenmiş
           adı boşsa onu, değilse adres ekli hâlini alır; o da doluysa sıra
           numarası eklenir.

        Sonuç yalnız anahtar kümesine ve içeriğe bağlıdır; `keys` sırasına ve
        karma tohumuna bağlı değildir.
        """
        assigned: dict[str, str] = {}
        taken: set[str] = set()

        def is_free(candidate: str) -> bool:
            folded = candidate.casefold()
            return folded not in taken and not _RESERVED_FILE_STEM_RE.match(folded)

        def take(key: str, candidate: str) -> None:
            assigned[key] = candidate
            taken.add(candidate.casefold())

        pending: list[tuple[str, str]] = []
        for key in sorted(set(keys)):
            safe = self._sanitize_stem(key)
            if safe == key and len(safe) <= _MAX_FILE_STEM_LEN and is_free(safe):
                take(key, safe)
            else:
                pending.append((key, safe))

        for key, safe in pending:
            if len(safe) <= _MAX_FILE_STEM_LEN and is_free(safe):
                take(key, safe)
                continue
            suffix = self._disambiguator(key, file_contents.get(key, ""))
            base = safe[:_MAX_FILE_STEM_LEN - len(suffix) - 1]
            candidate = f"{base}_{suffix}"
            ordinal = 1
            while not is_free(candidate):
                ordinal += 1
                candidate = f"{base}_{suffix}_{ordinal}"
            take(key, candidate)

        return assigned

    def _check_placement(
        self, units: dict[str, str], ledger: _BuildLedger, src_dir: Path,
    ) -> tuple[list[str], list[str], list[str]]:
        """Değişmezi denetle: her birim çıktıda tam bir kez yer alır.

        Defter çokluğu verir (bir birim kaç dosyaya kondu, bir yola kaç kez
        yazıldı); disk varlığı verir (dosya yerinde mi, içerik içinde mi).
        `src/` altında bu kurulumun yazmadığı kaynak dosya da ihlaldir: aynı
        fonksiyon eski bir kurulumdan kalan dosyada ikinci kez durabilir.

        Returns:
            (eksik birimler, birden çok yerleşen birimler, hata iletileri)
        """
        on_disk: set[str] = set()
        for file_key in sorted(ledger.file_units):
            try:
                text = (ledger.root / ledger.files[file_key]).read_text(errors="replace")
            except OSError:
                continue
            # Aynı yola birden çok yazış olduysa yalnız sonuncusu diskte kalır.
            for unit in ledger.file_units[file_key][-1]:
                if units.get(unit, "").rstrip() in text:
                    on_disk.add(unit)

        missing: list[str] = []
        duplicated: list[str] = []
        for key in sorted(units):
            placed = len(ledger.placements.get(key, ()))
            if placed > 1:
                duplicated.append(key)
            elif placed == 0 or key not in on_disk:
                missing.append(key)

        stray = sorted(
            rel for rel in (
                path.relative_to(ledger.root).as_posix()
                for path in src_dir.rglob("*.c")
            )
            if rel.casefold() not in ledger.file_units
        )

        def examples(names: list[str]) -> str:
            shown = ", ".join(names[:_ERROR_EXAMPLE_LIMIT])
            return shown + (", ..." if len(names) > _ERROR_EXAMPLE_LIMIT else "")

        messages: list[str] = []
        if missing:
            messages.append(
                "Değişmez ihlali: %d fonksiyon çıktıda yok (%s)"
                % (len(missing), examples(missing))
            )
        if duplicated:
            messages.append(
                "Değişmez ihlali: %d fonksiyon çıktıda birden çok kez var (%s)"
                % (len(duplicated), examples(duplicated))
            )
        if stray:
            messages.append(
                "Değişmez ihlali: src/ altında bu kurulumun yazmadığı %d kaynak "
                "dosya var (%s)" % (len(stray), examples(stray))
            )
        return missing, duplicated, messages

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

        # Eşit puanda kural tablosundaki sıra kazanır; çağrılanların girdideki
        # sırası sonucu değiştirmez.
        return min(
            subsystem_scores,
            key=lambda subsys: (-subsystem_scores[subsys], _SUBSYSTEM_ORDER[subsys]),
        )

    # ------------------------------------------------------------------
    # Community detection (label propagation)
    # ------------------------------------------------------------------

    def _detect_communities(self, call_graph: dict) -> dict[str, str]:
        """Call graph'tan label propagation ile community tespit et.

        Undirected adjacency list olusturulur, her node kendi label'iyla
        baslar, iteratif olarak komsu cogunlugunun label'ini alir.
        3'ten az uyeli community'ler filtrelenir.

        Sonuç belirlenimcidir: yalnız kenar kümesine bağlıdır; kenarların
        girdideki sırasına ve PYTHONHASHSEED'e bağlı değildir. Düğümler ada
        göre sıralı dolaşılır; komşu etiketlerinde eşitlik `_pick_label` ile,
        eşit büyüklükteki toplulukların numarası etiket adıyla bozulur.

        Returns:
            {func_name: "group_N"} eslesmesi. Community'ye atanamayanlar
            sonucta yer almaz.
        """
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
                    majority = self._pick_label(node, neighbor_labels)
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
        # Numara büyüklük sırasıyla verilir; eşit büyüklükte etiket adı belirler
        # (yalnız büyüklükle sıralanınca eşitlikte girdi sırası belirliyordu).
        result: dict[str, str] = {}
        group_id = 0
        for label, members in sorted(
            community_members.items(), key=lambda x: (-len(x[1]), x[0]),
        ):
            if len(members) >= 3:
                group_name = "group_%d" % group_id
                for m in members:
                    result[m] = group_name
                group_id += 1

        return result

    @staticmethod
    def _pick_label(node: str, neighbor_labels: Counter) -> str:
        """Komşu etiketlerinden çoğunluğu seç; eşitliği belirlenimci boz.

        Eski kod `most_common(1)` ile eşitlikte sayaca ilk gireni alıyordu;
        sayaç bir `set` dolaşımıyla dolduğu için seçim PYTHONHASHSEED'e bağlıydı
        (aynı girdiyle koşudan koşuya farklı `subsystem_group_N` dizinleri).

        Eşitlik, (düğüm, etiket) çiftinin CRC32'siyle bozulur: sonuç her koşuda
        aynıdır, ama alfabetik olarak küçük etiketleri kayırmaz. "En küçük
        etiket" kuralı denendi ve seçilmedi: etiketi grafın bir ucundan yayıp
        toplulukları büyütüyordu (Debian coreutils/ls, 412 düğüm: en büyük
        topluluk o kuralla 336, CRC ile 60; eski kodda tohuma göre 69–288).
        """
        top = max(neighbor_labels.values())
        tied = [label for label, count in neighbor_labels.items() if count == top]
        if len(tied) == 1:
            return tied[0]
        return min(
            tied,
            key=lambda label: (zlib.crc32(f"{node}\0{label}".encode("utf-8", "surrogatepass")), label),
        )

    # ------------------------------------------------------------------
    # Dosya yazma yardimcilari
    # ------------------------------------------------------------------

    def _write_merged_files(
        self, dest_dir: Path, stems: list[str],
        file_contents: dict[str, str], ledger: _BuildLedger,
    ) -> None:
        """Küçük fonksiyonları birleştirip `thunks_and_stubs*.c` olarak yaz.

        Birleşik içerik MAX_LINES_PER_FILE satırı aşarsa parçalara ayrılır;
        kesim yalnız iki fonksiyonun arasından yapılır. Eski kod satır sayısına
        göre kesiyor, bir fonksiyonun gövdesini iki dosyaya bölebiliyordu
        (başlıksız `_partN.c` dosyaları).
        """
        banner_lines = _MERGED_BANNER.count("\n")
        parts: list[list[str]] = [[]]
        part_lines = banner_lines
        for stem in sorted(stems):
            # `_merge_small_functions` bloğu: ad satırı + içerik + boş satır
            lines = file_contents.get(stem, "").rstrip().count("\n") + 3
            if parts[-1] and part_lines + lines > self.MAX_LINES_PER_FILE:
                parts.append([])
                part_lines = banner_lines
            parts[-1].append(stem)
            part_lines += lines

        for idx, part in enumerate(parts):
            suffix = f"_part{idx + 1}" if len(parts) > 1 else ""
            ledger.write(
                dest_dir / f"{_MERGED_FILE_STEM}{suffix}.c",
                self._merge_small_functions(part, file_contents),
                tuple(part),
            )

    def _merge_small_functions(
        self, stems: list[str], file_contents: dict[str, str],
    ) -> str:
        """Kucuk fonksiyonlari tek string'de birlestirilmis content olarak dondur."""
        parts = [_MERGED_BANNER]
        for stem in sorted(stems):
            content = file_contents.get(stem, "")
            parts.append(f"// --- {stem} ---\n")
            parts.append(content.rstrip())
            parts.append("\n\n")
        return "".join(parts)

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

        # Call graph'tan fonksiyon imzalarini cikar (adres sırasıyla)
        declared: set[str] = set()
        wanted = set(func_stems)
        for addr, node in sorted(nodes.items(), key=lambda item: item[0]):
            name = node.get("name", "")
            if name in wanted and name not in declared:
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
            "include/                -- Type definitions and subsystem headers",
            "src/",
            "  main.c                -- Entry point functions (when detected)",
            "  subsystem_<name>/     -- Grouped by API usage (network, crypto, ...)",
            "                           or by call-graph community (group_N);",
            "                           subsystem_misc holds the uncategorized",
            "    <function>.c        -- One function per file",
            "    thunks_and_stubs.c  -- Short functions and thunks, merged",
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
