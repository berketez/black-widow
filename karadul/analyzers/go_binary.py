"""Go binary analiz modulu.

Go binary'ler isim kurtarma icin EN KOLAY hedef:
- GOPCLNTAB: Fonksiyon isimleri, dosya yollari, satir numaralari
- BUILDINFO: Go versiyonu, modul listesi, dependency tree
- Type descriptors: Tum struct ve interface tanimlari
- Goroutine analizi: Concurrent yapi kurtarma

Go binary'leri STRIP edilse bile GOPCLNTAB genelde kalir.

Strateji:
1. 'go tool objdump' veya 'strings' ile GOPCLNTAB parse
2. 'go version -m' ile BUILDINFO section -> Go versiyonu, modul listesi
3. strings + regex ile type descriptor -> struct/interface tanimlari
4. Symbol pattern analizi -> goroutine entry point tespiti

Fallback zinciri:
  go tool objdump -> nm -> strings + regex
Her adimda bir onceki basarisiz olursa sonraki denenir.
Go kurulu olmasa bile strings/nm ile %70+ isim kurtarma mumkun.
"""

from __future__ import annotations

import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any

from karadul.analyzers import register_analyzer
from karadul.analyzers.base import BaseAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Go binary tanimlama pattern'leri
# --------------------------------------------------------------------------

# GOPCLNTAB magic bytes (Go 1.2+): 0xFB 0xFF 0xFF 0xFF 0x00 0x00
_GOPCLNTAB_MAGIC_12 = b"\xfb\xff\xff\xff\x00\x00"
# Go 1.16+: 0xFA 0xFF 0xFF 0xFF 0x00 0x00
_GOPCLNTAB_MAGIC_116 = b"\xfa\xff\xff\xff\x00\x00"
# Go 1.18+: 0xF0 0xFF 0xFF 0xFF 0x00 0x00
_GOPCLNTAB_MAGIC_118 = b"\xf0\xff\xff\xff\x00\x00"
# Go 1.20+: 0xF1 0xFF 0xFF 0xFF 0x00 0x00
_GOPCLNTAB_MAGIC_120 = b"\xf1\xff\xff\xff\x00\x00"

_GOPCLNTAB_MAGICS = [
    _GOPCLNTAB_MAGIC_120,
    _GOPCLNTAB_MAGIC_118,
    _GOPCLNTAB_MAGIC_116,
    _GOPCLNTAB_MAGIC_12,
]

# Go binary icinde bulunmasi beklenen runtime string'leri
_GO_RUNTIME_SIGNATURES = [
    "runtime.gopanic",
    "runtime.goexit",
    "runtime.main",
    "runtime.newproc",
    "runtime/internal",
    "go.buildid",
]

# Go fonksiyon ismi pattern'i: package.Function veya package.(*Type).Method
_GO_FUNC_PATTERN = re.compile(
    r"^([a-zA-Z0-9_]+(?:/[a-zA-Z0-9_.\-]+)*)"  # package path
    r"\."                                         # separator
    r"(\(?\*?[a-zA-Z_][a-zA-Z0-9_]*\)?)?"       # optional type
    r"\.?"
    r"([a-zA-Z_][a-zA-Z0-9_]*)$"                 # function/method name
)

# Go dosya yolu pattern'i (GOPCLNTAB'dan gelen)
_GO_FILE_PATTERN = re.compile(
    r"^(?:/[a-zA-Z0-9_.@\-]+)+\.go$"
    r"|^[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-/]+\.go$"
)

# Go type descriptor pattern'leri
_GO_TYPE_PATTERNS = {
    "struct": re.compile(r"^(?:main|[a-zA-Z0-9_/]+)\.([A-Z][a-zA-Z0-9_]*)$"),
    "interface": re.compile(r"^(?:main|[a-zA-Z0-9_/]+)\.([A-Z][a-zA-Z0-9_]*)$"),
    "method_set": re.compile(
        r"^(?:main|[a-zA-Z0-9_/]+)\.\(\*([A-Z][a-zA-Z0-9_]*)\)\.([a-zA-Z_][a-zA-Z0-9_]*)$"
    ),
}

# Goroutine entry point pattern'leri
_GOROUTINE_PATTERNS = [
    re.compile(r"^(.+)\.func\d+$"),         # anonymous goroutine (closure)
    re.compile(r"^(.+)\.\(\*\w+\)\.\w+$"),  # method goroutine
]

# BUILDINFO magic string
_BUILDINFO_MAGIC = b"\xff Go buildinf:"


@register_analyzer(TargetType.GO_BINARY)
class GoBinaryAnalyzer(BaseAnalyzer):
    """Go binary analiz motoru.

    Go binary'lerin icindeki zengin metadata'yi cikarir:
    - GOPCLNTAB: Fonksiyon isimleri + dosya yollari + satir numaralari
    - BUILDINFO: Go versiyonu + modul adi + dependency listesi
    - Type descriptors: Struct ve interface tanimlari
    - Goroutine entry point'leri

    Fallback zinciri sayesinde Go kurulu olmasa bile
    strings/nm ile calismaya devam eder.
    """

    supported_types = [TargetType.GO_BINARY]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.runner = SubprocessRunner(config)
        self._go_available: bool | None = None

    # ------------------------------------------------------------------
    # Public interface (BaseAnalyzer)
    # ------------------------------------------------------------------

    @staticmethod
    def can_handle(target_info: TargetInfo) -> bool:
        """Go binary mi kontrol et.

        Binary icindeki Go-spesifik string'lere bakar.
        """
        try:
            with open(target_info.path, "rb") as f:
                # Ilk 2MB'i oku (Go metadata genellikle burada baslar)
                data = f.read(2 * 1024 * 1024)
        except OSError:
            return False

        text = data.decode("ascii", errors="replace")

        # En az 2 Go runtime signature'i bulunmali
        hits = sum(1 for sig in _GO_RUNTIME_SIGNATURES if sig in text)
        if hits >= 2:
            return True

        # GOPCLNTAB magic bytes kontrolu
        for magic in _GOPCLNTAB_MAGICS:
            if magic in data:
                return True

        return False

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Go binary statik analizi.

        Siralama:
        1. Raw binary'yi kopyala
        2. GOPCLNTAB parse -> fonksiyon isimleri, dosya yollari
        3. BUILDINFO extraction -> Go versiyonu, modul listesi
        4. Type descriptor extraction -> struct/interface tanimlari
        5. Goroutine entry point tespiti

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Statik analiz sonucu.
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []
        stats: dict[str, Any] = {
            "analyzer": "go_binary",
            "go_tool_available": self._check_go_available(),
        }

        binary_path = target.path

        # 1. Raw binary'yi kopyala
        try:
            raw_copy = workspace.get_stage_dir("raw") / target.name
            if binary_path.is_file():
                shutil.copy2(str(binary_path), str(raw_copy))
                artifacts["raw_binary"] = raw_copy
        except OSError as exc:
            errors.append("Raw binary kopyalanamadi: %s" % exc)

        # 2. GOPCLNTAB parse
        gopclntab = self._extract_gopclntab(binary_path)
        if gopclntab and gopclntab.get("functions"):
            gop_path = workspace.save_json("static", "gopclntab", gopclntab)
            artifacts["gopclntab"] = gop_path
            stats["gopclntab_function_count"] = len(gopclntab["functions"])
            stats["gopclntab_file_count"] = len(gopclntab.get("source_files", []))
            logger.info(
                "GOPCLNTAB: %d fonksiyon, %d kaynak dosya",
                len(gopclntab["functions"]),
                len(gopclntab.get("source_files", [])),
            )
        else:
            errors.append("GOPCLNTAB parse edilemedi veya bos")
            stats["gopclntab_function_count"] = 0

        # 3. BUILDINFO
        buildinfo = self._extract_buildinfo(binary_path)
        if buildinfo:
            bi_path = workspace.save_json("static", "go_buildinfo", buildinfo)
            artifacts["go_buildinfo"] = bi_path
            stats["go_version"] = buildinfo.get("go_version", "unknown")
            stats["module_path"] = buildinfo.get("module_path", "unknown")
            stats["dependency_count"] = len(buildinfo.get("dependencies", []))
            logger.info(
                "BUILDINFO: go=%s, module=%s, %d dependency",
                stats["go_version"],
                stats["module_path"],
                stats["dependency_count"],
            )
        else:
            errors.append("BUILDINFO cikarilmadi (normal stripped binary icin)")

        # 4. Type descriptors
        types = self._extract_type_descriptors(binary_path)
        if types:
            types_path = workspace.save_json("static", "go_types", types)
            artifacts["go_types"] = types_path
            stats["struct_count"] = len(types.get("structs", []))
            stats["interface_count"] = len(types.get("interfaces", []))
            stats["method_count"] = len(types.get("methods", []))

        # 5. Goroutine tespiti
        if gopclntab and gopclntab.get("functions"):
            goroutines = self._detect_goroutines(gopclntab["functions"])
            if goroutines:
                gor_path = workspace.save_json("static", "go_goroutines", {
                    "total": len(goroutines),
                    "goroutines": goroutines,
                })
                artifacts["go_goroutines"] = gor_path
                stats["goroutine_count"] = len(goroutines)

        # 6. strings extraction (nm/strings fallback data icin)
        string_list = self.runner.run_strings(binary_path)
        if string_list:
            strings_data = {
                "total": len(string_list),
                "strings": string_list[:10000],
            }
            str_path = workspace.save_json("static", "strings_raw", strings_data)
            artifacts["strings_raw"] = str_path
            stats["string_count"] = len(string_list)

        # 7. nm symbol table (fallback + ek bilgi)
        symbols = self._run_nm(binary_path)
        if symbols is not None:
            sym_path = workspace.save_json("static", "symbols", symbols)
            artifacts["symbols"] = sym_path
            stats["symbol_count"] = len(symbols.get("symbols", []))

        # Paket yapisi analizi
        if gopclntab and gopclntab.get("functions"):
            packages = self._extract_packages(gopclntab["functions"])
            if packages:
                pkg_path = workspace.save_json("static", "go_packages", packages)
                artifacts["go_packages"] = pkg_path
                stats["package_count"] = len(packages.get("packages", []))

        duration = time.monotonic() - start
        stats["total_duration"] = round(duration, 3)

        # En az GOPCLNTAB veya symbols bulundu mu?
        has_useful_data = bool(gopclntab and gopclntab.get("functions")) or (
            symbols is not None and symbols.get("symbols")
        )

        return StageResult(
            stage_name="static",
            success=has_useful_data or len(artifacts) > 0,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Go binary deobfuscation.

        Go binary'ler icin klasik deobfuscation uygulanamaz.
        GOPCLNTAB zaten orijinal isimleri icerdiginden,
        bu stage GOPCLNTAB verisini deobfuscated dizinine kopyalar.
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []

        # GOPCLNTAB verisini deobfuscated dizinine tasi
        gopclntab = workspace.load_json("static", "gopclntab")
        if gopclntab:
            deobf_path = workspace.save_json("deobfuscated", "gopclntab_resolved", gopclntab)
            artifacts["gopclntab_resolved"] = deobf_path
        else:
            errors.append("GOPCLNTAB verisi bulunamadi — statik analiz basarisiz olmus olabilir")

        # Build info'yu da tasi
        buildinfo = workspace.load_json("static", "go_buildinfo")
        if buildinfo:
            bi_path = workspace.save_json("deobfuscated", "go_buildinfo", buildinfo)
            artifacts["go_buildinfo"] = bi_path

        return StageResult(
            stage_name="deobfuscate",
            success=len(errors) == 0 or len(artifacts) > 0,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            errors=errors,
        )

    def reconstruct(self, target: TargetInfo, workspace: Workspace) -> StageResult | None:
        """Go proje yapisini yeniden olustur.

        GoReconstructor'a delege eder.
        """
        try:
            from karadul.reconstruction.go_reconstructor import GoReconstructor
        except ImportError as exc:
            logger.warning("GoReconstructor yuklenemedi: %s", exc)
            return None

        start = time.monotonic()

        gopclntab = workspace.load_json("static", "gopclntab")
        buildinfo = workspace.load_json("static", "go_buildinfo")
        types_data = workspace.load_json("static", "go_types")
        packages_data = workspace.load_json("static", "go_packages")

        if not gopclntab:
            return StageResult(
                stage_name="reconstruct",
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=["GOPCLNTAB verisi olmadan reconstruct yapilamaz"],
            )

        analysis_results = {
            "gopclntab": gopclntab,
            "buildinfo": buildinfo or {},
            "types": types_data or {},
            "packages": packages_data or {},
        }

        reconstructor = GoReconstructor()
        output_dir = workspace.get_stage_dir("reconstructed") / "go_project"

        try:
            recon_result = reconstructor.reconstruct(analysis_results, output_dir)
        except Exception as exc:
            logger.exception("Go reconstruction hatasi: %s", exc)
            return StageResult(
                stage_name="reconstruct",
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=[f"{type(exc).__name__}: {exc}"],
            )

        # Sonuc raporunu kaydet
        report_path = workspace.save_json("reconstructed", "go_reconstruction_report", recon_result)

        return StageResult(
            stage_name="reconstruct",
            success=True,
            duration_seconds=time.monotonic() - start,
            artifacts={
                "go_project_dir": output_dir,
                "reconstruction_report": report_path,
            },
            stats=recon_result,
        )

    # ------------------------------------------------------------------
    # GOPCLNTAB extraction
    # ------------------------------------------------------------------

    def _extract_gopclntab(self, binary_path: Path) -> dict[str, Any] | None:
        """GOPCLNTAB'dan fonksiyon isimleri ve dosya yollari cikar.

        Go binary'lerin sonunda bir pclntab (program counter line table) var.
        Bu tablo strip edilse bile genellikle korunur.

        Fallback zinciri:
        1. 'go tool objdump' (en kapsamli)
        2. 'nm -g' ile sembol tablosu
        3. 'strings' + regex ile isim cikartma
        """
        # Strateji 1: go tool objdump
        if self._check_go_available():
            result = self._gopclntab_via_objdump(binary_path)
            if result and result.get("functions"):
                result["extraction_method"] = "go_tool_objdump"
                return result

        # Strateji 2: nm ile sembol tablosu
        result = self._gopclntab_via_nm(binary_path)
        if result and result.get("functions"):
            result["extraction_method"] = "nm"
            return result

        # Strateji 3: strings + regex fallback
        result = self._gopclntab_via_strings(binary_path)
        if result and result.get("functions"):
            result["extraction_method"] = "strings_regex"
            return result

        return None

    def _gopclntab_via_objdump(self, binary_path: Path) -> dict[str, Any] | None:
        """'go tool objdump' ile fonksiyon listesi cikar.

        En zengin bilgiyi verir: fonksiyon adi, adres, dosya:satir.
        """
        result = self.runner.run_command(
            ["go", "tool", "objdump", str(binary_path)],
            timeout=120,
        )
        if not result.success:
            logger.debug("go tool objdump basarisiz: %s", result.stderr[:200])
            return None

        functions: list[dict[str, Any]] = []
        source_files: set[str] = set()
        current_func: dict[str, Any] | None = None

        # go tool objdump ciktisi:
        # TEXT main.main(SB) /Users/user/project/main.go
        #   main.go:10  0x1001000  MOVQ ...
        func_header_re = re.compile(
            r"^TEXT\s+(\S+)\(SB\)\s+(.+)$"
        )
        source_line_re = re.compile(
            r"^\s+(\S+\.go):(\d+)\s+"
        )

        for line in result.stdout.splitlines():
            # Yeni fonksiyon basligi
            m = func_header_re.match(line)
            if m:
                if current_func:
                    functions.append(current_func)
                func_name = m.group(1)
                source_path = m.group(2).strip()
                current_func = {
                    "name": func_name,
                    "source_file": source_path,
                    "lines": [],
                }
                if source_path.endswith(".go"):
                    source_files.add(source_path)
                continue

            # Kaynak satir referansi
            m = source_line_re.match(line)
            if m and current_func is not None:
                file_ref = m.group(1)
                line_num = int(m.group(2))
                if not current_func["lines"] or current_func["lines"][-1] != line_num:
                    current_func["lines"].append(line_num)

        if current_func:
            functions.append(current_func)

        return {
            "total_functions": len(functions),
            "functions": functions,
            "source_files": sorted(source_files),
        }

    def _gopclntab_via_nm(self, binary_path: Path) -> dict[str, Any] | None:
        """nm ile Go sembollerini cikar."""
        nm_path = str(self.config.tools.nm)
        result = self.runner.run_command(
            [nm_path, str(binary_path)],
            timeout=60,
        )
        if not result.success:
            logger.debug("nm basarisiz: %s", result.stderr[:200])
            return None

        functions: list[dict[str, Any]] = []
        source_files: set[str] = set()

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue

            # nm ciktisi: address type name
            if len(parts) == 3:
                addr, sym_type, name = parts
            else:
                addr, name = None, parts[-1]
                sym_type = parts[0] if len(parts) > 1 else "U"

            # Go fonksiyonu pattern'i: package.Function
            if sym_type in ("T", "t") and "." in name:
                # Go source file bilgisi nm'den gelmez ama
                # fonksiyon isimlerinden paket yolu cikarabiliriz
                pkg = name.rsplit(".", 1)[0] if "." in name else ""

                functions.append({
                    "name": name,
                    "address": addr,
                    "type": sym_type,
                    "package": pkg,
                })

                # Paket yolundan dosya yolu tahmin et
                if "/" in pkg:
                    source_files.add(pkg.replace("/", "/") + "/*.go")

        return {
            "total_functions": len(functions),
            "functions": functions,
            "source_files": sorted(source_files),
        }

    def _gopclntab_via_strings(self, binary_path: Path) -> dict[str, Any] | None:
        """strings + regex ile Go fonksiyon isimlerini cikar.

        En dusuk kaliteli ama her zaman calisan yontem.
        """
        string_list = self.runner.run_strings(binary_path)
        if not string_list:
            return None

        functions: list[dict[str, Any]] = []
        source_files: set[str] = set()
        seen_names: set[str] = set()

        # Go paket/fonksiyon pattern'i: package.Function veya package.(*Type).Method
        go_func_re = re.compile(
            r"^([a-zA-Z0-9_]+(?:/[a-zA-Z0-9_.\-]+)*)"
            r"\."
            r"(?:\(\*([A-Z][a-zA-Z0-9_]*)\)\.)??"
            r"([a-zA-Z_][a-zA-Z0-9_]*)$"
        )

        # Go dosya yolu pattern'i
        go_file_re = re.compile(
            r"^.*\.go$"
        )

        for s in string_list:
            s = s.strip()
            if not s or len(s) < 4 or len(s) > 500:
                continue

            # Fonksiyon ismi mi?
            m = go_func_re.match(s)
            if m and s not in seen_names:
                pkg_path = m.group(1)
                type_name = m.group(2)  # None olabilir
                func_name = m.group(3)

                # Cok generic isimleri filtrele (false positive azalt)
                if func_name in ("init", "main") and not pkg_path:
                    continue
                # runtime, internal gibi standart Go paketlerini de dahil et
                if any(
                    pkg_path.startswith(p) for p in (
                        "runtime", "internal", "sync", "syscall", "os",
                        "fmt", "io", "net", "encoding", "crypto", "reflect",
                        "math", "strings", "bytes", "bufio", "context",
                        "errors", "log", "path", "sort", "strconv", "time",
                        "unicode", "regexp", "hash", "compress", "archive",
                        "database", "html", "image", "mime", "text",
                    )
                ) or "/" in pkg_path or pkg_path == "main":
                    seen_names.add(s)
                    func_entry: dict[str, Any] = {
                        "name": s,
                        "package": pkg_path,
                        "function": func_name,
                    }
                    if type_name:
                        func_entry["receiver_type"] = type_name
                    functions.append(func_entry)

            # .go dosya yolu mu?
            if go_file_re.match(s) and "/" in s:
                source_files.add(s)

        return {
            "total_functions": len(functions),
            "functions": functions,
            "source_files": sorted(source_files),
        }

    # ------------------------------------------------------------------
    # BUILDINFO extraction
    # ------------------------------------------------------------------

    def _extract_buildinfo(self, binary_path: Path) -> dict[str, Any] | None:
        """Go BUILDINFO section parse.

        'go version -m binary' komutu ile:
        - Go versiyonu (go1.21.5)
        - Modul adi (github.com/user/project)
        - Dependency tree (path => version)
        - Build settings (CGO, tags, vb.)

        Go kurulu degilse binary icindeki BUILDINFO magic'den parse eder.
        """
        # Strateji 1: go version -m (en guvenilir)
        if self._check_go_available():
            result = self.runner.run_command(
                ["go", "version", "-m", str(binary_path)],
                timeout=30,
            )
            if result.success and result.stdout.strip():
                return self._parse_go_version_output(result.stdout)

        # Strateji 2: Binary icinden strings ile BUILDINFO cikar
        return self._buildinfo_via_strings(binary_path)

    def _parse_go_version_output(self, output: str) -> dict[str, Any] | None:
        """'go version -m' ciktisini parse et.

        Ornek cikti:
            /path/to/binary: go1.21.5
                path    github.com/user/project
                mod     github.com/user/project (devel)
                dep     github.com/pkg/errors   v0.9.1  h1:FEBLx...
                build   -compiler=gc
                build   CGO_ENABLED=1
        """
        lines = output.strip().splitlines()
        if not lines:
            return None

        info: dict[str, Any] = {
            "go_version": "",
            "module_path": "",
            "dependencies": [],
            "build_settings": {},
        }

        # Ilk satir: /path/to/binary: go1.21.5
        first_line = lines[0]
        go_ver_match = re.search(r"go(\d+\.\d+(?:\.\d+)?)", first_line)
        if go_ver_match:
            info["go_version"] = "go" + go_ver_match.group(1)

        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) < 2:
                continue

            key = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ""

            if key == "path":
                info["module_path"] = value
            elif key == "mod":
                info["module_path"] = value.split()[0] if value else ""
                if len(value.split()) > 1:
                    info["module_version"] = value.split()[1]
            elif key == "dep":
                # parts zaten tab ile split edilmis: ["dep", "path", "version", "hash"]
                dep: dict[str, str] = {"path": value}
                if len(parts) > 2:
                    dep["version"] = parts[2].strip()
                if len(parts) > 3:
                    dep["hash"] = parts[3].strip()
                info["dependencies"].append(dep)
            elif key == "build":
                kv = value.split("=", 1)
                if len(kv) == 2:
                    info["build_settings"][kv[0]] = kv[1]
                else:
                    info["build_settings"][value] = True

        return info if info["go_version"] else None

    def _buildinfo_via_strings(self, binary_path: Path) -> dict[str, Any] | None:
        """Binary strings'den Go buildinfo cikar (go kurulu olmasa bile).

        Go module path'leri genellikle github.com/... formatinda.
        """
        string_list = self.runner.run_strings(binary_path)
        if not string_list:
            return None

        info: dict[str, Any] = {
            "go_version": "",
            "module_path": "",
            "dependencies": [],
            "build_settings": {},
        }

        go_ver_re = re.compile(r"^go(\d+\.\d+(?:\.\d+)?)$")
        module_re = re.compile(r"^((?:github|gitlab|bitbucket)\.\w+/[\w.\-]+/[\w.\-]+)")
        dep_ver_re = re.compile(r"^([\w./\-]+)@v(\d+\.\d+\.\d+)")

        seen_modules: set[str] = set()

        for s in string_list:
            s = s.strip()
            if not s:
                continue

            # Go versiyon tespiti
            m = go_ver_re.match(s)
            if m and not info["go_version"]:
                info["go_version"] = "go" + m.group(1)
                continue

            # go1.XX.Y formatinda (ornegin "go1.21.5")
            if s.startswith("go1.") and len(s) < 12 and not info["go_version"]:
                info["go_version"] = s
                continue

            # Module path tespiti
            m = module_re.match(s)
            if m and not info["module_path"]:
                info["module_path"] = m.group(1)
                continue

            # Dependency tespiti
            m = dep_ver_re.match(s)
            if m:
                dep_path = m.group(1)
                dep_ver = m.group(2)
                if dep_path not in seen_modules:
                    seen_modules.add(dep_path)
                    info["dependencies"].append({
                        "path": dep_path,
                        "version": "v" + dep_ver,
                    })

        return info if info["go_version"] or info["module_path"] else None

    # ------------------------------------------------------------------
    # Type descriptor extraction
    # ------------------------------------------------------------------

    def _extract_type_descriptors(self, binary_path: Path) -> dict[str, Any] | None:
        """Go type metadata parse.

        strings + regex ile:
        - Type isimlerini bul (struct, interface)
        - Method set'leri
        - reflect metadata
        """
        string_list = self.runner.run_strings(binary_path)
        if not string_list:
            return None

        structs: list[dict[str, str]] = []
        interfaces: list[dict[str, str]] = []
        methods: list[dict[str, str]] = []

        seen_types: set[str] = set()
        seen_methods: set[str] = set()

        struct_re = _GO_TYPE_PATTERNS["struct"]
        method_re = _GO_TYPE_PATTERNS["method_set"]

        for s in string_list:
            s = s.strip()
            if not s or len(s) < 3 or len(s) > 300:
                continue

            # Method set: package.(*Type).Method
            m = method_re.match(s)
            if m and s not in seen_methods:
                seen_methods.add(s)
                methods.append({
                    "full_name": s,
                    "receiver_type": m.group(1),
                    "method_name": m.group(2),
                })
                # Receiver type'i da struct olarak kaydet
                type_name = m.group(1)
                pkg = s.split(".")[0] if "." in s else "main"
                type_key = f"{pkg}.{type_name}"
                if type_key not in seen_types:
                    seen_types.add(type_key)
                    structs.append({
                        "name": type_name,
                        "package": pkg,
                        "full_name": type_key,
                    })
                continue

            # Struct/interface ismi: package.TypeName (buyuk harfle baslar)
            m = struct_re.match(s)
            if m:
                type_name = m.group(1)
                pkg = s.rsplit(".", 1)[0] if "." in s else "main"
                type_key = f"{pkg}.{type_name}"
                if type_key not in seen_types:
                    seen_types.add(type_key)

                    # Interface mi struct mi? Heuristik:
                    # Interface isimleri genellikle -er, -able, -or ile biter
                    is_interface = (
                        type_name.endswith("er")
                        or type_name.endswith("or")
                        or type_name.endswith("able")
                        or type_name.endswith("Handler")
                        or type_name.endswith("Writer")
                        or type_name.endswith("Reader")
                    )

                    entry = {
                        "name": type_name,
                        "package": pkg,
                        "full_name": type_key,
                    }
                    if is_interface:
                        interfaces.append(entry)
                    else:
                        structs.append(entry)

        if not structs and not interfaces and not methods:
            return None

        return {
            "structs": structs,
            "interfaces": interfaces,
            "methods": methods,
            "total_types": len(structs) + len(interfaces),
            "total_methods": len(methods),
        }

    # ------------------------------------------------------------------
    # Goroutine detection
    # ------------------------------------------------------------------

    def _detect_goroutines(self, functions: list[dict]) -> list[dict[str, Any]]:
        """Goroutine entry point'leri tespit et.

        Pattern'ler:
        - func.N suffix: anonymous goroutine (closure)
        - runtime.newproc, runtime.goexit referanslari
        - 'go ' prefix pattern
        """
        goroutines: list[dict[str, Any]] = []
        seen: set[str] = set()

        for func in functions:
            name = func.get("name", "")
            if not name or name in seen:
                continue

            # Anonymous goroutine: package.Function.func1
            if re.match(r".+\.func\d+$", name):
                seen.add(name)
                # Parent fonksiyonu bul
                parent = re.sub(r"\.func\d+$", "", name)
                goroutines.append({
                    "name": name,
                    "type": "anonymous_closure",
                    "parent_function": parent,
                    "package": func.get("package", ""),
                })
                continue

            # Runtime goroutine yonetimi
            if name.startswith("runtime.") and any(
                kw in name for kw in ("goexit", "newproc", "gopark", "goready", "gosched")
            ):
                seen.add(name)
                goroutines.append({
                    "name": name,
                    "type": "runtime_goroutine_mgmt",
                    "package": "runtime",
                })

        return goroutines

    # ------------------------------------------------------------------
    # Package analysis
    # ------------------------------------------------------------------

    def _extract_packages(self, functions: list[dict]) -> dict[str, Any] | None:
        """Fonksiyon listesinden Go paket yapisini cikar."""
        package_funcs: dict[str, list[str]] = {}

        for func in functions:
            name = func.get("name", "")
            pkg = func.get("package", "")

            if not pkg and "." in name:
                # Paket yolunu fonksiyon isminden cikar
                # main.handleRequest -> package = "main"
                # github.com/user/pkg.Func -> package = "github.com/user/pkg"
                pkg = name.rsplit(".", 1)[0]
                # Method receiver'i temizle: pkg.(*Type).Method -> pkg
                if ".(*" in pkg:
                    pkg = pkg.split(".(")[0]

            if pkg:
                if pkg not in package_funcs:
                    package_funcs[pkg] = []
                package_funcs[pkg].append(name)

        if not package_funcs:
            return None

        packages = []
        for pkg_name, funcs in sorted(package_funcs.items()):
            packages.append({
                "name": pkg_name,
                "function_count": len(funcs),
                "functions": funcs[:50],  # max 50 fonksiyon listele
                "is_stdlib": self._is_go_stdlib(pkg_name),
            })

        # User vs stdlib istatistikleri
        user_pkgs = [p for p in packages if not p["is_stdlib"]]
        stdlib_pkgs = [p for p in packages if p["is_stdlib"]]

        return {
            "total": len(packages),
            "user_packages": len(user_pkgs),
            "stdlib_packages": len(stdlib_pkgs),
            "packages": packages,
        }

    @staticmethod
    def _is_go_stdlib(pkg_name: str) -> bool:
        """Go standart kutuphane paketi mi?"""
        stdlib_prefixes = (
            "runtime", "internal", "sync", "syscall", "os", "fmt",
            "io", "net", "encoding", "crypto", "reflect", "math",
            "strings", "bytes", "bufio", "context", "errors", "log",
            "path", "sort", "strconv", "time", "unicode", "regexp",
            "hash", "compress", "archive", "database", "html", "image",
            "mime", "text", "debug", "go/", "testing", "unsafe",
            "plugin", "embed", "iter", "maps", "slices", "cmp",
        )
        # Stdlib paketleri "/" icermez (runtime/internal gibi ozel durumlar haric)
        # veya bilinen prefix'lerle baslar
        first_part = pkg_name.split("/")[0]
        return first_part in stdlib_prefixes or pkg_name in stdlib_prefixes

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _run_nm(self, binary_path: Path) -> dict[str, Any] | None:
        """nm ile symbol table'i cikar."""
        nm_path = str(self.config.tools.nm)
        result = self.runner.run_command(
            [nm_path, str(binary_path)],
            timeout=60,
        )
        if not result.success:
            logger.debug("nm basarisiz: %s", result.stderr[:200])
            return None

        symbols: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) == 3:
                symbols.append({
                    "address": parts[0],
                    "type": parts[1],
                    "name": parts[2],
                })
            elif len(parts) == 2:
                symbols.append({
                    "address": None,
                    "type": parts[0],
                    "name": parts[1],
                })

        return {
            "binary": str(binary_path),
            "total": len(symbols),
            "symbols": symbols,
        }

    def _check_go_available(self) -> bool:
        """Go toolchain'in mevcut olup olmadigini kontrol et.

        Sonucu cache'ler, tekrar tekrar calistirmaz.
        """
        if self._go_available is not None:
            return self._go_available

        result = self.runner.run_command(
            ["go", "version"],
            timeout=10,
        )
        self._go_available = result.success
        if result.success:
            logger.debug("Go toolchain mevcut: %s", result.stdout.strip())
        else:
            logger.debug("Go toolchain bulunamadi, fallback yontemler kullanilacak")
        return self._go_available
