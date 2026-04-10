"""Mach-O binary analyzer.

macOS Mach-O ve Universal binary dosyalari icin statik analiz:
- otool ile dynamic library listesi ve load commands
- strings ile string extraction
- nm ile symbol table
- lief ile header analiz (opsiyonel)
- Ghidra headless ile tam analiz (function list, strings, call graph, decompile)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
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
from karadul.ghidra.headless import GhidraHeadless
from karadul.ghidra.project import GhidraProject

logger = logging.getLogger(__name__)


@register_analyzer(TargetType.MACHO_BINARY)
@register_analyzer(TargetType.UNIVERSAL_BINARY)
@register_analyzer(TargetType.ELF_BINARY)
@register_analyzer(TargetType.PE_BINARY)
@register_analyzer(TargetType.BUN_BINARY)
class MachOAnalyzer(BaseAnalyzer):
    """Native binary analyzer (Mach-O, ELF, PE).

    macOS native binary'ler icin otool, strings, nm, lief ve
    Ghidra ile kapsamli statik analiz yapar.
    ELF ve PE binary'ler icin otool-spesifik adimlar atlanir,
    Ghidra headless ile tam analiz yapilir.
    """

    supported_types = [
        TargetType.MACHO_BINARY, TargetType.UNIVERSAL_BINARY,
        TargetType.ELF_BINARY, TargetType.PE_BINARY,
        TargetType.BUN_BINARY,
    ]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.runner = SubprocessRunner(config)
        self.ghidra = GhidraHeadless(config)

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Native binary statik analizi (Mach-O, ELF, PE).

        Siralama:
        1. Raw binary'yi kopyala
        2. otool -L ile dynamic libraries (Mach-O only)
        3. otool -l ile load commands (Mach-O only)
        4. strings ile string extraction
        5. nm ile symbol table
        6. lief ile header analiz (opsiyonel)
        7. Ghidra headless ile tam analiz

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Statik analiz sonucu.
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []
        stats: dict[str, Any] = {}

        binary_path = target.path
        static_dir = workspace.get_stage_dir("static")

        # 0. Universal binary icin lipo thin -- arm64 slice'i cikar
        if target.target_type == TargetType.UNIVERSAL_BINARY:
            thin_path = workspace.get_stage_dir("raw") / f"{target.name}_arm64"
            try:
                proc = subprocess.run(
                    ["lipo", str(binary_path), "-thin", "arm64", "-output", str(thin_path)],
                    capture_output=True, text=True, timeout=30,
                )
                if proc.returncode == 0 and thin_path.exists():
                    logger.info("Universal binary: arm64 slice cikarildi -> %s", thin_path)
                    binary_path = thin_path
                    stats["lipo_thin"] = "arm64"
                else:
                    # arm64 yoksa x86_64 dene
                    proc = subprocess.run(
                        ["lipo", str(target.path), "-thin", "x86_64", "-output", str(thin_path)],
                        capture_output=True, text=True, timeout=30,
                    )
                    if proc.returncode == 0 and thin_path.exists():
                        logger.info("Universal binary: x86_64 slice cikarildi -> %s", thin_path)
                        binary_path = thin_path
                        stats["lipo_thin"] = "x86_64"
                    else:
                        logger.warning("lipo thin basarisiz, orijinal binary kullanilacak: %s", proc.stderr)
            except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
                logger.warning("lipo thin hatasi: %s", exc)
                errors.append(f"lipo thin hatasi: {exc}")

        # 1. Raw binary'yi kopyala
        try:
            raw_copy = workspace.get_stage_dir("raw") / target.name
            if binary_path.is_file():
                shutil.copy2(str(binary_path), str(raw_copy))
                artifacts["raw_binary"] = raw_copy
        except OSError as exc:
            errors.append("Raw binary kopyalanamadi: %s" % exc)

        # otool adimlari sadece Mach-O icin (ELF/PE icin atlanir)
        is_macho = target.target_type in (
            TargetType.MACHO_BINARY, TargetType.UNIVERSAL_BINARY,
            TargetType.BUN_BINARY,
        )

        # 2. otool -L: dynamic libraries (Mach-O only)
        if is_macho:
            dylibs = self._run_otool_libs(binary_path)
            if dylibs is not None:
                dylib_path = workspace.save_json("static", "dynamic_libraries", dylibs)
                artifacts["dynamic_libraries"] = dylib_path
                stats["dylib_count"] = len(dylibs.get("libraries", []))
        else:
            logger.info("otool -L atlandi (%s icin gecerli degil)", target.target_type.value)

        # 3. otool -l: load commands (Mach-O only)
        if is_macho:
            load_cmds = self._run_otool_load_commands(binary_path)
            if load_cmds:
                lcmd_path = workspace.save_artifact("static", "load_commands.txt", load_cmds)
                artifacts["load_commands"] = lcmd_path
        else:
            logger.info("otool -l atlandi (%s icin gecerli degil)", target.target_type.value)

        # 4. strings -- buyuk binary'ler icin mmap kullan
        threshold_bytes = (
            self.config.binary_reconstruction.large_binary_threshold_mb
            * 1024 * 1024
        )
        is_large_binary = target.file_size > threshold_bytes

        if is_large_binary:
            logger.info(
                "Buyuk binary (%.0f MB): mmap ile string extraction",
                target.file_size / (1024 * 1024),
            )
            string_list = self._extract_strings_mmap(
                binary_path,
                min_length=self.config.analysis.string_min_length,
            )
            stats["string_extraction_method"] = "mmap"
        else:
            string_list = self.runner.run_strings(binary_path)
            stats["string_extraction_method"] = "subprocess"

        if string_list:
            strings_data = {
                "total": len(string_list),
                "strings": string_list[:10000],  # max 10K string
            }
            str_path = workspace.save_json("static", "strings_raw", strings_data)
            artifacts["strings_raw"] = str_path
            stats["string_count"] = len(string_list)

        # 5. nm: symbol table
        symbols = self._run_nm(binary_path)
        if symbols is not None:
            sym_path = workspace.save_json("static", "symbols", symbols)
            artifacts["symbols"] = sym_path
            stats["symbol_count"] = len(symbols.get("symbols", []))

        # 6. lief (opsiyonel)
        lief_data = self._run_lief(binary_path)
        if lief_data is not None:
            lief_path = workspace.save_json("static", "lief_analysis", lief_data)
            artifacts["lief_analysis"] = lief_path
            stats["lief_available"] = True
        else:
            stats["lief_available"] = False

        # 7. Ghidra headless analiz
        ghidra_result = self._run_ghidra(binary_path, workspace)
        if ghidra_result is not None:
            if ghidra_result.get("success"):
                # Script ciktilarini artifact olarak kaydet
                for script_name, output in ghidra_result.get("scripts_output", {}).items():
                    ghidra_art_path = workspace.save_json(
                        "static", "ghidra_%s" % script_name, output,
                    )
                    artifacts["ghidra_%s" % script_name] = ghidra_art_path

                stats["ghidra_success"] = True
                stats["ghidra_duration"] = ghidra_result.get("duration_seconds", 0)

                # Ghidra'dan gelen istatistikler
                combined = ghidra_result.get("scripts_output", {}).get("combined_results", {})
                if combined:
                    summary = combined.get("summary", {})
                    stats["ghidra_function_count"] = summary.get("function_count", 0)
                    stats["ghidra_string_count"] = summary.get("string_count", 0)
                    stats["ghidra_call_graph_edges"] = summary.get("call_graph_edges", 0)
                    stats["ghidra_decompiled"] = summary.get("decompiled_success", 0)
            else:
                errors.append(
                    "Ghidra analiz basarisiz (rc=%d)" % ghidra_result.get("returncode", -1)
                )
                stats["ghidra_success"] = False
        else:
            stats["ghidra_available"] = False

        # 8. Binary Intelligence -- string clustering + mimari cikarim
        try:
            from karadul.analyzers.binary_intelligence import BinaryIntelligence

            bi = BinaryIntelligence(self.config)

            # String, symbol ve dylib verilerini hazirla
            bi_strings = string_list if string_list else []
            bi_symbols = [
                sym.get("name", "")
                for sym in (symbols or {}).get("symbols", [])
                if sym.get("name")
            ]
            bi_dylibs = [
                lib.get("path", "")
                for lib in (dylibs or {}).get("libraries", [])
                if lib.get("path")
            ]

            intel_report = bi.analyze(
                strings=bi_strings,
                symbols=bi_symbols,
                dylibs=bi_dylibs,
                target_name=target.name,
            )

            # Ghidra decompile ciktisi varsa onu da analiz et
            decompiled_dir = workspace.get_stage_dir("static") / "ghidra_output" / "decompiled"
            if decompiled_dir.exists():
                func_analyses = bi.analyze_decompiled(decompiled_dir)
                intel_report.architecture.function_analyses = func_analyses
                stats["intel_functions_analyzed"] = len(func_analyses)

            # Raporu workspace'e kaydet
            intel_path = workspace.save_json(
                "static", "intelligence_report", intel_report.to_dict(),
            )
            artifacts["intelligence_report"] = intel_path

            # Istatistikleri ekle
            arch = intel_report.architecture
            stats["intel_app_type"] = arch.app_type
            stats["intel_subsystem_count"] = len(arch.subsystems)
            stats["intel_algorithm_count"] = len(arch.algorithms)
            stats["intel_security_count"] = len(arch.security)
            stats["intel_protocol_count"] = len(arch.protocols)

            logger.info(
                "Binary Intelligence: type=%s, %d subsystems, %d algorithms, "
                "%d security mechanisms, %d protocols",
                arch.app_type,
                len(arch.subsystems),
                len(arch.algorithms),
                len(arch.security),
                len(arch.protocols),
            )

        except Exception as exc:
            logger.warning("Binary Intelligence hatasi: %s", exc)
            errors.append("Binary Intelligence hatasi: %s" % exc)

        duration = time.monotonic() - start

        return StageResult(
            stage_name="static",
            success=len(errors) == 0 or len(artifacts) > 0,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Binary deobfuscation = Ghidra decompilation ciktisi.

        Binary'ler icin klasik deobfuscation uygulanamaz.
        Bunun yerine Ghidra'nin decompilation ciktisi
        deobfuscated dizinine kopyalanir.

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Deobfuscation sonucu.
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []

        static_dir = workspace.get_stage_dir("static")
        deobf_dir = workspace.get_stage_dir("deobfuscated")

        # Ghidra decompiled dizinini bul
        ghidra_output = static_dir / "ghidra_output"
        decompiled_src = ghidra_output / "decompiled"

        if decompiled_src.exists() and decompiled_src.is_dir():
            # Decompiled dosyalari kopyala
            decompiled_dest = deobf_dir / "decompiled"
            try:
                shutil.copytree(str(decompiled_src), str(decompiled_dest))
                artifacts["decompiled_dir"] = decompiled_dest

                # Dosya sayisini say
                c_files = list(decompiled_dest.glob("*.c"))
                artifacts["decompiled_count"] = decompiled_dest
                logger.info(
                    "Decompiled fonksiyonlar kopyalandi: %d dosya", len(c_files),
                )
            except OSError as exc:
                errors.append("Decompiled dosyalar kopyalanamadi: %s" % exc)
        else:
            # Ghidra ciktisi yoksa, sadece decompiled.json'dan bilgi al
            decompiled_json = static_dir / "ghidra_decompiled.json"
            if decompiled_json.exists():
                try:
                    shutil.copy2(str(decompiled_json), str(deobf_dir / "decompiled.json"))
                    artifacts["decompiled_json"] = deobf_dir / "decompiled.json"
                except OSError as exc:
                    errors.append("decompiled.json kopyalanamadi: %s" % exc)
            else:
                errors.append(
                    "Ghidra decompilation ciktisi bulunamadi. "
                    "Statik analiz basarili tamamlanmis olmali."
                )

        duration = time.monotonic() - start

        return StageResult(
            stage_name="deobfuscate",
            success=len(errors) == 0,
            duration_seconds=duration,
            artifacts=artifacts,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Private helper metodlar
    # ------------------------------------------------------------------

    def _run_otool_libs(self, binary_path: Path) -> dict[str, Any] | None:
        """otool -L ile dynamic library listesini cikar."""
        output = self.runner.run_otool(binary_path, flags=["-L"])
        if not output:
            return None

        libraries = []
        for line in output.splitlines()[1:]:  # ilk satir dosya adi
            line = line.strip()
            if not line:
                continue
            # Format: /path/to/lib.dylib (compatibility version X, current version Y)
            parts = line.split(" (")
            if parts:
                lib_path = parts[0].strip()
                version_info = parts[1].rstrip(")") if len(parts) > 1 else ""
                libraries.append({
                    "path": lib_path,
                    "version_info": version_info,
                })

        return {
            "binary": str(binary_path),
            "total": len(libraries),
            "libraries": libraries,
        }

    def _run_otool_load_commands(self, binary_path: Path) -> str:
        """otool -l ile load commands ciktisini al."""
        return self.runner.run_otool(binary_path, flags=["-l"])

    def _run_nm(self, binary_path: Path) -> dict[str, Any] | None:
        """nm ile symbol table'i cikar."""
        nm_path = str(self.config.tools.nm)
        result = self.runner.run_command(
            [nm_path, "-g", str(binary_path)],  # -g: external (global) symbols
            timeout=60,
        )
        if not result.success:
            # nm basarisiz olabilir (stripped binary vb.)
            logger.debug("nm basarisiz: %s", result.stderr[:200])
            return None

        symbols = []
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
                # Undefined symbol (adres yok)
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

    def _run_lief(self, binary_path: Path) -> dict[str, Any] | None:
        """lief ile Mach-O header analizi (opsiyonel).

        lief kurulu degilse None dondurur, hata vermez.
        """
        try:
            import lief
        except ImportError:
            logger.debug("lief kurulu degil, atlanacak")
            return None

        try:
            binary = lief.parse(str(binary_path))
            if binary is None:
                return None

            result: dict[str, Any] = {
                "format": str(binary.format),
                "header": {},
                "segments": [],
                "sections": [],
                "libraries": [],
            }

            # Header bilgileri
            if hasattr(binary, "header"):
                h = binary.header
                result["header"] = {
                    "magic": str(h.magic) if hasattr(h, "magic") else None,
                    "cpu_type": str(h.cpu_type) if hasattr(h, "cpu_type") else None,
                    "file_type": str(h.file_type) if hasattr(h, "file_type") else None,
                    "flags": int(h.flags) if hasattr(h, "flags") else None,
                }

            # Segments
            if hasattr(binary, "segments"):
                for seg in binary.segments:
                    result["segments"].append({
                        "name": seg.name,
                        "virtual_address": seg.virtual_address,
                        "virtual_size": seg.virtual_size,
                        "file_offset": seg.file_offset,
                        "file_size": seg.file_size,
                    })

            # Sections
            if hasattr(binary, "sections"):
                for sec in binary.sections:
                    result["sections"].append({
                        "name": sec.name,
                        "segment": sec.segment.name if hasattr(sec, "segment") and sec.segment else None,
                        "size": sec.size,
                        "offset": sec.offset,
                    })

            # Libraries
            if hasattr(binary, "libraries"):
                for lib in binary.libraries:
                    result["libraries"].append(str(lib.name))

            return result

        except Exception as exc:
            logger.warning("lief analiz hatasi: %s", exc)
            return None

    def _extract_bun_js(
        self, binary_path: Path, workspace: Workspace,
    ) -> Path | None:
        """Bun compiled binary'den __BUN segmentindeki JS bundle'i cikar.

        Bun runtime `bun build --compile` ile JS kodunu Mach-O binary'nin
        __BUN segmentine zlib-compressed olarak gomer. Bu metod:
        1. lief ile binary'yi parse eder
        2. __BUN segmentini bulur
        3. Segment content'ini raw bytes olarak okur
        4. zlib decompress dener (Bun genelde compress eder)
        5. Basarisizsa raw bytes kaydeder
        6. workspace/static/bun_bundle.js olarak yazar

        Args:
            binary_path: Bun compiled binary dosya yolu.
            workspace: Calisma dizini.

        Returns:
            Cikarilan JS dosyasinin Path'i, basarisizsa None.
        """
        try:
            import lief
        except ImportError:
            logger.warning("lief kurulu degil, BUN JS extraction atlanacak")
            return None

        try:
            binary = lief.parse(str(binary_path))
            if binary is None:
                logger.warning("lief binary parse edemedi: %s", binary_path)
                return None

            # __BUN segmentini bul
            bun_segment = None
            if hasattr(binary, "segments"):
                for seg in binary.segments:
                    if seg.name in ("__BUN", "__bun"):
                        bun_segment = seg
                        break

            if bun_segment is None:
                logger.warning("__BUN segmenti bulunamadi: %s", binary_path)
                return None

            # Segment content'ini raw bytes olarak oku
            # lief'in content property'si bazen eksik/bos olabiliyor,
            # dogrudan dosyadan offset+size ile okumak daha guvenilir
            raw_data = binary_path.read_bytes()
            offset = bun_segment.file_offset
            size = bun_segment.file_size

            if offset + size > len(raw_data):
                logger.warning(
                    "__BUN segment sinirlari dosya disinda: offset=%d size=%d file=%d",
                    offset, size, len(raw_data),
                )
                return None

            segment_bytes = raw_data[offset:offset + size]
            logger.info(
                "__BUN segment bulundu: offset=%d size=%d (%.1f MB)",
                offset, size, size / (1024 * 1024),
            )

            # Decompress dene (zlib)
            import zlib
            js_content: bytes
            is_compressed = False
            try:
                js_content = zlib.decompress(segment_bytes)
                is_compressed = True
                logger.info(
                    "__BUN segment decompress basarili: %d -> %d bytes (%.1fx)",
                    size, len(js_content), len(js_content) / max(size, 1),
                )
            except zlib.error:
                # Compress edilmemis olabilir, raw olarak kaydet
                js_content = segment_bytes
                logger.info("__BUN segment zlib degil, raw bytes kaydedilecek")

            # Workspace'e kaydet
            static_dir = workspace.get_stage_dir("static")
            output_path = static_dir / "bun_bundle.js"
            output_path.write_bytes(js_content)

            logger.info(
                "BUN JS extracted: %s (%d bytes, compressed=%s)",
                output_path, len(js_content), is_compressed,
            )
            return output_path

        except Exception as exc:
            logger.warning("BUN JS extraction hatasi: %s", exc)
            return None

    @staticmethod
    def _extract_strings_mmap(
        binary_path: Path,
        min_length: int = 4,
        max_strings: int = 50000,
    ) -> list[str]:
        """Memory-mapped file reading ile buyuk binary'den string cikar.

        224MB+ dosyalari subprocess ile okumak yerine mmap ile dogrudan
        bellege map'leyerek ASCII string'leri cikarir. mmap OS seviyesinde
        sayfa sayfa okur, tum dosyayi RAM'e almaz.

        Args:
            binary_path: Binary dosya yolu.
            min_length: Minimum string uzunlugu.
            max_strings: Maksimum cikarilacak string sayisi.

        Returns:
            Cikarilan string listesi.
        """
        import mmap

        strings: list[str] = []

        try:
            with open(binary_path, "rb") as f:
                # mmap ile dosyayi bellege maple (read-only)
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    file_size = mm.size()
                    current: list[int] = []
                    processed = 0

                    for i in range(file_size):
                        byte = mm[i]
                        # Printable ASCII: 0x20 (space) - 0x7E (~)
                        if 0x20 <= byte <= 0x7E:
                            current.append(byte)
                        else:
                            if len(current) >= min_length:
                                strings.append(bytes(current).decode("ascii"))
                                if len(strings) >= max_strings:
                                    logger.info(
                                        "mmap strings: max_strings (%d) limitine ulasildi "
                                        "(dosyanin %.0f%%'si taranmis)",
                                        max_strings,
                                        (i / file_size) * 100,
                                    )
                                    return strings
                            current = []

                        # Her 50MB'de progress logla
                        processed += 1
                        if processed % (50 * 1024 * 1024) == 0:
                            logger.info(
                                "mmap strings: %.0f MB / %.0f MB taranmis (%d string bulundu)",
                                processed / (1024 * 1024),
                                file_size / (1024 * 1024),
                                len(strings),
                            )

                    # Dosya sonunda kalan string
                    if len(current) >= min_length:
                        strings.append(bytes(current).decode("ascii"))

        except (OSError, ValueError) as exc:
            logger.error("mmap string extraction hatasi: %s", exc)

        try:
            file_mb = binary_path.stat().st_size / (1024 * 1024)
        except OSError:
            file_mb = 0.0
        logger.info(
            "mmap strings: %d string cikarildi (%.0f MB dosya)",
            len(strings), file_mb,
        )
        return strings

    def _run_ghidra(
        self, binary_path: Path, workspace: Workspace,
    ) -> dict[str, Any] | None:
        """Ghidra headless analiz calistir.

        Ghidra mevcut degilse None dondurur.
        """
        if not self.ghidra.is_available():
            logger.info("Ghidra mevcut degil, atlanacak")
            return None

        # Ghidra proje dizini
        ghidra_proj = GhidraProject(workspace, self.config)
        ghidra_proj.create()

        # Varsayilan scriptleri al
        scripts = self.ghidra.get_default_scripts()
        if not scripts:
            logger.warning("Ghidra scriptleri bulunamadi: %s", self.config.ghidra_scripts_dir)
            return None

        try:
            result = self.ghidra.analyze(
                binary_path=binary_path,
                project_dir=ghidra_proj.project_dir,
                project_name="karadul_%s" % workspace.target_name,
                scripts=scripts,
                output_dir=ghidra_proj.get_output_dir(),
            )
            return result
        except Exception as exc:
            logger.error("Ghidra analiz hatasi: %s", exc)
            return {"success": False, "error": str(exc)}
        finally:
            # Proje dosyalarini temizle (ciktilar kalsin)
            ghidra_proj.cleanup()
