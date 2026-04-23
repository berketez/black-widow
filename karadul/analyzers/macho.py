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
import os as _os_module
import shutil
import stat as _stat_module
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from karadul.decompilers.base import DecompilerBackend

from karadul.analyzers import register_analyzer
from karadul.analyzers.base import BaseAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.safe_subprocess import resolve_tool, safe_run
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.ghidra.headless import GhidraHeadless
from karadul.ghidra.project import GhidraProject

logger = logging.getLogger(__name__)

# TOCTOU-safe kopyalama yardimcilari (v1.10.0 Batch 5B HIGH-4).
_os_fstat = _os_module.fstat
_os_chmod = _os_module.chmod


def _stat_is_regular(st: Any) -> bool:
    """os.stat_result/os.fstat_result'un regular file'a isaret ettigini dogrula."""
    try:
        return _stat_module.S_ISREG(st.st_mode)
    except AttributeError:
        return False


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
        # v1.10.0 M4 (Berke karari): backend factory adapter.
        # create_backend() ghidra backend'i icin dahili olarak GhidraHeadless
        # sariyor; davranis ozdes. Config'te decompilers.primary_backend
        # "angr" olarak set edilirse AngrBackend kullanilir.
        # Fallback: backend olusturulmasi basarisiz ise (factory/config hatasi)
        # dogrudan GhidraHeadless'a don.
        try:
            from karadul.decompilers import create_backend as _create_backend

            self._backend: DecompilerBackend | None = _create_backend(config)
            # Ghidra backend'in lazy-init property'si uzerinden GhidraHeadless
            # instance'ini al (eski analyze_static kodu self.ghidra uzerinden
            # direkt cagri yapiyor; davranisi bozmamak icin ayni referansi tut).
            _backend_ghidra = getattr(self._backend, "ghidra", None)
            self.ghidra = _backend_ghidra if _backend_ghidra is not None else GhidraHeadless(config)
        except Exception as _exc:  # pragma: no cover - defensive
            logger.debug(
                "Backend factory basarisiz, GhidraHeadless direkt kullanilacak: %s",
                _exc,
            )
            self._backend = None
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

        # 1. Raw binary'yi isaretle.
        # v1.10.0 Batch 5B HIGH-4: TOCTOU-safe kopyalama. Eski yol
        # ``is_file() + os.symlink()`` sırasinda attacker binary_path'i
        # symlink ile degistirebilirdi (time-of-check to time-of-use).
        # Yeni yol: open()+fstat() ile handle acilir, inode dogrulanir,
        # copyfileobj ayni handle uzerinden calisir. Symlink pattern'i
        # tamamen kaldirildi -- basit kopya (disk kullanimi marjinal).
        try:
            raw_copy = workspace.get_stage_dir("raw") / target.name
            # Ayni dosya kontrolu (universal thin slice edge case)
            try:
                same_file = raw_copy.resolve() == binary_path.resolve()
            except (OSError, RuntimeError):
                same_file = False
            if same_file:
                artifacts["raw_binary"] = raw_copy
            else:
                # Eski sembol varsa temizle (follow_symlinks=False)
                if raw_copy.is_symlink() or raw_copy.exists():
                    try:
                        raw_copy.unlink()
                    except OSError:
                        logger.debug(
                            "Raw binary mevcut dosya silinemedi: %s",
                            raw_copy, exc_info=True,
                        )
                # TOCTOU-safe: fh.fileno() uzerinden read
                with open(binary_path, "rb") as src_fh:
                    src_stat = _os_fstat(src_fh.fileno())
                    if not _stat_is_regular(src_stat):
                        errors.append(
                            "Raw binary duzgun dosya degil (device/fifo?): %s"
                            % binary_path
                        )
                    else:
                        with open(raw_copy, "wb") as dst_fh:
                            shutil.copyfileobj(src_fh, dst_fh, length=1024 * 1024)
                        # Permission bitlerini koru (copy2 davranisinin bir bolumu)
                        try:
                            _os_chmod(raw_copy, src_stat.st_mode & 0o7777)
                        except OSError:
                            pass
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
                dst = deobf_dir / "decompiled.json"
                try:
                    # v1.10.0 Batch 5B HIGH-4: symlink pattern kaldirildi.
                    # TOCTOU-safe fstat + copyfileobj.
                    if dst.is_symlink() or dst.exists():
                        try:
                            dst.unlink()
                        except OSError:
                            pass
                    with open(decompiled_json, "rb") as _src_fh:
                        _src_st = _os_fstat(_src_fh.fileno())
                        if _stat_is_regular(_src_st):
                            with open(dst, "wb") as _dst_fh:
                                shutil.copyfileobj(_src_fh, _dst_fh, length=1024 * 1024)
                    artifacts["decompiled_json"] = dst
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
        """otool -l ile load commands ciktisini al.

        v1.10.0 Batch 5B MED-12: otool -l stdout unbounded -> max_bytes ile
        sinirla. Dev-size binary icin otool -l 500MB+ olabilir; ondan
        aciri Ghidra/bellege sigmaz. Limit SecurityConfig'ten geliyor.
        """
        max_out = self.config.security.max_otool_output_bytes
        otool_path = resolve_tool("otool") or str(self.config.tools.otool)
        try:
            result = safe_run(
                [otool_path, "-l", str(binary_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,  # binary safety -- byte sayiyoruz
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            logger.warning("otool -l timeout: %s", binary_path)
            return ""
        except FileNotFoundError:
            return ""

        raw = result.stdout or b""
        if len(raw) > max_out:
            logger.warning(
                "otool -l ciktisi %d > max %d, kirpiliyor (%s)",
                len(raw), max_out, binary_path,
            )
            raw = raw[:max_out]
        return raw.decode("utf-8", errors="replace")

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

            # lief Binary union format attribute'u icerebilir ama COFF yoktur —
            # getattr ile guvenli eris.
            binary_format = getattr(binary, "format", None)
            result: dict[str, Any] = {
                "format": str(binary_format) if binary_format is not None else "unknown",
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

            # Segments (lief Segment union — attribute'lar getattr ile alinir)
            if hasattr(binary, "segments"):
                for seg in binary.segments:
                    result["segments"].append({
                        "name": getattr(seg, "name", None),
                        "virtual_address": getattr(seg, "virtual_address", None),
                        "virtual_size": getattr(seg, "virtual_size", None),
                        "file_offset": getattr(seg, "file_offset", None),
                        "file_size": getattr(seg, "file_size", None),
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

            # Libraries (lief lib union — name attribute getattr ile alinir)
            if hasattr(binary, "libraries"):
                for lib in binary.libraries:
                    lib_name = getattr(lib, "name", None)
                    if lib_name is not None:
                        result["libraries"].append(str(lib_name))

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

            # __BUN segmentini bul (lief Segment union, name getattr ile alinir)
            bun_segment = None
            if hasattr(binary, "segments"):
                for seg in binary.segments:
                    seg_name = getattr(seg, "name", None)
                    if seg_name in ("__BUN", "__bun"):
                        bun_segment = seg
                        break

            if bun_segment is None:
                logger.warning("__BUN segmenti bulunamadi: %s", binary_path)
                return None

            # Segment content'ini raw bytes olarak oku (v1.10.0 H3: mmap)
            # Eskiden `binary_path.read_bytes()` ile tum binary (200 MB+) RAM'e
            # aliniyordu. `mmap` ile yalnizca offset+size bolumu alinir, geri
            # kalani OS'un sayfa cache'inde kalir, anlik RSS = segment boyutu.
            import mmap as _mmap
            offset = int(getattr(bun_segment, "file_offset", 0))
            size = int(getattr(bun_segment, "file_size", 0))
            segment_bytes: bytes
            # v1.10.0 Batch 5B MED-13: negatif offset veya size; malicious
            # __BUN segment integer overflow/underflow koruma.
            if offset < 0 or size < 0 or size > (2 * 1024 ** 3):
                logger.warning(
                    "__BUN segment gecersiz offset/size: offset=%d size=%d",
                    offset, size,
                )
                return None
            try:
                with open(binary_path, "rb") as _fh:
                    file_size = _os_fstat(_fh.fileno()).st_size
                    if offset + size > file_size:
                        logger.warning(
                            "__BUN segment sinirlari dosya disinda: "
                            "offset=%d size=%d file=%d",
                            offset, size, file_size,
                        )
                        return None
                    with _mmap.mmap(
                        _fh.fileno(), 0, access=_mmap.ACCESS_READ,
                    ) as mm:
                        segment_bytes = bytes(mm[offset:offset + size])
            except (OSError, ValueError) as exc:
                logger.warning("BUN segment mmap okuma hatasi: %s", exc)
                return None
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

        PERF (v1.10.0 C1): Python byte-by-byte loop yerine `re.finditer`
        kullanir. 200 MB binary'de ~30 dk -> ~2-3 sn (100-1000x hizlanma).
        Regex C implementasyonu sayfa-sayfa mmap'i tarayabilir.

        Args:
            binary_path: Binary dosya yolu.
            min_length: Minimum string uzunlugu.
            max_strings: Maksimum cikarilacak string sayisi.

        Returns:
            Cikarilan string listesi.
        """
        import mmap
        import re as _re

        strings: list[str] = []
        # Minimum uzunluk >= 1 olmali (re repeat spec guvenligi)
        if min_length < 1:
            min_length = 1
        # re.finditer mmap nesnelerini dogrudan tarayabilir (buffer protocol).
        # [\x20-\x7E]{N,} = printable ASCII, space (0x20) - tilde (0x7E).
        ascii_re = _re.compile(
            rb"[\x20-\x7E]{%d,}" % min_length,
        )

        try:
            with open(binary_path, "rb") as f:
                # mmap ile dosyayi bellege maple (read-only)
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    file_size = mm.size()
                    for match in ascii_re.finditer(mm):
                        raw = match.group()
                        # decode kesin basarili: regex zaten ASCII range [0x20-0x7E]
                        strings.append(raw.decode("ascii"))
                        if len(strings) >= max_strings:
                            logger.info(
                                "mmap strings: max_strings (%d) limitine ulasildi "
                                "(dosyanin %.0f%%'si taranmis)",
                                max_strings,
                                (match.end() / file_size) * 100 if file_size else 100,
                            )
                            return strings

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
        """Decompiler backend'i calistir.

        v1.11.0 Phase 1B: Backend-agnostic. `config.decompilers.primary_backend`
        'ghidra' ise eski Ghidra yolu aynen korunur (3576 PASS baseline). 'angr'
        (veya ileride baska) secilirse AngrBackend.decompile() cagrilir ve
        sonuc Ghidra JSON semasina cevrilip static/'e yazilir -- downstream
        pipeline step'leri (ghidra_metadata, binary_prep, semantic_naming...)
        dokunulmadan calisir.

        Fallback: primary backend `is_available()` False ise
        `create_backend_with_fallback()` chain'i yurutur. Normalde Ghidra kurulu
        oldugu icin angr kurulu degilken angr primary secilirse Ghidra'ya duser.

        Returns:
            Ghidra analyze() ile birebir uyumlu dict (scripts_output icerir).
            Hic bir backend kullanilamiyorsa None.
        """
        primary = getattr(
            self.config.decompilers, "primary_backend", "ghidra",
        ).lower()

        # Fast path: primary == ghidra + ghidra mevcut => eski kod YOLU (TEST
        # BASELINE burasi). Dokunulmamis davranis.
        if primary == "ghidra" and self.ghidra.is_available():
            return self._run_ghidra_legacy(binary_path, workspace)

        # Backend-agnostic yol: factory ile secim + fallback.
        try:
            from karadul.decompilers import create_backend_with_fallback

            backend, tried = create_backend_with_fallback(self.config)
        except Exception as exc:
            logger.warning(
                "Decompiler backend olusturulamadi (primary=%s): %s",
                primary, exc,
            )
            # Son care: eski Ghidra yolu (mevcut self.ghidra).
            if self.ghidra.is_available():
                return self._run_ghidra_legacy(binary_path, workspace)
            return None

        if backend.name == "ghidra":
            # Factory ghidra'ya duserse eski yolu kullan -- JSON adapter
            # gereksiz (Ghidra zaten Ghidra JSON uretiyor).
            logger.info("Decompiler backend: ghidra (tried=%s)", tried)
            # Mevcut self.ghidra'yi kullan; backend lazy-init ayni instance'i
            # paylasmayabilir ama davranis aynidir.
            return self._run_ghidra_legacy(binary_path, workspace)

        # Non-Ghidra backend (angr, vs). decompile() cagir ve JSON'a cevir.
        logger.info(
            "Decompiler backend: %s (tried=%s)", backend.name, tried,
        )
        try:
            from karadul.decompilers.pipeline_adapter import (
                write_ghidra_shape_artifacts,
            )

            static_dir = workspace.get_stage_dir("static")
            decompile_out = static_dir / f"{backend.name}_output"
            decompile_out.mkdir(parents=True, exist_ok=True)

            timeout = float(
                getattr(self.config.timeouts, "ghidra_analysis", 3600),
            )
            result = backend.decompile(
                binary=binary_path,
                output_dir=decompile_out,
                timeout=timeout,
            )
        except Exception as exc:
            logger.error(
                "Non-Ghidra backend '%s' cokti: %s. Ghidra'ya dusuluyor.",
                backend.name, exc,
            )
            if self.ghidra.is_available():
                return self._run_ghidra_legacy(binary_path, workspace)
            return {"success": False, "error": str(exc)}

        # Ghidra sema'sina cevir + static/ altina yaz (downstream step'ler
        # icin).
        ghidra_dict = write_ghidra_shape_artifacts(
            result=result,
            output_dir=workspace.get_stage_dir("static"),
        )
        return ghidra_dict

    def _run_ghidra_legacy(
        self, binary_path: Path, workspace: Workspace,
    ) -> dict[str, Any] | None:
        """Orijinal Ghidra headless yolu -- 3576 PASS baseline korunur."""
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
