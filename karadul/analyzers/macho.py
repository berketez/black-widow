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


# ELF sabitleri (System V gABI): özel bölüm indisleri, bölüm tipi ve bayrakları, simge bağlama ve tipi.
_SHN_UNDEF, _SHN_ABS, _SHN_COMMON = 0, 0xFFF1, 0xFFF2
_SHT_NOBITS = 8
_SHF_WRITE, _SHF_ALLOC, _SHF_EXECINSTR = 0x1, 0x2, 0x4
_STB_GLOBAL, _STB_WEAK, _STB_GNU_UNIQUE = 1, 2, 10
_STT_OBJECT, _STT_SECTION, _STT_FILE, _STT_COMMON, _STT_GNU_IFUNC = 1, 3, 4, 5, 10


def _elf_nm_letter(
    binding: int, sym_type: int, shndx: int,
    sec_type: int | None, sec_flags: int | None,
) -> str:
    """Dış (global/zayıf) ELF simgesinin ``nm`` harfi; llvm-nm ``getNMTypeChar`` kuralı.

    Bölümü bilinmeyen tanımlı simge "?" alır (nm de öyle yazar).
    """
    if binding == _STB_WEAK:
        letter = "v" if sym_type == _STT_OBJECT else "w"
        return letter if shndx == _SHN_UNDEF else letter.upper()
    if shndx == _SHN_UNDEF:
        return "U"
    if shndx == _SHN_COMMON or sym_type == _STT_COMMON:
        return "C"
    if binding == _STB_GNU_UNIQUE:
        return "u"
    if sym_type == _STT_GNU_IFUNC:
        return "i"
    if shndx == _SHN_ABS:
        return "A"
    if sec_flags is None:
        return "?"
    if sec_flags & _SHF_EXECINSTR:
        return "T"
    if sec_type == _SHT_NOBITS:
        return "B"
    if sec_flags & _SHF_ALLOC:
        return "D" if sec_flags & _SHF_WRITE else "R"
    return "?" if sec_flags & _SHF_WRITE else "N"


# Mach-O evrensel (fat) başlığı: <mach-o/fat.h>, <mach/machine.h>.
_FAT_MAGIC, _FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
_FAT_MAX_ARCH = 64  # 0xCAFEBABE Java sınıf dosyasının da imzası; makul üst sınır
_CPU_ARCH_ABI64, _CPU_ARCH_ABI64_32 = 0x01000000, 0x02000000
_CPU_TYPE_X86, _CPU_TYPE_ARM = 7, 12
_CPU_SUBTYPE_MASK = 0x00FFFFFF
_MACHO_THIN_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")


def _fat_arch_name(cputype: int, cpusubtype: int) -> str:
    """Mimari adı (`lipo -archs` adlarıyla aynı; bilinmeyen alt tür sayısıyla yazılır)."""
    sub = cpusubtype & _CPU_SUBTYPE_MASK
    if cputype == _CPU_TYPE_ARM | _CPU_ARCH_ABI64:
        return {0: "arm64", 1: "arm64v8", 2: "arm64e"}.get(sub, "arm64_sub%d" % sub)
    if cputype == _CPU_TYPE_X86 | _CPU_ARCH_ABI64:
        return {3: "x86_64", 8: "x86_64h"}.get(sub, "x86_64_sub%d" % sub)
    if cputype == _CPU_TYPE_ARM | _CPU_ARCH_ABI64_32:
        return "arm64_32"
    if cputype == _CPU_TYPE_X86:
        return "i386"
    if cputype == _CPU_TYPE_ARM:
        return "arm_sub%d" % sub
    return "cpu%d_sub%d" % (cputype, sub)


def _fat_slice_rank(cputype: int, cpusubtype: int) -> int:
    """Küçük olan önce seçilir: arm64, arm64e, öbür arm64, x86_64, x86_64h, öbürleri."""
    sub = cpusubtype & _CPU_SUBTYPE_MASK
    if cputype == _CPU_TYPE_ARM | _CPU_ARCH_ABI64:
        return {0: 0, 1: 0, 2: 1}.get(sub, 2)
    if cputype == _CPU_TYPE_X86 | _CPU_ARCH_ABI64:
        return 3 if sub == 3 else 4
    return 5


def read_fat_slices(path: Path) -> list[dict[str, Any]]:
    """Evrensel Mach-O başlığındaki dilimler (dosya sırasıyla); başlık geçersizse ValueError."""
    import struct

    size = path.stat().st_size
    with open(path, "rb") as fh:
        head = fh.read(8)
        if len(head) < 8:
            raise ValueError("dosya fat başlığı için çok kısa")
        magic, nfat = struct.unpack(">II", head)
        if magic not in (_FAT_MAGIC, _FAT_MAGIC_64):
            raise ValueError("fat imzası yok (0x%08x)" % magic)
        if not 0 < nfat <= _FAT_MAX_ARCH:
            raise ValueError("dilim sayısı geçersiz: %d" % nfat)
        is64 = magic == _FAT_MAGIC_64
        entry_size = 32 if is64 else 20
        table = fh.read(entry_size * nfat)
    if len(table) < entry_size * nfat:
        raise ValueError("fat dilim tablosu kesik")
    slices = []
    for i in range(nfat):
        rec = table[i * entry_size:(i + 1) * entry_size]
        if is64:
            cputype, cpusubtype, offset, length, _align, _res = struct.unpack(">iiQQII", rec)
        else:
            cputype, cpusubtype, offset, length, _align = struct.unpack(">iiIII", rec)
        if length <= 0 or offset + length > size:
            raise ValueError("dilim %d dosya dışına taşıyor (ofset %d, boy %d)" % (i, offset, length))
        slices.append({
            "arch": _fat_arch_name(cputype, cpusubtype), "cputype": cputype,
            "cpusubtype": cpusubtype & 0xFFFFFFFF, "offset": offset, "size": length,
            "rank": _fat_slice_rank(cputype, cpusubtype), "index": i,
        })
    return slices


def select_fat_slice(slices: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Tercih sırasında ilk dilim; eşitlikte dosyadaki ilk (belirlenimci)."""
    return min(slices, key=lambda s: (s["rank"], s["index"])) if slices else None


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

    # static/strings_raw.json'a yazılan dizgi sınırı (kesilen sayı dosyada yazılır).
    STRINGS_RAW_LIMIT = 10000

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

        # 0. Evrensel (fat) ikiliden tek mimari dilimi çıkar. Eski kod `lipo -thin arm64`
        # deniyordu: macOS sistem ikilileri arm64e taşıdığı için bu düşüyor, x86_64'e geçip
        # dilimi yine `<ad>_arm64` adıyla yazıyordu; yalnız arm64e taşıyanlarda (ssh, sshd,
        # ioreg) ikisi de düşüp şişman dosya taranıyordu. Şimdi fat başlığı okunur, dilim
        # tercih sırasıyla seçilir (arm64 > arm64e > öbür arm64 > x86_64 > …) ve baytları
        # aynen kopyalanır (`lipo -thin` çıktısıyla bayt bayt aynı); dosya adı gerçek
        # mimariyi söyler. Seçilemezse durum açıkça yazılır.
        if target.target_type == TargetType.UNIVERSAL_BINARY:
            sliced = self._extract_universal_slice(
                Path(binary_path), workspace, target.name, stats, errors,
            )
            if sliced is not None:
                binary_path = sliced

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

        # v1.21 bug fix: dylibs ELF/PE icin (is_macho == False) hic atanmadan
        # asagidaki Binary Intelligence blogunda (satir ~319) kullaniliyordu ->
        # UnboundLocalError ("cannot access local variable 'dylibs'"). Her yolda
        # tanimli olmasi icin bastan None'a init et. Mach-O yolunda gercek deger
        # _run_otool_libs ile uzerine yazilir (mevcut davranis korunur).
        dylibs: dict[str, Any] | None = None

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
            written = min(len(string_list), self.STRINGS_RAW_LIMIT)
            strings_data = {
                "total": len(string_list),
                # Kayıp sayacı (B-B4): dosya ilk STRINGS_RAW_LIMIT dizgiyi taşır, kalanı
                # sessizce düşmez, sayısı ve nedeni yazılır.
                "written": written,
                "truncated": len(string_list) - written,
                "truncated_reason": (
                    "strings_raw.json yalnız ilk %d dizgiyi taşır" % self.STRINGS_RAW_LIMIT
                    if len(string_list) > written else None
                ),
                "strings": string_list[:written],
            }
            str_path = workspace.save_json("static", "strings_raw", strings_data)
            artifacts["strings_raw"] = str_path
            stats["string_count"] = len(string_list)
            if strings_data["truncated"]:
                stats["strings_raw_truncated"] = strings_data["truncated"]

        # 5. nm: symbol table
        symbols = self._run_nm(binary_path)
        # `nm -g` stripped ELF'te dinamik simgeleri göstermez (-D yok); PATH'teki nm ELF'i hiç
        # okumayabilir (conda cctools nm). nm simge vermediyse ELF'in dinamik simge tablosu okunur.
        if target.target_type == TargetType.ELF_BINARY and not (symbols or {}).get("symbols"):
            dynsym = self._run_elf_dynsym(binary_path)
            if dynsym is not None:
                symbols = dynsym
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
            # Rapordaki summary.total_imports bu anahtardan okunur (reporting/json_report.py).
            if "imported_functions" in lief_data:
                stats["imports_found"] = len(lief_data["imported_functions"])
        else:
            stats["lief_available"] = False

        # 7. Ghidra headless analiz
        ghidra_result = self._run_ghidra(binary_path, workspace)
        # Ghidra koştu ama başarısız olduysa ``static`` aşaması da başarısızdır (GHIDRA-09):
        # aşağı akışın tamamı decompile çıktısına dayanır; ham ikili kopyası başarı sayılmaz.
        ghidra_failed = False
        if ghidra_result is not None:
            self._record_ghidra_outcome(ghidra_result, workspace, artifacts, stats)
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
                    # "Kurtarılan fonksiyon" = programın fonksiyonları; içe aktarım taslakları
                    # (thunk) ayrı alanda (GHIDRA-10). Eski özetlerde ayrım yoksa toplam yazılır.
                    stats["ghidra_function_count"] = summary.get("function_count", 0)
                    if "function_total" in summary:
                        stats["ghidra_function_total"] = summary["function_total"]
                        stats["ghidra_thunk_count"] = summary.get("thunk_count", 0)
                        stats["ghidra_external_count"] = summary.get("external_count", 0)
                    stats["ghidra_string_count"] = summary.get("string_count", 0)
                    stats["ghidra_call_graph_edges"] = summary.get("call_graph_edges", 0)
                    stats["ghidra_decompiled"] = summary.get("decompiled_success", 0)
                # Başarıyı bozmayan ama düşen adımlar (dizgi, tip, xref, CFG, BSim …) görünür olsun.
                for step, msg in sorted((ghidra_result.get("step_errors") or {}).items()):
                    errors.append("Ghidra adımı başarısız (%s): %s" % (step, msg))
            else:
                ghidra_failed = True
                reason = ghidra_result.get("error") or "neden bildirilmedi"
                rc = ghidra_result.get("returncode")
                if isinstance(rc, int) and not isinstance(rc, bool):
                    reason = "%s (çıkış kodu %d)" % (reason, rc)
                errors.append("Ghidra analizi başarısız: %s" % reason)
                stats["ghidra_success"] = False
                stats["ghidra_error"] = reason
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
            success=(not ghidra_failed) and (len(errors) == 0 or len(artifacts) > 0),
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

    def _run_elf_dynsym(self, binary_path: Path) -> dict[str, Any] | None:
        """ELF dinamik simge tablosunun dış simgeleri, ``nm -gD`` kayıtlarıyla aynı biçimde.

        Ad sürüm eki (``@GLIBC_2.17``) taşımaz. lief yoksa ya da tablo okunamazsa None.
        """
        try:
            import lief
        except ImportError:
            return None

        try:
            binary = lief.parse(str(binary_path))
            if binary is None:
                return None
            width = 16 if int(binary.header.identity_class) == 2 else 8  # ELFCLASS64 = 2
            symbols: list[dict[str, Any]] = []
            for sym in binary.dynamic_symbols:
                binding, sym_type = int(sym.binding), int(sym.type)
                # nm -g yalnız dış simgeleri yazar; bölüm/dosya simgeleri ve adsız giriş atlanır.
                if (
                    not sym.name
                    or binding not in (_STB_GLOBAL, _STB_WEAK, _STB_GNU_UNIQUE)
                    or sym_type in (_STT_SECTION, _STT_FILE)
                ):
                    continue
                sec = sym.section if sym.shndx not in (_SHN_UNDEF, _SHN_ABS, _SHN_COMMON) else None
                letter = _elf_nm_letter(
                    binding, sym_type, sym.shndx,
                    int(sec.type) if sec is not None else None,
                    int(sec.flags) if sec is not None else None,
                )
                symbols.append({
                    "address": None if sym.shndx == _SHN_UNDEF else f"{sym.value:0{width}x}",
                    "type": letter,
                    "name": sym.name,
                })
        except Exception as exc:
            logger.warning("ELF dinamik simge tablosu okunamadi: %s", exc)
            return None

        return {
            "binary": str(binary_path),
            "total": len(symbols),
            "symbols": symbols,
            "source": "elf_dynamic_symbols",
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

            # Libraries: lief 0.17'de Mach-O DylibCommand nesnesi (.name) verir, ELF ve PE düz
            # metin (str'de .name yok; eskiden ELF listesi hep boş kalıyordu). İkisi de okunur.
            if hasattr(binary, "libraries"):
                for lib in binary.libraries:
                    lib_name = lib if isinstance(lib, str) else getattr(lib, "name", None)
                    if lib_name is not None:
                        result["libraries"].append(str(lib_name))

            # İthal fonksiyon adları (rapordaki total_imports bunların sayısıdır). Ayrı try: okunamazsa
            # öbür alanlar yine döner, anahtar hiç yazılmaz (sayı bilinmiyor, 0 değil).
            try:
                result["imported_functions"] = [
                    str(getattr(fn, "name", fn)) for fn in binary.imported_functions
                ]
            except Exception:
                logger.debug("lief imported_functions okunamadi", exc_info=True)

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

    @staticmethod
    def _extract_universal_slice(
        fat_path: Path, workspace: Workspace, target_name: str,
        stats: dict[str, Any], errors: list[str],
    ) -> Path | None:
        """Evrensel ikiliden seçilen dilimi ``raw/<ad>_<mimari>``'ye yaz; seçim dosyası static'te.

        Dönüş: dilim yolu; seçilemezse None (çağıran şişman dosyayla sürer, neden ``errors``'ta
        ve ``stats.universal_slice_error``'da). ``static/universal_slice.json`` aşağı akışın
        (``binary_prep``) hangi dosyayı kullanacağını söyler.
        """
        static_dir = workspace.get_stage_dir("static")
        try:
            slices = read_fat_slices(fat_path)
        except (OSError, ValueError) as exc:
            reason = "fat başlığı okunamadı: %s" % exc
            slices, chosen = [], None
        else:
            chosen = select_fat_slice(slices)
            reason = None if chosen else "dilim yok"
        stats["universal_slices"] = [s["arch"] for s in slices]
        thin_path: Path | None = None
        if chosen is not None:
            thin_path = workspace.get_stage_dir("raw") / f"{target_name}_{chosen['arch']}"
            try:
                with open(fat_path, "rb") as src:
                    src.seek(chosen["offset"])
                    data = src.read(chosen["size"])
                if len(data) != chosen["size"] or data[:4] not in _MACHO_THIN_MAGICS:
                    raise ValueError("dilim %s Mach-O değil ya da kesik" % chosen["arch"])
                thin_path.write_bytes(data)
            except (OSError, ValueError) as exc:
                reason = "dilim %s çıkarılamadı: %s" % (chosen["arch"], exc)
                thin_path = None
        record: dict[str, Any] = {
            "slices": [{k: s[k] for k in ("arch", "cputype", "cpusubtype", "offset", "size")}
                       for s in slices],
            "selected": chosen["arch"] if thin_path is not None else None,
            "path": thin_path.name if thin_path is not None else None,
            "error": reason,
        }
        try:
            workspace.save_json("static", "universal_slice", record)
        except Exception as exc:  # pragma: no cover - savunma
            logger.warning("universal_slice.json yazilamadi (%s): %s", static_dir, exc)
        if thin_path is None:
            stats["universal_slice"] = None
            stats["universal_slice_error"] = reason
            errors.append("Evrensel ikiliden dilim seçilemedi (%s); şişman dosya analiz edildi"
                          % reason)
            logger.warning("Evrensel ikili: dilim secilemedi: %s", reason)
            return None
        stats["universal_slice"] = chosen["arch"]
        logger.info("Evrensel ikili: %s dilimi secildi (%s) -> %s",
                    chosen["arch"], ", ".join(stats["universal_slices"]), thin_path)
        return thin_path

    @staticmethod
    def _record_ghidra_outcome(
        ghidra_result: dict[str, Any], workspace: Workspace,
        artifacts: dict[str, Path], stats: dict[str, Any],
    ) -> None:
        """Ghidra'nın günlüğünü ve sonuç durumunu başarıdan bağımsız olarak diske yaz (GHIDRA-09).

        ``static/ghidra_log.txt``: her çıkarım adımının OK/WARN/FAIL/FATAL satırı (eskiden hiçbir
        yere yazılmıyordu). ``static/ghidra_status.json``: başarı, neden, düşen adımlar, fonksiyon
        sayıları (program / thunk / dış) ve decompile kayıp sayaçları.
        """
        log_text = ghidra_result.get("ghidra_log")
        if log_text:
            try:
                artifacts["ghidra_log"] = workspace.save_artifact(
                    "static", "ghidra_log.txt", log_text,
                )
            except Exception as exc:
                logger.warning("Ghidra gunlugu yazilamadi: %s", exc)
        out = ghidra_result.get("scripts_output") or {}
        funcs = out.get("functions") or {}
        dec = out.get("decompiled") or {}
        status = {
            "success": bool(ghidra_result.get("success")),
            "error": ghidra_result.get("error"),
            "step_errors": ghidra_result.get("step_errors") or {},
            "mode": ghidra_result.get("mode"),
            "returncode": ghidra_result.get("returncode"),
            "duration_seconds": ghidra_result.get("duration_seconds"),
            "functions": {
                k: funcs[k] for k in (
                    "total", "program_function_count", "thunk_count", "external_count",
                ) if k in funcs
            },
            "decompile": {
                k: dec[k] for k in (
                    "total_attempted", "success", "failed", "skipped",
                    "functions_total", "functions_written", "functions_truncated",
                    "functions_order", "losses",
                ) if k in dec
            },
            "outputs": sorted(out.keys()),
        }
        try:
            artifacts["ghidra_status"] = workspace.save_json("static", "ghidra_status", status)
        except Exception as exc:
            logger.warning("Ghidra durum dosyasi yazilamadi: %s", exc)
        if status["step_errors"]:
            stats["ghidra_step_errors"] = dict(sorted(status["step_errors"].items()))
        truncated = status["decompile"].get("functions_truncated")
        if truncated:
            stats["ghidra_decompiled_json_truncated"] = truncated

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

        # Varsayilan scriptleri al. Betikler yalnız analyzeHeadless (CLI) yolunda koşar;
        # PyGhidra yolu Ghidra API'sini doğrudan kullanır. Eski kod betik yoksa Ghidra'yı
        # hiç çalıştırmadan None dönüyordu ve sonuç "Ghidra yok" gibi görünüyordu.
        scripts = self.ghidra.get_default_scripts()
        pyghidra_ok = bool(getattr(self.ghidra, "pyghidra_available", lambda: False)())
        if not scripts and not pyghidra_ok:
            logger.warning("Ghidra scriptleri bulunamadi: %s", self.config.ghidra_scripts_dir)
            return {
                "success": False,
                "error": "Ghidra betikleri bulunamadı (%s); PyGhidra yokken analyzeHeadless "
                         "yalnız bu betiklerle çıktı üretir" % self.config.ghidra_scripts_dir,
            }

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
