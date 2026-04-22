"""Swift binary analiz modulu.

macOS/iOS uygulamalari icin Swift-spesifik analiz:
- Swift demangle: Mangled Swift sembollerini coz ($s prefix)
- ObjC interop metadata: @objc class'lar, bridge fonksiyonlar
- Swift protocol witness table: Protocol conformance
- Swift type metadata: struct/class/enum tanimlari
- String interpolation kalintilari: Degisken isimleri

Swift binary'ler Mach-O formatindadir. Bu analyzer MACHO_BINARY
tipini destekler ama registry'ye KAYIT OLMAZ (MachOAnalyzer zaten
kayitli). Bunun yerine can_handle() ile Swift binary mi tespit eder
ve MachOAnalyzer sonuclarina ek olarak Swift-spesifik bilgi cikarir.

Strateji:
1. can_handle ile Swift binary tespit ($s prefix symbols, _swift_ refs)
2. xcrun swift-demangle ile mangled sembol cozumleme
3. strings + regex fallback (xcrun yoksa)
4. ObjC interop metadata extraction (_OBJC_CLASS_$_ refs)
5. Protocol witness table extraction
6. Type metadata (struct/class/enum) extraction
"""

from __future__ import annotations

import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any

from karadul.analyzers.base import BaseAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Swift binary tanimlama pattern'leri
# --------------------------------------------------------------------------

# Swift mangled sembol prefix'leri
# Swift 5+: $s veya $S prefix
# Eski Swift (4.x): _$s veya _$S
_SWIFT_MANGLED_PREFIX = re.compile(r"[\s_]?\$[sS][a-zA-Z0-9_]+")

# Swift runtime kütüphane referanslari
_SWIFT_RUNTIME_SIGNATURES = [
    "_swift_allocObject",
    "_swift_release",
    "_swift_retain",
    "swift_getObjectType",
    "_swift_bridgeObjectRelease",
    "_swift_beginAccess",
    "_swift_endAccess",
    "libswiftCore",
    "libswiftFoundation",
    "Swift.String",
    "Swift.Int",
    "Swift.Array",
    "Swift.Optional",
    "swift::metadataimpl",
    "swift_conformsToProtocol",
]

# ObjC interop pattern'leri
_OBJC_CLASS_REF = re.compile(r"_OBJC_CLASS_\$_(\w+)")
_OBJC_METACLASS_REF = re.compile(r"_OBJC_METACLASS_\$_(\w+)")

# Swift protocol witness table
_PROTOCOL_WITNESS = re.compile(
    r"protocol witness for ([^\s]+) in conformance ([^\s]+)"
)
# Fallback: mangled protocol conformance ($s...WP suffix)
_PROTOCOL_CONFORMANCE_MANGLED = re.compile(r"\$[sS][a-zA-Z0-9_]+WP\b")

# Swift type metadata pattern'leri
_TYPE_METADATA = re.compile(
    r"type metadata (?:accessor for |for )([^\s]+(?:\.[^\s]+)*)"
)
_NOMINAL_TYPE_DESCRIPTOR = re.compile(
    r"nominal type descriptor for ([^\s]+(?:\.[^\s]+)*)"
)

# Swift demangled fonksiyon pattern'i
_SWIFT_FUNC_PATTERN = re.compile(
    r"^(?:(?:static )?)?(\S+?)\.(\S+)\(.*?\)"
)

# String interpolation kalintisi pattern'leri
_STRING_INTERP = re.compile(
    r"[\w.]+\.(?:init|description|debugDescription|customMirror)"
)

# Swift enum case pattern
_ENUM_CASE = re.compile(
    r"enum case (?:for )?(\S+(?:\.\S+)*)"
)


class SwiftBinaryAnalyzer(BaseAnalyzer):
    """Swift binary analiz motoru.

    Swift binary'lerin icindeki Swift-spesifik metadata'yi cikarir:
    - Demangled sembol isimleri (xcrun swift-demangle veya regex fallback)
    - ObjC interop class/protocol referanslari
    - Protocol witness table (conformance bilgisi)
    - Type metadata (struct/class/enum tanimlari)
    - String interpolation kalintilari

    NOT: Bu analyzer MACHO_BINARY registry'sine KAYIT OLMAZ.
    MachOAnalyzer zaten MACHO_BINARY icin kayitli. Bu analyzer
    ek bir katman olarak can_handle() ile Swift binary tespit eder
    ve ek bilgi cikarir.
    """

    supported_types = [TargetType.MACHO_BINARY]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.runner = SubprocessRunner(config)
        self._swift_demangle_available: bool | None = None

    # ------------------------------------------------------------------
    # Swift binary tespit
    # ------------------------------------------------------------------

    @staticmethod
    def can_handle(target_info: TargetInfo) -> bool:
        """Swift binary mi kontrol et.

        Binary icinde Swift-spesifik sembol ve runtime referanslarina bakar.
        En az 2 Swift signature bulunmasi veya $s prefix'li mangled
        sembol bulunmasi gerekir.

        Args:
            target_info: Hedef bilgileri.

        Returns:
            True ise Swift binary.
        """
        # Hizli kontrol: language zaten SWIFT ise
        if target_info.language == Language.SWIFT:
            return True

        # TargetType kontrolu
        if target_info.target_type not in (
            TargetType.MACHO_BINARY,
            TargetType.UNIVERSAL_BINARY,
        ):
            return False

        try:
            with open(target_info.path, "rb") as f:
                # Ilk 2MB'i oku (Swift metadata genellikle burada)
                data = f.read(2 * 1024 * 1024)
        except OSError:
            return False

        text = data.decode("ascii", errors="replace")

        # Swift runtime signature kontrolu
        hits = sum(1 for sig in _SWIFT_RUNTIME_SIGNATURES if sig in text)
        if hits >= 2:
            return True

        # $s prefix mangled sembol kontrolu
        swift_mangled = _SWIFT_MANGLED_PREFIX.findall(text[:500_000])
        if len(swift_mangled) >= 5:
            return True

        return False

    # ------------------------------------------------------------------
    # Public interface (BaseAnalyzer)
    # ------------------------------------------------------------------

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Swift binary statik analizi.

        Siralama:
        1. Raw binary'yi kopyala
        2. Swift sembol demangle (xcrun swift-demangle veya regex)
        3. ObjC interop metadata extraction
        4. Protocol witness table extraction
        5. Type metadata extraction
        6. String extraction ve analiz

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
            "analyzer": "swift_binary",
            "swift_demangle_available": self._check_swift_demangle(),
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

        # 2. Swift sembol demangle
        swift_symbols = self._demangle_swift_symbols(binary_path)
        if swift_symbols and swift_symbols.get("symbols"):
            sym_path = workspace.save_json("static", "swift_symbols", swift_symbols)
            artifacts["swift_symbols"] = sym_path
            stats["swift_symbol_count"] = len(swift_symbols["symbols"])
            stats["demangled_count"] = swift_symbols.get("demangled_count", 0)
            stats["demangle_method"] = swift_symbols.get("method", "unknown")
            logger.info(
                "Swift symbols: %d total, %d demangled (method=%s)",
                len(swift_symbols["symbols"]),
                swift_symbols.get("demangled_count", 0),
                swift_symbols.get("method", "unknown"),
            )
        else:
            errors.append("Swift sembol extraction basarisiz veya bos")
            stats["swift_symbol_count"] = 0

        # 3. ObjC interop metadata
        objc_interop = self._extract_objc_interop(binary_path)
        if objc_interop and (objc_interop.get("classes") or objc_interop.get("metaclasses")):
            objc_path = workspace.save_json("static", "objc_interop", objc_interop)
            artifacts["objc_interop"] = objc_path
            stats["objc_class_count"] = len(objc_interop.get("classes", []))
            stats["objc_metaclass_count"] = len(objc_interop.get("metaclasses", []))
            logger.info(
                "ObjC interop: %d classes, %d metaclasses",
                len(objc_interop.get("classes", [])),
                len(objc_interop.get("metaclasses", [])),
            )

        # 4. Protocol witness table
        protocols = self._extract_protocols(binary_path)
        if protocols and protocols.get("witnesses"):
            proto_path = workspace.save_json("static", "swift_protocols", protocols)
            artifacts["swift_protocols"] = proto_path
            stats["protocol_witness_count"] = len(protocols["witnesses"])
            stats["protocol_conformance_count"] = protocols.get(
                "mangled_conformance_count", 0,
            )
            logger.info(
                "Protocols: %d witnesses, %d conformances",
                len(protocols["witnesses"]),
                protocols.get("mangled_conformance_count", 0),
            )

        # 5. Type metadata
        types = self._extract_type_metadata(binary_path)
        if types and (types.get("types") or types.get("nominal_descriptors")):
            types_path = workspace.save_json("static", "swift_types", types)
            artifacts["swift_types"] = types_path
            stats["type_count"] = len(types.get("types", []))
            stats["nominal_descriptor_count"] = len(types.get("nominal_descriptors", []))
            stats["enum_case_count"] = len(types.get("enum_cases", []))
            logger.info(
                "Types: %d metadata, %d nominal descriptors, %d enum cases",
                len(types.get("types", [])),
                len(types.get("nominal_descriptors", [])),
                len(types.get("enum_cases", [])),
            )

        # 6. Strings extraction
        string_list = self.runner.run_strings(binary_path)
        if string_list:
            # Swift-specific string'leri filtrele
            swift_strings = self._filter_swift_strings(string_list)
            strings_data = {
                "total_strings": len(string_list),
                "swift_relevant_count": len(swift_strings),
                "swift_strings": swift_strings[:5000],
                "all_strings": string_list[:10000],
            }
            str_path = workspace.save_json("static", "strings_raw", strings_data)
            artifacts["strings_raw"] = str_path
            stats["string_count"] = len(string_list)
            stats["swift_string_count"] = len(swift_strings)

        # 7. nm symbol table
        symbols = self._run_nm(binary_path)
        if symbols is not None:
            sym_path = workspace.save_json("static", "symbols", symbols)
            artifacts["symbols"] = sym_path
            stats["symbol_count"] = len(symbols.get("symbols", []))

        duration = time.monotonic() - start
        stats["total_duration"] = round(duration, 3)

        has_useful_data = bool(
            swift_symbols and swift_symbols.get("symbols")
        ) or bool(
            objc_interop and objc_interop.get("classes")
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
        """Swift binary deobfuscation.

        Swift binary'ler icin deobfuscation = demangled sembol tablosu.
        Statik analiz ciktisindaki demangled Swift sembollerini
        deobfuscated dizinine tasir.
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []

        # Swift symbols verisini deobfuscated dizinine tasi
        swift_symbols = workspace.load_json("static", "swift_symbols")
        if swift_symbols:
            deobf_path = workspace.save_json(
                "deobfuscated", "swift_symbols_resolved", swift_symbols,
            )
            artifacts["swift_symbols_resolved"] = deobf_path
        else:
            errors.append(
                "Swift sembol verisi bulunamadi — statik analiz basarisiz olmus olabilir"
            )

        # ObjC interop verisini de tasi
        objc_interop = workspace.load_json("static", "objc_interop")
        if objc_interop:
            objc_path = workspace.save_json(
                "deobfuscated", "objc_interop_resolved", objc_interop,
            )
            artifacts["objc_interop_resolved"] = objc_path

        # Protocol verisini de tasi
        protocols = workspace.load_json("static", "swift_protocols")
        if protocols:
            proto_path = workspace.save_json(
                "deobfuscated", "swift_protocols_resolved", protocols,
            )
            artifacts["swift_protocols_resolved"] = proto_path

        # Type metadata
        types = workspace.load_json("static", "swift_types")
        if types:
            types_path = workspace.save_json(
                "deobfuscated", "swift_types_resolved", types,
            )
            artifacts["swift_types_resolved"] = types_path

        return StageResult(
            stage_name="deobfuscate",
            success=len(errors) == 0 or len(artifacts) > 0,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Private helper metodlar
    # ------------------------------------------------------------------

    def _check_swift_demangle(self) -> bool:
        """xcrun swift-demangle mevcut mu kontrol et."""
        if self._swift_demangle_available is not None:
            return self._swift_demangle_available

        result = self.runner.run_command(
            ["xcrun", "swift-demangle", "--version"],
            timeout=10,
        )
        self._swift_demangle_available = result.success
        if not result.success:
            logger.debug("xcrun swift-demangle mevcut degil, regex fallback kullanilacak")
        return self._swift_demangle_available

    def _demangle_swift_symbols(self, binary_path: Path) -> dict[str, Any] | None:
        """Swift mangled sembollerini coz.

        Strateji:
        1. nm ile mangled sembol listesini al
        2. $s/$S prefix'li semolleri filtrele
        3. xcrun swift-demangle ile toplu demangle (varsa)
        4. Yoksa regex-based temel cozumleme (fallback)
        """
        # nm ile tum sembolleri al
        nm_result = self.runner.run_command(
            [str(self.config.tools.nm), "-g", str(binary_path)],
            timeout=60,
        )

        mangled_symbols: list[str] = []
        all_nm_symbols: list[dict[str, str]] = []

        if nm_result.success:
            for line in nm_result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 2)
                name = ""
                sym_type = ""
                address = ""
                if len(parts) == 3:
                    address, sym_type, name = parts
                elif len(parts) == 2:
                    sym_type, name = parts

                if name:
                    all_nm_symbols.append({
                        "address": address or None,
                        "type": sym_type,
                        "name": name,
                    })
                    # Swift mangled sembol tespiti
                    clean = name.lstrip("_")
                    if clean.startswith("$s") or clean.startswith("$S"):
                        mangled_symbols.append(name)

        # strings fallback: nm basarisiz ise veya mangled sembol bulunamadiysa
        if not mangled_symbols:
            string_list = self.runner.run_strings(binary_path)
            for s in string_list:
                s_clean = s.strip().lstrip("_")
                if s_clean.startswith("$s") or s_clean.startswith("$S"):
                    mangled_symbols.append(s.strip())

        if not mangled_symbols:
            return {"symbols": [], "demangled_count": 0, "method": "none"}

        # Demangle: xcrun swift-demangle tercih, regex fallback
        if self._check_swift_demangle():
            return self._demangle_with_xcrun(mangled_symbols, all_nm_symbols)
        else:
            return self._demangle_with_regex(mangled_symbols, all_nm_symbols)

    def _demangle_with_xcrun(
        self,
        mangled: list[str],
        all_symbols: list[dict[str, str]],
    ) -> dict[str, Any]:
        """xcrun swift-demangle ile toplu demangle.

        Mangled sembolleri stdin'den pipe ile verir, demangled ciktiyi okur.
        Bu sayede N sembol icin tek subprocess fork yeterli (eskiden N fork).
        """
        import subprocess

        batch_size = 5000
        demangled_map: dict[str, str] = {}

        for i in range(0, len(mangled), batch_size):
            batch = mangled[i:i + batch_size]
            input_text = "\n".join(batch) + "\n"

            # v1.10.0 Fix Sprint HIGH-5: Popen context manager + timeout
            # kill/wait ile kaynak sizintisi onleme.
            try:
                with subprocess.Popen(
                    ["xcrun", "swift-demangle"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ) as proc:
                    try:
                        stdout, _ = proc.communicate(input_text, timeout=60)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        try:
                            proc.communicate(timeout=5)
                        except Exception:
                            pass
                        logger.warning(
                            "xcrun swift-demangle batch timeout (batch %d)", i,
                        )
                        continue
                    output_lines = stdout.strip().split("\n")

                    # xcrun swift-demangle satir satir okuyup satir satir yazar
                    for sym, demangled in zip(batch, output_lines):
                        demangled = demangled.strip()
                        if demangled and demangled != sym:
                            demangled_map[sym] = demangled
            except OSError as exc:
                logger.warning("xcrun swift-demangle batch hatasi: %s", exc)

        symbols = []
        for sym in mangled:
            entry: dict[str, Any] = {"mangled": sym}
            if sym in demangled_map:
                entry["demangled"] = demangled_map[sym]
            symbols.append(entry)

        return {
            "total": len(mangled),
            "demangled_count": len(demangled_map),
            "method": "xcrun_swift_demangle",
            "symbols": symbols,
        }

    def _demangle_with_regex(
        self,
        mangled: list[str],
        all_symbols: list[dict[str, str]],
    ) -> dict[str, Any]:
        """Regex-based temel Swift sembol cozumleme (fallback).

        xcrun yoksa temel pattern matching ile sembol tiplerini tespit eder.
        Tam demangle yapmaz ama sembol TIPINI (function, type, protocol vb.)
        belirler.
        """
        symbols = []
        demangled_count = 0

        for sym in mangled:
            entry: dict[str, Any] = {"mangled": sym}
            clean = sym.lstrip("_")

            # Temel suffix-based tip tespiti
            # Swift mangling suffix'leri:
            #   ...C  = class
            #   ...V  = struct
            #   ...O  = enum
            #   ...P  = protocol
            #   ...WP = protocol witness table
            #   ...Ma = type metadata accessor
            #   ...N  = nominal type descriptor
            #   ...fC = function (method)
            kind = "unknown"
            if clean.endswith("WP"):
                kind = "protocol_witness"
            elif clean.endswith("Ma"):
                kind = "type_metadata_accessor"
            elif clean.endswith("MC") or clean.endswith("fC"):
                kind = "function"
            elif clean.endswith("N"):
                kind = "nominal_type_descriptor"
            elif re.search(r"C\d+", clean):
                kind = "class_or_method"
            elif re.search(r"V\d+", clean):
                kind = "struct"
            elif re.search(r"O\d+", clean):
                kind = "enum"
            elif re.search(r"P\d+", clean):
                kind = "protocol"

            if kind != "unknown":
                entry["kind"] = kind
                demangled_count += 1

            symbols.append(entry)

        return {
            "total": len(mangled),
            "demangled_count": demangled_count,
            "method": "regex_fallback",
            "symbols": symbols,
        }

    def _extract_objc_interop(self, binary_path: Path) -> dict[str, Any] | None:
        """ObjC interop class referanslarini cikar.

        _OBJC_CLASS_$_ClassName ve _OBJC_METACLASS_$_ClassName
        pattern'lerini nm ve strings ciktisinda arar.
        """
        classes: list[str] = []
        metaclasses: list[str] = []
        bridge_methods: list[str] = []

        # nm ile sembol tablosu
        nm_result = self.runner.run_command(
            [str(self.config.tools.nm), str(binary_path)],
            timeout=60,
        )

        search_text = ""
        if nm_result.success:
            search_text = nm_result.stdout
        else:
            # Fallback: strings
            string_list = self.runner.run_strings(binary_path)
            search_text = "\n".join(string_list)

        # ObjC class referanslari
        for match in _OBJC_CLASS_REF.finditer(search_text):
            cls_name = match.group(1)
            if cls_name not in classes:
                classes.append(cls_name)

        # ObjC metaclass referanslari
        for match in _OBJC_METACLASS_REF.finditer(search_text):
            meta_name = match.group(1)
            if meta_name not in metaclasses:
                metaclasses.append(meta_name)

        # @objc bridge metod tespiti (demangled ciktidan)
        # strings'te "@objc" pattern'i ara
        string_list = self.runner.run_strings(binary_path)
        for s in string_list:
            if "@objc" in s and "." in s:
                bridge_methods.append(s.strip())

        if not classes and not metaclasses:
            return None

        return {
            "classes": sorted(classes),
            "metaclasses": sorted(metaclasses),
            "bridge_methods": bridge_methods[:500],
            "total_classes": len(classes),
            "total_metaclasses": len(metaclasses),
        }

    def _extract_protocols(self, binary_path: Path) -> dict[str, Any] | None:
        """Swift protocol witness table bilgisini cikar.

        Demangled sembollerden protocol witness pattern'lerini arar.
        Ayrica mangled sembollerden $s...WP (protocol conformance) sayar.
        """
        witnesses: list[dict[str, str]] = []
        mangled_conformances: list[str] = []

        # nm ile sembol tablosu
        nm_result = self.runner.run_command(
            [str(self.config.tools.nm), str(binary_path)],
            timeout=60,
        )

        nm_text = nm_result.stdout if nm_result.success else ""

        # xcrun swift-demangle ile toplu demangle (stdin pipe)
        if self._check_swift_demangle() and nm_text:
            import subprocess

            # Mangled swift sembollerini filtrele
            swift_syms = []
            for line in nm_text.splitlines():
                parts = line.strip().split(None, 2)
                name = parts[-1] if parts else ""
                clean = name.lstrip("_")
                if clean.startswith("$s") or clean.startswith("$S"):
                    swift_syms.append(name)

            # Toplu demangle: tek subprocess, stdin pipe
            # v1.10.0 Fix Sprint HIGH-5: Popen context manager -- proses kapanma
            # ve FD sizinti engelleme.
            if swift_syms:
                syms_batch = swift_syms[:3000]  # limit
                input_text = "\n".join(syms_batch) + "\n"
                try:
                    with subprocess.Popen(
                        ["xcrun", "swift-demangle"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    ) as proc:
                        try:
                            stdout, _ = proc.communicate(input_text, timeout=60)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            try:
                                proc.communicate(timeout=5)
                            except Exception:
                                pass
                            logger.warning("xcrun swift-demangle protocol batch timeout")
                            stdout = ""
                        output_lines = stdout.strip().split("\n") if stdout else []

                        for sym, demangled in zip(syms_batch, output_lines):
                            demangled = demangled.strip()
                            match = _PROTOCOL_WITNESS.search(demangled)
                            if match:
                                witnesses.append({
                                    "protocol_method": match.group(1),
                                    "conformance": match.group(2),
                                    "mangled": sym,
                                })
                except OSError as exc:
                    logger.warning("xcrun swift-demangle protocol batch hatasi: %s", exc)
        else:
            # Fallback: strings'te protocol witness pattern'i ara
            string_list = self.runner.run_strings(binary_path)
            for s in string_list:
                match = _PROTOCOL_WITNESS.search(s)
                if match:
                    witnesses.append({
                        "protocol_method": match.group(1),
                        "conformance": match.group(2),
                    })

        # Mangled conformance sayimi ($s...WP)
        search_text = nm_text or "\n".join(self.runner.run_strings(binary_path))
        for match in _PROTOCOL_CONFORMANCE_MANGLED.finditer(search_text):
            mangled_conformances.append(match.group(0))

        if not witnesses and not mangled_conformances:
            return None

        return {
            "witnesses": witnesses,
            "mangled_conformance_count": len(mangled_conformances),
            "mangled_conformances": mangled_conformances[:500],
        }

    def _extract_type_metadata(self, binary_path: Path) -> dict[str, Any] | None:
        """Swift type metadata cikar.

        Demangled sembollerden type metadata accessor ve
        nominal type descriptor pattern'lerini arar.
        """
        types: list[dict[str, str]] = []
        nominal_descriptors: list[str] = []
        enum_cases: list[str] = []

        # Oncelikle demangled semboller gerekiyor
        # strings fallback her zaman calisiyor
        string_list = self.runner.run_strings(binary_path)
        full_text = "\n".join(string_list)

        # Type metadata accessor pattern
        for match in _TYPE_METADATA.finditer(full_text):
            type_name = match.group(1)
            types.append({"name": type_name, "kind": "metadata"})

        # Nominal type descriptor
        for match in _NOMINAL_TYPE_DESCRIPTOR.finditer(full_text):
            desc = match.group(1)
            if desc not in nominal_descriptors:
                nominal_descriptors.append(desc)

        # Enum case'ler
        for match in _ENUM_CASE.finditer(full_text):
            case_name = match.group(1)
            if case_name not in enum_cases:
                enum_cases.append(case_name)

        # xcrun swift-demangle ile zengin metadata (toplu stdin pipe)
        if self._check_swift_demangle():
            import subprocess

            nm_result = self.runner.run_command(
                [str(self.config.tools.nm), str(binary_path)],
                timeout=60,
            )
            if nm_result.success:
                # Metadata ve descriptor sembollerini topla
                metadata_syms = []  # (name, kind) tuples
                for line in nm_result.stdout.splitlines():
                    parts = line.strip().split(None, 2)
                    name = parts[-1] if parts else ""
                    clean = name.lstrip("_")

                    if clean.startswith(("$s", "$S")) and clean.endswith("Ma"):
                        metadata_syms.append((name, "metadata_accessor"))
                    elif clean.startswith(("$s", "$S")) and clean.endswith("N"):
                        metadata_syms.append((name, "nominal_descriptor"))

                # Toplu demangle: tek subprocess
                # v1.10.0 Fix Sprint HIGH-5: Popen context manager.
                if metadata_syms:
                    sym_names = [s[0] for s in metadata_syms]
                    input_text = "\n".join(sym_names) + "\n"
                    try:
                        with subprocess.Popen(
                            ["xcrun", "swift-demangle"],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        ) as proc:
                            try:
                                stdout, _ = proc.communicate(input_text, timeout=60)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                try:
                                    proc.communicate(timeout=5)
                                except Exception:
                                    pass
                                logger.warning("xcrun swift-demangle type metadata timeout")
                                stdout = ""
                            output_lines = stdout.strip().split("\n") if stdout else []

                            for (name, kind), demangled in zip(metadata_syms, output_lines):
                                demangled = demangled.strip()
                                if kind == "metadata_accessor":
                                    tm_match = _TYPE_METADATA.search(demangled)
                                    if tm_match:
                                        type_name = tm_match.group(1)
                                        if not any(t["name"] == type_name for t in types):
                                            types.append({
                                                "name": type_name,
                                                "kind": "metadata_accessor",
                                                "mangled": name,
                                            })
                                elif kind == "nominal_descriptor":
                                    nd_match = _NOMINAL_TYPE_DESCRIPTOR.search(demangled)
                                    if nd_match:
                                        desc = nd_match.group(1)
                                        if desc not in nominal_descriptors:
                                            nominal_descriptors.append(desc)
                    except OSError as exc:
                        logger.warning("xcrun swift-demangle type metadata batch hatasi: %s", exc)

        if not types and not nominal_descriptors and not enum_cases:
            return None

        return {
            "types": types,
            "nominal_descriptors": nominal_descriptors,
            "enum_cases": enum_cases,
            "total_types": len(types),
            "total_nominal_descriptors": len(nominal_descriptors),
            "total_enum_cases": len(enum_cases),
        }

    def _filter_swift_strings(self, string_list: list[str]) -> list[str]:
        """String listesinden Swift-relevant olanlari filtrele.

        Swift runtime, framework, protocol ve type referanslarini
        iceren string'leri dondurur.
        """
        swift_keywords = {
            "Swift.", "swift_", "$s", "$S",
            "@objc", "NSObject", "UIKit",
            "SwiftUI", "Combine", "Foundation",
            "protocol witness", "type metadata",
            "nominal type descriptor",
            ".init(", ".deinit",
        }

        result = []
        for s in string_list:
            s_stripped = s.strip()
            if not s_stripped or len(s_stripped) < 4:
                continue
            for kw in swift_keywords:
                if kw in s_stripped:
                    result.append(s_stripped)
                    break

        return result

    def _run_nm(self, binary_path: Path) -> dict[str, Any] | None:
        """nm ile symbol table'i cikar."""
        nm_path = str(self.config.tools.nm)
        result = self.runner.run_command(
            [nm_path, "-g", str(binary_path)],
            timeout=60,
        )
        if not result.success:
            logger.debug("nm basarisiz: %s", result.stderr[:200] if result.stderr else "")
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
