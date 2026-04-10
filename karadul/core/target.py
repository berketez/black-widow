"""Target detection sistemi.

Verilen dosya/dizin icin hedef tipini, dilini ve metadata'sini tespit eder.
Magic bytes, dosya uzantisi ve icerik analizi kullanir.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TargetType(Enum):
    """Hedef dosya tipleri."""

    JS_BUNDLE = "js_bundle"
    ELECTRON_APP = "electron_app"
    MACHO_BINARY = "macho_binary"
    UNIVERSAL_BINARY = "universal_binary"
    GO_BINARY = "go_binary"
    BUN_BINARY = "bun_binary"
    ELF_BINARY = "elf_binary"
    PE_BINARY = "pe_binary"
    JAVA_JAR = "java_jar"
    ANDROID_APK = "android_apk"
    DOTNET_ASSEMBLY = "dotnet_assembly"
    DELPHI_BINARY = "delphi_binary"
    PYTHON_PACKED = "python_packed"
    APP_BUNDLE = "app_bundle"
    UNKNOWN = "unknown"


class Language(Enum):
    """Kaynak dil tespiti."""

    JAVASCRIPT = "javascript"
    RUST = "rust"
    GO = "go"
    SWIFT = "swift"
    C = "c"
    CPP = "cpp"
    OBJECTIVE_C = "objc"
    JAVA = "java"
    KOTLIN = "kotlin"
    CSHARP = "csharp"
    DELPHI = "delphi"
    PYTHON = "python"
    UNKNOWN = "unknown"


# Magic bytes sabitleri
_MACHO_64_MAGIC = 0xFEEDFACF
_MACHO_32_MAGIC = 0xFEEDFACE
_UNIVERSAL_MAGIC = 0xCAFEBABE
# Little-endian varyantlari
_MACHO_64_CIGAM = 0xCFFAEDFE
_MACHO_32_CIGAM = 0xCEFAEDFE

_MACHO_MAGICS = {_MACHO_64_MAGIC, _MACHO_32_MAGIC, _MACHO_64_CIGAM, _MACHO_32_CIGAM}

# ELF / PE / ZIP (JAR/APK) magic bytes
_ELF_MAGIC = b'\x7fELF'
_PE_MAGIC = b'MZ'
_ZIP_MAGIC = b'PK\x03\x04'


@dataclass
class TargetInfo:
    """Tespit edilen hedef bilgileri.

    Attributes:
        path: Hedef dosyanin mutlak yolu.
        name: Hedef adi (dosya adi veya .app bundle adi).
        target_type: Tespit edilen hedef tipi.
        language: Tespit edilen kaynak dil.
        file_size: Dosya boyutu (byte).
        file_hash: SHA-256 hash (hex).
        metadata: Ek bilgiler (arch, bundler, framework vb.).
    """

    path: Path
    name: str
    target_type: TargetType
    language: Language
    file_size: int
    file_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable dict'e donustur."""
        return {
            "path": str(self.path),
            "name": self.name,
            "target_type": self.target_type.value,
            "language": self.language.value,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetInfo:
        """Dict'ten olustur."""
        return cls(
            path=Path(data["path"]),
            name=data["name"],
            target_type=TargetType(data["target_type"]),
            language=Language(data["language"]),
            file_size=data["file_size"],
            file_hash=data["file_hash"],
            metadata=data.get("metadata", {}),
        )


class TargetDetector:
    """Hedef dosya/dizin tipi tespit edici.

    Kullanim:
        detector = TargetDetector()
        info = detector.detect("/path/to/binary")
    """

    # Icerik-bazli JS bundler tespiti
    _JS_BUNDLER_SIGNATURES: dict[str, str] = {
        "__webpack_require__": "webpack",
        "__webpack_modules__": "webpack",
        "parcelRequire": "parcel",
        "System.register": "systemjs",
        "_rollupPluginBabelHelpers": "rollup",
        "define([": "amd/requirejs",
    }

    # Binary string'lerden dil tespiti
    _LANGUAGE_SIGNATURES: dict[str, Language] = {
        "rust_begin_unwind": Language.RUST,
        "rust_panic": Language.RUST,
        "__rust_alloc": Language.RUST,
        "core::panicking": Language.RUST,
        "runtime.gopanic": Language.GO,
        "runtime.goexit": Language.GO,
        "runtime/internal": Language.GO,
        "go.buildid": Language.GO,
        "_swift_": Language.SWIFT,
        "Swift.": Language.SWIFT,
        "swift::": Language.SWIFT,
        "__cxa_throw": Language.CPP,
        "std::": Language.CPP,
        "__gnu_cxx": Language.CPP,
        "objc_msgSend": Language.OBJECTIVE_C,
        "@objc": Language.OBJECTIVE_C,
        "NSObject": Language.OBJECTIVE_C,
    }

    # Hash buffer boyutu (8 KB)
    _HASH_CHUNK_SIZE = 8192

    def detect(self, path: str | Path) -> TargetInfo:
        """Hedef dosya/dizinin tipini tespit et.

        Args:
            path: Analiz edilecek dosya veya dizin yolu.

        Returns:
            TargetInfo: Tespit sonucu.

        Raises:
            FileNotFoundError: Dosya/dizin bulunamazsa.
            PermissionError: Okuma izni yoksa.
        """
        target_path = Path(path).resolve()

        if not target_path.exists():
            raise FileNotFoundError(f"Hedef bulunamadi: {target_path}")

        # .app bundle kontrolu (dizin)
        if target_path.is_dir() and target_path.suffix == ".app":
            return self._detect_app_bundle(target_path)

        if not target_path.is_file():
            raise ValueError(f"Hedef bir dosya veya .app dizini olmali: {target_path}")

        file_size = target_path.stat().st_size
        file_hash = self._compute_sha256(target_path)
        suffix = target_path.suffix.lower()

        # .asar dosyasi -> Electron
        if suffix == ".asar":
            # ASAR yolundan uygulama adini cikar
            # Tipik yol: /Applications/Element.app/Contents/Resources/app.asar
            # stem = "app" yerine .app bundle adini bul
            asar_name = target_path.stem  # "app"
            for parent in target_path.parents:
                if parent.suffix == ".app":
                    asar_name = parent.stem  # "Element"
                    break
            return TargetInfo(
                path=target_path,
                name=asar_name,
                target_type=TargetType.ELECTRON_APP,
                language=Language.JAVASCRIPT,
                file_size=file_size,
                file_hash=file_hash,
                metadata={"format": "asar_archive"},
            )

        # .js dosyasi -> JS bundle analizi
        if suffix in (".js", ".mjs", ".cjs"):
            return self._detect_js_file(target_path, file_size, file_hash)

        # Binary dosya -> magic bytes kontrolu
        return self._detect_binary(target_path, file_size, file_hash)

    def _detect_app_bundle(self, app_path: Path) -> TargetInfo:
        """macOS .app bundle TAM analizi.

        Tum bilesenleri kesfeder:
        - Contents/MacOS/* — tum binary'ler
        - Contents/Frameworks/**/*.framework — framework binary'leri
        - Contents/Resources/**/*.jar — JAR dosyalari
        - Contents/Resources/**/*.dylib — ek kutuphaneler
        - Contents/Resources/app.asar — Electron JS
        - Contents/Resources/jre.bundle/ — bundled JRE
        """
        macos_dir = app_path / "Contents" / "MacOS"
        resources_dir = app_path / "Contents" / "Resources"
        frameworks_dir = app_path / "Contents" / "Frameworks"

        components: list[dict[str, Any]] = []  # [{path, type, size, name}]

        # 1. Contents/MacOS/ deki tum binary'ler
        if macos_dir.exists():
            for f in sorted(macos_dir.iterdir()):
                if f.is_file() and not f.name.startswith('.'):
                    magic = self._read_magic(f)
                    if magic in _MACHO_MAGICS or magic == _UNIVERSAL_MAGIC:
                        components.append({
                            "path": str(f),
                            "type": "macho_binary",
                            "size": f.stat().st_size,
                            "name": f.name,
                        })

        # 2. Contents/Frameworks/ deki framework binary'leri
        if frameworks_dir.exists():
            for fw in sorted(frameworks_dir.rglob("*.framework")):
                fw_binary = fw / fw.stem  # SomeFramework.framework/SomeFramework
                if fw_binary.is_file():
                    components.append({
                        "path": str(fw_binary),
                        "type": "macho_binary",
                        "size": fw_binary.stat().st_size,
                        "name": f"Framework: {fw.stem}",
                    })

        # 3. JAR dosyalari (Resources ve alt dizinler)
        if resources_dir.exists():
            for jar in sorted(resources_dir.rglob("*.jar")):
                components.append({
                    "path": str(jar),
                    "type": "java_jar",
                    "size": jar.stat().st_size,
                    "name": jar.name,
                })

        # 4. dylib dosyalari (jre.bundle dahil)
        if resources_dir.exists():
            for dylib in sorted(resources_dir.rglob("*.dylib")):
                components.append({
                    "path": str(dylib),
                    "type": "macho_binary",
                    "size": dylib.stat().st_size,
                    "name": dylib.name,
                })

        # 5. Electron tespiti (app.asar veya app/package.json olmali)
        is_electron = False
        asar_path = resources_dir / "app.asar" if resources_dir.exists() else None
        app_dir = resources_dir / "app" if resources_dir.exists() else None
        if asar_path and asar_path.exists():
            is_electron = True
        elif app_dir and app_dir.exists():
            # app/ dizini varsa Electron olmasi icin package.json veya main.js olmali
            if (app_dir / "package.json").exists() or (app_dir / "main.js").exists():
                is_electron = True
        if is_electron:
            effective_asar = asar_path if (asar_path and asar_path.exists()) else app_dir
            components.append({
                "path": str(effective_asar),
                "type": "electron_app",
                "size": effective_asar.stat().st_size if effective_asar.is_file() else 0,
                "name": "Electron App",
            })

        # 6. Info.plist metadata
        info_plist = app_path / "Contents" / "Info.plist"
        bundle_id = ""
        bundle_version = ""
        if info_plist.exists():
            try:
                import plistlib
                with open(info_plist, "rb") as fp:
                    plist = plistlib.load(fp)
                bundle_id = plist.get("CFBundleIdentifier", "")
                bundle_version = plist.get(
                    "CFBundleShortVersionString",
                    plist.get("CFBundleVersion", ""),
                )
            except Exception:
                logger.debug("Plist parse basarisiz, atlaniyor", exc_info=True)

        # Ana binary (en buyuk Mach-O)
        macho_components = [c for c in components if c["type"] == "macho_binary"]
        main_binary_path: Path | None = None
        if macho_components:
            main = max(macho_components, key=lambda c: c["size"])
            main_binary_path = Path(main["path"])

        # Hash
        hash_target = main_binary_path or info_plist
        if hash_target and hash_target.exists():
            file_hash = self._compute_sha256(hash_target)
            total_size = sum(c["size"] for c in components)
        else:
            file_hash = ""
            total_size = 0

        metadata: dict[str, Any] = {
            "bundle": True,
            "bundle_id": bundle_id,
            "bundle_version": bundle_version,
            "main_binary": str(main_binary_path) if main_binary_path else None,
            "electron": is_electron,
            "components": components,
            "component_count": len(components),
            "total_size": total_size,
        }

        # APP_BUNDLE olarak dondur — artik tek binary'ye indirgeme YOK
        return TargetInfo(
            path=app_path,  # .app dizininin kendisi
            name=app_path.stem,
            target_type=TargetType.APP_BUNDLE,
            language=Language.UNKNOWN,  # Birden fazla dil olabilir
            file_size=total_size,
            file_hash=file_hash,
            metadata=metadata,
        )

    def _detect_js_file(
        self, path: Path, file_size: int, file_hash: str
    ) -> TargetInfo:
        """JavaScript dosyasi analizi. Bundler tespiti yapar."""
        metadata: dict[str, Any] = {}

        # Dosyanin ilk 64KB'ini oku (bundler tespiti icin yeterli)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(65536)
        except OSError:
            head = ""

        # Bundler tespiti
        for signature, bundler in self._JS_BUNDLER_SIGNATURES.items():
            if signature in head:
                metadata["bundler"] = bundler
                break

        # AI CLI tespiti
        head_lower = head.lower()
        if "anthropic" in head_lower or "claude" in head_lower:
            metadata["ai_framework"] = "anthropic"
        elif "openai" in head_lower:
            metadata["ai_framework"] = "openai"

        # Akilli isimlendirme: .app icindeki JS dosyalari icin
        # "main" yerine "Cursor-main" gibi isim ver
        # Extensions altindaki dosyalar icin extension adini da ekle
        # Ornek: extensions/cursor-agent-exec/dist/main.js -> "Cursor-cursor-agent-exec"
        js_name = path.stem
        for parent in path.parents:
            if parent.suffix == ".app":
                app_name = parent.stem
                # .app'den sonraki relative path'e bak
                try:
                    rel = path.relative_to(parent)
                    parts = rel.parts
                    # extensions/<ext-name>/... kalibinda mi?
                    if "extensions" in parts:
                        ext_idx = parts.index("extensions")
                        if ext_idx + 1 < len(parts):
                            ext_name = parts[ext_idx + 1]
                            js_name = f"{app_name}-{ext_name}"
                        else:
                            js_name = f"{app_name}-{path.stem}"
                    else:
                        js_name = f"{app_name}-{path.stem}"
                except ValueError:
                    js_name = f"{app_name}-{path.stem}"
                metadata["parent_app"] = app_name
                break

        return TargetInfo(
            path=path,
            name=js_name,
            target_type=TargetType.JS_BUNDLE,
            language=Language.JAVASCRIPT,
            file_size=file_size,
            file_hash=file_hash,
            metadata=metadata,
        )

    def _detect_binary(
        self, path: Path, file_size: int, file_hash: str
    ) -> TargetInfo:
        """Binary dosya analizi. Magic bytes + string analizi."""
        magic = self._read_magic(path)

        # Raw ilk 4 byte (ELF/PE/ZIP karsilastirmasi icin)
        try:
            with open(path, "rb") as f:
                magic4 = f.read(4)
        except OSError:
            magic4 = b""

        # --- Mach-O ---
        if magic == _UNIVERSAL_MAGIC:
            target_type = TargetType.UNIVERSAL_BINARY
            language = self._detect_language_from_binary(path)
            metadata: dict[str, Any] = {"arch": "universal"}
            if magic is not None:
                metadata["magic"] = f"0x{magic:08X}"
            return TargetInfo(
                path=path, name=path.stem, target_type=target_type,
                language=language, file_size=file_size, file_hash=file_hash,
                metadata=metadata,
            )

        if magic in _MACHO_MAGICS:
            language = self._detect_language_from_binary(path)
            metadata = {}
            if magic is not None:
                metadata["magic"] = f"0x{magic:08X}"
            # v1.6.3: Mach-O Go binary tespiti (gh, kubectl vb.)
            # Onceden sadece ELF'de Go kontrolu vardi — Mach-O Go binary'ler
            # yanlis pipeline'a giriyordu (88+ dk yerine 2-3 dk).
            if language == Language.GO or self._is_go_binary(path):
                return TargetInfo(
                    path=path, name=path.stem,
                    target_type=TargetType.GO_BINARY,
                    language=Language.GO,
                    file_size=file_size, file_hash=file_hash,
                    metadata=metadata,
                )
            # v1.8.0: Bun compiled binary tespiti (bun build --compile)
            # __BUN segmenti iceren Mach-O binary'ler — gomulu JS kodu var.
            if self._has_bun_segment(path):
                metadata["bun_compiled"] = True
                return TargetInfo(
                    path=path, name=path.stem,
                    target_type=TargetType.BUN_BINARY,
                    language=Language.JAVASCRIPT,
                    file_size=file_size, file_hash=file_hash,
                    metadata=metadata,
                )
            return TargetInfo(
                path=path, name=path.stem, target_type=TargetType.MACHO_BINARY,
                language=language, file_size=file_size, file_hash=file_hash,
                metadata=metadata,
            )

        # --- ELF binary ---
        if magic4[:4] == _ELF_MAGIC:
            language = self._detect_language_from_binary(path)
            metadata = {"format": "elf"}
            if magic is not None:
                metadata["magic"] = f"0x{magic:08X}"
            # Go kontrolu
            if language == Language.GO or self._is_go_binary(path):
                return TargetInfo(
                    path=path, name=path.stem,
                    target_type=TargetType.GO_BINARY,
                    language=Language.GO,
                    file_size=file_size, file_hash=file_hash,
                    metadata=metadata,
                )
            return TargetInfo(
                path=path, name=path.stem, target_type=TargetType.ELF_BINARY,
                language=language, file_size=file_size, file_hash=file_hash,
                metadata=metadata,
            )

        # --- PE / DLL ---
        if magic4[:2] == _PE_MAGIC:
            language = self._detect_language_from_binary(path)
            metadata = {"format": "pe"}
            if magic is not None:
                metadata["magic"] = f"0x{magic:08X}"
            # .NET kontrolu
            if self._is_dotnet(path):
                return TargetInfo(
                    path=path, name=path.stem,
                    target_type=TargetType.DOTNET_ASSEMBLY,
                    language=Language.CSHARP,
                    file_size=file_size, file_hash=file_hash,
                    metadata={**metadata, "runtime": ".net"},
                )
            # Delphi kontrolu
            if self._is_delphi(path):
                return TargetInfo(
                    path=path, name=path.stem,
                    target_type=TargetType.DELPHI_BINARY,
                    language=Language.DELPHI,
                    file_size=file_size, file_hash=file_hash,
                    metadata={**metadata, "runtime": "delphi"},
                )
            # v1.6.3: PE Go binary tespiti (Windows Go binary'ler)
            if language == Language.GO or self._is_go_binary(path):
                return TargetInfo(
                    path=path, name=path.stem,
                    target_type=TargetType.GO_BINARY,
                    language=Language.GO,
                    file_size=file_size, file_hash=file_hash,
                    metadata=metadata,
                )
            return TargetInfo(
                path=path, name=path.stem, target_type=TargetType.PE_BINARY,
                language=language, file_size=file_size, file_hash=file_hash,
                metadata=metadata,
            )

        # --- JAR / APK (ZIP format) ---
        if magic4[:4] == _ZIP_MAGIC:
            jar_apk = self._is_jar_or_apk(path)
            if jar_apk == "apk":
                return TargetInfo(
                    path=path, name=path.stem,
                    target_type=TargetType.ANDROID_APK,
                    language=Language.JAVA,
                    file_size=file_size, file_hash=file_hash,
                    metadata={"format": "apk"},
                )
            elif jar_apk == "jar":
                return TargetInfo(
                    path=path, name=path.stem,
                    target_type=TargetType.JAVA_JAR,
                    language=Language.JAVA,
                    file_size=file_size, file_hash=file_hash,
                    metadata={"format": "jar"},
                )
            # ZIP ama ne JAR ne APK -- unknown olarak dondur
            pass

        # --- Bilinmeyen format ---
        language = self._detect_language_from_binary(path)
        metadata = {}
        if magic is not None:
            metadata["magic"] = f"0x{magic:08X}"

        return TargetInfo(
            path=path,
            name=path.stem,
            target_type=TargetType.UNKNOWN,
            language=language,
            file_size=file_size,
            file_hash=file_hash,
            metadata=metadata,
        )

    def _detect_language_from_binary(self, path: Path) -> Language:
        """Binary icindeki string'lerden kaynak dili tespit et.

        Dosyanin ilk 1MB'ini tarar. Dil puanlama sistemiyle en olasi dili secer.
        """
        scores: dict[Language, int] = {}
        try:
            with open(path, "rb") as f:
                data = f.read(1_048_576)  # 1 MB
        except OSError:
            return Language.UNKNOWN

        text = data.decode("ascii", errors="replace")

        for signature, lang in self._LANGUAGE_SIGNATURES.items():
            if signature in text:
                scores[lang] = scores.get(lang, 0) + 1

        if not scores:
            return Language.UNKNOWN

        return max(scores, key=lambda k: scores[k])

    def _is_go_binary(self, path: Path) -> bool:
        """ELF binary'nin Go ile derlenmis olup olmadigini kontrol et.

        GOPCLNTAB section, go runtime string'leri ve .go.buildid aranir.
        """
        try:
            with open(path, "rb") as f:
                # Ilk 2MB'i tara — Go section header'lari genellikle burada
                data = f.read(2_097_152)
        except OSError:
            return False

        # GOPCLNTAB: Go pclntab section marker
        if b"GOPCLNTAB" in data or b"\xFB\xFF\xFF\xFF\x00\x00" in data:
            return True
        # go.buildid: Go binary'lerde build ID section'i
        if b"go.buildid" in data or b"Go build" in data:
            return True
        # runtime.gopanic vb. Go runtime string'leri
        # (_detect_language_from_binary zaten bunlari kontrol ediyor ama
        #  burada ELF-spesifik olarak cagiriyoruz)
        text = data.decode("ascii", errors="replace")
        go_markers = ("runtime.gopanic", "runtime.goexit", "runtime/internal")
        return any(marker in text for marker in go_markers)

    @staticmethod
    def _has_bun_segment(path: Path) -> bool:
        """Mach-O binary'de __BUN segmenti olup olmadigini kontrol et.

        Bun runtime `bun build --compile` ile JS kodunu __BUN segmentine gomer.
        lief ile segment listesini tarar; lief yoksa raw bytes'ta segment
        adini arar (fallback).
        """
        try:
            import lief
            binary = lief.parse(str(path))
            if binary is None:
                return False
            if hasattr(binary, "segments"):
                for seg in binary.segments:
                    if seg.name in ("__BUN", "__bun"):
                        return True
            return False
        except ImportError:
            pass
        except Exception:
            logger.debug("Lief ile BUN segment kontrolu basarisiz, atlaniyor", exc_info=True)

        # Fallback: lief yoksa raw bytes'ta segment adini ara
        try:
            with open(path, "rb") as f:
                # Ilk 4KB'de segment header'lari olmali
                data = f.read(4096)
            return b"__BUN" in data or b"__bun" in data
        except OSError:
            return False

    @staticmethod
    def _is_dotnet(path: Path) -> bool:
        """PE binary'nin .NET assembly olup olmadigini kontrol et.

        mscoree.dll referansi ve CLI header'i aranir.
        """
        try:
            with open(path, "rb") as f:
                data = f.read(1_048_576)  # 1 MB
        except OSError:
            return False

        # mscoree.dll: .NET CLR runtime yukleyicisi — her .NET PE'de bulunur
        if b"mscoree.dll" in data or b"_CorExeMain" in data:
            return True
        # mscorlib veya System.Runtime referansi
        if b"mscorlib" in data or b"System.Runtime" in data:
            return True
        return False

    @staticmethod
    def _is_delphi(path: Path) -> bool:
        """PE binary'nin Delphi ile derlenip derlenmedigini kontrol et.

        Delphi compiler string'leri, runtime marker'lari ve RTTI aranir.
        """
        try:
            with open(path, "rb") as f:
                data = f.read(524_288)  # 512 KB
        except OSError:
            return False

        # Delphi compiler/runtime marker'lari
        delphi_markers = (
            b"Borland Delphi",
            b"CodeGear Delphi",
            b"Embarcadero Delphi",
            b"@System@TObject@",
            b"System.SysUtils",
        )
        hits = sum(1 for m in delphi_markers if m in data)
        if hits >= 2:
            return True

        # Delphi mangled names: @Unit@Class@Method$qqr
        import re
        mangled = re.findall(
            rb"@[A-Z][A-Za-z0-9_]+@[A-Z][A-Za-z0-9_]+@[A-Za-z_]\w*\$qqr",
            data,
        )
        if len(mangled) >= 5:
            return True

        return False

    @staticmethod
    def _is_jar_or_apk(path: Path) -> str | None:
        """ZIP dosyasinin JAR mi APK mi oldugunu kontrol et.

        Returns:
            "jar" | "apk" | None
        """
        import zipfile

        try:
            if not zipfile.is_zipfile(path):
                return None
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()

                # APK: classes.dex dosyasi + AndroidManifest.xml
                has_dex = any(n.endswith(".dex") for n in names)
                has_manifest_apk = "AndroidManifest.xml" in names
                if has_dex and has_manifest_apk:
                    return "apk"

                # JAR: META-INF/MANIFEST.MF veya .class dosyalari
                has_class = any(n.endswith(".class") for n in names)
                has_manifest_jar = "META-INF/MANIFEST.MF" in names
                if has_class or has_manifest_jar:
                    return "jar"
        except (zipfile.BadZipFile, OSError, KeyError):
            return None

        return None

    @staticmethod
    def _read_magic(path: Path) -> int | None:
        """Dosyanin ilk 4 byte'ini big-endian uint32 olarak oku."""
        try:
            with open(path, "rb") as f:
                data = f.read(4)
            if len(data) < 4:
                return None
            return struct.unpack(">I", data)[0]
        except OSError:
            return None

    @staticmethod
    def _compute_sha256(path: Path) -> str:
        """Dosyanin SHA-256 hash'ini hesapla."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()
