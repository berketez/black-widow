"""Smart target resolver -- isim veya kisa ad ile hedef binary/bundle bul.

Kullanici tam yol yerine uygulama adi verebilir:
    karadul analyze scapy
    karadul analyze firefox
    karadul analyze openssl

Arama sirasi:
    1. Tam yol mu? (zaten dosya/dizin)
    2. ALL_TARGETS hardcoded listede mi? (batch.py)
    3. PATH'te binary mi? (which/shutil.which)
    4. macOS uygulamasi mi? (/Applications/*.app)
    5. Homebrew paketi mi? (/opt/homebrew/bin, /opt/homebrew/Cellar)
    6. Python paketi mi? (import -> native .so/.dylib bul)
    7. Spotlight araması (mdfind)
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_target(name_or_path: str) -> Path:
    """Isim veya yoldan hedef dosya/dizin bul.

    Args:
        name_or_path: Tam yol, uygulama adi, paket adi, veya binary adi.

    Returns:
        Bulunan dosyanin Path'i.

    Raises:
        FileNotFoundError: Hedef bulunamadiiysa.
    """
    # v1.9.1: Input validation
    if not name_or_path or not name_or_path.strip():
        raise FileNotFoundError("Hedef belirtilmedi. Dosya yolu veya uygulama adi verin.")

    # 1. Tam yol mu?
    p = Path(name_or_path)
    if p.is_file():
        return p.resolve()
    if p.is_dir():
        return p.resolve()

    # Resolve kismi (~, relative path)
    expanded = Path(name_or_path).expanduser()
    if expanded.is_file() or expanded.is_dir():
        return expanded.resolve()

    name = name_or_path.strip()
    # Guvenlik: sadece basit identifier kabul et (path separator, newline vb. yok)
    if not all(c.isalnum() or c in "-_." for c in name):
        raise FileNotFoundError(
            f"'{name_or_path}' gecerli bir dosya yolu veya uygulama adi degil."
        )
    name_lower = name.lower()

    # 2. Hardcoded target listesi
    resolved = _check_known_targets(name_lower)
    if resolved:
        logger.info("Bilinen hedef: %s -> %s", name, resolved)
        return resolved

    # 3. PATH'te binary
    resolved = _check_path_binary(name)
    if resolved:
        logger.info("PATH binary: %s -> %s", name, resolved)
        return resolved

    # 4. macOS /Applications/*.app
    resolved = _check_macos_app(name)
    if resolved:
        logger.info("macOS app: %s -> %s", name, resolved)
        return resolved

    # 5. Homebrew
    resolved = _check_homebrew(name)
    if resolved:
        logger.info("Homebrew: %s -> %s", name, resolved)
        return resolved

    # 6. Python paketi (native extension)
    resolved = _check_python_package(name)
    if resolved:
        logger.info("Python paketi: %s -> %s", name, resolved)
        return resolved

    # 7. Spotlight (mdfind)
    resolved = _check_spotlight(name)
    if resolved:
        logger.info("Spotlight: %s -> %s", name, resolved)
        return resolved

    raise FileNotFoundError(
        f"'{name}' bulunamadi. Denenen yerler:\n"
        f"  - Dosya sistemi: {p}\n"
        f"  - PATH: which {name}\n"
        f"  - /Applications/{name}.app\n"
        f"  - Homebrew: /opt/homebrew/bin/{name}\n"
        f"  - Python: import {name}\n"
        f"  - Spotlight: mdfind {name}\n"
        f"Tam dosya yolunu verin."
    )


# ---------------------------------------------------------------------------
# Arama stratejileri
# ---------------------------------------------------------------------------


def _check_known_targets(name: str) -> Path | None:
    """batch.py ALL_TARGETS'ta ara."""
    try:
        from karadul.batch import ALL_TARGETS
        if name in ALL_TARGETS:
            p = Path(ALL_TARGETS[name])
            if p.exists():
                return p.resolve()
    except ImportError:
        pass
    return None


def _check_path_binary(name: str) -> Path | None:
    """shutil.which ile PATH'te ara."""
    found = shutil.which(name)
    if found:
        p = Path(found).resolve()
        # Symlink'i takip et
        if p.is_symlink():
            p = p.resolve()
        if p.is_file():
            return p
    return None


def _check_macos_app(name: str) -> Path | None:
    """/Applications'da .app ara."""
    apps_dir = Path("/Applications")
    if not apps_dir.is_dir():
        return None

    # Tam isim deneme
    candidates = [
        apps_dir / f"{name}.app",
        apps_dir / f"{name.title()}.app",
        apps_dir / f"{name.upper()}.app",
    ]

    for app in candidates:
        if app.is_dir():
            # Binary'yi bul: Contents/MacOS/ altinda
            macos_dir = app / "Contents" / "MacOS"
            if macos_dir.is_dir():
                binaries = sorted(macos_dir.iterdir())
                for b in binaries:
                    if b.is_file() and not b.name.startswith("."):
                        return b

            # Electron: Contents/Resources/app.asar
            asar = app / "Contents" / "Resources" / "app.asar"
            if asar.is_file():
                return asar

            return app

    # Fuzzy: ismini iceren app ara
    for app in sorted(apps_dir.iterdir()):
        if app.suffix == ".app" and name.lower() in app.stem.lower():
            macos_dir = app / "Contents" / "MacOS"
            if macos_dir.is_dir():
                binaries = sorted(macos_dir.iterdir())
                for b in binaries:
                    if b.is_file() and not b.name.startswith("."):
                        return b
            return app

    return None


def _check_homebrew(name: str) -> Path | None:
    """Homebrew'da ara."""
    brew_bin = Path("/opt/homebrew/bin") / name
    if brew_bin.exists():
        return brew_bin.resolve()

    # Cellar'da ara
    cellar = Path("/opt/homebrew/Cellar") / name
    if cellar.is_dir():
        # En son versiyon
        versions = sorted(cellar.iterdir(), reverse=True)
        for v in versions:
            bin_dir = v / "bin"
            if bin_dir.is_dir():
                for b in sorted(bin_dir.iterdir()):
                    if b.is_file() and not b.name.startswith("."):
                        return b.resolve()
            # lib altinda .dylib ara
            lib_dir = v / "lib"
            if lib_dir.is_dir():
                dylibs = sorted(lib_dir.glob("*.dylib"))
                if dylibs:
                    return dylibs[0].resolve()

    return None


def _check_python_package(name: str) -> Path | None:
    """Python import ile native extension (.so/.dylib) bul.

    Guvenlik: subprocess yerine importlib.util.find_spec kullanir (RCE onlemi).
    """
    try:
        import importlib.util
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None:
            return None

        pkg_path = Path(spec.origin)
        if not pkg_path.exists():
            return None

        pkg_dir = pkg_path.parent

        # Native extension'lar (.so, .dylib, .pyd)
        native_exts = list(pkg_dir.rglob("*.so")) + list(pkg_dir.rglob("*.dylib"))
        if native_exts:
            # En buyuk .so dosyasini don (ana extension)
            native_exts.sort(key=lambda f: f.stat().st_size, reverse=True)
            return native_exts[0].resolve()

        # Pure Python paket — __init__.py dondur (JS analizi icin)
        init = pkg_dir / "__init__.py"
        if init.is_file():
            return init

        return pkg_path.resolve()

    except (subprocess.TimeoutExpired, Exception):
        return None


def _check_spotlight(name: str) -> Path | None:
    """macOS Spotlight (mdfind) ile ara."""
    try:
        # Binary / executable ara
        result = subprocess.run(
            ["mdfind", f"kMDItemFSName == '*{name}*'", "-onlyin", "/usr/local",
             "-onlyin", "/opt/homebrew", "-onlyin", "/Applications"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            p = Path(line)
            if p.is_file() and p.stat().st_size > 1000:
                # Binary mi kontrol et
                if p.suffix in (".dylib", ".so", ".a", ".app", ".asar", ""):
                    return p.resolve()
                if _is_binary(p):
                    return p.resolve()

    except (subprocess.TimeoutExpired, Exception):
        pass

    return None


def _is_binary(path: Path) -> bool:
    """Dosyanin binary olup olmadigini kontrol et (ilk 4 byte magic)."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        # Mach-O: feedface, feedfacf, cafebabe (fat)
        # ELF: 7f454c46
        # PE: 4d5a
        return magic in (
            b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",  # Mach-O 32/64
            b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",  # Mach-O reversed
            b"\xca\xfe\xba\xbe",  # Fat binary
            b"\x7fELF",           # ELF
            b"MZ\x90\x00",       # PE
        ) or magic[:2] == b"MZ"
    except Exception:
        logger.debug("Binary magic byte kontrolu basarisiz, False donuyor", exc_info=True)
        return False
