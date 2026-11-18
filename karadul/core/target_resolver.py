"""Smart target resolver -- isim veya kisa ad ile hedef binary/bundle bul.

Kullanici tam yol yerine uygulama adi verebilir:
    karadul analyze scapy
    karadul analyze firefox
    karadul analyze openssl

Arama sirasi:
    1. Tam yol mu? (zaten dosya/dizin)
       Yol ya da dosya adi gibi gorunen girdi (ayrac, ``~``, bastaki nokta ya
       da uzanti: ``evil.pyc``, ``a.b``) YALNIZ dosya sisteminde aranir;
       bulunamazsa acik hata verilir, baska yere bakilmaz.
    2. ALL_TARGETS hardcoded listede mi? (batch.py)
    3. PATH'te binary mi? (shutil.which, tam ad)
    4. macOS uygulamasi mi? (/Applications/<ad>.app, tam ad)
    5. Homebrew paketi mi? (/opt/homebrew/bin/<ad>, Cellar/<ad>/*/bin/<ad>)
    6. Python paketi mi? (site-packages dizinlerinde DOSYA SISTEMI aramasi)
    7. Spotlight araması (mdfind, tam dosya adi; tek sonuc)

Guvenlik (BICIM-07):
    * Hicbir yolda Python modulu ice aktarilmaz ya da calistirilmaz.
      Eskiden ``importlib.util.find_spec("a.b")`` ust paket ``a``'yi ICE
      AKTARIYORDU; ``python -m karadul`` ile ``sys.path[0]`` calisma dizini
      oldugundan ornek klasorundeki ``evil/__init__.py`` calisiyordu.
      Python paketi aramasi artik yalniz site-packages dizinlerinde dosya
      sistemiyle yapilir; calisma dizinine bakilmaz.
    * Bulanik eslesmeler (adi iceren uygulama, Cellar'daki baska ikili,
      Spotlight'ta birden cok sonuc) sessizce hedef SECILMEZ; hata mesajinda
      "benzer adlar" olarak listelenir.
"""

from __future__ import annotations

import logging
import os
import shutil
import site
import subprocess
import sysconfig
from pathlib import Path

logger = logging.getLogger(__name__)

# Hata mesajinda gosterilecek en cok oneri sayisi
_MAX_SUGGESTIONS = 8


def _looks_like_path(name: str) -> bool:
    """Girdi bir yol ya da dosya adi gibi mi gorunuyor?

    Ayrac (``/``), ``~`` ya da ``.`` ile baslama, ya da uzanti (``evil.pyc``,
    ``a.b``, ``python3.12``) -> evet. Boyle girdide yalniz dosya sistemine
    bakilir.
    """
    if "/" in name or os.sep in name or (os.altsep and os.altsep in name):
        return True
    if name.startswith(("~", ".")):
        return True
    return Path(name).suffix != ""


def resolve_target(name_or_path: str) -> Path:
    """Isim veya yoldan hedef dosya/dizin bul.

    Args:
        name_or_path: Tam yol, uygulama adi, paket adi, veya binary adi.

    Returns:
        Bulunan dosyanin Path'i.

    Raises:
        FileNotFoundError: Hedef bulunamadiysa (ya da yalniz bulanik eslesme
            varsa; adaylar mesajda listelenir, hicbiri secilmez).
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
    try:
        expanded = Path(name_or_path).expanduser()
    except RuntimeError:  # "~bilinmeyenkullanici/..." -> ev dizini yok
        expanded = Path(name_or_path)
    if expanded.is_file() or expanded.is_dir():
        return expanded.resolve()

    name = name_or_path.strip()

    # BICIM-07: yol/dosya adi gibi gorunen girdi yalniz dosya sisteminde aranir.
    if _looks_like_path(name):
        raise FileNotFoundError(
            f"'{name_or_path}' bulunamadi: dosya sisteminde boyle bir dosya ya da "
            f"dizin yok ({expanded.absolute()}).\n"
            "Yol ya da dosya adi gibi gorunen girdi (uzanti, '/', '~', bastaki "
            "nokta) yalniz dosya sisteminde aranir; PATH, uygulama, paket ya da "
            "Spotlight aramasi yapilmaz.\n"
            "Tam dosya yolunu verin."
        )

    # Guvenlik: sadece basit identifier kabul et (path separator, newline vb. yok)
    if not all(c.isalnum() or c in "-_" for c in name):
        raise FileNotFoundError(
            f"'{name_or_path}' gecerli bir dosya yolu veya uygulama adi degil."
        )
    name_lower = name.lower()
    suggestions: list[Path] = []

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
    resolved = _check_macos_app(name, suggestions)
    if resolved:
        logger.info("macOS app: %s -> %s", name, resolved)
        return resolved

    # 5. Homebrew
    resolved = _check_homebrew(name, suggestions)
    if resolved:
        logger.info("Homebrew: %s -> %s", name, resolved)
        return resolved

    # 6. Python paketi (yalniz dosya sistemi; ice aktarma YOK)
    resolved = _check_python_package(name)
    if resolved:
        logger.warning("Python paketi: %s -> %s (hedef bu dosya)", name, resolved)
        return resolved

    # 7. Spotlight (mdfind, tam ad)
    resolved = _check_spotlight(name, suggestions)
    if resolved:
        logger.warning("Spotlight: %s -> %s (hedef bu dosya)", name, resolved)
        return resolved

    msg = (
        f"'{name}' bulunamadi. Denenen yerler:\n"
        f"  - Dosya sistemi: {p}\n"
        f"  - PATH: which {name}\n"
        f"  - /Applications/{name}.app\n"
        f"  - Homebrew: /opt/homebrew/bin/{name}\n"
        f"  - Python: site-packages altinda '{name}' paketi/modulu (ice aktarilmadi)\n"
        f"  - Spotlight: tam dosya adi '{name}'\n"
    )
    uniq: list[Path] = []
    for s in suggestions:
        if s not in uniq:
            uniq.append(s)
    if uniq:
        msg += "Benzer adlar (otomatik SECILMEDI):\n"
        msg += "".join(f"  - {s}\n" for s in uniq[:_MAX_SUGGESTIONS])
        if len(uniq) > _MAX_SUGGESTIONS:
            msg += f"  - ... (+{len(uniq) - _MAX_SUGGESTIONS})\n"
    msg += "Tam dosya yolunu verin."
    raise FileNotFoundError(msg)


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


def _app_main_binary(app: Path) -> Path:
    """.app paketinin ana ikilisi (yoksa Electron app.asar, yoksa paket)."""
    macos_dir = app / "Contents" / "MacOS"
    if macos_dir.is_dir():
        for b in sorted(macos_dir.iterdir()):
            if b.is_file() and not b.name.startswith("."):
                return b
    asar = app / "Contents" / "Resources" / "app.asar"
    if asar.is_file():
        return asar
    return app


def _check_macos_app(name: str, suggestions: list[Path] | None = None) -> Path | None:
    """/Applications'da .app ara (yalniz tam ad; bulanik eslesme oneri olur)."""
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
            return _app_main_binary(app)

    # Bulanik: adi iceren uygulamalar SECILMEZ, yalniz oneri (BICIM-07)
    if suggestions is not None:
        try:
            for app in sorted(apps_dir.iterdir()):
                if app.suffix == ".app" and name.lower() in app.stem.lower():
                    suggestions.append(app)
        except OSError:
            pass
    return None


def _check_homebrew(name: str, suggestions: list[Path] | None = None) -> Path | None:
    """Homebrew'da ara (yalniz <ad> adli ikili; digerleri oneri olur)."""
    brew_bin = Path("/opt/homebrew/bin") / name
    if brew_bin.exists():
        return brew_bin.resolve()

    # Cellar'da ara
    cellar = Path("/opt/homebrew/Cellar") / name
    if cellar.is_dir():
        # En son versiyon
        versions = sorted(cellar.iterdir(), reverse=True)
        for v in versions:
            exact = v / "bin" / name
            if exact.is_file():
                return exact.resolve()
        if suggestions is not None:
            for v in versions:
                bin_dir = v / "bin"
                if bin_dir.is_dir():
                    suggestions.extend(
                        b for b in sorted(bin_dir.iterdir())
                        if b.is_file() and not b.name.startswith(".")
                    )
                lib_dir = v / "lib"
                if lib_dir.is_dir():
                    suggestions.extend(sorted(lib_dir.glob("*.dylib")))

    return None


def _python_package_dirs() -> list[Path]:
    """Kurulu Python paketlerinin dizinleri (site-packages); calisma dizini HARIC."""
    raw: list[str] = []
    paths = sysconfig.get_paths()
    for key in ("purelib", "platlib"):
        if paths.get(key):
            raw.append(paths[key])
    try:
        raw.extend(site.getsitepackages())
    except AttributeError:  # bazi sanal ortamlarda yok
        pass
    try:
        user_site = site.getusersitepackages()
        if user_site:
            raw.append(user_site)
    except AttributeError:
        pass

    try:
        cwd = Path.cwd().resolve()
    except OSError:
        cwd = None
    out: list[Path] = []
    for entry in raw:
        if not entry:
            continue
        try:
            d = Path(entry).resolve()
        except OSError:
            continue
        if d == cwd or not d.is_dir() or d in out:
            continue
        out.append(d)
    return out


_NATIVE_SUFFIXES = (".so", ".dylib", ".pyd")


def _check_python_package(name: str) -> Path | None:
    """Kurulu Python paketinde native extension (.so/.dylib) bul.

    Guvenlik (BICIM-07): ``importlib`` KULLANILMAZ; hicbir modul ice
    aktarilmaz. Yalniz site-packages dizinlerinde ``<ad>/`` paketi,
    ``<ad>.*.so`` uzanti modulu ya da ``<ad>.py`` aranir (dosya sistemi).
    Noktali ad zaten buraya gelmez (yol gibi sayilir).
    """
    if not name.isidentifier():
        return None
    for base in _python_package_dirs():
        pkg_dir = base / name
        if pkg_dir.is_dir():
            native_exts = [
                f for f in pkg_dir.rglob("*")
                if f.suffix in _NATIVE_SUFFIXES and f.is_file()
            ]
            if native_exts:
                # En buyuk native dosya (ana extension)
                native_exts.sort(key=lambda f: f.stat().st_size, reverse=True)
                return native_exts[0].resolve()
            init = pkg_dir / "__init__.py"
            if init.is_file():
                return init.resolve()
            continue
        # Tek dosyalik uzanti modulu: <ad>.cpython-312-darwin.so, <ad>.so
        for ext in sorted(base.glob(f"{name}.*")):
            if ext.suffix in _NATIVE_SUFFIXES and ext.is_file():
                return ext.resolve()
        module = base / f"{name}.py"
        if module.is_file():
            return module.resolve()
    return None


def _check_spotlight(name: str, suggestions: list[Path] | None = None) -> Path | None:
    """macOS Spotlight (mdfind) ile TAM dosya adiyla ara.

    Tek aday varsa o dondurulur; birden cok aday varsa hicbiri secilmez,
    hepsi oneri olur (BICIM-07: sessizce baska ikili secilmez).
    """
    try:
        result = subprocess.run(
            ["mdfind", f"kMDItemFSName == '{name}'", "-onlyin", "/usr/local",
             "-onlyin", "/opt/homebrew", "-onlyin", "/Applications"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None

        found: list[Path] = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            p = Path(line)
            if p.name != name:
                continue
            if p.is_file() and p.stat().st_size > 1000 and (
                p.suffix in (".dylib", ".so", ".a", ".asar", "") or _is_binary(p)
            ):
                rp = p.resolve()
                if rp not in found:
                    found.append(rp)
        if len(found) == 1:
            return found[0]
        if suggestions is not None:
            suggestions.extend(found)

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
