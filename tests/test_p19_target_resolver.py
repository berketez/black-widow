"""P19 / BICIM-07: hedef çözücü hiçbir yolda Python modülü içe aktarmaz.

Eskiden `importlib.util.find_spec("evil.payload")` üst paket `evil`'i İÇE
AKTARIYORDU; `python -m karadul` ile `sys.path[0]` çalışma dizini olduğundan
örnek klasöründeki `evil/__init__.py` çalışıyordu. Ayrıca bulunamayan ad için
cwd'deki en büyük `.so`, `/Applications`'ta adı içeren bir uygulama ya da
Spotlight'ın jokerli sonucu sessizce hedef seçiliyordu.

İşaret modülleri bu testlerin yazdığı zararsız dosyalardır (bir dosya yazarlar).
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from karadul.core import target_resolver as tr
from karadul.core.target_resolver import resolve_target

MARK = 'open({path!r}, "w").write("ran")\n'


def _uniq(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


@pytest.fixture
def evil_cwd(tmp_path, monkeypatch):
    """cwd = tmp ve sys.path[0] = cwd (python -m karadul ile aynı durum)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))
    # Spotlight alt süreci testte koşmasın (ad zaten benzersiz)
    monkeypatch.setattr(tr, "_check_spotlight", lambda *a, **k: None)
    return tmp_path


def test_dotted_name_does_not_import_parent_package(evil_cwd):
    pkg = _uniq("p19evil")
    marker = evil_cwd / "IMPORTED_MARKER"
    (evil_cwd / pkg).mkdir()
    (evil_cwd / pkg / "__init__.py").write_text(MARK.format(path=str(marker)))
    with pytest.raises(FileNotFoundError):
        resolve_target(f"{pkg}.payload")
    assert not marker.exists(), "hedef çözücü cwd'deki paketi içe aktardı"
    assert pkg not in sys.modules


def test_typo_pyc_does_not_import_sibling_module(evil_cwd):
    """Kulvardaki gösterim: evil.py varken `evil.pyc` (yok) verilir."""
    mod = _uniq("p19evil")
    marker = evil_cwd / "IMPORTED_MARKER"
    (evil_cwd / f"{mod}.py").write_text(MARK.format(path=str(marker)))
    with pytest.raises(FileNotFoundError) as exc:
        resolve_target(f"{mod}.pyc")
    assert not marker.exists()
    assert mod not in sys.modules
    assert "yalniz dosya sisteminde" in str(exc.value)


def test_undotted_name_does_not_pick_file_from_cwd(evil_cwd):
    """cwd'deki modül adı verilince cwd'deki en büyük .so hedef seçilmez."""
    mod = _uniq("p19evil")
    marker = evil_cwd / "IMPORTED_MARKER"
    (evil_cwd / f"{mod}.py").write_text(MARK.format(path=str(marker)))
    (evil_cwd / "big.so").write_bytes(b"\x7fELF" + b"\x00" * 5000)
    with pytest.raises(FileNotFoundError):
        resolve_target(mod)
    assert not marker.exists()


@pytest.mark.parametrize("arg", ["evil.payload", "a.b", "python3.99", "~nosuchuser_p19/x", "./nope"])
def test_path_like_input_filesystem_only(evil_cwd, monkeypatch, arg):
    called = []
    monkeypatch.setattr(tr, "_check_path_binary", lambda n: called.append(n))
    monkeypatch.setattr(tr, "_check_python_package", lambda n: called.append(n))
    with pytest.raises(FileNotFoundError) as exc:
        resolve_target(arg)
    assert called == []
    assert "yalniz dosya sisteminde" in str(exc.value)


def test_existing_path_still_resolves(evil_cwd):
    f = evil_cwd / "sample.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 16)
    assert resolve_target("sample.bin") == f.resolve()
    assert resolve_target(str(f)) == f.resolve()


# ------------------------------------------------- Python paketi (dosya sistemi)


def _fake_site(tmp_path: Path, monkeypatch) -> Path:
    site_dir = tmp_path / "site-packages"
    site_dir.mkdir()
    monkeypatch.setattr(tr, "_python_package_dirs", lambda: [site_dir.resolve()])
    return site_dir


def test_python_package_found_without_import(tmp_path, monkeypatch):
    site_dir = _fake_site(tmp_path, monkeypatch)
    pkg = _uniq("p19pkg")
    marker = tmp_path / "IMPORTED_MARKER"
    (site_dir / pkg / "sub").mkdir(parents=True)
    (site_dir / pkg / "__init__.py").write_text(MARK.format(path=str(marker)))
    (site_dir / pkg / "sub" / "_core.cpython-312-darwin.so").write_bytes(b"\x00" * 3000)
    (site_dir / pkg / "_small.so").write_bytes(b"\x00" * 100)
    got = tr._check_python_package(pkg)
    assert got == (site_dir / pkg / "sub" / "_core.cpython-312-darwin.so").resolve()
    assert not marker.exists()
    assert pkg not in sys.modules


def test_python_pure_package_returns_init(tmp_path, monkeypatch):
    site_dir = _fake_site(tmp_path, monkeypatch)
    pkg = _uniq("p19pkg")
    (site_dir / pkg).mkdir()
    (site_dir / pkg / "__init__.py").write_text("x = 1\n")
    assert tr._check_python_package(pkg) == (site_dir / pkg / "__init__.py").resolve()


def test_python_single_file_extension_module(tmp_path, monkeypatch):
    site_dir = _fake_site(tmp_path, monkeypatch)
    mod = _uniq("p19ext")
    ext = site_dir / f"{mod}.cpython-312-darwin.so"
    ext.write_bytes(b"\x00" * 10)
    (site_dir / "other_big.so").write_bytes(b"\x00" * 9000)  # seçilmemeli
    assert tr._check_python_package(mod) == ext.resolve()


def test_python_package_dirs_exclude_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tr.sysconfig, "get_paths",
                        lambda: {"purelib": str(tmp_path), "platlib": str(tmp_path)})
    monkeypatch.setattr(tr.site, "getsitepackages", lambda: [str(tmp_path)])
    monkeypatch.setattr(tr.site, "getusersitepackages", lambda: str(tmp_path))
    assert tmp_path.resolve() not in tr._python_package_dirs()


# ------------------------------------------------- bulanık eşleşme seçilmez


class _FakeProc:
    def __init__(self, stdout: str):
        self.returncode = 0
        self.stdout = stdout
        self.stderr = ""


def test_spotlight_multiple_exact_hits_not_chosen(tmp_path, monkeypatch):
    name = _uniq("p19tool")
    a = tmp_path / "a" / name
    b = tmp_path / "b" / name
    for f in (a, b):
        f.parent.mkdir()
        f.write_bytes(b"\x7fELF" + b"\x00" * 2000)
    monkeypatch.setattr(tr.subprocess, "run",
                        lambda *a_, **k: _FakeProc(f"{a}\n{b}\n"))
    sugg: list[Path] = []
    assert tr._check_spotlight(name, sugg) is None
    assert sorted(sugg) == sorted([a.resolve(), b.resolve()])


def test_spotlight_single_exact_hit_chosen_other_names_ignored(tmp_path, monkeypatch):
    name = _uniq("p19tool")
    exact = tmp_path / name
    other = tmp_path / f"{name}-helper"
    for f in (exact, other):
        f.write_bytes(b"\x7fELF" + b"\x00" * 2000)
    monkeypatch.setattr(tr.subprocess, "run",
                        lambda *a_, **k: _FakeProc(f"{other}\n{exact}\n"))
    assert tr._check_spotlight(name, []) == exact.resolve()
    monkeypatch.setattr(tr.subprocess, "run", lambda *a_, **k: _FakeProc(f"{other}\n"))
    assert tr._check_spotlight(name, []) is None


@pytest.mark.skipif(not Path("/Applications/Safari.app").is_dir(),
                    reason="/Applications/Safari.app yok")
def test_fuzzy_app_is_suggestion_not_target(monkeypatch):
    """Kulvar: `afar` eskiden sessizce Safari'yi hedef seçiyordu."""
    monkeypatch.setattr(tr, "_check_spotlight", lambda *a, **k: None)
    with pytest.raises(FileNotFoundError) as exc:
        resolve_target("afar")
    assert "Safari.app" in str(exc.value)
    assert "SECILMEDI" in str(exc.value)


def test_cli_subprocess_does_not_import(tmp_path):
    """Uçtan uca: `python -c` (sys.path[0] = cwd) ile çözücü içe aktarma yapmaz."""
    pkg = _uniq("p19evil")
    marker = tmp_path / "IMPORTED_MARKER"
    (tmp_path / pkg).mkdir()
    (tmp_path / pkg / "__init__.py").write_text(MARK.format(path=str(marker)))
    root = Path(tr.__file__).resolve().parents[2]
    code = (
        "import sys\n"
        "from karadul.core.target_resolver import resolve_target\n"
        "try:\n    resolve_target(sys.argv[1])\nexcept FileNotFoundError:\n    pass\n"
    )
    import os
    env = dict(os.environ, PYTHONPATH=str(root), PYTHONDONTWRITEBYTECODE="1")
    subprocess.run([sys.executable, "-c", code, f"{pkg}.payload"], cwd=tmp_path,
                   env=env, check=True, timeout=120, capture_output=True)
    assert not marker.exists()
