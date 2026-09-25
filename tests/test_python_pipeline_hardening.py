"""Python (PyInstaller/cx_Freeze) hattının sertleştirme testleri (2026-09-25).

Her sınıf bir maddeyi kilitler; her korumanın testi mutation ile kanıtlandı
(koruma geri alınınca ilgili test düşer). Sentetik girdiler zararsızdır: hiçbir
test yorumlayıcıyı çökertmeye yönelik veri üretmez.
"""

from __future__ import annotations

import marshal
import os
import sys
import time
from pathlib import Path

import pytest

from karadul.analyzers import pyc_decompiler as pd
from karadul.analyzers.pyc_decompiler import repair_pyc_header

RUNNING = f"{sys.version_info.major}.{sys.version_info.minor}"


def _pyc(path: Path, src: str = "def f():\n    return 1\n") -> Path:
    """Çalışan yorumlayıcı sürümünde, başlığı geçerli .pyc."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(repair_pyc_header(marshal.dumps(compile(src, "m.py", "exec")), RUNNING))
    return path


@pytest.fixture
def ana_surec_unmarshal_yasak(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Ana süreçte marshal.loads çağrılırsa kaydet ve patlat."""
    calls: list[int] = []

    def _yasak(*_a: object, **_k: object) -> object:
        calls.append(os.getpid())
        raise AssertionError("güvenilmeyen .pyc ana süreçte unmarshal edildi")

    monkeypatch.setattr(marshal, "loads", _yasak)
    return calls


# ---------------------------------------------------------------------------
# Madde 1: stdlib dis yedeği güvenilmeyen .pyc'yi süreç içinde açmıyor
# ---------------------------------------------------------------------------

class TestMadde1StdlibDisAyriSurecte:
    def test_yedek_ana_surecte_unmarshal_etmez(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        ana_surec_unmarshal_yasak: list[int],
    ) -> None:
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)  # pycdas yok
        p = _pyc(tmp_path / "m.pyc")
        res = pd._disassemble(p, RUNNING, timeout=30)
        assert res is not None and res[1] == "disasm"
        assert "RETURN_CONST" in res[0] or "RETURN_VALUE" in res[0]
        assert ana_surec_unmarshal_yasak == []

    def test_pycdas_dokemeyince_de_ana_surecte_acmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        ana_surec_unmarshal_yasak: list[int],
    ) -> None:
        """pycdas kurulu ama içeriği dökemedi -> yedek yine alt süreçte (kod değil -> None)."""
        import subprocess
        monkeypatch.setattr(
            pd, "resolve_tool", lambda name, **k: "/fake/pycdas" if name == "pycdas" else None,
        )
        monkeypatch.setattr(pd, "safe_run", lambda *a, **k: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"x (Python 3.12)\n", stderr=b""))
        p = tmp_path / "int.pyc"
        p.write_bytes(repair_pyc_header(bytes([ord("i")]) + (42).to_bytes(4, "little"), RUNNING))
        assert pd._disassemble(p, RUNNING, timeout=30) is None
        assert pd._stdlib_dis_isolated(p, timeout=30) == (None, "not_code")
        assert ana_surec_unmarshal_yasak == []

    def test_zaman_asimi_alt_sureci_oldurur(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(pd, "_DIS_CHILD_SCRIPT", "import time\ntime.sleep(30)\n")
        t0 = time.monotonic()
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=0.5) == (None, "timeout")
        assert time.monotonic() - t0 < 10

    def test_cagiranin_uzun_zaman_asimi_alt_surec_tavanini_asmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """config.timeouts.subprocess (7200 sn) dosya başına tavanı büyütmez."""
        monkeypatch.setattr(pd, "_DIS_CHILD_SCRIPT", "import time\ntime.sleep(30)\n")
        monkeypatch.setattr(pd, "_DIS_CHILD_TIMEOUT", 0.5)
        t0 = time.monotonic()
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=7200) == (None, "timeout")
        assert time.monotonic() - t0 < 10

    @pytest.mark.skipif(pd._process_memory_bytes(os.getpid()) is None,
                        reason="bu platformda süreç belleği ölçülemiyor")
    def test_bellek_bekcisi_alt_sureci_oldurur(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Tavanı aşan alt süreç (sıradan bytearray) bekçi tarafından öldürülür."""
        monkeypatch.setattr(pd, "_DIS_MAX_MEMORY_BYTES", 64 * 1024 ** 2)
        monkeypatch.setattr(pd, "_DIS_CHILD_SCRIPT", (
            "import time\n"
            "b = bytearray(256 * 1024 * 1024)\n"
            "for i in range(0, len(b), 4096):\n"
            "    b[i] = 1\n"
            "time.sleep(30)\n"
        ))
        t0 = time.monotonic()
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=30) == (None, "memory")
        assert time.monotonic() - t0 < 20

    def test_cikti_tavaninda_kesilir_ve_isaretlenir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(pd, "_DIS_MAX_OUTPUT_BYTES", 120)
        text, status = pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=30)
        assert status == "truncated"
        assert text is not None and text.rstrip().endswith(pd._DIS_TRUNCATED_MARKER)
        assert len(text.encode("utf-8")) <= 120 + len(pd._DIS_TRUNCATED_MARKER.encode()) + 4

    def test_donmus_uygulamada_surec_ici_yedege_donmez(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        ana_surec_unmarshal_yasak: list[int],
    ) -> None:
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=30) == (
            None, "no_interpreter")
        assert ana_surec_unmarshal_yasak == []

    def test_cikti_tekrarlanabilir(self, tmp_path: Path) -> None:
        """Hash tohumu sabit + adres yok: iki ayrı alt süreç aynı metni üretir."""
        # 12 öğeli küme: rastgele tohumla iki sürecin aynı sırayı tutturması olası değil
        src = "def f():\n    return 1\nT = {%s}\n" % ", ".join(repr(("k%d" % i, "v")) for i in range(12))
        p = _pyc(tmp_path / "m.pyc", src)
        a, st_a = pd._stdlib_dis_isolated(p, timeout=30)
        b, st_b = pd._stdlib_dis_isolated(p, timeout=30)
        assert st_a == st_b == "ok" and a == b
        assert "<code object f, file" in a and " at 0x" not in a
        assert "frozenset" in a

    def test_surum_farkliysa_alt_surec_bile_acilmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)
        spawned: list[object] = []
        monkeypatch.setattr(pd, "_stdlib_dis_isolated",
                            lambda *a, **k: spawned.append(a) or (None, "x"))
        other = "3.8" if RUNNING != "3.8" else "3.9"
        assert pd._disassemble(_pyc(tmp_path / "m.pyc"), other, timeout=30) is None
        assert spawned == []


# ---------------------------------------------------------------------------
# Madde 2: static TOC cookie'yi çıkarıcıyla aynı kaynaktan (big-endian) okuyor
# ---------------------------------------------------------------------------

REAL_HELLO = Path("/private/tmp/pycdc_e2e/py312/dist/hello")
REAL_APP = Path("/private/tmp/pycdc_e2e/py312_mod/dist/app")


def _analyzer():  # type: ignore[no-untyped-def]
    from karadul.analyzers.python_binary import PythonBinaryAnalyzer
    from karadul.config import Config
    return PythonBinaryAnalyzer(Config())


def _pyi_blob(files: list[tuple[str, bytes, int]], py_ver: int = 312) -> bytes:
    """Gerçek CArchive düzeni (tests.test_packed_binary kurucusu) + seçilen cookie sürümü."""
    import struct
    from karadul.analyzers.packed_binary import PYINSTALLER_MAGIC
    from tests.test_packed_binary import _build_pyinstaller_blob
    blob, cookie_offset = _build_pyinstaller_blob(files)
    ver_at = cookie_offset + len(PYINSTALLER_MAGIC) + 12
    return blob[:ver_at] + struct.pack("!I", py_ver) + blob[ver_at + 4:]


class TestMadde2CookieTekKaynak:
    def test_static_toc_cikariciyla_ayni(self) -> None:
        from karadul.analyzers.packed_binary import PyInstallerExtractor, locate_pyinstaller_archive
        blob = _pyi_blob([
            ("app", marshal.dumps(compile("x = 1\n", "app", "exec")), ord("s")),
            ("pyimod01_archive", b"\x00" * 8, ord("m")),
            ("PYZ.pyz", b"PYZ\x00" + b"\x00" * 20, ord("z")),
        ])
        res = _analyzer()._parse_pyinstaller_toc(blob)
        assert res is not None
        assert res["python_version"] == "3.12"
        assert [(e["name"], e["type"]) for e in res["entries"]] == [
            ("app", "s"), ("pyimod01_archive", "m"), ("PYZ.pyz", "z"),
        ]
        info = locate_pyinstaller_archive(blob)
        toc = PyInstallerExtractor._parse_toc(blob, info["toc_start"], info["toc_length"])
        assert [e["name"] for e in toc] == [e["name"] for e in res["entries"]]
        assert res["package_length"] == info["package_length"]

    @pytest.mark.parametrize("pyver,beklenen", [
        (312, "3.12"), (309, "3.9"), (27, "2.7"), (39, "3.9"),
        # little-endian okunmuş 312 (eski hata) ve anlamsız değerler sürüm sayılmaz
        (939589632, None), (0, None), (150, None), (7, None),
    ])
    def test_cookie_surumu_makul_degilse_raporlanmaz(self, pyver: int, beklenen: object) -> None:
        from karadul.analyzers.packed_binary import pyinstaller_python_version
        assert pyinstaller_python_version(pyver) == beklenen

    def test_kisa_cookie_none(self) -> None:
        from karadul.analyzers.packed_binary import PYINSTALLER_MAGIC
        assert _analyzer()._parse_pyinstaller_toc(b"\x00" * 64 + PYINSTALLER_MAGIC + b"\x01") is None

    @pytest.mark.skipif(not REAL_HELLO.is_file(), reason=f"gerçek binary yok: {REAL_HELLO}")
    def test_gercek_binary_surum_ve_girdiler(self) -> None:
        res = _analyzer()._parse_pyinstaller_toc(REAL_HELLO.read_bytes())
        assert res is not None
        assert res["python_version"] == "3.12"       # eskiden "9395896.32"
        assert res["total"] == 52                      # eskiden 0
        names = {e["name"] for e in res["entries"]}
        assert {"hello", "PYZ.pyz", "struct", "pyiboot01_bootstrap"} <= names


# ---------------------------------------------------------------------------
# Madde 3: modül envanteri string taramasından değil, iki TOC'den
# ---------------------------------------------------------------------------

def _pyi_binary_with_pyz(tmp_path: Path) -> Path:
    """CArchive: app(s) + pyiboot01_bootstrap(s) + struct(m) + PYZ(z: helper/json/_pyi_rth_utils)."""
    import importlib.util
    from karadul.analyzers.packed_binary import PYZ_ITEM_MODULE, PYZ_ITEM_PKG
    from tests.test_packed_binary import _build_pyinstaller_blob
    from tests.test_pyz_archive import _build_pyz, _code, _z
    pyz = _build_pyz([
        ("helper", PYZ_ITEM_MODULE, _z(_code("def yardim(x):\n    return x * 2\n", "helper"))),
        ("json", PYZ_ITEM_PKG, _z(_code("", "json"))),
        ("_pyi_rth_utils", PYZ_ITEM_PKG, _z(_code("", "_pyi_rth_utils"))),
    ], pymagic=importlib.util.MAGIC_NUMBER)
    blob, _ = _build_pyinstaller_blob([
        ("app", _code("import helper\n", "app"), ord("s")),
        ("pyiboot01_bootstrap", _code("", "pyiboot01_bootstrap"), ord("s")),
        ("struct", _code("", "struct"), ord("m")),
        ("PYZ.pyz", pyz, ord("z")),
    ])
    binp = tmp_path / "app"
    binp.write_bytes(b"_MEIPASS\x00" + blob)
    return binp


def _static_and_reconstruct(tmp_path: Path, binp: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    import json
    from karadul.core.target import Language, TargetInfo, TargetType
    from karadul.core.workspace import Workspace
    monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)
    an = _analyzer()
    monkeypatch.setattr(an.runner, "run_strings", lambda *a, **k: [])
    target = TargetInfo(path=binp, name=binp.name, target_type=TargetType.PYTHON_PACKED,
                        language=Language.PYTHON, file_size=binp.stat().st_size, file_hash="x")
    ws = Workspace(tmp_path / "ws", binp.name)
    ws.create()
    st = an.analyze_static(target, ws)
    rec = an.reconstruct(target, ws)
    manifest = json.loads((rec.artifacts["python_project"] / "manifest.json").read_text())
    return st, ws.load_json("static", "python_modules"), manifest


class TestMadde3EnvanterTekKaynak:
    def test_static_envanter_toclardan(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        st, mods, _ = _static_and_reconstruct(tmp_path, _pyi_binary_with_pyz(tmp_path), monkeypatch)
        assert mods["source"] == "pyinstaller_toc"
        cats = {m["name"]: (m["type"], m["origin"]) for m in mods["modules"]}
        assert cats == {
            "app": ("user", "carchive"), "pyiboot01_bootstrap": ("pyinstaller", "carchive"),
            "struct": ("stdlib", "carchive"), "helper": ("user", "pyz"),
            "json": ("stdlib", "pyz"), "_pyi_rth_utils": ("pyinstaller", "pyz"),
        }
        assert (mods["total"], mods["user_count"], mods["stdlib_count"],
                mods["pyinstaller_count"]) == (6, 2, 2, 2)
        assert not any(n.startswith("zPYZ") for n in cats)
        assert st.stats["functions"] == st.stats["module_count"] == 6
        assert st.stats["module_source"] == "pyinstaller_toc"

    def test_manifest_module_summary_pyz_bolumuyle_tutarli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _, mods, manifest = _static_and_reconstruct(
            tmp_path, _pyi_binary_with_pyz(tmp_path), monkeypatch)
        ms, pyz = manifest["module_summary"], manifest["pyz"]
        assert ms == {"source": "pyinstaller_toc", "total": 6, "user": 2, "stdlib": 2,
                      "pyinstaller": 2}
        from_pyz = [m for m in mods["modules"] if m["origin"] == "pyz"]
        assert pyz["modules_extracted"] == len(from_pyz)
        assert pyz["decompile_chain"] == sum(m["type"] == "user" for m in from_pyz)
        assert pyz["skipped_stdlib"] == sum(m["type"] == "stdlib" for m in from_pyz)
        assert pyz["skipped_pyinstaller"] == sum(m["type"] == "pyinstaller" for m in from_pyz)

    def test_toc_bossa_string_taramasi_etiketli(self, tmp_path: Path) -> None:
        import struct
        from karadul.analyzers.packed_binary import PYINSTALLER_MAGIC
        data = b"_MEIPASS\x00myapp.pyc\x00" + PYINSTALLER_MAGIC + struct.pack("!IIII", 0, 0, 0, 312)
        an = _analyzer()
        inv = an._pyinstaller_module_inventory(data, None)
        assert inv is not None and inv["total"] == 0
        scan = an._extract_embedded_modules(data)
        assert scan["source"] == "string_scan"

    @pytest.mark.skipif(not REAL_HELLO.is_file(), reason=f"gerçek binary yok: {REAL_HELLO}")
    def test_gercek_binary_envanteri(self) -> None:
        inv = _analyzer()._pyinstaller_module_inventory(REAL_HELLO.read_bytes(), None)
        assert (inv["total"], inv["user_count"], inv["stdlib_count"],
                inv["pyinstaller_count"]) == (109, 1, 103, 5)
        assert [m["name"] for m in inv["modules"] if m["type"] == "user"] == ["hello"]


# ---------------------------------------------------------------------------
# Madde 4: tek stdlib tanımı (classify_pyz_module) -- string taraması dahil
# ---------------------------------------------------------------------------

class TestMadde4TekStdlibTanimi:
    NAMES = ["os", "zoneinfo", "_ssl", "distutils.core", "imp", "test.support",
             "tomllib", "pyimod01_archive", "myapp", "requests"]

    def _scan(self, version: str | None) -> dict[str, str]:
        data = b"\x00".join(n.encode() + b".pyc" for n in self.NAMES)
        res = _analyzer()._extract_embedded_modules(data, version)
        return {m["name"]: m["type"] for m in res["modules"]}

    def test_string_taramasi_siniflandiriciyi_kullanir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import karadul.analyzers.python_binary as pbin
        monkeypatch.setattr(pbin, "classify_pyz_module", lambda name, version=None: "SINAMA")
        assert set(self._scan("3.12").values()) == {"SINAMA"}

    def test_kararlar_pyz_envanteriyle_ayni(self) -> None:
        from karadul.analyzers.packed_binary import classify_pyz_module
        for version in ("3.11", "3.12", "3.13"):
            got = self._scan(version)
            assert got == {n: classify_pyz_module(n, version) for n in self.NAMES}

    def test_hedef_surume_gore(self) -> None:
        v311, v312 = self._scan("3.11"), self._scan("3.12")
        assert v311["distutils.core"] == "stdlib" and v312["distutils.core"] == "user"
        assert v312["zoneinfo"] == v312["_ssl"] == "stdlib"   # eski sabit listede yoktu
        assert v312["pyimod01_archive"] == "pyinstaller"

    def test_static_asama_surumu_iletir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from karadul.core.target import Language, TargetInfo, TargetType
        from karadul.core.workspace import Workspace
        binp = tmp_path / "cxf"
        binp.write_bytes(b"cx_Freeze\x00Python 3.11.9\x00distutils.pyc\x00myapp.pyc\x00")
        an = _analyzer()
        monkeypatch.setattr(an.runner, "run_strings", lambda *a, **k: [])
        ws = Workspace(tmp_path / "ws", "cxf")
        ws.create()
        st = an.analyze_static(TargetInfo(
            path=binp, name="cxf", target_type=TargetType.PYTHON_PACKED,
            language=Language.PYTHON, file_size=binp.stat().st_size, file_hash="x"), ws)
        mods = ws.load_json("static", "python_modules")
        assert mods["source"] == "string_scan" and mods["python_version"] == "3.11.9"
        assert {m["name"]: m["type"] for m in mods["modules"]} == {
            "distutils": "stdlib", "myapp": "user"}
        assert st.stats["stdlib_modules"] == 1 and st.stats["user_modules"] == 1


# ---------------------------------------------------------------------------
# Madde 5: decompile zincirine üst sınır + dürüst raporlama
# ---------------------------------------------------------------------------

def _efs(tmp_path: Path, names: list[str]) -> list:  # type: ignore[type-arg]
    from karadul.analyzers.packed_binary import ExtractedFile
    out = []
    for n in names:
        p = tmp_path / (n + ".pyc")
        p.write_bytes(b"x")
        out.append(ExtractedFile(path=p, original_name=n, file_type="pyc", size=1,
                                 metadata={"pyz_module": True, "pyz_category": "user"}))
    return out


class TestMadde5ZincirUstSiniri:
    def test_secim_kucuk_paketler_once_sira_korunur(self, tmp_path: Path) -> None:
        from karadul.analyzers.packed_binary import select_decompile_chain
        names = ["big.a", "big.b", "app", "big.c", "myapp.x", "myapp.y", "big.d"]
        keep, skipped = select_decompile_chain(_efs(tmp_path, names), 4)
        assert [e.original_name for e in keep] == ["big.a", "app", "myapp.x", "myapp.y"]
        assert [e.original_name for e in skipped] == ["big.b", "big.c", "big.d"]
        keep, skipped = select_decompile_chain(_efs(tmp_path, names), 7)
        assert len(keep) == 7 and skipped == []
        keep, skipped = select_decompile_chain(_efs(tmp_path, names), 0)
        assert keep == [] and len(skipped) == 7

    def test_config_varsayilan_ve_yaml(self) -> None:
        from karadul.config import Config
        assert Config().security.max_python_decompile_modules == 2000
        cfg = Config._from_dict({"security": {"max_python_decompile_modules": 7}})
        assert cfg.security.max_python_decompile_modules == 7

    def test_zincir_siniri_uygular_ve_raporlar(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import json
        import karadul.analyzers.python_binary as pbin
        from karadul.analyzers.pyc_decompiler import DecompileResult
        calls: list[str] = []
        monkeypatch.setattr(pbin, "decompile_pyc", lambda pyc, out, **k: calls.append(
            k["out_stem"]) or DecompileResult(source_path=pyc, method="disasm", is_disassembly=True))
        an = _analyzer()
        an.config.security.max_python_decompile_modules = 3
        files = _efs(tmp_path, ["big.a", "big.b", "big.c", "app", "big.d"])
        s = an._decompile_pyc_files(files, tmp_path / "proj")
        assert calls == ["big.a", "big.b", "app"]
        assert (s["total_pyc"], s["limit"], s["skipped_by_limit"]) == (3, 3, 2)
        assert s["disasm"] + s["decompiled"] + s["partial"] + s["failed"] == s["total_pyc"]
        listing = json.loads((tmp_path / "proj" / s["skipped_list"]).read_text())
        assert [e["name"] for e in listing["skipped"]] == ["big.c", "big.d"]
        note = pbin._pyinstaller_note(s)
        assert "2 .pyc decompile üst sınırı (3)" in note

    def test_hepsi_atlanirsa_not_bos_paket_demez(self) -> None:
        from karadul.analyzers.python_binary import _pyinstaller_note
        note = _pyinstaller_note({"total_pyc": 0, "skipped_by_limit": 5, "limit": 0,
                                  "skipped_list": "decompile_skipped.json"})
        assert "bulunamadi" not in note and "5 .pyc" in note

    def test_cikarici_eski_decompiler_yoluna_da_siniri_uygular(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from karadul.analyzers.packed_binary import PyInstallerExtractor
        from karadul.config import Config
        seen: list[str] = []
        monkeypatch.setattr(PyInstallerExtractor, "_try_decompile_pyc_files", staticmethod(
            lambda files, out: seen.extend(ef.original_name for ef in files) or []))
        cfg = Config()
        cfg.security.max_python_decompile_modules = 2
        PyInstallerExtractor(cfg).extract(_pyi_binary_with_pyz(tmp_path), tmp_path / "out")
        # adaylar: CArchive app, pyiboot01_bootstrap, struct + PYZ helper (hepsi tek modüllü
        # grup -> arşiv sırası); sınır 2 -> ilk ikisi
        assert seen == ["app", "pyiboot01_bootstrap"]
        cfg.security.max_python_decompile_modules = 1
        seen.clear()
        PyInstallerExtractor(cfg).extract(_pyi_binary_with_pyz(tmp_path), tmp_path / "out2")
        assert seen == ["app"]

    def test_uctan_uca_manifest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json
        from karadul.core.target import Language, TargetInfo, TargetType
        from karadul.core.workspace import Workspace
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)
        an = _analyzer()
        an.config.security.max_python_decompile_modules = 1
        monkeypatch.setattr(an.runner, "run_strings", lambda *a, **k: [])
        binp = _pyi_binary_with_pyz(tmp_path)
        target = TargetInfo(path=binp, name="app", target_type=TargetType.PYTHON_PACKED,
                            language=Language.PYTHON, file_size=binp.stat().st_size, file_hash="x")
        ws = Workspace(tmp_path / "ws", "lim")
        ws.create()
        an.analyze_static(target, ws)
        rec = an.reconstruct(target, ws)
        proj = rec.artifacts["python_project"]
        manifest = json.loads((proj / "manifest.json").read_text())
        # zincir adayları: CArchive 3 .pyc (app, pyiboot01_bootstrap, struct) + PYZ helper
        assert manifest["decompile"]["total_pyc"] == 1
        assert manifest["decompile"]["skipped_by_limit"] == 3
        assert "3 .pyc decompile üst sınırı (1)" in manifest["note"]
        assert (proj / "decompile_skipped.json").is_file()
