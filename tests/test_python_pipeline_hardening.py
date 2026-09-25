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
        monkeypatch.setattr(
            pd, "resolve_tool", lambda name, **k: "/fake/pycdas" if name == "pycdas" else None,
        )
        monkeypatch.setattr(pd, "_run_tool", lambda *a, **k: pd._ChildRun(
            0, b"x (Python 3.12)\n", b""))
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
        monkeypatch.setattr(pd, "_CHILD_TIMEOUT", 0.5)
        t0 = time.monotonic()
        assert pd._stdlib_dis_isolated(_pyc(tmp_path / "m.pyc"), timeout=7200) == (None, "timeout")
        assert time.monotonic() - t0 < 10

    @pytest.mark.skipif(pd._process_memory_bytes(os.getpid()) is None,
                        reason="bu platformda süreç belleği ölçülemiyor")
    def test_bellek_bekcisi_alt_sureci_oldurur(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Tavanı aşan alt süreç (sıradan bytearray) bekçi tarafından öldürülür."""
        monkeypatch.setattr(pd, "_CHILD_MAX_MEMORY_BYTES", 64 * 1024 ** 2)
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
        monkeypatch.setattr(pd, "_CHILD_MAX_OUTPUT_BYTES", 120)
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
        assert st.stats["python_modules_total"] == 6
        assert st.stats["python_modules_source"] == "pyinstaller_toc"

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
        assert st.stats["python_modules_stdlib"] == 1 and st.stats["python_modules_user"] == 1


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
                                 metadata={"pyz_module": True, "module_category": "user"}))
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
        # adaylar (tur 2 politikası): CArchive betiği app + PYZ helper; pyiboot01_bootstrap
        # (PyInstaller) ve struct (stdlib) zincire girmez. Sınır 2 -> ikisi de.
        assert seen == ["app", "helper"]
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
        # zincir adayları: CArchive betiği app + PYZ helper (stdlib/PyInstaller hariç)
        assert manifest["decompile"]["total_pyc"] == 1
        assert manifest["decompile"]["skipped_by_limit"] == 1
        assert "1 .pyc decompile üst sınırı (1)" in manifest["note"]
        assert (proj / "decompile_skipped.json").is_file()


# ---------------------------------------------------------------------------
# Madde 6: decompyle3/uncompyle6 çıktısı pycdc'yle aynı doğrulamadan geçer
# ---------------------------------------------------------------------------

# uncompyle6/decompyle3 3.9.3'ün çözemediği bölüm için yazdığı biçim (parser_error.py)
_FAILED_SECTION = ("def f(x):\n--- This code section failed: ---\n\n"
                   " L.   2         0  LOAD_FAST                'x'\n\n"
                   "Parse error at or near `RETURN_VALUE' instruction at offset 4\n")


def _fake_pylib_code(
    monkeypatch: pytest.MonkeyPatch, root: Path, sources: dict[str, str],
) -> None:
    """Diskte sahte decompyle3/uncompyle6 paketleri (kaynak kodu verilen) + sys.path.

    Kütüphane artık AYRI SÜREÇTE çağrılır: ana süreç yalnız find_spec ile yerini
    bulur, alt süreç paketi bu kökten import eder.
    """
    for name in ("decompyle3", "uncompyle6"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    for name, code in sources.items():
        (root / name).mkdir(parents=True, exist_ok=True)
        (root / name / "__init__.py").write_text(code, encoding="utf-8")
    monkeypatch.syspath_prepend(str(root))


def _fake_pylib(monkeypatch: pytest.MonkeyPatch, root: Path, outputs: dict[str, str]) -> None:
    """Sahte kütüphaneler: decompile_file sabit metni yazar."""
    _fake_pylib_code(monkeypatch, root, {
        name: f"def decompile_file(path, out):\n    out.write({text!r})\n"
        for name, text in outputs.items()})


def _pyc38(tmp_path: Path) -> Path:
    p = tmp_path / "m.pyc"
    p.write_bytes(repair_pyc_header(marshal.dumps(compile("x = 1\n", "m", "exec")), "3.8"))
    return p


class TestMadde6PylibDogrulama:
    @pytest.fixture(autouse=True)
    def _arac_yok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)   # pycdc/pycdas yok

    @pytest.mark.parametrize("cikti,beklenen", [
        (_FAILED_SECTION, "This code section failed"),
        # yalnız işaret: derlenebilir (yorum) ama araç hata bildirdi
        ("x = 1\n# NOTE: have internal decompilation grammar errors.\n", "grammar errors"),
        # yalnız compile: işaret yok, sözdizimi bozuk
        ("def f(:\n    return 1\n", "SyntaxError"),
    ], ids=["bolum", "isaret", "compile"])
    def test_dogrulanamayan_cikti_kaynak_sayilmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cikti: str, beklenen: str,
    ) -> None:
        _fake_pylib(monkeypatch, tmp_path / "site", {"decompyle3": cikti})
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8")
        assert res.success is False and res.method == "decompyle3_partial"
        assert not (tmp_path / "out" / "m.py").exists()
        assert beklenen in (res.partial_reason or "")
        text = res.partial_path.read_text(encoding="utf-8")
        assert text.startswith("# KARADUL: decompyle3 çıktısı DOĞRULANAMADI")
        assert cikti in text

    def test_gecerli_cikti_kaynak(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _fake_pylib(monkeypatch, tmp_path / "site", {"decompyle3": "# decompyle3 version 3.9.3\nx = 1\n"})
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8")
        assert res.success is True and res.method == "decompyle3"
        assert (tmp_path / "out" / "m.py").read_text().endswith("x = 1\n")

    def test_ilk_kutuphane_kismiysa_ikincisi_denenir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _fake_pylib(monkeypatch, tmp_path / "site", {"decompyle3": _FAILED_SECTION, "uncompyle6": "x = 1\n"})
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8")
        assert res.success is True and res.method == "uncompyle6"

    def test_pycdc_kismi_varsa_o_saklanir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pd, "resolve_tool",
                            lambda name, **k: "/fake/pycdc" if name == "pycdc" else None)
        monkeypatch.setattr(pd, "_run_tool", lambda *a, **k: pd._ChildRun(
            0, b"y = 2\n" + pd._PYCDC_INCOMPLETE_MARKER.encode() + b"\n", b""))
        _fake_pylib(monkeypatch, tmp_path / "site", {"decompyle3": _FAILED_SECTION})
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8")
        assert res.method == "pycdc_partial"
        assert res.partial_path.read_text(encoding="utf-8").startswith("# KARADUL: pycdc")


class TestMadde6CliDogrulama:
    """PyInstallerExtractor._try_decompile_pyc_files: CLI hata verse de 0 ile çıkar."""

    def _run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str, stderr: str):  # type: ignore[no-untyped-def]
        import subprocess
        import karadul.analyzers.packed_binary as pb
        from karadul.analyzers.packed_binary import ExtractedFile, PyInstallerExtractor
        monkeypatch.setattr(pb, "resolve_tool",
                            lambda name, **k: "/fake/uncompyle6" if name == "uncompyle6" else None)

        def fake_run(cmd, **k):  # type: ignore[no-untyped-def]
            Path(cmd[2]).write_text(text)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr=stderr)

        monkeypatch.setattr(pb, "safe_run", fake_run)
        pyc = tmp_path / "m.pyc"
        pyc.write_bytes(b"x")
        return PyInstallerExtractor._try_decompile_pyc_files(
            [ExtractedFile(path=pyc, original_name="m", file_type="pyc", size=1)], tmp_path / "o")

    def test_isaretli_cikti_partial(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        out = self._run(tmp_path, monkeypatch, _FAILED_SECTION, "")
        assert [(e.file_type, e.path.name) for e in out] == [("python_partial", "m.partial.py")]
        assert not (tmp_path / "o" / "decompiled_python" / "m.py").exists()
        assert out[0].path.read_text(encoding="utf-8").startswith(
            "# KARADUL: uncompyle6 çıktısı DOĞRULANAMADI")

    def test_yalniz_stderr_hatasi_partial(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        out = self._run(tmp_path, monkeypatch, "x = 1\n",
                        "\n# file m.pyc\n# Deparsing stopped due to parse error\n")
        assert out[0].file_type == "python_partial"
        assert any("stderr" in p for p in out[0].metadata["problems"])

    def test_gecerli_cikti_kaynak(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        out = self._run(tmp_path, monkeypatch, "def main():\n    pass\n", "")
        assert [(e.file_type, e.path.name) for e in out] == [("python_source", "m.py")]


# ---------------------------------------------------------------------------
# Madde 7: cx_Freeze -- aynı adlı .pyc'ler çakışmaz, hedef dizine yazılmaz
# ---------------------------------------------------------------------------

def _real_pyc(src: str) -> bytes:
    import importlib.util
    import struct
    return importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, 0, 0) + marshal.dumps(
        compile(src, "m.py", "exec"))


def _cxfreeze_dist(tmp_path: Path) -> tuple[Path, dict[str, bytes]]:
    """library.zip + lib/ düzeni; dönen sözlük: arşiv yolu -> özgün .pyc baytları."""
    import zipfile
    dist = tmp_path / "dist"
    lib = dist / "lib"
    lib.mkdir(parents=True)
    (dist / "app").write_bytes(b"cx_Freeze\x00")
    zipped = {n: _real_pyc(src) for n, src in [
        ("pkg_a/__init__.pyc", "A = 1"), ("pkg_b/__init__.pyc", "B = 2"),
        ("a/b_c.pyc", "ABC = 1"), ("a_b/c.pyc", "ABC = 2"),
        ("Foo.pyc", "FOO = 1"), ("foo.pyc", "foo = 2"), ("dup/__init__.pyc", "D = 1"),
    ]}
    with zipfile.ZipFile(lib / "library.zip", "w") as zf:
        for n, data in zipped.items():
            zf.writestr(n, data)
    loose = {n: _real_pyc(src) for n, src in [
        ("pkg_x/__init__.pyc", "X = 1"), ("pkg_y/__init__.pyc", "Y = 2"),
        ("dup/__init__.pyc", "D = 2"),
    ]}
    for n, data in loose.items():
        (lib / n).parent.mkdir(parents=True, exist_ok=True)
        (lib / n).write_bytes(data)
    return dist, {**{"zip:" + k: v for k, v in zipped.items()},
                  **{"lib:" + k: v for k, v in loose.items()}}


class TestMadde7CxFreezeAdCakismasi:
    @pytest.mark.parametrize("yol,beklenen", [
        ("pkg/__init__.pyc", ("pkg", True)),
        ("a/b_c.pyc", ("a.b_c", False)),
        ("pkg\\sub\\__init__.pyc", ("pkg.sub", True)),
        ("pkg/__pycache__/m.cpython-312.pyc", ("pkg.m", False)),
        ("__init__.pyc", ("__init__", False)),
        ("../../evil.pyc", ("evil", False)),
        ("CON.pyc", ("_CON", False)),
    ])
    def test_modul_adi(self, yol: str, beklenen: tuple[str, bool]) -> None:
        from karadul.analyzers.python_binary import _cxfreeze_module_name
        assert _cxfreeze_module_name(yol) == beklenen

    def test_her_pyc_ayri_dosya_icerik_korunur(self, tmp_path: Path) -> None:
        dist, originals = _cxfreeze_dist(tmp_path)
        ext, _ = _analyzer()._extract_cxfreeze(dist / "app", tmp_path / "out" / "extracted")
        assert len(ext) == len(originals) == 10
        assert len({e.path.name.casefold() for e in ext}) == 10      # harf duyarsız FS'de de ayrı
        for e in ext:
            key = ("zip:" if e.metadata["cxfreeze_origin"] == "library.zip" else "lib:") \
                + e.metadata["archive_path"]
            assert e.path.read_bytes() == originals[key], key
        names = {e.original_name for e in ext}
        assert {"pkg_a", "pkg_b", "pkg_x", "pkg_y", "a.b_c", "a_b.c", "Foo", "foo", "dup"} <= names
        dups = sorted(e.path.name for e in ext if e.original_name == "dup")
        assert dups == ["dup.pyc", "dup~2.pyc"]

    def test_hedef_dagitim_dizinine_yazilmaz(self, tmp_path: Path) -> None:
        dist, _ = _cxfreeze_dist(tmp_path)
        (dist / "lib" / "pkg_z").mkdir()
        (dist / "lib" / "pkg_z" / "mod.pyc").write_bytes(      # başlıksız -> onarım gerekir
            marshal.dumps(compile("Z = 1", "z", "exec")))
        before = sorted(p for p in dist.rglob("*"))
        an = _analyzer()
        ext, _ = an._extract_cxfreeze(dist / "app", tmp_path / "proj" / "extracted")
        s = an._decompile_pyc_files(ext, tmp_path / "proj", py_version=RUNNING)
        assert sorted(p for p in dist.rglob("*")) == before
        assert all(tmp_path / "proj" in e.path.parents for e in ext)
        out = sorted(p.name for p in (tmp_path / "proj" / "source").iterdir())
        for stem in ("pkg_x.", "pkg_y.", "pkg_z.mod."):   # uzantı araca göre (.py/.disasm.txt)
            assert any(n.startswith(stem) for n in out), (stem, out)
        assert not any(n.startswith("__init__") for n in out)
        assert s["total_pyc"] == 11

    def test_lib_disina_cikan_symlink_izlenmez(self, tmp_path: Path) -> None:
        dist, _ = _cxfreeze_dist(tmp_path)
        outside = tmp_path / "disarida"
        outside.mkdir()
        (outside / "gizli.pyc").write_bytes(b"GIZLI")
        (dist / "lib" / "kacak.pyc").symlink_to(outside / "gizli.pyc")
        (dist / "lib" / "kacakdizin").symlink_to(outside, target_is_directory=True)
        ext, rep = _analyzer()._extract_cxfreeze(dist / "app", tmp_path / "out")
        assert not any(e.path.read_bytes() == b"GIZLI" for e in ext)
        assert not any("kacak" in e.original_name for e in ext)
        # kaçak yol sessizce değil, sayılarak atlanır (manifest cxfreeze.skipped)
        assert rep["skipped"].get("outside_lib", 0) >= 1
        assert any(m["path"] == "kacak.pyc" for m in rep["skipped_members"])


# ===========================================================================
# 2. tur (2026-09-25)
# ===========================================================================

# ---------------------------------------------------------------------------
# Tur 2 / Madde 1: cx_Freeze library.zip sınırlı ve akışlı okunur (zip bombası)
# ---------------------------------------------------------------------------

def _zip(path: Path, members: list[tuple[str, bytes, int]]) -> Path:
    """(ad, veri, sıkıştırma) üyeleriyle ZIP yaz."""
    import zipfile
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data, method in members:
            zf.writestr(zipfile.ZipInfo(name), data, compress_type=method)
    return path


def _cxf_app(tmp_path: Path, dist: str = "dist") -> Path:
    app = tmp_path / dist / "app"
    app.parent.mkdir(parents=True, exist_ok=True)
    app.write_bytes(b"cx_Freeze\x00")
    return app


def _patch_eocd_count(path: Path, count: int) -> None:
    """EOCD'deki girdi sayısını yalanla (merkezi dizin olduğu gibi kalır)."""
    import struct
    data = bytearray(path.read_bytes())
    pos = data.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, pos + 8, count, count)
    path.write_bytes(bytes(data))


class TestTur2Madde1CxFreezeZipSiniri:
    MIB = 1024 * 1024

    def test_bomba_uye_acilmadan_atlanir_ve_sayilir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import zipfile
        import karadul.analyzers.python_binary as pbin
        monkeypatch.setattr(pbin, "_MAX_PYINSTALLER_DECOMPRESS", self.MIB)
        # Eski yol (zf.read) bir daha kullanılmamalı: sınırsız açar.
        monkeypatch.setattr(zipfile.ZipFile, "read", lambda *a, **k: pytest.fail("zf.read"))
        app = _cxf_app(tmp_path)
        good = _real_pyc("x = 1\n")
        _zip(app.parent / "lib" / "library.zip", [
            ("iyi.pyc", good, zipfile.ZIP_DEFLATED),
            ("bomba.pyc", b"\x00" * (2 * self.MIB), zipfile.ZIP_DEFLATED),   # ~2 KB sıkışık
        ])
        ext, rep = _analyzer()._extract_cxfreeze(app, tmp_path / "out")
        assert [e.original_name for e in ext] == ["iyi"]
        assert rep["skipped"] == {"too_large": 1}
        assert rep["skipped_members"] == [{"origin": "library.zip", "path": "bomba.pyc",
                                           "reason": "too_large", "size": 2 * self.MIB}]
        # Bildirilen boyut sınırı aşıyorsa hiç açılmaz: yalnız iyi üyenin baytları sayıldı.
        assert rep["bytes_read"] == len(good)
        assert (rep["library_zip"], rep["library_zip_entries"], rep["library_zip_pyc"],
                rep["extracted"]) == ("lib/library.zip", 2, 2, 1)

    def test_toplam_butce_uyeler_ve_lib_arasinda_paylasilir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import zipfile
        app = _cxf_app(tmp_path)
        _zip(app.parent / "lib" / "library.zip", [
            (f"m{i}.pyc", bytes([i]) * 1000, zipfile.ZIP_DEFLATED) for i in range(3)])
        (app.parent / "lib" / "gevsek.pyc").write_bytes(b"\x07" * 600)
        (app.parent / "lib" / "ufak.pyc").write_bytes(b"\x08" * 400)
        an = _analyzer()
        an.config.security.max_archive_extract_size = 2500
        ext, rep = an._extract_cxfreeze(app, tmp_path / "out")
        # 500 bayt kaldı: m2 (1000) ve lib/gevsek (600) sığmaz, lib/ufak (400) sığar.
        assert [e.original_name for e in ext] == ["m0", "m1", "ufak"]
        assert rep["skipped"] == {"total_limit": 2}
        assert {m["path"] for m in rep["skipped_members"]} == {"m2.pyc", "gevsek.pyc"}
        assert rep["bytes_read"] == 2400                      # bütçeyi aşan üye açılmadı

    def test_lib_serbest_dosya_uye_siniri(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import karadul.analyzers.python_binary as pbin
        monkeypatch.setattr(pbin, "_MAX_PYINSTALLER_DECOMPRESS", 4096)
        app = _cxf_app(tmp_path)
        (app.parent / "lib" / "pkg").mkdir(parents=True)
        (app.parent / "lib" / "pkg" / "buyuk.pyc").write_bytes(b"\x00" * 5000)
        (app.parent / "lib" / "pkg" / "kucuk.pyc").write_bytes(b"\x00" * 100)
        ext, rep = _analyzer()._extract_cxfreeze(app, tmp_path / "out")
        assert [e.original_name for e in ext] == ["pkg.kucuk"]
        assert rep["skipped"] == {"too_large": 1} and rep["lib_pyc"] == 2
        assert rep["bytes_read"] == 100

    def test_bzip2_ve_sifreli_uye_reddedilir(self, tmp_path: Path) -> None:
        """zipfile bzip2/lzma'yı max_length'siz açar; şifreli üye parola ister."""
        import struct
        import zipfile
        app = _cxf_app(tmp_path)
        z = _zip(app.parent / "lib" / "library.zip", [
            ("bz.pyc", b"x" * 100, zipfile.ZIP_BZIP2),
            ("sifreli.pyc", b"y" * 100, zipfile.ZIP_STORED),
            ("iyi.pyc", b"z" * 100, zipfile.ZIP_STORED),
        ])
        data = bytearray(z.read_bytes())
        cd = data.find(b"PK\x01\x02")          # merkezi dizinde sifreli.pyc girdisi
        while data[cd + 46:cd + 46 + 11] != b"sifreli.pyc":
            cd = data.find(b"PK\x01\x02", cd + 4)
        flags = struct.unpack_from("<H", data, cd + 8)[0]
        struct.pack_into("<H", data, cd + 8, flags | 0x1)
        z.write_bytes(bytes(data))
        ext, rep = _analyzer()._extract_cxfreeze(app, tmp_path / "out")
        assert [e.original_name for e in ext] == ["iyi"]
        assert rep["skipped"] == {"unsupported_compression": 1, "encrypted": 1}

    def test_merkezi_dizin_acilmadan_denetlenir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Girdi sayısı ya da dizin boyutu sınırı aşan arşiv zipfile'a hiç verilmez."""
        import zipfile
        import karadul.analyzers.python_binary as pbin
        from karadul.analyzers.packed_binary import PyInstallerExtractor
        monkeypatch.setattr(PyInstallerExtractor, "MAX_TOC_ENTRIES", 3)
        # (a) bildirilen sayı sınırın üstünde
        app_a = _cxf_app(tmp_path, "a")
        _zip(app_a.parent / "lib" / "library.zip",
             [(f"m{i}.pyc", b"x", zipfile.ZIP_STORED) for i in range(5)])
        # (b) sayı yalan (1) ama merkezi dizin 3 * 128 bayttan büyük
        app_b = _cxf_app(tmp_path, "b")
        z = _zip(app_b.parent / "lib" / "library.zip",
                 [(f"uzun_bir_modul_adi_{i:02d}.pyc", b"x", zipfile.ZIP_STORED) for i in range(8)])
        _patch_eocd_count(z, 1)
        monkeypatch.setattr(pbin.zipfile, "ZipFile",
                            lambda *a, **k: pytest.fail("ZipFile sınır denetiminden önce açıldı"))
        ext, rep = _analyzer()._extract_cxfreeze(app_a, tmp_path / "o1")
        assert ext == [] and "5 girdi" in rep["error"]
        ext, rep = _analyzer()._extract_cxfreeze(app_b, tmp_path / "o2")
        assert ext == [] and "1 girdi" in rep["error"] and "sınırı aşıyor" in rep["error"]

    def test_eocd_sayisi_yalansa_acildiktan_sonra_da_sinirlanir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import zipfile
        from karadul.analyzers.packed_binary import PyInstallerExtractor
        monkeypatch.setattr(PyInstallerExtractor, "MAX_TOC_ENTRIES", 3)
        app = _cxf_app(tmp_path)
        z = _zip(app.parent / "lib" / "library.zip",
                 [(f"m{i}.pyc", b"x", zipfile.ZIP_STORED) for i in range(5)])
        _patch_eocd_count(z, 1)                  # dizin küçük (5 * 51 < 3 * 128)
        ext, rep = _analyzer()._extract_cxfreeze(app, tmp_path / "out")
        assert [e.original_name for e in ext] == ["m0", "m1", "m2"]
        assert rep["skipped"] == {"entry_limit": 2} and rep["library_zip_entries"] == 5

    def test_eocd_okuyucu_zipfile_ile_ayni_kaydi_bulur(self, tmp_path: Path) -> None:
        import zipfile
        from karadul.analyzers.python_binary import _zip_directory_bounds
        z = _zip(tmp_path / "a.zip", [("a.pyc", b"1", zipfile.ZIP_STORED),
                                      ("bb.pyc", b"2", zipfile.ZIP_STORED)])
        assert _zip_directory_bounds(z) == (2, 2 * 46 + len("a.pyc") + len("bb.pyc"))
        with zipfile.ZipFile(z, "a") as zf:     # yorumlu arşiv: imza yorum alanında aranır
            zf.comment = b"yorum PK\x05 degil"
        assert _zip_directory_bounds(z) == (2, 2 * 46 + 11)
        # ZIP64 yer belirleyicisi: zipfile ZIP64 kaydını kullanırdı -> açılmaz (None)
        data = z.read_bytes()
        pos = data.rfind(b"PK\x05\x06")
        (tmp_path / "z64.zip").write_bytes(
            data[:pos] + b"PK\x06\x07" + b"\x00" * 16 + data[pos:])
        assert _zip_directory_bounds(tmp_path / "z64.zip") is None
        (tmp_path / "bos").write_bytes(b"zip degil")
        assert _zip_directory_bounds(tmp_path / "bos") is None

    def test_akisli_okuyucu_sinirda_birakir(self) -> None:
        """Bildirilen boyuta güvenmeden: akış sınırı aşınca okuma durur."""
        import io
        from karadul.analyzers.python_binary import _read_zip_member_bounded
        reads: list[int] = []

        class _Akis(io.RawIOBase):
            kalan = 10 * 1024 * 1024

            def read(self, n: int = -1) -> bytes:  # type: ignore[override]
                reads.append(n)
                n = self.kalan if n < 0 else min(n, self.kalan)
                self.kalan -= n
                return b"\x00" * n

        class _Zip:
            def open(self, info):  # type: ignore[no-untyped-def]
                return _Akis()

        data, reason, produced = _read_zip_member_bounded(_Zip(), None, 100_000)  # type: ignore[arg-type]
        assert (data, reason, produced) == (None, "too_large", 100_001)
        assert max(reads) <= 64 * 1024 and -1 not in reads

    def test_manifest_ve_not_atlanani_gosterir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import json
        import zipfile
        import karadul.analyzers.python_binary as pbin
        from karadul.core.target import Language, TargetInfo, TargetType
        from karadul.core.workspace import Workspace
        monkeypatch.setattr(pbin, "_MAX_PYINSTALLER_DECOMPRESS", self.MIB)
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)
        app = _cxf_app(tmp_path)
        _zip(app.parent / "lib" / "library.zip", [
            ("uygulama__main__.pyc", _real_pyc("def f():\n    return 1\n"), zipfile.ZIP_DEFLATED),
            ("bomba.pyc", b"\x00" * (2 * self.MIB), zipfile.ZIP_DEFLATED),
        ])
        an = _analyzer()
        monkeypatch.setattr(an.runner, "run_strings", lambda *a, **k: [])
        target = TargetInfo(path=app, name="app", target_type=TargetType.PYTHON_PACKED,
                            language=Language.PYTHON, file_size=app.stat().st_size, file_hash="x")
        ws = Workspace(tmp_path / "ws", "cxf")
        ws.create()
        an.analyze_static(target, ws)
        rec = an.reconstruct(target, ws)
        manifest = json.loads((rec.artifacts["python_project"] / "manifest.json").read_text())
        assert manifest["packer"] == "cx_freeze"
        assert manifest["cxfreeze"]["skipped"] == {"too_large": 1}
        assert manifest["cxfreeze"]["skipped_members"][0]["path"] == "bomba.pyc"
        assert "1 .pyc sınır/biçim nedeniyle okunmadı" in manifest["note"]
        assert any("okunmadı" in e for e in manifest["extraction_errors"])
        assert not any("bulunamadi" in e for e in manifest["extraction_errors"])


# ---------------------------------------------------------------------------
# Tur 2 / Madde 2: stdlib/PyInstaller politikası CArchive ve cx_Freeze'e de uygulanır
# ---------------------------------------------------------------------------

def _run_pipeline(tmp_path: Path, binp: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """static + reconstruct (araç yok): (static sonucu, reconstruct sonucu, manifest, proje)."""
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
    proj = rec.artifacts["python_project"]
    return st, rec, json.loads((proj / "manifest.json").read_text()), proj


def _extract_seen(tmp_path: Path, binp: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """PyInstallerExtractor.extract: (sonuç, eski decompiler yoluna giden adlar)."""
    from karadul.analyzers.packed_binary import PyInstallerExtractor
    from karadul.config import Config
    seen: list[str] = []
    monkeypatch.setattr(PyInstallerExtractor, "_try_decompile_pyc_files", staticmethod(
        lambda files, out: seen.extend(ef.original_name for ef in files) or []))
    return PyInstallerExtractor(Config()).extract(binp, tmp_path / "out"), seen


class TestTur2Madde2TekPolitika:
    @pytest.mark.parametrize("name,type_name,beklenen", [
        ("struct", "MODULE", "stdlib"),
        ("pyimod01_archive", "MODULE", "pyinstaller"),
        ("pyiboot01_bootstrap", "SCRIPT", "pyinstaller"),
        ("pyi_rth_inspect", "SCRIPT", "pyinstaller"),
        ("hello", "SCRIPT", "user"),
        ("calendar", "SCRIPT", "user"),      # stdlib adlı giriş betiği uygulamanın kodudur
        ("calendar", "MODULE", "stdlib"),
    ])
    def test_carchive_siniflandirma(self, name: str, type_name: str, beklenen: str) -> None:
        from karadul.analyzers.packed_binary import classify_carchive_module
        assert classify_carchive_module(name, type_name, "3.12") == beklenen

    def test_carchive_ve_pyz_tek_politika_manifestte_acik(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import json
        _, rec, manifest, proj = _run_pipeline(tmp_path, _pyi_binary_with_pyz(tmp_path), monkeypatch)
        em = manifest["extracted_modules"]
        assert (em["modules_extracted"], em["decompile_chain"], em["skipped_stdlib"],
                em["skipped_pyinstaller"]) == (6, 2, 2, 2)
        per = {"modules_extracted": 3, "decompile_chain": 1, "skipped_stdlib": 1,
               "skipped_pyinstaller": 1}
        assert em["by_origin"] == {"carchive": per, "pyz": per}
        # zincir: CArchive betiği app + PYZ helper; struct/pyiboot01_bootstrap artık girmiyor
        assert manifest["decompile"]["total_pyc"] == 2
        stems = {p.name.split(".", 1)[0] for p in (proj / "source").iterdir()}
        assert stems == {"app", "helper"}
        listing = json.loads((proj / em["modules_list"]).read_text())
        assert {m["name"]: (m["origin"], m["category"], m["decompile_chain"])
                for m in listing["modules"]} == {
            "app": ("carchive", "user", True),
            "pyiboot01_bootstrap": ("carchive", "pyinstaller", False),
            "struct": ("carchive", "stdlib", False),
            "helper": ("pyz", "user", True),
            "json": ("pyz", "stdlib", False),
            "_pyi_rth_utils": ("pyz", "pyinstaller", False),
        }
        assert ("Python modülleri: 6 çıkarıldı (CArchive 3, PYZ 3); 2 tanesi decompile "
                "zincirine girdi; 2 stdlib ve 2 PyInstaller iç modülü yalnız listelendi"
                ) in manifest["note"]
        assert {k: rec.stats[k] for k in (
            "python_modules_extracted", "python_modules_decompile_chain",
            "python_modules_skipped_stdlib", "python_modules_skipped_pyinstaller",
            "python_decompile_skipped_by_limit")} == {
            "python_modules_extracted": 6, "python_modules_decompile_chain": 2,
            "python_modules_skipped_stdlib": 2, "python_modules_skipped_pyinstaller": 2,
            "python_decompile_skipped_by_limit": 0}

    def test_static_envanter_ve_cikarici_ayni_karari_verir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Stdlib adlı giriş betiği ('calendar', 's') her iki yerde de kullanıcı kodu."""
        blob = _pyi_blob([
            ("calendar", marshal.dumps(compile("print(1)\n", "calendar", "exec")), ord("s")),
            ("struct", marshal.dumps(compile("", "struct", "exec")), ord("m")),
        ])
        binp = tmp_path / "cal"
        binp.write_bytes(b"_MEIPASS\x00" + blob)
        inv = _analyzer()._pyinstaller_module_inventory(binp.read_bytes(), None)
        assert {m["name"]: m["type"] for m in inv["modules"]} == {
            "calendar": "user", "struct": "stdlib"}
        res, seen = _extract_seen(tmp_path, binp, monkeypatch)
        cats = {ef.original_name: ef.metadata["module_category"]
                for ef in res.extracted_files if ef.file_type == "pyc"}
        assert cats == {"calendar": "user", "struct": "stdlib"}
        assert seen == ["calendar"]

    def test_carchive_surumu_cookieden(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """PYZ yoksa sürüm cookie'den: distutils 3.11'de stdlib (çalışan 3.12'de değil)."""
        blob = _pyi_blob([("distutils", marshal.dumps(compile("", "d", "exec")), ord("m"))],
                         py_ver=311)
        binp = tmp_path / "eski"
        binp.write_bytes(blob)
        res, seen = _extract_seen(tmp_path, binp, monkeypatch)
        (ef,) = [e for e in res.extracted_files if e.file_type == "pyc"]
        assert ef.metadata["module_category"] == "stdlib" and seen == []

    def test_cxfreeze_stdlib_zincire_girmez(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import zipfile
        app = _cxf_app(tmp_path)
        lib = app.parent / "lib"
        _zip(lib / "library.zip", [
            (n, _real_pyc("X = 1\n"), zipfile.ZIP_DEFLATED) for n in (
                "uygulama__main__.pyc", "os.pyc", "json/__init__.pyc",
                "email/mime/text.pyc", "benim/cekirdek.pyc")])
        for rel in ("xml/dom/__init__.pyc", "ucuncu/modul.pyc"):
            (lib / rel).parent.mkdir(parents=True)
            (lib / rel).write_bytes(_real_pyc("Y = 2\n"))
        _, rec, manifest, proj = _run_pipeline(tmp_path, app, monkeypatch)
        em = manifest["extracted_modules"]
        assert (em["modules_extracted"], em["decompile_chain"], em["skipped_stdlib"],
                em["skipped_pyinstaller"]) == (7, 3, 4, 0)
        assert em["by_origin"] == {
            "library.zip": {"modules_extracted": 5, "decompile_chain": 2,
                            "skipped_stdlib": 3, "skipped_pyinstaller": 0},
            "lib": {"modules_extracted": 2, "decompile_chain": 1,
                    "skipped_stdlib": 1, "skipped_pyinstaller": 0},
        }
        assert manifest["decompile"]["total_pyc"] == 3
        stems = {p.name.split(".disasm")[0].split(".partial")[0].removesuffix(".py")
                 for p in (proj / "source").iterdir()}
        assert stems == {"uygulama__main__", "benim.cekirdek", "ucuncu.modul"}
        assert (manifest["cxfreeze"]["python_version"],
                manifest["cxfreeze"]["python_version_source"]) == (RUNNING, "pyc_header")
        assert "3 tanesi decompile zincirine girdi; 4 stdlib yalnız listelendi" in manifest["note"]
        assert rec.stats["python_modules_skipped_stdlib"] == 4

    def test_decompile_suzgeci_kategoriye_bakar(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import karadul.analyzers.python_binary as pbin
        from karadul.analyzers.pyc_decompiler import DecompileResult
        calls: list[str] = []
        monkeypatch.setattr(pbin, "decompile_pyc", lambda pyc, out, **k: calls.append(
            k["out_stem"]) or DecompileResult(source_path=pyc, method="disasm", is_disassembly=True))
        files = _efs(tmp_path, ["app", "os", "pyimod01_archive", "kategorisiz"])
        files[1].metadata["module_category"] = "stdlib"
        files[2].metadata["module_category"] = "pyinstaller"
        del files[3].metadata["module_category"]
        s = _analyzer()._decompile_pyc_files(files, tmp_path / "proj")
        assert calls == ["app", "kategorisiz"] and s["total_pyc"] == 2

    @pytest.mark.skipif(not REAL_HELLO.is_file(), reason=f"gerçek binary yok: {REAL_HELLO}")
    def test_gercek_hello_zinciri_yalniz_uygulama(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Static envanterle (109 = 1 + 103 + 5) aynı sayılar; zincirde yalnız 'hello'."""
        from karadul.analyzers.python_binary import _extracted_modules_summary
        res, seen = _extract_seen(tmp_path, REAL_HELLO, monkeypatch)
        s = _extracted_modules_summary(res.extracted_files, tmp_path, "3.12")
        assert (s["modules_extracted"], s["decompile_chain"], s["skipped_stdlib"],
                s["skipped_pyinstaller"]) == (109, 1, 103, 5)
        assert s["by_origin"]["carchive"] == {"modules_extracted": 7, "decompile_chain": 1,
                                              "skipped_stdlib": 1, "skipped_pyinstaller": 5}
        assert seen == ["hello"]


# ---------------------------------------------------------------------------
# Tur 2 / Madde 3: static sayaçlar -- kullanıcı kodu ayrı, "functions" uydurulmaz
# ---------------------------------------------------------------------------

class TestTur2Madde3Sayaclar:
    def test_sentetik_sayaclar(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        st, _, _, _ = _run_pipeline(tmp_path, _pyi_binary_with_pyz(tmp_path), monkeypatch)
        assert {k: st.stats[k] for k in (
            "python_modules_total", "python_modules_user", "python_modules_stdlib",
            "python_modules_pyinstaller", "python_modules_source")} == {
            "python_modules_total": 6, "python_modules_user": 2, "python_modules_stdlib": 2,
            "python_modules_pyinstaller": 2, "python_modules_source": "pyinstaller_toc"}
        assert st.stats["functions_found"] == "N/A" and "functions" not in st.stats
        # eski genel adlar (module_count vb.) python_modules_* ile değişti: tek ad
        assert not {"module_count", "user_modules", "stdlib_modules", "pyinstaller_modules",
                    "module_source"} & set(st.stats)

    @pytest.mark.skipif(not REAL_HELLO.is_file(), reason=f"gerçek binary yok: {REAL_HELLO}")
    def test_gercek_hello(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Eskiden CLI 'Functions recovered 109' diyordu; kullanıcının 1 modülü var."""
        from karadul.core.target import Language, TargetInfo, TargetType
        from karadul.core.workspace import Workspace
        an = _analyzer()
        monkeypatch.setattr(an.runner, "run_strings", lambda *a, **k: [])
        ws = Workspace(tmp_path / "ws", "hello")
        ws.create()
        st = an.analyze_static(TargetInfo(
            path=REAL_HELLO, name="hello", target_type=TargetType.PYTHON_PACKED,
            language=Language.PYTHON, file_size=REAL_HELLO.stat().st_size, file_hash="x"), ws)
        assert (st.stats["python_modules_total"], st.stats["python_modules_user"],
                st.stats["python_modules_stdlib"], st.stats["python_modules_pyinstaller"]) == (
            109, 1, 103, 5)
        assert st.stats["functions_found"] == "N/A" and "functions" not in st.stats


# ---------------------------------------------------------------------------
# Tur 2 / Madde 4: pycdc/pycdas çıktısı ebeveynde üst sınırlı toplanır
# ---------------------------------------------------------------------------

def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


class TestTur2Madde4CiktiTavani:
    # Sonsuz yazan çocuk: 64 KiB + 1 ms uyku (~60 MB/sn). Bekçi yoksa zaman aşımına
    # (burada 3 sn) kadar yazar -- test yine düşer ama disk birkaç yüz MB'ı geçmez.
    _SONSUZ = ("import sys, time\nwhile True:\n"
               "    sys.{akim}.buffer.write((b'x' * 1023 + b'\\n') * 64)\n"
               "    sys.{akim}.buffer.flush()\n    time.sleep(0.001)\n")

    def test_sonsuz_stdout_bekcide_kesilir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Çıktı ebeveyn belleğine ve diske sınırsız akmaz: tavanda süreç öldürülür."""
        monkeypatch.setattr(pd, "_CHILD_MAX_OUTPUT_BYTES", 256 * 1024)
        monkeypatch.setattr(pd, "_CHILD_TIMEOUT", 3.0)
        # pycdc/pycdas'ın kullandığı yol (_run_tool): tavanı varsayılandan alır.
        run = pd._run_tool(_py(self._SONSUZ.format(akim="stdout")), timeout=7200)
        assert run.status == "truncated" and run.returncode is None
        assert 0 < len(run.stdout) <= 256 * 1024 and run.stdout.endswith(b"\n")

    def test_bitmis_surecin_fazla_ciktisi_da_kirpilir(self) -> None:
        """Bekçi örneklemeden önce biten sürecin fazlası da okunmaz (bellek sınırı)."""
        run = pd._run_capped(_py("print('a' * 99)\n"), timeout=30, max_output=50)
        assert run.status == "truncated" and len(run.stdout) <= 50

    def test_ebeveyn_bellegi_tavanla_sinirli(self) -> None:
        """Çocuk 20 MB yazıp çıksa da ebeveyn yalnız tavan kadarını okur (tracemalloc)."""
        import tracemalloc
        tracemalloc.start()
        try:
            run = pd._run_capped(_py("import sys\nsys.stdout.buffer.write(b'x' * 20_000_000)\n"),
                                 timeout=30, max_output=1000)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert run.status == "truncated" and len(run.stdout) <= 1000
        assert peak < 2 * 1024 * 1024, peak

    def test_sonsuz_stderr_de_kesilir(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pd, "_CHILD_MAX_OUTPUT_BYTES", 256 * 1024)
        monkeypatch.setattr(pd, "_CHILD_TIMEOUT", 3.0)
        run = pd._run_capped(_py(self._SONSUZ.format(akim="stderr")), timeout=7200)
        assert run.status == "truncated"
        assert len(run.stderr) <= pd._CHILD_MAX_STDERR_BYTES

    def test_arac_zaman_asimi_tavani(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """pycdc/pycdas da dis gibi dosya başına tavanlı (config 7200 sn değil)."""
        monkeypatch.setattr(pd, "_CHILD_TIMEOUT", 0.5)
        t0 = time.monotonic()
        run = pd._run_tool(_py("import time\ntime.sleep(30)\n"), timeout=7200)
        assert (run.status, run.stdout) == ("timeout", b"")
        assert time.monotonic() - t0 < 10

    def test_normal_cikti_ve_rc(self) -> None:
        run = pd._run_capped(_py(
            "import sys\nprint('merhaba')\nprint('uyari', file=sys.stderr)\nsys.exit(3)\n"),
            timeout=30)
        assert (run.status, run.returncode, run.stdout, run.stderr) == (
            "ok", 3, b"merhaba\n", b"uyari\n")

    def test_kesilen_pycdc_kaynagi_kismi_sayilir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Kesik çıktı derlense bile doğrulanmış kaynak DEĞİL; kesilme işaretlenir."""
        monkeypatch.setattr(pd, "resolve_tool",
                            lambda name, **k: "/fake/pycdc" if name == "pycdc" else None)
        monkeypatch.setattr(pd, "_run_tool", lambda *a, **k: pd._ChildRun(
            None, b"def f():\n    return 1\n", b"", "truncated"))
        other = "3.8" if RUNNING != "3.8" else "3.9"      # disasm yok: tek sonuç kısmi çıktı
        p = tmp_path / "m.pyc"
        p.write_bytes(repair_pyc_header(marshal.dumps(compile("x = 1", "m", "exec")), other))
        res = pd.decompile_pyc(p, tmp_path / "out", py_version=other)
        assert res.success is False and res.method == "pycdc_partial" and res.truncated
        assert "sınırında kesildi" in (res.partial_reason or "")
        assert "çöktü" not in (res.partial_reason or "")    # bekçi öldürdü, çöküş değil
        text = res.partial_path.read_text(encoding="utf-8")
        assert text.rstrip().endswith("sınırında kesildi (eksik)")
        assert not (tmp_path / "out" / "m.py").exists()

    def test_kesilen_pycdas_disasm_isaretli_ve_sayilir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import karadul.analyzers.python_binary as pbin
        from karadul.analyzers.packed_binary import ExtractedFile
        monkeypatch.setattr(pd, "resolve_tool",
                            lambda name, **k: "/fake/pycdas" if name == "pycdas" else None)
        monkeypatch.setattr(pd, "_run_tool", lambda *a, **k: pd._ChildRun(
            None, b"m.pyc (Python 3.12)\n[Code]\n    File Name: m.py\n", b"", "truncated"))
        other = "3.8" if RUNNING != "3.8" else "3.9"
        p = tmp_path / "m.pyc"
        p.write_bytes(repair_pyc_header(marshal.dumps(compile("x = 1", "m", "exec")), other))
        s = _analyzer()._decompile_pyc_files(
            [ExtractedFile(path=p, original_name="m", file_type="pyc", size=1)],
            tmp_path / "proj", py_version=other)
        assert (s["disasm"], s["output_truncated"]) == (1, 1)
        text = (tmp_path / "proj" / "source" / "m.disasm.txt").read_text(encoding="utf-8")
        assert text.rstrip().endswith(pd._DIS_TRUNCATED_MARKER)
        assert "çıktı tavanında kesildi" in pbin._pyinstaller_note(s)

    def test_pycdas_zaman_asiminda_disasm_sayilmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sözleşme: yalnız tam (ok) ya da açıkça kesilmiş çıktı disassembly sayılır."""
        monkeypatch.setattr(pd, "resolve_tool",
                            lambda name, **k: "/fake/pycdas" if name == "pycdas" else None)
        monkeypatch.setattr(pd, "_run_tool", lambda *a, **k: pd._ChildRun(
            0, b"m.pyc (Python 3.12)\n[Code]\n", b"", "memory"))
        other = "3.8" if RUNNING != "3.8" else "3.9"
        p = tmp_path / "m.pyc"
        p.write_bytes(repair_pyc_header(marshal.dumps(compile("x = 1", "m", "exec")), other))
        assert pd._disassemble(p, other, timeout=30) is None

    @pytest.mark.skipif(not (Path(__file__).resolve().parents[1] / "vendor" / "pycdc" / "pycdas").is_file(),
                        reason="vendor/pycdc yok (scripts/setup_pycdc.sh)")
    def test_gercek_pycdas_tavanda_kesilir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        vendor = str(Path(__file__).resolve().parents[1] / "vendor" / "pycdc")
        monkeypatch.setattr(pd, "_CHILD_MAX_OUTPUT_BYTES", 4096)
        src = "".join(f"def f{i}(a, b):\n    return a * {i} + b\n" for i in range(200))
        p = _pyc(tmp_path / "buyuk.pyc", src)
        res = pd._disassemble(p, RUNNING, timeout=30, extra_paths=[vendor])
        assert res is not None
        text, method, truncated = res
        assert (method, truncated) == ("disasm", True)
        assert "[Code]" in text and text.rstrip().endswith(pd._DIS_TRUNCATED_MARKER)
        assert len(text.encode("utf-8")) <= 4096 + len(pd._DIS_TRUNCATED_MARKER.encode()) + 2


# ---------------------------------------------------------------------------
# Tur 2 / Madde 5: decompyle3/uncompyle6 kütüphane yolu ayrı süreçte, sınırlı
# (kurulu değiller: diskte sahte paketlerle kanıt)
# ---------------------------------------------------------------------------

class TestTur2Madde5PylibAltSurec:
    @pytest.fixture(autouse=True)
    def _arac_yok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pd, "resolve_tool", lambda name, **k: None)   # pycdc/pycdas yok

    def test_ana_surec_kutuphaneyi_ne_import_eder_ne_unmarshal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        ana_surec_unmarshal_yasak: list[int],
    ) -> None:
        """Gerçek kütüphane gibi .pyc'yi marshal ile açar -- ama alt süreçte."""
        izler = tmp_path / "iz.txt"
        _fake_pylib_code(monkeypatch, tmp_path / "site", {"decompyle3": (
            "import marshal, os\n"
            f"open({str(izler)!r}, 'a').write('import %d\\n' % os.getpid())\n"
            "def decompile_file(path, out):\n"
            "    data = open(path, 'rb').read()\n"
            "    try:\n"
            "        marshal.loads(data[16:])   # 3.8 gövdesi çalışan sürümde açılmayabilir\n"
            "    except Exception:\n"
            "        pass\n"
            "    out.write('x = 1\\n')\n"
        )})
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8")
        assert res.success is True and res.method == "decompyle3"
        assert "decompyle3" not in sys.modules
        pids = [int(ln.split()[1]) for ln in izler.read_text().splitlines()]
        assert pids and os.getpid() not in pids          # modül kodu yalnız alt süreçte çalıştı
        assert ana_surec_unmarshal_yasak == []

    @pytest.mark.parametrize("tavan,cagiran", [(0.5, 7200.0), (60.0, 0.5)],
                             ids=["dosya_basi_tavan", "cagiranin_suresi"])
    def test_takilan_kutuphane_zaman_asiminda_birakilir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tavan: float, cagiran: float,
    ) -> None:
        """Hem dosya başı tavan (_CHILD_TIMEOUT) hem çağıranın daha kısa süresi geçerli."""
        monkeypatch.setattr(pd, "_CHILD_TIMEOUT", tavan)
        _fake_pylib_code(monkeypatch, tmp_path / "site", {"decompyle3": (
            "import time\ndef decompile_file(path, out):\n    time.sleep(30)\n")})
        t0 = time.monotonic()
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8",
                               timeout=cagiran)
        assert time.monotonic() - t0 < 10
        assert res.method == "none" and res.success is False

    def test_durdurulan_surecin_ciktisi_kullanilmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sözleşme: zaman aşımı/bellek durumunda (çıktı olsa bile) kaynak sayılmaz."""
        _fake_pylib(monkeypatch, tmp_path / "site", {"decompyle3": "x = 1\n"})
        monkeypatch.setattr(pd, "_run_capped", lambda *a, **k: pd._ChildRun(
            None, b"x = 1\n", b"", "timeout"))
        assert pd._decompile_with_pylib(_pyc38(tmp_path), "3.8", timeout=30) is None

    @pytest.mark.skipif(pd._process_memory_bytes(os.getpid()) is None,
                        reason="bu platformda süreç belleği ölçülemiyor")
    def test_bellek_bekcisi(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pd, "_CHILD_MAX_MEMORY_BYTES", 64 * 1024 ** 2)
        _fake_pylib_code(monkeypatch, tmp_path / "site", {"decompyle3": (
            "import time\ndef decompile_file(path, out):\n"
            "    b = bytearray(256 * 1024 * 1024)\n"
            "    for i in range(0, len(b), 4096):\n        b[i] = 1\n"
            "    time.sleep(30)\n")})
        t0 = time.monotonic()
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8")
        assert time.monotonic() - t0 < 20
        assert res.method == "none"

    def test_cikti_tavaninda_kesilir_kismi_sayilir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(pd, "_CHILD_MAX_OUTPUT_BYTES", 4096)
        _fake_pylib_code(monkeypatch, tmp_path / "site", {"decompyle3": (
            "def decompile_file(path, out):\n"
            "    for i in range(100000):\n        out.write('x%d = 1\\n' % i)\n")})
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8")
        assert res.success is False and res.method == "decompyle3_partial" and res.truncated
        assert "sınırında kesildi" in (res.partial_reason or "")
        text = res.partial_path.read_text(encoding="utf-8")
        assert text.rstrip().endswith("sınırında kesildi (eksik)")
        assert len(text.encode("utf-8")) < 4096 + 1024

    def test_hata_veren_kutuphanenin_yarim_ciktisi_kullanilmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _fake_pylib_code(monkeypatch, tmp_path / "site", {
            "decompyle3": ("def decompile_file(path, out):\n    out.write('y = 2\\n')\n"
                           "    out.flush()\n    raise RuntimeError('ayristirici')\n"),
            "uncompyle6": "def decompile_file(path, out):\n    out.write('x = 1\\n')\n",
        })
        res = pd.decompile_pyc(_pyc38(tmp_path), tmp_path / "out", py_version="3.8")
        assert res.success is True and res.method == "uncompyle6"
        assert (tmp_path / "out" / "m.py").read_text() == "x = 1\n"

    def test_kurulu_degilse_alt_surec_acilmaz(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        for name in ("decompyle3", "uncompyle6"):
            if pd._pylib_search_root(name) is not None:
                pytest.skip(f"{name} bu ortamda kurulu")
        monkeypatch.setattr(pd, "_run_capped", lambda *a, **k: pytest.fail("alt süreç açıldı"))
        assert pd._decompile_with_pylib(_pyc38(tmp_path), "3.8", timeout=30) is None

    def test_310_ve_sonrasi_denenmez(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _fake_pylib(monkeypatch, tmp_path / "site", {"decompyle3": "x = 1\n"})
        monkeypatch.setattr(pd, "_run_capped", lambda *a, **k: pytest.fail("alt süreç açıldı"))
        assert pd._decompile_with_pylib(_pyc38(tmp_path), "3.10", timeout=30) is None
