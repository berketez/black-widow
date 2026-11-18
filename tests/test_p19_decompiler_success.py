"""P19 / BICIM-05: jadx ve ILSpy "başarılı" denetimi araç çökse de doğruydu.

Çıktı dizini önce yaratıldığı için `returncode == 0 or output_dir.exists()`
hep doğruydu; araç 0 dosya üretip çökse de `decompiled: True`. Artık başarı =
en az bir kaynak dosyası; kod != 0 ve dosya varsa `partial` + stderr'in ilk
satırı. jadx/ILSpy makinede kurulu değil: testler küçük sahte araç betiği
kullanır (yalnız bizim yazdığımız betik çalışır; analiz edilen dosya değil).
"""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path

import pytest

from karadul.analyzers.dotnet_binary import DotNetBinaryAnalyzer
from karadul.analyzers.java_binary import JavaBinaryAnalyzer
from karadul.config import Config
from karadul.core.target import Language, TargetInfo, TargetType
from karadul.core.workspace import Workspace

_SCRIPT = """#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--output-dir" ] || [ "$prev" = "--outputdir" ]; then out="$a"; fi
  prev="$a"
done
n={n}
i=0
while [ $i -lt $n ]; do
  mkdir -p "$out/src/p"
  echo "class C$i {{}}" > "$out/src/p/C$i.{ext}"
  i=$((i+1))
done
{stderr}
exit {code}
"""


def _fake_tool(tmp_path: Path, *, n: int, ext: str, code: int, stderr: str = "") -> str:
    p = tmp_path / f"fake_{ext}_{n}_{code}.sh"
    err = f'echo "{stderr}" >&2' if stderr else ""
    p.write_text(_SCRIPT.format(n=n, ext=ext, code=code, stderr=err))
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return str(p)


# --------------------------------------------------------------------- jadx


@pytest.mark.parametrize("n,code,success,partial", [
    (0, 1, False, False),   # çöktü, çıktı yok (eskiden success=True)
    (0, 0, False, False),   # kod 0 ama hiç .java yok
    (3, 1, True, True),     # "finished with errors": kısmi
    (2, 0, True, False),    # tam başarı
])
def test_jadx_success_semantics(tmp_path, n, code, success, partial):
    an = JavaBinaryAnalyzer(Config())
    an._jadx_path = _fake_tool(tmp_path, n=n, ext="java", code=code,
                               stderr="ERROR - jadx: bad dex\nikinci satir")
    out = tmp_path / "out"
    res = an._decompile_with_jadx(tmp_path / "x.apk", out)
    assert res["success"] is success
    assert bool(res.get("partial")) is partial
    assert res["source_files"] == n
    if not success or partial:
        assert res["error"] == "ERROR - jadx: bad dex"


def test_jadx_crash_static_stats_and_reconstruct(tmp_path):
    jar = tmp_path / "a.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Main-Class: com.x.Main\n")
        zf.writestr("com/x/Main.class", b"\xca\xfe\xba\xbe" + b"\x00" * 8)
    an = JavaBinaryAnalyzer(Config())
    an._jadx_path = _fake_tool(tmp_path, n=0, ext="java", code=1, stderr="ERROR - boom")
    ws = Workspace(tmp_path / "ws", "a")
    ws.create()
    ti = TargetInfo(path=jar, name="a", target_type=TargetType.JAVA_JAR,
                    language=Language.JAVA, file_size=jar.stat().st_size, file_hash="x")
    st = an.analyze_static(ti, ws)
    assert st.stats["decompiled"] is False
    assert any("jadx basarisiz: ERROR - boom" in e for e in st.errors)
    an.reconstruct(ti, ws)
    assert not (ws.get_stage_dir("reconstructed") / "java_project" / "src").exists()


def test_jadx_partial_static_stats(tmp_path):
    jar = tmp_path / "a.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("com/x/Main.class", b"\xca\xfe\xba\xbe" + b"\x00" * 8)
    an = JavaBinaryAnalyzer(Config())
    an._jadx_path = _fake_tool(tmp_path, n=3, ext="java", code=1,
                               stderr="ERROR - finished with errors, count: 2")
    ws = Workspace(tmp_path / "ws", "a")
    ws.create()
    ti = TargetInfo(path=jar, name="a", target_type=TargetType.JAVA_JAR,
                    language=Language.JAVA, file_size=jar.stat().st_size, file_hash="x")
    st = an.analyze_static(ti, ws)
    assert st.stats["decompiled"] is True and st.stats["decompiled_partial"] is True
    assert any("kismi" in e for e in st.errors)


# --------------------------------------------------------------------- ILSpy


@pytest.mark.parametrize("n,code,success,partial", [
    (0, 1, False, False),
    (0, 0, False, False),
    (3, 2, True, True),
    (1, 0, True, False),
])
def test_ilspy_success_semantics(tmp_path, n, code, success, partial):
    an = DotNetBinaryAnalyzer(Config())
    an._ilspy_path = _fake_tool(tmp_path, n=n, ext="cs", code=code,
                                stderr="Unhandled exception. System.BadImageFormatException")
    res = an._decompile_with_ilspy(tmp_path / "x.dll", tmp_path / "out")
    assert res["success"] is success
    assert bool(res.get("partial")) is partial
    assert res["source_files"] == n
    if not success or partial:
        assert res["error"].startswith("Unhandled exception.")


def test_ilspy_crash_static_stats(tmp_path):
    from tests.test_dotnet_binary import _build_minimal_pe

    dll = tmp_path / "x.dll"
    dll.write_bytes(_build_minimal_pe(has_cli=True))
    an = DotNetBinaryAnalyzer(Config())
    an._ilspy_path = _fake_tool(tmp_path, n=0, ext="cs", code=1, stderr="crash")
    ws = Workspace(tmp_path / "ws", "x")
    ws.create()
    ti = TargetInfo(path=dll, name="x", target_type=TargetType.DOTNET_ASSEMBLY,
                    language=Language.CSHARP, file_size=dll.stat().st_size, file_hash="x")
    st = an.analyze_static(ti, ws)
    assert st.stats["decompiled"] is False
    assert any("ILSpy basarisiz: crash" in e for e in st.errors)
