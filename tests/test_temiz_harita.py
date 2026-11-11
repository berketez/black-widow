"""Temiz çıktının README'si diskteki çıktıyı anlatır.

Çıktı sağlamlığı denetimi (``docs/arge/2026-11-10_cikti_saglamligi/rapor.md`` bulgu 20) 119/119
ikilide README'nin ``src/main.c``, ``src/modules/``, ``src/types/`` dediğini, yazılan çıktının ise
``src/src/subsystem_*/`` olduğunu gösterdi: yapı dile göre elle yazılmış sabit bir ağaçtı.
Kilitlenen davranışlar:
  - "Output Structure" bloğundaki her satır diskte var olan bir girdidir; üst düzeydeki ve
    ``src/``'nin altındaki her girdi listelenir;
  - dizinin yanındaki sayı içindeki (alt dizinler dahil) dosya sayısıdır;
  - "Source Files" diskteki ``src/`` dosya sayısıdır (biçimlendiricinin sayacı değil);
  - "Names Recovered" haritadaki ``total_mappings``'tir;
  - kalabalık dizin kesilir ve kalan girdi sayısı yazılır.

Mutasyon koruması: ``scripts/measurement/mutation_specs_temiz_harita.json``.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from karadul.core import output_formatter as of
from karadul.core.output_formatter import OutputFormatter
from karadul.core.result import PipelineResult, StageResult
from karadul.core.workspace import Workspace


# ---------------------------------------------------------------------------
# Yardımcılar
# ---------------------------------------------------------------------------

@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    w = Workspace(base_dir=tmp_path / "workspaces", target_name="ornek")
    w.create()
    return w


def _sonuc(ws: Workspace, language: str = "c") -> PipelineResult:
    r = PipelineResult(target_name="ornek", target_hash="abc", workspace_path=ws.path)
    r.add_stage_result(StageResult(stage_name="identify", success=True, duration_seconds=0.0,
                                   stats={"target_type": "elf_binary", "language": language}))
    r.add_stage_result(StageResult(stage_name="reconstruct", success=True, duration_seconds=0.0,
                                   stats={}))
    return r


def _proje_agaci(ws: Workspace) -> None:
    """CProjectBuilder biçiminde bir proje ağacı (gerçek çıktıdaki yerleşim)."""
    proje = ws.get_stage_dir("reconstructed") / "project"
    for alt, ad, govde in (
        ("src/subsystem_io", "parse.c", "int parse(void)\n{\n  return 0;\n}\n"),
        ("src/subsystem_io", "load.c", "int load(void)\n{\n  return parse();\n}\n"),
        ("src/subsystem_misc", "FUN_00101000.c", "void FUN_00101000(void)\n{\n  return;\n}\n"),
        ("src", "main.c", "int main(void)\n{\n  return load();\n}\n"),
        ("include", "types.h", "typedef int undefined4;\n"),
        ("analysis", "notes.md", "not\n"),
    ):
        d = proje / alt
        d.mkdir(parents=True, exist_ok=True)
        (d / ad).write_text(govde, encoding="utf-8")
    (proje / "Makefile").write_text("all:\n", encoding="utf-8")
    (proje / ".clangd").write_text("CompileFlags: {}\n", encoding="utf-8")


def _yapi_blogu(readme: str) -> list[str]:
    m = re.search(r"## Output Structure\n\n```\n(.*?)\n```", readme, re.S)
    assert m, "README'de Output Structure bloğu yok"
    return m.group(1).split("\n")


def _ayristir(satirlar: list[str]):
    """Blok satırları -> (girdiler, kesilenler). girdi: (göreli yol, dizin mi, yorum)."""
    girdiler, kesilen = [], []
    ust: Path | None = None
    for satir in satirlar[1:]:
        girinti = len(satir) - len(satir.lstrip(" "))
        derinlik = girinti // 2
        govde = satir.strip()
        etiket, _, yorum = govde.partition("#")
        etiket, yorum = etiket.strip(), yorum.strip()
        m = re.fullmatch(r"\.\.\. \((\d+) more\)", etiket)
        if m:
            kesilen.append((derinlik, int(m.group(1))))
            continue
        dizin = etiket.endswith("/")
        ad = etiket.rstrip("/")
        if derinlik == 1:
            yol = Path(ad)
            ust = yol if dizin else None
        else:
            assert derinlik == 2 and ust is not None, satir
            yol = ust / ad
        girdiler.append((yol, dizin, yorum))
    return girdiler, kesilen


def _dosya_sayisi(d: Path) -> int:
    return sum(1 for p in d.rglob("*") if p.is_file())


def _bicimle(ws: Workspace, out: Path, language: str = "c") -> str:
    fr = OutputFormatter(ws, _sonuc(ws, language)).format_output(out, fmt="clean")
    assert fr.success, fr.errors
    return (out / "README.md").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# README: yapı diskten
# ---------------------------------------------------------------------------

def test_readme_yapisi_diskteki_cikti(ws, tmp_path):
    _proje_agaci(ws)
    out = tmp_path / "temiz"
    readme = _bicimle(ws, out)
    satirlar = _yapi_blogu(readme)
    assert satirlar[0] == "temiz/"
    girdiler, kesilen = _ayristir(satirlar)
    assert kesilen == []
    # her satır diskte var; dizin işareti doğru
    for yol, dizin, _ in girdiler:
        assert (out / yol).exists(), yol
        assert (out / yol).is_dir() == dizin, yol
    # üst düzeydeki ve src/ altındaki her girdi listede
    listelenen = {yol for yol, _, _ in girdiler}
    beklenen = {p.relative_to(out) for p in out.iterdir()}
    beklenen |= {p.relative_to(out) for p in (out / "src").iterdir()}
    assert listelenen == beklenen
    # eski sabit ağaç yazılmıyor (bu yerleşimde yoklar)
    assert Path("src/main.c") not in listelenen
    assert Path("src/modules") not in listelenen and Path("src/types") not in listelenen
    assert "modules/" not in "\n".join(satirlar) and "types/" not in "\n".join(satirlar)


def test_dizin_sayisi_alt_dizinler_dahil_dosya_sayisi(ws, tmp_path):
    _proje_agaci(ws)
    out = tmp_path / "temiz"
    girdiler, _ = _ayristir(_yapi_blogu(_bicimle(ws, out)))
    yorumlar = {yol: yorum for yol, dizin, yorum in girdiler if dizin}
    assert yorumlar[Path("src")] == f"Reconstructed source code, {_dosya_sayisi(out / 'src')} files"
    assert yorumlar[Path("src/src")] == "4 files"          # iki alt sistem dizini + main.c
    assert yorumlar[Path("src/include")] == "1 file"
    for yol, yorum in yorumlar.items():
        assert yorum.endswith(f"{_dosya_sayisi(out / yol)} files") or \
            yorum.endswith(f"{_dosya_sayisi(out / yol)} file"), (yol, yorum)


def test_ust_duzey_aciklamalar_yalniz_bilinen_dosyalara(ws, tmp_path):
    _proje_agaci(ws)
    out = tmp_path / "temiz"
    girdiler, _ = _ayristir(_yapi_blogu(_bicimle(ws, out)))
    yorumlar = {str(yol): yorum for yol, _, yorum in girdiler}
    assert yorumlar["README.md"] == "This file"
    assert yorumlar["naming_map.json"].startswith("Name mappings")
    assert yorumlar["report.json"] == "Machine-readable analysis report"
    # src/ altındaki dosyaya açıklama uydurulmaz
    assert yorumlar["src/Makefile"] == "" and yorumlar["src/.clangd"] == ""


def test_proje_agaci_yoksa_main_modules_types_diskte_oldugu_icin_yazilir(ws, tmp_path):
    """Proje ağacı yokken biçimlendirici main.c + modules/ + types/ yazar; README onları anlatır."""
    commented = ws.get_stage_dir("reconstructed") / "commented"
    commented.mkdir(parents=True)
    (commented / "big.c").write_text("int big(void)\n{\n  return 1;\n}\n" * 20, encoding="utf-8")
    (commented / "net.c").write_text("int net(void)\n{\n  return 2;\n}\n", encoding="utf-8")
    (commented / "t.h").write_text("typedef int x_t;\n", encoding="utf-8")
    out = tmp_path / "temiz"
    girdiler, _ = _ayristir(_yapi_blogu(_bicimle(ws, out)))
    listelenen = {str(yol) for yol, _, _ in girdiler}
    assert {"src/main.c", "src/modules", "src/types"} <= listelenen
    for yol, _, _ in girdiler:
        assert (out / yol).exists()


def test_source_files_diskten_sayaci_sisik_olsa_da(ws, tmp_path):
    """Genel dal aynı adlı dosyaları üst üste yazıp her yazmayı sayar; README diskteki sayıyı yazar."""
    rec = ws.get_stage_dir("reconstructed")
    for asama in ("annotated", "merged", "typed", "commented"):
        d = rec / asama
        d.mkdir(parents=True)
        (d / "parse.c").write_text(f"// {asama}\nint parse(void)\n{{\n  return 0;\n}}\n", encoding="utf-8")
    out = tmp_path / "temiz"
    fr = OutputFormatter(ws, _sonuc(ws, "cpp")).format_output(out, fmt="clean")
    assert fr.src_files == 4                                 # biçimlendiricinin sayacı
    readme = (out / "README.md").read_text(encoding="utf-8")
    disk = _dosya_sayisi(out / "src")
    assert disk == 1
    assert f"| Source Files | {disk} |" in readme


def test_names_recovered_haritadaki_total_mappings(ws, tmp_path):
    _proje_agaci(ws)
    out = tmp_path / "temiz"
    readme = _bicimle(ws, out)
    harita = json.loads((out / "naming_map.json").read_text(encoding="utf-8"))
    assert f"| Names Recovered | {harita['total_mappings']} |" in readme


def test_kalabalik_dizin_kesilir_kalan_sayilir(tmp_path):
    out = tmp_path / "temiz"
    src = out / "src"
    src.mkdir(parents=True)
    n = of.README_TREE_MAX_ENTRIES + 7
    for i in range(n):
        (src / f"f{i:03d}.c").write_text("int x;\n", encoding="utf-8")
    satirlar = OutputFormatter._output_tree_lines(out)
    girdiler, kesilen = _ayristir(satirlar)
    assert kesilen == [(2, 7)]
    assert len([g for g in girdiler if g[0].parent == Path("src")]) == of.README_TREE_MAX_ENTRIES
    # sınırda kesme yok
    (src / "f000.c").unlink()
    for i in range(1, 7):
        (src / f"f{i:03d}.c").unlink()
    _, kesilen = _ayristir(OutputFormatter._output_tree_lines(out))
    assert kesilen == []


def test_readme_henuz_yazilmadiysa_bu_dosya_olarak_listelenir(tmp_path):
    out = tmp_path / "temiz"
    (out / "src").mkdir(parents=True)
    (out / "naming_map.json").write_text("{}", encoding="utf-8")
    girdiler, _ = _ayristir(OutputFormatter._output_tree_lines(out))
    assert (Path("README.md"), False, "This file") in girdiler
    assert [str(g[0]) for g in girdiler] == ["src", "naming_map.json", "README.md"]
