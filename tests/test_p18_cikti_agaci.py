"""P18 — çıktı ağacı: alt sistem başlıkları, içe aktarım taslakları, tip öntanımı.

B-B1: ``include/subsystem_*.h`` bildirimleri tanımın kendisinden kurulur. Eski başlık
çağrı grafındaki Ghidra adından ``void ad(void);`` yazıyordu: yeniden adlandırılan
fonksiyonda eski ad, C++ adında geçersiz C adı (``operator.new``), her fonksiyonda
tanımdan farklı imza (birleşik 119 koşu: 66 860 bildirimin 36 083'ü imza farklı,
22 976'sı tanımsız ad, 11'i geçersiz C adı).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from karadul.reconstruction.c_project_builder import CProjectBuilder, definition_signatures


class _Alan:
    def __init__(self, kok: Path) -> None:
        self._kok = kok

    def get_stage_dir(self, ad: str) -> Path:
        return self._kok / ad


def _birim(baslik_ad: str, adres: str, govde_imza: str, satir: int = 12) -> str:
    return (
        f'#include "types.h"\n\n// Function: {baslik_ad}\n// Address:  {adres}\n\n'
        f"/* WARNING: yorum {{ ayraç }} içeriyor */\n"
        f"{govde_imza}\n\n{{\n" + "  puts(\"{ dizgide ayraç }\");\n" * satir + "}\n"
    )


def _kur(tmp_path: Path, birimler: dict[str, str], dugumler: dict[str, str]) -> Path:
    kaynak = tmp_path / "kaynak"
    kaynak.mkdir()
    for ad, icerik in birimler.items():
        (kaynak / f"{ad}.c").write_text(icerik)
    (tmp_path / "static").mkdir(exist_ok=True)
    (tmp_path / "static" / "ghidra_call_graph.json").write_text(json.dumps({
        "program": "deneme",
        "nodes": {a: {"name": n, "address": a, "callees": [], "callers": []}
                  for a, n in dugumler.items()},
        "edges": [],
    }))
    sonuc = CProjectBuilder(None).build(kaynak, tmp_path / "proje", workspace=_Alan(tmp_path))
    assert sonuc.success, sonuc.errors
    return tmp_path / "proje"


def _bildirimler(proje: Path) -> list[str]:
    satirlar = []
    for h in sorted((proje / "include").glob("subsystem_*.h")):
        for s in h.read_text().splitlines():
            if s and not s.startswith(("#", "//")):
                satirlar.append(s)
    return satirlar


def test_baslik_bildirimi_tanimin_adi_ve_imzasi(tmp_path):
    """Yeniden adlanan ve C++ adlı fonksiyonda başlık tanımla aynı ad ve imzayı söyler."""
    proje = _kur(tmp_path, {
        "FUN_00001000": _birim("parse_args", "00001000", "int parse_args(char **argv,int argc)"),
        "operator.new": _birim("operator.new", "00002000", "void * operator_new(ulong param_1)"),
    }, {"00001000": "FUN_00001000", "00002000": "operator.new"})
    bildirim = _bildirimler(proje)
    assert "int parse_args(char **argv,int argc);  // @00001000" in bildirim
    assert "void * operator_new(ulong param_1);  // @00002000" in bildirim
    metin = "\n".join(bildirim)
    assert "FUN_00001000" not in metin
    assert "operator.new" not in metin
    assert "(void);" not in metin


def test_her_bildirim_bir_tanima_denk(tmp_path):
    """Başlıktaki her bildirim src/ altındaki bir tanımın imzasıdır (ad + tip)."""
    proje = _kur(tmp_path, {
        f"FUN_0000{i}000": _birim(f"islev_{i}", f"0000{i}000", f"long islev_{i}(long param_1)")
        for i in range(1, 6)
    }, {f"0000{i}000": f"FUN_0000{i}000" for i in range(1, 6)})
    tanimlar = set()
    for c in (proje / "src").rglob("*.c"):
        tanimlar.update(imza for _ad, imza in definition_signatures(c.read_text()))
    bildirim = [re.sub(r";\s*//.*$|;$", "", s) for s in _bildirimler(proje)]
    assert len(bildirim) == 5
    assert set(bildirim) <= tanimlar


def test_tanim_imzasi_yorum_dizgi_onislemci_atlanir():
    kod = (
        '#include "types.h"\n// Function: f\n/* { */\n'
        "uint\nf(code *cb,\n  int (*g)(int))\n\n{\n  if (x) {\n    puts(\"}\");\n  }\n}\n"
        "int g(void) { return 0; }\n"
    )
    assert definition_signatures(kod) == [
        ("f", "uint f(code *cb, int (*g)(int))"), ("g", "int g(void)")]


def test_tanimi_okunamayan_birim_bildirilmez(tmp_path):
    proje = _kur(tmp_path, {
        "FUN_00003000": "// Function: FUN_00003000\n// Address:  00003000\n" + "// x\n" * 12,
    }, {"00003000": "FUN_00003000"})
    assert _bildirimler(proje) == []
    metin = "\n".join(h.read_text() for h in (proje / "include").glob("subsystem_*.h"))
    assert "FUN_00003000: no C-declarable function definition found in source; not declared" in metin


def test_nitelikli_cpp_adi_c_bildirimi_olmaz(tmp_path):
    """Ghidra'nın nitelikli C++ adı (`std::x`, `A::~A`) başlıkta yalnız yorum olarak durur."""
    proje = _kur(tmp_path, {
        "now": _birim("std::chrono::now", "00004000",
                      "void std::chrono::_V2::system_clock::now(void)"),
        "_State": _birim("~_State", "00005000",
                         "void __thiscall std::thread::_State::~_State(_State *this)"),
    }, {"00004000": "now", "00005000": "~_State"})
    assert _bildirimler(proje) == []
    metin = "\n".join(h.read_text() for h in (proje / "include").glob("subsystem_*.h"))
    assert metin.count("// qualified C++ name, not a C declaration:") == 2


def _fonksiyonlar(tmp_path: Path, kayitlar: list[tuple[str, str, bool]]) -> None:
    (tmp_path / "static").mkdir(exist_ok=True)
    (tmp_path / "static" / "ghidra_functions.json").write_text(json.dumps({
        "functions": [{"name": n, "address": a, "size": 8, "is_thunk": t}
                      for n, a, t in kayitlar]}))


def test_thunk_birimleri_ayri_dizinde_ve_readme_program_sayisi(tmp_path):
    """Ghidra is_thunk birimleri alt sistemlere değil src/import_thunks/'a; README program
    fonksiyonu sayısı thunk'sız (rapordaki ``ghidra_function_count`` ile aynı anlam)."""
    _fonksiyonlar(tmp_path, [
        ("fclose", "00001000", True), ("malloc", "00002000", True),
        ("entry", "00003000", True), ("FUN_00004000", "00004000", False),
        ("FUN_00005000", "00005000", False),
    ])
    proje = _kur(tmp_path, {
        "fclose": _birim("fclose", "00001000", "int fclose(FILE *__stream)", satir=20),
        "malloc": _birim("malloc", "00002000", "void * malloc(size_t __size)"),
        "entry": _birim("entry", "00003000", "void entry(void)"),
        "FUN_00004000": _birim("islev_a", "00004000", "long islev_a(long param_1)"),
        "FUN_00005000": _birim("islev_b", "00005000", "long islev_b(long param_1)"),
    }, {"00001000": "fclose", "00002000": "malloc", "00003000": "entry",
        "00004000": "FUN_00004000", "00005000": "FUN_00005000"})
    thunk_dosyasi = proje / "src" / "import_thunks" / "import_thunks.c"
    metin = thunk_dosyasi.read_text()
    assert "Thunk functions (Ghidra is_thunk)" in metin
    assert "Address:  00001000" in metin and "Address:  00002000" in metin
    for c in (proje / "src").rglob("*.c"):
        if c != thunk_dosyasi:
            icerik = c.read_text()
            assert "Address:  00001000" not in icerik and "Address:  00002000" not in icerik
    # Giriş noktası thunk olsa da main.c'de; thunk sayısına girer.
    assert "Address:  00003000" in (proje / "src" / "main.c").read_text()
    readme = (proje / "README.md").read_text()
    assert "- **Decompiled functions:** 5" in readme
    assert "- **Program functions:** 2" in readme
    assert ("- **Thunks (import stubs, `src/import_thunks/`):** 2 "
            "(+1 entry-point thunk in `src/main.c`)") in readme
    assert "int fclose(FILE *__stream);  // @00001000" in (
        proje / "include" / "import_thunks.h").read_text()


def test_thunk_bilgisi_yoksa_bilinmiyor_yazilir(tmp_path):
    """Ghidra fonksiyon listesi yoksa thunk sayısı uydurulmaz; yerleşim eskisi gibi."""
    proje = _kur(tmp_path, {
        "fclose": _birim("fclose", "00001000", "int fclose(FILE *__stream)"),
    }, {"00001000": "fclose"})
    readme = (proje / "README.md").read_text()
    assert "- **Thunks:** unknown (Ghidra function list with is_thunk not found)" in readme
    assert "Program functions" not in readme
    assert not (proje / "src" / "import_thunks").exists()


def test_is_thunk_alani_olmayan_eski_liste_bilinmiyor(tmp_path):
    """P16a öncesi fonksiyon listesinde ``is_thunk`` yok: thunk sayısı 0 değil, bilinmiyor."""
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "ghidra_functions.json").write_text(json.dumps({
        "functions": [{"name": "fclose", "address": "00001000", "size": 8}]}))
    proje = _kur(tmp_path, {
        "fclose": _birim("fclose", "00001000", "int fclose(FILE *__stream)"),
    }, {"00001000": "fclose"})
    readme = (proje / "README.md").read_text()
    assert "- **Thunks:** unknown (Ghidra function list with is_thunk not found)" in readme
    assert "Program functions" not in readme


def test_ayni_ad_farkli_imza_bir_kez_bildirilir(tmp_path):
    """Aynı ad iki birimde farklı imzayla: tek bildirim (adres sırasında ilki), öbürü yorum."""
    proje = _kur(tmp_path, {
        "dup": _birim("dup", "00006000", "int dup(int param_1)"),
        "dup_00007000": _birim("dup", "00007000", "long dup(long param_1)"),
    }, {"00006000": "dup", "00007000": "dup"})
    assert _bildirimler(proje) == ["int dup(int param_1);  // @00006000"]
    metin = "\n".join(h.read_text() for h in (proje / "include").glob("subsystem_*.h"))
    assert ("// also defined with another signature (not declared twice): "
            "long dup(long param_1);  // @00007000") in metin


# ---------------------------------------------------------------------------
# B-B8 + yedek yol (proje ağacı yokken): types.h tek kez, göreli yol korunur,
# undefinedN Ghidra adıyla kalır (P18 Kalem 3).
# ---------------------------------------------------------------------------

def _yedek_yol_cikti(tmp_path: Path) -> Path:
    from karadul.core.output_formatter import OutputFormatter
    from karadul.core.result import PipelineResult, StageResult
    from karadul.core.workspace import Workspace

    ws = Workspace(base_dir=tmp_path / "ws", target_name="deneme")
    ws.create()
    rec = ws.get_stage_dir("reconstructed")
    for alt in ("a", "b", "c"):
        (rec / "commented" / alt).mkdir(parents=True)
        (rec / "commented" / alt / "util.c").write_text(
            f'undefined8 util_{alt}(undefined4 x)\n{{\n  puts("undefined symbol");\n}}\n')
    (rec / "commented" / "types.h").write_text("/* kaynak dizindeki types.h */\n")
    (rec / "typed").mkdir()
    (rec / "typed" / "types.h").write_text(
        "#ifndef RECOVERED_TYPES_H\n#define RECOVERED_TYPES_H\n"
        "struct kurtarilan { int a; };\n#endif /* RECOVERED_TYPES_H */\n")
    sonuc = PipelineResult(target_name="deneme", target_hash="00", workspace_path=ws.path)
    sonuc.add_stage_result(StageResult(stage_name="identify", success=True,
                                       duration_seconds=0.1, stats={"language": "c"}))
    cikti = tmp_path / "out"
    OutputFormatter(ws, sonuc).format_output(cikti, fmt="clean")
    return cikti / "src"


def test_yedek_yol_ayni_adli_dosyalar_ezilmez(tmp_path):
    src = _yedek_yol_cikti(tmp_path)
    kaynaklar = sorted(p.relative_to(src).as_posix() for p in src.rglob("*.c"))
    assert len(kaynaklar) == 3, kaynaklar
    metin = "".join((src / k).read_text() for k in kaynaklar)
    assert all(f"util_{x}" in metin for x in "abc")


def test_yedek_yol_types_h_tek_ve_typedefli(tmp_path):
    src = _yedek_yol_cikti(tmp_path)
    basliklar = sorted(p.relative_to(src).as_posix() for p in src.rglob("*.h"))
    assert basliklar == ["types/types.h"]
    tipler = (src / "types" / "types.h").read_text()
    assert "typedef uint64_t  undefined8;" in tipler
    assert "typedef uint8_t   undefined;" in tipler
    assert "struct kurtarilan { int a; };" in tipler
    assert "kaynak dizindeki types.h" not in tipler


def test_yedek_yol_undefined_ve_dizgi_korunur(tmp_path):
    src = _yedek_yol_cikti(tmp_path)
    metin = "".join(p.read_text() for p in src.rglob("*.c"))
    assert "undefined8 util_" in metin and "(undefined4 x)" in metin
    assert 'puts("undefined symbol")' in metin
    assert "uint64_t" not in metin


# ---------------------------------------------------------------------------
# Kalem 5: yapı adayı dosyaları çıktıya girmez; README yerini ve sayısını söyler.
# ---------------------------------------------------------------------------

def test_aday_dosyalari_ciktiya_girmez_readme_soyler(tmp_path):
    src = _yedek_yol_cikti(tmp_path)  # adaysız: bölüm yok
    assert "Unverified Struct Candidates" not in (src.parent / "README.md").read_text()

    from karadul.core.output_formatter import OutputFormatter
    from karadul.core.result import PipelineResult, StageResult
    from karadul.core.workspace import Workspace

    ws = Workspace(base_dir=tmp_path / "ws2", target_name="deneme")
    ws.create()
    rec = ws.get_stage_dir("reconstructed")
    (rec / "commented").mkdir(parents=True)
    (rec / "commented" / "f.c").write_text("int f(void)\n{\n  return 0;\n}\n")
    (rec / "typed").mkdir()
    (rec / "typed" / "types_candidates.txt").write_text(
        "/* doğrulanmamış aday\n * Aday sayısı: 7\n */\nstruct recovered_struct_001 { int a; };\n")
    (rec / "struct_recovered_candidates").mkdir()
    (rec / "struct_recovered_candidates" / "struct_candidates.txt").write_text(
        "/*\n * Aday: 11; uygulama: kapalı\n */\n")
    sonuc = PipelineResult(target_name="deneme", target_hash="00", workspace_path=ws.path)
    sonuc.add_stage_result(StageResult(stage_name="identify", success=True,
                                       duration_seconds=0.1, stats={"language": "c"}))
    cikti = tmp_path / "out2"
    OutputFormatter(ws, sonuc).format_output(cikti, fmt="clean")
    readme = (cikti / "README.md").read_text()
    assert "## Unverified Struct Candidates (not in this output)" in readme
    assert "- `<workspace>/reconstructed/typed/types_candidates.txt` (7 candidates)" in readme
    assert ("- `<workspace>/reconstructed/struct_recovered_candidates/struct_candidates.txt` "
            "(11 candidates)") in readme
    assert not [p for p in cikti.rglob("*candidates*")]
    assert "recovered_struct_001" not in "".join(
        p.read_text() for p in cikti.rglob("*") if p.is_file() and p.suffix in (".c", ".h"))
