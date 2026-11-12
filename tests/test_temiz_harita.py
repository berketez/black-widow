"""Temiz çıktının README'si diskteki çıktıyı, ad haritası koda uygulanmış adları anlatır.

Çıktı sağlamlığı denetimi (``docs/arge/2026-11-10_cikti_saglamligi/rapor.md`` bulgu 6 ve 20):
119/119 ikilide README ``src/main.c``, ``src/modules/``, ``src/types/`` diyordu, yazılan çıktı ise
``src/src/subsystem_*/`` idi; ``naming_map.json`` koda uygulanmamış adları (6 675) ve eski = yeni
girişleri (9 823) "eşleme" olarak listeliyordu; Mach-O'da ``$`` taşıyan adlar vardı.

README için kilitlenen davranışlar:
  - "Output Structure" bloğundaki her satır diskte var olan bir girdidir; üst düzeydeki ve
    ``src/``'nin altındaki her girdi listelenir;
  - dizinin yanındaki sayı içindeki (alt dizinler dahil) dosya sayısıdır;
  - "Source Files" diskteki ``src/`` dosya sayısıdır (biçimlendiricinin sayacı değil);
  - "Names Recovered" haritadaki ``total_mappings``'tir;
  - kalabalık dizin kesilir ve kalan girdi sayısı yazılır.

Ad haritası için kilitlenen davranışlar (biçim 1.1):
  - ``mappings`` yalnız temiz çıktının C kodunda (yorum ve dizgi dışında) görülen yeniden
    adlandırmaları taşır; ``total_mappings`` onları sayar;
  - öbür kayıtlar silinmez: alanlarıyla ve ``reason`` ile ``candidates``'e gider
    (``same_as_original``, ``not_in_code`` ya da ``name_validity`` nedeni);
  - geçersiz C adı, kodda geçse bile eşleme olmaz;
  - doğrulanacak C kodu yoksa (JS) yalnız eski = yeni girişler ayrılır, ``applied_check``
    ``not_checked`` olur.

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


def test_source_files_diskten_sayaci_sisik_olsa_da(ws, tmp_path, monkeypatch):
    """Biçimlendiricinin sayacı diskteki dosya sayısından büyük olsa da README diskteki sayıyı yazar.

    Bu sayaç farkını eskiden genel dal üretiyordu (aynı adlı dosyaları üst üste yazıp her yazmayı
    sayıyordu; dil ``cpp``). O ezme 2026-11-12'de giderildi (``tests/test_cikti_hatalari.py``);
    sayaç farkı burada kaynak biçimlendiricisi yerine konarak üretilir.
    """
    def _sisik_sayac(self, src_dir):
        (src_dir / "parse.c").write_text("int parse(void)\n{\n  return 0;\n}\n", encoding="utf-8")
        return 4, []

    monkeypatch.setattr(OutputFormatter, "_format_binary_sources", _sisik_sayac)
    out = tmp_path / "temiz"
    fr = OutputFormatter(ws, _sonuc(ws, "c")).format_output(out, fmt="clean")
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


# ---------------------------------------------------------------------------
# Ad haritası: yalnız koda uygulanmış adlar eşlemedir
# ---------------------------------------------------------------------------

def _kodlu_alan(ws: Workspace, dosyalar: dict[str, str], c_namer: dict[str, str],
                imza: list[dict] | None = None) -> None:
    """Proje ağacı (verilen .c/.h metinleri) + c_namer haritası + imza eşleşmeleri."""
    rec = ws.get_stage_dir("reconstructed")
    for goreli, metin in dosyalar.items():
        p = rec / "project" / goreli
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(metin, encoding="utf-8")
    (rec / "src").mkdir(parents=True, exist_ok=True)
    (rec / "src" / "naming_map.json").write_text(
        json.dumps({"global": c_namer, "per_function": {}}), encoding="utf-8")
    if imza is not None:
        ws.save_json("reconstructed", "signature_matches", {"total": len(imza), "matches": imza})


def _imza(orijinal: str, ad: str, kutuphane: str = "libc", guven: float = 0.9) -> dict:
    return {"original": orijinal, "matched": ad, "library": kutuphane, "confidence": guven}


_KOD = {
    # c_namer FUN_00101000 -> parse_args: tanım ve çağrı yeni adda
    "src/subsystem_io/parse_args.c": (
        "/* @calls FUN_00102000 */\n"
        "int parse_args(int argc)\n{\n  return __ctype_b_loc() + strlen(\"x\");\n}\n"),
    # imza önerisi FUN_00102000 -> update_record: kod hâlâ FUN_00102000 tanımlıyor
    "src/subsystem_io/FUN_00102000.c": "void FUN_00102000(void)\n{\n  parse_args(1);\n}\n",
    # ithal sarmalayıcılar (Ghidra thunk'ları): adları değişmedi
    "src/subsystem_misc/__ctype_b_loc.c": "int __ctype_b_loc(void)\n{\n  return 0;\n}\n",
    "src/subsystem_misc/strlen.c": "int strlen(char *s)\n{\n  return 0;\n}\n",
    "src/main.c": "int main(void)\n{\n  _fopen$DARWIN_EXTSN(0);\n  return parse_args(0);\n}\n",
}


def _harita(out: Path) -> dict:
    return json.loads((out / "naming_map.json").read_text(encoding="utf-8"))


def test_yalniz_uygulanan_ad_esleme_digerleri_gerekcesiyle_aday(ws, tmp_path):
    imza = [_imza("FUN_00102000", "update_record", "sqlite3", 0.79),
            _imza("strlen", "strlen"),
            _imza("__ctype_b_loc", "ctype_b_loc", guven=0.98),
            _imza("_fopen$DARWIN_EXTSN", "fopen$DARWIN_EXTSN")]
    _kodlu_alan(ws, _KOD, {"FUN_00101000": "parse_args"}, imza)
    out = tmp_path / "temiz"
    _bicimle(ws, out)
    h = _harita(out)
    assert h["version"] == of.NAMING_MAP_FORMAT_VERSION == "1.1"
    assert h["applied_check"] == of.APPLIED_CHECK_C_SOURCE
    assert set(h["mappings"]) == {"FUN_00101000"}
    assert h["mappings"]["FUN_00101000"]["new_name"] == "parse_args"
    assert h["mappings"]["FUN_00101000"]["source"] == "c_namer"
    assert h["total_mappings"] == len(h["mappings"]) == 1
    nedenler = {k: v["reason"] for k, v in h["candidates"].items()}
    assert nedenler == {
        "FUN_00102000": of.CANDIDATE_NOT_IN_CODE,
        "strlen": of.CANDIDATE_SAME_AS_ORIGINAL,
        "__ctype_b_loc": of.CANDIDATE_NOT_IN_CODE,
        "_fopen$DARWIN_EXTSN": "invalid_c_identifier",
    }
    assert h["total_candidates"] == len(h["candidates"]) == 4
    # hiçbir kayıt silinmedi; aday kendi alanlarını taşır
    assert set(h["mappings"]) | set(h["candidates"]) == {"FUN_00101000"} | {m["original"] for m in imza}
    assert not set(h["mappings"]) & set(h["candidates"])
    assert h["candidates"]["FUN_00102000"] == {
        "new_name": "update_record", "source": "signature_db", "confidence": 0.79,
        "library": "sqlite3", "reason": of.CANDIDATE_NOT_IN_CODE}
    assert h["sources"] == ["signature_db", "c_namer"]


def test_eski_ad_yalniz_bir_cagrida_kalsa_da_tanim_yeni_addaysa_uygulanmis(ws, tmp_path):
    kod = {"src/a.c": "int read_conf(void)\n{\n  return 0;\n}\n",
           "src/b.c": "int caller(void)\n{\n  return FUN_00103000();\n}\n"}
    _kodlu_alan(ws, kod, {"FUN_00103000": "read_conf"})
    out = tmp_path / "temiz"
    _bicimle(ws, out)
    assert set(_harita(out)["mappings"]) == {"FUN_00103000"}


def test_yeni_ad_baska_fonksiyonun_tanimiysa_eski_tanim_durdukca_uygulanmamis(ws, tmp_path):
    """İmza FUN_A için log_debug öneriyor; log_debug adını c_namer FUN_B'ye vermiş; FUN_A duruyor."""
    kod = {"src/a.c": "void FUN_00104000(void)\n{\n  log_debug();\n}\n",
           "src/b.c": "void log_debug(void)\n{\n  return;\n}\n"}
    _kodlu_alan(ws, kod, {"FUN_00105000": "log_debug"}, [_imza("FUN_00104000", "log_debug")])
    out = tmp_path / "temiz"
    _bicimle(ws, out)
    h = _harita(out)
    assert set(h["mappings"]) == {"FUN_00105000"}
    assert h["candidates"]["FUN_00104000"]["reason"] == of.CANDIDATE_NOT_IN_CODE


def test_veri_adi_eski_ad_koddan_kalkinca_uygulanmis(ws, tmp_path):
    kod = {"src/a.c": "int f(void)\n{\n  return g_config + DAT_00106000;\n}\n",
           "include/globals.h": "extern int g_config;\nextern int g_table;\n"}
    _kodlu_alan(ws, kod, {"DAT_00107000": "g_config", "DAT_00106000": "g_table",
                          "DAT_00108000": "g_unused"})
    out = tmp_path / "temiz"
    _bicimle(ws, out)
    h = _harita(out)
    assert set(h["mappings"]) == {"DAT_00107000"}
    # DAT_00106000 kodda duruyor (yeni ad başlıkta geçse de); g_unused kodda hiç yok
    assert h["candidates"]["DAT_00106000"]["reason"] == of.CANDIDATE_NOT_IN_CODE
    assert h["candidates"]["DAT_00108000"]["reason"] == of.CANDIDATE_NOT_IN_CODE


def test_yorumda_ya_da_dizgide_gecen_ad_kodda_sayilmaz(ws, tmp_path):
    kod = {"src/a.c": ("// open_db burada degil\n/* open_db: belge */\n"
                       "int f(void)\n{\n  puts(\"open_db\");\n  return 'o';\n}\n")}
    _kodlu_alan(ws, kod, {"FUN_00109000": "open_db"})
    out = tmp_path / "temiz"
    _bicimle(ws, out)
    h = _harita(out)
    assert h["mappings"] == {}
    assert h["candidates"]["FUN_00109000"]["reason"] == of.CANDIDATE_NOT_IN_CODE


def test_gecersiz_c_adi_kodda_gecse_de_esleme_olmaz(ws, tmp_path):
    """``long`` kodda tip olarak geçer, eski ad kodda yok: yine de eşleme değil (ad süzgeci)."""
    kod = {"src/a.c": "long f(void)\n{\n  return 0;\n}\n"}
    _kodlu_alan(ws, kod, {"FUN_0010a000": "long", "FUN_0010b000": "uint32_t"})
    out = tmp_path / "temiz"
    _bicimle(ws, out)
    h = _harita(out)
    assert h["mappings"] == {}
    assert h["candidates"]["FUN_0010a000"]["reason"] == "invalid_c_keyword"


def test_dolar_isaretli_ad_tek_sozcuk(ws, tmp_path):
    """``_fopen$X`` kodda tek ad: ``$`` ile bölünürse eski ad kodda yok sanılır."""
    kod = {"src/a.c": "int g(void)\n{\n  return _fopen$X(0) + my_fopen;\n}\n"}
    _kodlu_alan(ws, kod, {}, [_imza("_fopen$X", "my_fopen")])
    out = tmp_path / "temiz"
    _bicimle(ws, out)
    h = _harita(out)
    assert h["mappings"] == {}
    assert h["candidates"]["_fopen$X"]["reason"] == of.CANDIDATE_NOT_IN_CODE


def test_adres_anahtarinda_eski_ad_ghidranin_verdigi_ad(ws, tmp_path):
    """c_namer anahtarı adresten kurulur; Ghidra o fonksiyona ``entry``/sembol adı vermişse kodda
    geçen eski ad odur. ``start`` kodda bir alan adı olarak geçse de giriş fonksiyonu hâlâ ``entry``;
    ``full_write`` Ghidra'nın zaten verdiği ad (kod değişmedi)."""
    kod = {"src/main.c": "void entry(long p)\n{\n  struct r x;\n  x.start = 0;\n}\n",
           "src/io/full_write.c": "long full_write(int fd)\n{\n  return 0;\n}\n",
           "src/io/g.c": "int g(void)\n{\n  return full_write(1);\n}\n"}
    _kodlu_alan(ws, kod, {"FUN_00105dc0": "start", "FUN_001322e4": "full_write"})
    ws.save_json("static", "ghidra_functions", {"functions": [
        {"name": "entry", "address": "00105dc0"}, {"name": "full_write", "address": "001322e4"},
        {"name": "g", "address": "0x105000"}]})
    out = tmp_path / "temiz"
    _bicimle(ws, out)
    h = _harita(out)
    assert h["mappings"] == {}
    assert h["candidates"]["FUN_00105dc0"]["reason"] == of.CANDIDATE_NOT_IN_CODE
    assert h["candidates"]["FUN_001322e4"]["reason"] == of.CANDIDATE_SAME_AS_ORIGINAL


def test_adres_anahtari_cozumu_yalniz_yer_tutucuda():
    adlar = {0x105dc0: "entry", 0x1000052f4: "Settings_write"}
    assert OutputFormatter._name_in_code("FUN_00105dc0", adlar) == "entry"
    assert OutputFormatter._name_in_code("FUN_1000052f4", adlar) == "Settings_write"
    assert OutputFormatter._name_in_code("FUN_00999999", adlar) == "FUN_00999999"   # adres yok
    assert OutputFormatter._name_in_code("DAT_00105dc0", adlar) == "DAT_00105dc0"   # veri anahtarı
    assert OutputFormatter._name_in_code("strlen", adlar) == "strlen"


def test_c_ciktisi_kodsuzsa_hicbir_ad_uygulanmis_sayilmaz(ws, tmp_path):
    _kodlu_alan(ws, {}, {"FUN_00101000": "parse_args"})
    f = OutputFormatter(ws, _sonuc(ws, "c"))
    h = f._build_naming_map(tmp_path / "bos_src", "c")
    assert h["applied_check"] == of.APPLIED_CHECK_C_SOURCE
    assert h["mappings"] == {} and h["total_mappings"] == 0
    assert h["candidates"]["FUN_00101000"]["reason"] == of.CANDIDATE_NOT_IN_CODE


def test_js_ciktisinda_denetim_yok_yalniz_ozdes_ayrilir(js_ws, tmp_path):
    named = js_ws.get_stage_dir("reconstructed") / "named_project"
    named.mkdir(parents=True)
    (named / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    (named / "naming-manifest.json").write_text(json.dumps({"modules": {
        "1234": {"name": "file-system", "source": "npm", "confidence": 0.8},
        "lodash": {"name": "lodash", "source": "npm", "confidence": 0.9}}}), encoding="utf-8")
    out = tmp_path / "temiz"
    OutputFormatter(js_ws, _sonuc(js_ws, "javascript")).format_output(out, fmt="clean")
    h = _harita(out)
    assert h["applied_check"] == of.APPLIED_CHECK_NOT_CHECKED
    assert set(h["mappings"]) == {"1234"}          # C ad kuralı JS modül adına uygulanmaz
    assert h["candidates"]["lodash"]["reason"] == of.CANDIDATE_SAME_AS_ORIGINAL
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "was not checked against the code" in readme


@pytest.fixture
def js_ws(tmp_path: Path) -> Workspace:
    w = Workspace(base_dir=tmp_path / "js_workspaces", target_name="paket")
    w.create()
    return w


def test_readme_aday_sayisi_ve_anlami(ws, tmp_path):
    _kodlu_alan(ws, _KOD, {"FUN_00101000": "parse_args"},
                [_imza("FUN_00102000", "update_record"), _imza("strlen", "strlen")])
    out = tmp_path / "temiz"
    readme = _bicimle(ws, out)
    h = _harita(out)
    assert f"| Names Recovered | {h['total_mappings']} |" in readme
    assert f"| Name Candidates (not applied) | {h['total_candidates']} |" in readme
    assert (h["total_mappings"], h["total_candidates"]) == (1, 2)
    assert "counts only renames that appear in the code under `src/`" in readme


@pytest.mark.parametrize("baslik, ad", [
    ("void FUN_00101000(void)\n", "FUN_00101000"),
    ("static int\nparse_args(int argc, char **argv) ", "parse_args"),
    ("void walk(void (*cb)(int, char *), int n)", "walk"),
    # işlev göstericisi döndüren tanım tanınmaz (Ghidra ``code *`` yazar); tanımlayıcı kuralına düşer
    ("code * (*resolver(int x))(void)", None),
    ("struct node ", None),
    ("int table[] = ", None),
    ("typedef struct ", None),
])
def test_tanim_basligindan_fonksiyon_adi(baslik, ad):
    assert OutputFormatter._definition_name(baslik) == ad


def test_dosya_kapsaminda_tanimlanan_adlar():
    kod = ("struct s {\n  int a;\n};\n"
           "int f(int x)\n{\n  if (x) {\n    g();\n  }\n  return 0;\n}\n"
           "int tablo[2] = {1, 2};\n"
           "void h(void)\n{\n}\n")
    assert OutputFormatter._defined_function_names(kod) == {"f", "h"}
    # dengesiz bir kapanış ayracından sonra gövde içi "if (...) {" tanım sayılmaz
    assert OutputFormatter._defined_function_names("}\nif (x) {\n}\nwhile (y) {\n}\n") == set()
