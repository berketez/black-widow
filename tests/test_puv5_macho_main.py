"""P-ÜV5: Mach-O ``LC_MAIN`` girişi = ``main`` (``ReconstructionStage._recover_main_from_entry``).

Sahte ``static`` dizini (``load_commands.txt``, ``ghidra_combined_results.json``,
``ghidra_functions.json``, decompile çıktısı) ve sahte ikili görüntü / Go okuyucu sonucuyla; gerçek
ikili yok. Plan: ``docs/arge/2026-11-19_mythos/ustveri/PLAN.md`` "P-ÜV5"; gönderim
``docs/arge/2026-11-23_dalga1/gonderim/PUV5.md``.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from karadul.analyzers.ustveri import go_pclntab
from karadul.stages import ReconstructionStage

TEXT = 0x100000000
ENTRYOFF = 0x1780
ENTRY = TEXT + ENTRYOFF


def _cfg(value: object = True) -> SimpleNamespace:
    return SimpleNamespace(binary_reconstruction=SimpleNamespace(enable_macho_entry_main=value))


def _load_commands(*, entryoffs=(ENTRYOFF,), unixthread_pc=None, text=TEXT) -> str:
    out = ["/x/raw/prog:", "Load command 0", "      cmd LC_SEGMENT_64", "  cmdsize 72",
           "  segname __PAGEZERO", "   vmaddr 0x0000000000000000", "   vmsize 0x0000000100000000",
           "Load command 1", "      cmd LC_SEGMENT_64", "  cmdsize 472", "  segname __TEXT",
           f"   vmaddr 0x{text:016x}", "   vmsize 0x0000000000028000",
           "Section", "  sectname __text", "   segname __TEXT", f"      addr 0x{text + 0x1780:016x}"]
    for i, off in enumerate(entryoffs):
        out += [f"Load command {10 + i}", "       cmd LC_MAIN", "   cmdsize 24",
                f"  entryoff {off}", " stacksize 0"]
    if unixthread_pc is not None:
        out += ["Load command 20", "        cmd LC_UNIXTHREAD", "    cmdsize 288",
                "     flavor ARM_THREAD_STATE64", "      count ARM_THREAD_STATE64_COUNT",
                "\t    x0  0x0000000000000000 x1  0x0000000000000000",
                f"\t    sp  0x0000000000000000 pc  0x{unixthread_pc:016x}",
                "\t  cpsr 0x00000000"]
    return "\n".join(out) + "\n"


def _static(tmp_path: Path, *, functions=None, image_base=TEXT, lc=None,
            c_files=("entry", "FUN_100001784")) -> Path:
    static = tmp_path / "static"
    dec = static / "ghidra_output" / "decompiled"
    dec.mkdir(parents=True)
    for name in c_files:
        (dec / f"{name}.c").write_text(f"// Function: {name}\nvoid {name}(void) {{ return; }}\n")
    if not any(n.startswith("FUN_") for n in c_files):
        (dec / "FUN_00000001.c").write_text("void FUN_00000001(void) {}\n")
    (static / "load_commands.txt").write_text(lc if lc is not None else _load_commands())
    (static / "ghidra_combined_results.json").write_text(
        json.dumps({"program_info": {"image_base": f"{image_base:x}"}}))
    if functions is None:
        functions = [{"name": "entry", "address": f"{image_base + ENTRYOFF:x}", "size": 4,
                      "is_thunk": True, "is_external": False},
                     {"name": "FUN_100001784", "address": f"{image_base + ENTRYOFF + 4:x}",
                      "size": 400, "is_thunk": False, "is_external": False}]
    (static / "ghidra_functions.json").write_text(json.dumps({"functions": functions}))
    return static


@pytest.fixture
def macho(monkeypatch):
    """Sahte ikili görüntü (Mach-O ``MH_EXECUTE``) ve Go okuyucu sonucu (öntanım: Go yok)."""
    state = {"image": SimpleNamespace(bicim="macho", dosya_turu=2),
             "go": go_pclntab.GoSonuc(durum=go_pclntab.DURUM_VERI_YOK, neden="Go pclntab yok")}
    monkeypatch.setattr(ReconstructionStage, "_open_macho_image",
                        staticmethod(lambda static_dir: state["image"]))
    monkeypatch.setattr(go_pclntab, "oku", lambda image: state["go"])
    return state


def _run(static: Path, cfg=None, names=None):
    names = {} if names is None else names
    stats: dict = {}
    ReconstructionStage()._recover_main_from_entry(names, static, stats, _cfg() if cfg is None else cfg)
    return names, stats


def _go_fn(name: str, start: int, end: int) -> go_pclntab.GoFonksiyon:
    return go_pclntab.GoFonksiyon(
        sira=0, giris=start, bitis=end, func_off=0, name_off=1, ad=name, args=0, deferreturn=0,
        pcsp=0, pcfile=0, pcln=0, npcdata=0, cu_offset=0, baslangic_satiri=0, func_id=0, flag=0,
        nfuncdata=0)


# ---------------------------------------------------------------------------------------------

def test_lc_main_girisi_main_adini_alir(tmp_path, macho):
    names, stats = _run(_static(tmp_path))
    assert names == {"entry": "main"}
    assert stats["main_recovered"] == "entry"
    rec = stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]
    assert rec["durum"] == "yazildi" and rec["giris"] == hex(ENTRY) and rec["anahtar"] == "entry"


@pytest.mark.parametrize("cfg", [None, _cfg(False), _cfg("true"), _cfg(1),
                                 SimpleNamespace(binary_reconstruction=None)])
def test_bayrak_kapaliyken_hicbir_sey_degismez(tmp_path, macho, cfg):
    names, stats = {}, {}
    ReconstructionStage()._recover_main_from_entry(names, _static(tmp_path), stats, cfg)
    assert names == {} and stats == {}


def test_lc_unixthread_main_sayilmaz(tmp_path, macho):
    lc = _load_commands(entryoffs=(), unixthread_pc=ENTRY)
    names, stats = _run(_static(tmp_path, lc=lc))
    assert names == {}
    rec = stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]
    assert rec["durum"] == "yazilmadi" and rec["neden"] == "lc_unixthread"
    assert rec["unixthread_pc"] == hex(ENTRY)


def test_elf_kalibi_once_gelir_macho_kurali_kosmaz(tmp_path, macho):
    static = _static(tmp_path)
    dec = static / "ghidra_output" / "decompiled"
    (dec / "FUN_00102cc0.c").write_text(
        "void FUN_00102cc0(void)\n{\n  __libc_start_main(FUN_00101b00,0,0,0,0,0,0);\n}\n")
    names, stats = _run(static)
    assert names == {"FUN_00101b00": "main"}
    assert stats["main_recovered"] == "FUN_00101b00"
    assert ReconstructionStage.MACHO_MAIN_STATS_KEY not in stats


def test_elf_bicimli_ikilide_macho_kurali_ad_yazmaz(tmp_path, macho):
    macho["image"] = SimpleNamespace(bicim="elf", dosya_turu=2)
    names, stats = _run(_static(tmp_path))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == "ikili_okunamadi"


def test_load_commands_yoksa_kayit_da_yok(tmp_path, macho):
    static = _static(tmp_path)
    (static / "load_commands.txt").unlink()
    names, stats = _run(static)
    assert names == {} and stats == {}


def test_go_ic_baglayici_girisi_main_yazilmaz(tmp_path, macho):
    macho["go"] = go_pclntab.GoSonuc(durum=go_pclntab.DURUM_CALISTI, fonksiyonlar=[
        _go_fn("_rt0_arm64_darwin", ENTRY, ENTRY + 0x20), _go_fn("main.main", ENTRY + 0x20, ENTRY + 0x80)])
    names, stats = _run(_static(tmp_path))
    assert names == {}
    rec = stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]
    assert rec["neden"] == "go_giris_main_main_degil" and rec["go_adi"] == "_rt0_arm64_darwin"


def test_go_dis_baglayici_main_saplamasi_da_yazilmaz(tmp_path, macho):
    macho["go"] = go_pclntab.GoSonuc(durum=go_pclntab.DURUM_CALISTI,
                                      fonksiyonlar=[_go_fn("main", ENTRY, ENTRY + 0x10)])
    names, stats = _run(_static(tmp_path))
    assert names == {} and stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["go_adi"] == "main"


def test_go_giris_main_main_ise_yazilir(tmp_path, macho):
    macho["go"] = go_pclntab.GoSonuc(durum=go_pclntab.DURUM_CALISTI,
                                      fonksiyonlar=[_go_fn("main.main", ENTRY, ENTRY + 0x40)])
    names, stats = _run(_static(tmp_path))
    assert names == {"entry": "main"}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["go_adi"] == "main.main"


@pytest.mark.parametrize("durum", [go_pclntab.DURUM_TUTARSIZ, go_pclntab.DURUM_DESTEKLENMIYOR,
                                   go_pclntab.DURUM_HATA])
def test_go_okunamazsa_yazilmaz(tmp_path, macho, durum):
    macho["go"] = go_pclntab.GoSonuc(durum=durum, neden="x")
    names, stats = _run(_static(tmp_path))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == f"go_okunamadi:{durum}"


def test_go_tablosu_girisi_kapsamazsa_yazilmaz(tmp_path, macho):
    macho["go"] = go_pclntab.GoSonuc(durum=go_pclntab.DURUM_CALISTI,
                                      fonksiyonlar=[_go_fn("main.main", ENTRY + 0x100, ENTRY + 0x140)])
    names, stats = _run(_static(tmp_path))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == "go_giris_pclntab_disinda"


@pytest.mark.parametrize("ghidra_name", ["_main", "start_program", "main"])
def test_giriste_sembol_adi_varsa_dokunulmaz(tmp_path, macho, ghidra_name):
    fns = [{"name": ghidra_name, "address": f"{ENTRY:x}", "is_external": False}]
    names, stats = _run(_static(tmp_path, functions=fns, c_files=(ghidra_name, "FUN_100001784")))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == "ghidra_adli"


def test_adsiz_fun_girisi_kendi_anahtariyla_main(tmp_path, macho):
    fns = [{"name": f"FUN_{ENTRY:x}", "address": f"{ENTRY:x}", "is_external": False}]
    names, stats = _run(_static(tmp_path, functions=fns, c_files=(f"FUN_{ENTRY:x}",)))
    assert names == {f"FUN_{ENTRY:x}": "main"}


def test_goruntu_tabani_farki_uygulanir(tmp_path, macho):
    """Ghidra tabanı 0x200000000, ikilinin __TEXT'i 0x100000000: Ghidra adresi taban farkıyla."""
    base = 0x200000000
    fns = [{"name": "entry", "address": f"{base + ENTRYOFF:x}", "is_external": False},
           {"name": f"FUN_{ENTRY:x}", "address": f"{ENTRY:x}", "is_external": False}]
    static = _static(tmp_path, functions=fns, image_base=base, c_files=("entry", f"FUN_{ENTRY:x}"))
    names, stats = _run(static)
    assert names == {"entry": "main"}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["giris"] == hex(base + ENTRYOFF)


def test_thunk_girise_yazilir_hedefe_yazilmaz(tmp_path, macho):
    names, _ = _run(_static(tmp_path))   # öntanım: entry 4 baytlık thunk, hedef FUN_100001784
    assert names == {"entry": "main"} and "FUN_100001784" not in names


def test_mh_execute_degilse_yazilmaz(tmp_path, macho):
    macho["image"] = SimpleNamespace(bicim="macho", dosya_turu=6)   # MH_DYLIB
    names, stats = _run(_static(tmp_path))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == "mh_execute_degil"


def test_ikili_acilamazsa_yazilmaz(tmp_path, macho):
    macho["image"] = None
    names, stats = _run(_static(tmp_path))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == "ikili_okunamadi"


def test_birden_cok_farkli_lc_main_belirsiz(tmp_path, macho):
    lc = _load_commands(entryoffs=(ENTRYOFF, ENTRYOFF + 0x100))
    names, stats = _run(_static(tmp_path, lc=lc))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == "lc_main_belirsiz"


def test_kodda_tanimi_yoksa_yazilmaz(tmp_path, macho):
    names, stats = _run(_static(tmp_path, c_files=("FUN_100001784",)))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == "kodda_yok"


def test_giriste_ghidra_fonksiyonu_yoksa_yazilmaz(tmp_path, macho):
    fns = [{"name": "FUN_100001784", "address": f"{ENTRY + 4:x}", "is_external": False}]
    names, stats = _run(_static(tmp_path, functions=fns))
    assert names == {}
    assert stats[ReconstructionStage.MACHO_MAIN_STATS_KEY]["neden"] == "ghidra_fonksiyonu_yok"


def test_onceki_ad_ezilir_ve_ikinci_cagri_degistirmez(tmp_path, macho):
    static = _static(tmp_path)
    names, stats = _run(static, names={"entry": "davranissal_ad"})
    assert names == {"entry": "main"} and stats["main_recovered"] == "entry"
    snap = dict(names)
    _run(static, names=names)
    assert names == snap


def test_tohum_kunyesi_main_giris(tmp_path, macho):
    """``_seed_recovery_pre_names`` bayrağı bağlamdaki ayardan okur; künye türü ``main_giris``."""
    from karadul.reconstruction.tarif import baglama

    names, meta, stats = {}, {}, {}
    ctx = SimpleNamespace(target=None, config=_cfg())
    ReconstructionStage()._seed_recovery_pre_names(names, _static(tmp_path), ctx, stats, meta=meta)
    assert names["entry"] == "main"
    assert meta["entry"]["kind"] == baglama.KIND_MAIN == "main_giris"

    names2, meta2 = {}, {}
    ctx_off = SimpleNamespace(target=None, config=_cfg(False))
    ReconstructionStage()._seed_recovery_pre_names(names2, _static(tmp_path / "b"), ctx_off, {},
                                                   meta=meta2)
    assert "entry" not in names2


def test_load_commands_ayristirici():
    info = ReconstructionStage._parse_macho_load_commands(
        _load_commands(entryoffs=(6016,), unixthread_pc=0x100003F20, text=0x100000000))
    assert info["entryoffs"] == [6016]
    assert info["text_vmaddr"] == 0x100000000
    assert info["unixthread"] is True and info["unixthread_pcs"] == [0x100003F20]
    empty = ReconstructionStage._parse_macho_load_commands("")
    assert empty == {"entryoffs": [], "unixthread": False, "unixthread_pcs": [], "text_vmaddr": None}


def test_open_macho_image_dilim_secimi(tmp_path, monkeypatch):
    """Evrensel dosyada ``universal_slice.json``'un seçtiği ince dilim açılır; dosya yoksa None."""
    from karadul.analyzers.ustveri import goruntu

    static = tmp_path / "static"
    raw = tmp_path / "raw"
    static.mkdir()
    raw.mkdir()
    (static / "universal_slice.json").write_text(json.dumps({"path": "Prog_arm64"}))
    (raw / "target_info.json").write_text(json.dumps({"name": "Prog", "path": str(raw / "Prog")}))
    (raw / "Prog").write_bytes(b"FAT")
    (raw / "Prog_arm64").write_bytes(b"THIN")
    seen = []
    monkeypatch.setattr(goruntu, "urun_dilimi", lambda veri: None)
    monkeypatch.setattr(goruntu, "baytlardan",
                        lambda veri, dilim=None, kaynak="": seen.append((veri, kaynak)) or "img")
    assert ReconstructionStage._open_macho_image(static) == "img"
    assert seen[0][0] == b"THIN"
    assert ReconstructionStage._open_macho_image(tmp_path / "yok" / "static") is None
