#!/usr/bin/env python3
"""Fonksiyon kartı envanteri: adsız fonksiyonlarda kanıt türlerinin kapsamı (GT'siz sayım).

Soru: Bugün ürünün çıktısında, adı verilemeyen her fonksiyon için hangi kanıt türü
dosyada duruyor? Arayüz (``ui/server.py``) bunun ne kadarını gösteriyor?

Kullanım (depo kökünden; Karadul ve Ghidra koşmaz, yalnız saklı çıktıyı okur):

    python3 -I -B docs/arge/2026-11-11_fonksiyon_karti/envanter_sayim.py \
        --cikti docs/arge/2026-11-11_fonksiyon_karti/envanter_sayim.json

Okunmayanlar: GT (simge doğrusu, dbgsym, DWARF, ``macho_score.json``, ``run.json``),
kilitli setler, ``targets/``. Çıktıya fonksiyon adı, dizgi ya da adres yazılmaz; yalnız sayı.

Kaynak seçimi: yeni ürün koşusunda ikilinin dizininde ``BITTI`` varsa yeni koşu okunur
("yeni"); yoksa saklı taban koşusu okunur ("taban"). Adsız kümesi:
  * yeni: Ghidra'nın jenerik bıraktığı (``FUN_<onaltılık>``, thunk ve dış değil) ve
    ``reconstructed/src/naming_map.json`` ``global`` sözlüğünde anahtarı olmayan fonksiyon;
  * taban: bütün jenerik fonksiyonlar (yeni ürünün ad haritası henüz yok).

Arayüz sayımı arayüzün kendi fonksiyonlarını içe aktararak yapılır (``ui/server.py``:
``build_model``, ``_extract_strings``, ``_external_call_hints``, ``_naming_diagnosis``).
Ölçüm düzeninde temiz harita ``out/naming_map.json``'dadır (arayüz ``clean/`` arar); arayüzün
``cmap`` girdisi o dosyanın ``mappings`` bloğundan verilir.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "ui"))

import server as ui  # noqa: E402  (arayüzün kendisi; aynı kodla say)
from karadul.reconstruction.c_algorithm_id import _GHIDRA_WARNING_HEAD  # noqa: E402
from karadul.reconstruction.c_comment_generator import VULN_PATTERNS  # noqa: E402
from karadul.reconstruction.c_namer import _GHIDRA_AUTO_FUNC  # noqa: E402

HOME = Path.home()
DEFAULT_NEW = HOME / "karadul_olcum/runs/urun-yeni-93a2956"
DEFAULT_BASE_DEBIAN = HOME / "karadul_olcum/n1_debian13"
DEFAULT_BASE_MAC = REPO / "workspaces/olcum_mac/runs/ol7-c-b7faeac"
DEFAULT_TABLE = REPO / "docs/arge/2026-11-10_n4/tablo_yuvasi_sayim.json"
DONE_MARK = "BITTI"  # scripts/measurement/urun_kos.py: yalnız başarılı koşuda yazılır

# (birim, platform, program dizini, ikili). coreutils'ten üç ikili elle seçildi (küçük/orta/
# büyük ve bilinen üç komut); seçim GT'ye bakılmadan yapıldı.
BINARIES = [
    ("debian/tmux", "debian", "tmux", "tmux"),
    ("debian/tree", "debian", "tree", "tree"),
    ("debian/sqlite3", "debian", "sqlite3", "sqlite3"),
    ("debian/coreutils/cat", "debian", "coreutils", "cat"),
    ("debian/coreutils/ls", "debian", "coreutils", "ls"),
    ("debian/coreutils/sort", "debian", "coreutils", "sort"),
    ("mac/tmux", "mac", None, "tmux"),
    ("mac/htop", "mac", None, "htop"),
]

# Ghidra'nın decompile dosyasında disassembly dökümünün başı (karadul/ghidra/headless.py).
DISASM_MARK = "// --- DISASSEMBLY"
HEX_CONST_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
# Ghidra'nın veri etiketleri: DAT_<adres>, _DAT_<adres>, PTR_<…>. Metin vekili; Ghidra xref değil.
DATA_LABEL_RE = re.compile(r"\b(?:_?DAT_[0-9a-fA-F]+|PTR_\w+)")
# Decompile'ın eksik ya da kuşkulu olduğunu söyleyen Ghidra uyarıları; liste
# docs/arge/2026-11-10_cikti_saglamligi/rapor.md:149'dan aynen alındı.
DOUBTFUL_WARNINGS = (
    "Removing unreachable block",
    "Could not recover jumptable",
    "Treating indirect jump as call",
    "Type propagation algorithm not settling",
    "Restarted to delay deadcode elimination",
    "Heritage AFTER dead removal",
)
# binary_intelligence._analyze_single_file'ın içerik bulamayınca yazdığı geri dönüş metinleri
# (karadul/analyzers/binary_intelligence.py:1509, :1511, :1512).
FALLBACK_PURPOSES = {"void function (side effects)", "returns a value", "unknown purpose"}
VULN_WARNINGS = tuple(sorted({p["warning"] for p in VULN_PATTERNS}))
# Ghidra'nın yerleşik temel tip adları (tanım listesi; eşik değil). Bunların dışında kalan tip adı
# "adlı tip" sayılır: kütüphane başlığından (FILE, DIR …) ya da yapı kurtarmadan gelir.
GHIDRA_BASE_TYPES = {
    "undefined", "undefined1", "undefined2", "undefined3", "undefined4", "undefined5",
    "undefined6", "undefined7", "undefined8", "byte", "char", "uchar", "short", "ushort",
    "int", "uint", "long", "ulong", "longlong", "ulonglong", "bool", "float", "double",
    "void", "code", "wchar_t", "word", "dword", "qword", "sbyte", "unkbyte9", "unkbyte10",
}
TYPE_NOISE = {"const", "struct", "union", "enum", "volatile", "unsigned", "signed"}
SUBSYS_HEAD_RE = re.compile(r"^## (\S+) \((\d+) functions\)")
SUBSYS_ITEM_RE = re.compile(r"^- `([^`]+)`")
SUBSYS_MORE_RE = re.compile(r"^- _\.\.\. and (\d+) more_")
PART_RE = re.compile(r"_part\d+$")  # c_project_builder büyük dosyayı _partN.c'lere böler
GROUP_RE = re.compile(r"^group_\d+$")

# Kanıt türleri (anahtar -> tanım). Sayımdan önce yazıldı.
EVIDENCE_DEFS = {
    # Ghidra (static/, adres anahtarlı)
    "cagiran": "En az bir çağıran: ghidra_xrefs called_by ∪ ghidra_call_graph callers (kendisi hariç).",
    "cagrilan_ic": "En az bir iç çağrılan: çağrılanın ghidra_functions kaydı thunk/dış değil, ya da adı thunk_ ile başlıyor.",
    "cagrilan_ithal": "En az bir ithal çağrılan: çağrılan thunk ya da dış ve adı jenerik değil (FUN_/thunk_ ile başlamıyor).",
    "cagrilan_ithal_ayirt": "İthal çağrılanlardan en az biri arayüzün gürültü listesinde (ui/server.py _NOISE_CALLS) değil; Mach-O'da baştaki tek _ soyularak.",
    "cagrilan_ithal_yalniz_gurultu": "İthal çağrılanı var ama hepsi gürültü listesinde (cagrilan_ithal ∖ cagrilan_ithal_ayirt).",
    "dizgi_xref": "ghidra_xrefs strings_used boş değil (Ghidra veri başvurusu, dizgi tipli).",
    "dizgi_govde": "Decompile gövdesinde (disassembly hariç) en az bir \"…\" dizgi sabiti (arayüzün _STR_LIT_RE düzeni).",
    "sabit_govde": "Decompile gövdesinde en az bir 0x… onaltılık sabit.",
    "veri_etiketi_govde": "Decompile gövdesinde en az bir DAT_/_DAT_/PTR_ etiketi (veri başvurusunun metin vekili).",
    "imza_parametreli": "Ham decompile imza satırında en az bir parametre (void dışında).",
    "imza_adli_tip": "Ham decompile imzasında (dönüş ya da parametre) Ghidra'nın temel tip adları "
                     "(GHIDRA_BASE_TYPES) dışında bir tip adı; ör. FILE, DIR, tm, bir struct.",
    "ghidra_uyari": "Ham decompile metninde en az bir Ghidra uyarı yorumu (c_algorithm_id._GHIDRA_WARNING_HEAD).",
    "ghidra_uyari_kuskulu": "Ghidra uyarılarından en az biri rapor.md:149'daki 'eksik ya da kuşkulu decompile' listesinde.",
    "boyut_karmasiklik": "ghidra_functions size ve ghidra_cfg cyclomatic_complexity ikisi de var.",
    # Karadul (reconstructed/, çoğu ada anahtarlı). Anahtar olarak Ghidra adı (FUN_<adres>) ve, varsa,
    # ürünün o fonksiyona verdiği ad denenir (tabanda eski ürünün adı).
    "yerel_ad_kaydi": "naming_provenance.json per_function[FUN_…] var (yerel değişken/parametre adı kaydı).",
    "param_adi": "param_naming_map.json functions[FUN_…] var.",
    "param_alan_bilinen": "param_naming_map domain 'unknown' değil.",
    "blok_aciklama": "annotated/block_annotations.json annotated_functions içinde function_name == FUN_….",
    "algoritma_etiketi": "algorithms.json algorithms[].function == FUN_….",
    "bilesim_asamasi": "algorithm_compositions.json bir aşamanın functions listesinde FUN_….",
    "veri_akisi": "data_flow.json kenarında kaynak/hedef ya da data_flow_pipelines.json functions listesinde FUN_….",
    "struct_kaynagi": "struct_recovery.json enriched_structs[].source_functions içinde FUN_….",
    "amac_metni_icerikli": "intelligence_report function_analyses[FUN_…].purpose geri dönüş metinlerinden başka bir parça taşıyor.",
    "zeka_algoritma": "intelligence_report function_analyses[FUN_…].algorithms boş değil.",
    "zafiyet_uyarisi": "commented/FUN_….c içinde c_comment_generator.VULN_PATTERNS uyarılarından biri.",
    "alt_sistem_anlamli": "out/src/src/subsystem_<x>/ yerleşiminde x, group_N ve misc dışında (API kuralı; "
                          "c_project_builder.py:690-729). subsystem_map.md ilk 50 adla kesildiği için yerleşim okunur.",
    "alt_sistem_grup": "out/src/src/subsystem_group_N/ yerleşimi (çağrı grafı topluluğu; c_project_builder.py:735).",
    "adresi_baska_govdede": "Adı başka bir jenerik fonksiyonun decompile metninde çağrı kenarı olmadan geçiyor "
                            "(arayüz modelinin ters kenarı − Ghidra çağıranları): gösterici ataması, geri çağrı argümanı.",
    "bsim_aday": "bsim_shadow.json'da adayı var (arayüzün süzgeciyle: FUN_/DAT_ ve adres sonekli adlar hariç).",
    "imza_adayi_uygulanmamis": "signature_matches.json original == FUN_… (ad haritasına girmemiş imza adayı).",
    "ad_koken_global": "naming_provenance.json global[FUN_…] var (yalnız ad alanlarda olur; adsızda 0 beklenir).",
}

# "Kartı boş" tanımları (sayımdan önce yazıldı)
EMPTY_DEFS = {
    "kart_bos_ghidra": "Ghidra kanıtlarından hiçbiri yok: cagiran, cagrilan_ic, cagrilan_ithal, dizgi_xref, "
                       "dizgi_govde, veri_etiketi_govde. Geriye yalnız boyut/karmaşıklık ve yerleşim kalır.",
    "icerik_adsiz": "Fonksiyonun ne yaptığını adıyla söyleyen kanıt yok: cagrilan_ithal yok ve dizgi "
                    "(dizgi_xref ∪ dizgi_govde) yok. Kalan: çağrı ilişkisi, sabit, veri etiketi, boyut.",
    "ui_bos": "Arayüz bugün hiçbir kanıt satırı çizmez: ipucu yok, dizgi yok, çağrı bağlamı "
              "(build_model çağıran ∪ çağrılan) yok.",
    # Ek (sayımın ilk koşusundan sonra eklendi; adres başvurusu kanıtı ondan sonra tanımlandı)
    "kart_bos_tam": "kart_bos_ghidra ve adresi_baska_govdede de yok.",
    "iliski_yok": "Çağıran yok, iç çağrılan yok, adresi başka gövdede geçmiyor (fonksiyon ilişki "
                  "grafında yalnız ya da yalnız ithal çağrılarla bağlı).",
}
UI_COUNTER_KEYS = (
    "decompile_dosyasi_yok", "ghidra_functions_imza_dolu", "imza_satiri_bulunamadi",
    "eski_urun_adi_var", "eski_urun_adi_belirsiz", "alt_sistem_md_listesinde", "alt_sistem_kaydi_yok",
    "bsim_en_iyi_aday_ayni_adli_programdan", "ipucu", "ipucu_FUN_uygulanmamis_imza", "ipucu_kendisi",
    "ithal_var_ipucu_yok", "dizgi", "cagri_baglami", "ui_cagrilan_fazla", "ui_cagrilan_eksik",
    "ui_cagiran_fazla", "ui_cagiran_fazla_ghidra_cagirani_yok", "kart_bos_ghidra_ama_adresi_alinmis",
    "ui_cagiran_eksik", "ghidra_cagrilan_var_ui_hicbiri", "teshis_ikili_geneli_satir",
    "teshis_bsim_satiri", "teshis_imza_yok_ama_imza_adayi_var",
)
GHIDRA_KEYS = ("cagiran", "cagrilan_ic", "cagrilan_ithal", "dizgi_xref", "dizgi_govde",
               "veri_etiketi_govde")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path, missing: list[str]):
    if not path.is_file():
        missing.append(path.name)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        missing.append(path.name + " (okunamadı)")
        return None


def resolve_paths(args, platform_: str, program: str | None, binary: str) -> dict:
    if platform_ == "debian":
        new_dir = args.yeni / "debian" / program / binary
        base_dir = args.taban_debian / program / binary
    else:
        new_dir = args.yeni / "mac" / binary
        base_dir = args.taban_mac / binary
    mark = new_dir / DONE_MARK
    if mark.is_file() and mark.read_text(encoding="utf-8").strip() == "0":
        source, run_dir = "yeni", new_dir
    else:
        source, run_dir = "taban", base_dir
    ws_dirs = sorted((run_dir / "ws" / "workspaces").glob("*/*"))
    ws_dirs = [d for d in ws_dirs if d.is_dir()]
    if len(ws_dirs) != 1:
        raise SystemExit(f"{run_dir}: tek çalışma alanı beklendi, {len(ws_dirs)} bulundu")
    return {"kaynak": source, "kosu": run_dir, "ws": ws_dirs[0], "out": run_dir / "out",
            "yeni_dizin_var": new_dir.is_dir()}


def decompiled_body(text: str) -> str:
    """Decompile metninden disassembly dökümünü ve baştaki // başlık satırlarını at."""
    body = text.split(DISASM_MARK, 1)[0]
    lines = body.splitlines()
    i = 0
    while i < len(lines) and (lines[i].startswith("//") or not lines[i].strip()):
        i += 1
    return "\n".join(lines[i:])


def _base_type(decl: str, has_name: bool) -> str | None:
    """'char *param_1' -> 'char'; 'FILE *' -> 'FILE'. Çağırma kuralı (__x) atılır."""
    toks = [t for t in re.split(r"[\s*&]+", decl.strip()) if t and not t.startswith("__")]
    toks = [t for t in toks if t not in TYPE_NOISE]
    if has_name and len(toks) >= 2:
        toks = toks[:-1]
    return toks[-1] if toks else None


def signature_types(body: str, name: str) -> dict | None:
    """Ham decompile gövdesindeki imza satırından parametre sayısı ve adlı tip var mı."""
    for line in body.splitlines():
        s = line.strip()
        if f"{name}(" not in s or s.endswith(";") or s.startswith(("//", "/*")):
            continue
        head, _, rest = s.partition(f"{name}(")
        params = rest.rsplit(")", 1)[0]
        types = []
        ret = _base_type(head, has_name=False)
        if ret:
            types.append(ret)
        plist = [p.strip() for p in params.split(",") if p.strip() and p.strip() not in ("void", "...")]
        for p in plist:
            t = _base_type(p, has_name=True)
            if t:
                types.append(t)
        return {"param_sayisi": len(plist),
                "adli_tip": any(t not in GHIDRA_BASE_TYPES for t in types)}
    return None


def parse_subsystem_map(path: Path) -> tuple[dict[str, str], int]:
    """subsystem_map.md: ad -> alt sistem. İkinci değer: '... and N more' ile kesilen ad sayısı.

    Yazıcı her alt sistemde ilk 50 adı listeler (c_project_builder.py:1181-1184); md tam harita değil.
    """
    out: dict[str, str] = {}
    current = None
    cut = 0
    if not path.is_file():
        return out, 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = SUBSYS_HEAD_RE.match(line)
        if m:
            current = m.group(1)
            continue
        m = SUBSYS_ITEM_RE.match(line)
        if m and current:
            out.setdefault(m.group(1), current)
            continue
        m = SUBSYS_MORE_RE.match(line)
        if m:
            cut += int(m.group(1))
    return out, cut


def placement_map(src_root: Path) -> dict[str, str]:
    """out/src/src/subsystem_<x>/<ad>.c yerleşiminden ad -> alt sistem (dosya adı anahtarlı)."""
    out: dict[str, str] = {}
    if not src_root.is_dir():
        return out
    for d in sorted(src_root.glob("subsystem_*")):
        if not d.is_dir():
            continue
        sub = d.name[len("subsystem_"):]
        for c in sorted(d.rglob("*.c")):
            stem = PART_RE.sub("", c.stem)
            out.setdefault(stem, sub)
    return out


def strip_mac_prefix(name: str, platform_: str) -> str:
    return name[1:] if platform_ == "mac" and name.startswith("_") else name


def count_binary(args, unit: str, platform_: str, program: str | None, binary: str) -> dict:
    paths = resolve_paths(args, platform_, program, binary)
    ws, out = paths["ws"], paths["out"]
    st, rc = ws / "static", ws / "reconstructed"
    missing: list[str] = []

    funcs = load_json(st / "ghidra_functions.json", missing)["functions"]
    by_addr = {f["address"]: f for f in funcs}
    generic = {a: f for a, f in by_addr.items()
               if _GHIDRA_AUTO_FUNC.match(f["name"]) and not f["is_thunk"] and not f["is_external"]}
    generic_all = sum(1 for f in funcs if _GHIDRA_AUTO_FUNC.match(f["name"]))
    name_counts = collections.Counter(f["name"] for f in funcs)

    nm = load_json(rc / "src" / "naming_map.json", missing) or {}
    global_map = nm.get("global", {}) if isinstance(nm, dict) else {}
    if paths["kaynak"] == "yeni":
        unnamed = {a: f for a, f in generic.items() if f["name"] not in global_map}
    else:
        unnamed = dict(generic)
    # src_iterN haritalarında ayrıca ad alan jenerik (bilgi için; tanıma girmez)
    iter_named = set()
    for d in sorted(rc.glob("src_iter*")):
        im = load_json(d / "naming_map.json", missing) or {}
        iter_named |= {k for k in (im.get("global") or {}) if k not in global_map}

    xrefs = (load_json(st / "ghidra_xrefs.json", missing) or {}).get("function_xrefs", {})
    cg_nodes = (load_json(st / "ghidra_call_graph.json", missing) or {}).get("nodes", {})
    cfg = {f["address"]: f for f in (load_json(st / "ghidra_cfg.json", missing) or {}).get("functions", [])}

    prov = load_json(rc / "src" / "naming_provenance.json", missing) or {}
    prov_local = set((prov.get("per_function") or {}).keys())
    prov_global = set((prov.get("global") or {}).keys())
    pnm = (load_json(rc / "param_naming_map.json", missing) or {}).get("functions", {})
    blk = load_json(rc / "annotated" / "block_annotations.json", missing) or {}
    blk_names = {x.get("function_name") for x in blk.get("annotated_functions", [])}
    algs = (load_json(rc / "algorithms.json", missing) or {}).get("algorithms", [])
    alg_names = {x.get("function") for x in algs}
    comps = (load_json(rc / "algorithm_compositions.json", missing) or {}).get("compositions", [])
    comp_names = {fn for c in comps for s in c.get("stages", []) for fn in s.get("functions", [])}
    df = load_json(rc / "data_flow" / "data_flow.json", missing) or {}
    dfp = load_json(rc / "data_flow" / "data_flow_pipelines.json", missing) or {}
    df_names = set()
    for e in (df.get("graph") or {}).get("edges", []):
        df_names.add(e.get("source_func"))
        df_names.add(e.get("target_func"))
    for p in dfp.get("pipelines", []):
        df_names |= set(p.get("functions", []))
    sr = load_json(rc / "struct_recovered" / "struct_recovery.json", missing) or {}
    struct_names = {fn for s in sr.get("enriched_structs", []) for fn in (s.get("source_functions") or [])}
    intel = load_json(st / "intelligence_report.json", missing) or {}
    fa = {x["name"]: x for x in (intel.get("architecture") or {}).get("function_analyses", [])}
    subsys_md, subsys_md_cut = parse_subsystem_map(rc / "project" / "analysis" / "subsystem_map.md")
    subsys = placement_map(out / "src" / "src")
    if not subsys:
        missing.append("out/src/src/subsystem_*")
    # Ürünün verdiği adlar arasında belirsiz olanlar: başka bir Ghidra fonksiyonunun adıyla aynı ya
    # da haritada birden çok kez geçen ad. Ada anahtarlı kayıtta bu ad iki fonksiyonu karıştırır.
    product_name_counts = collections.Counter(v for v in global_map.values() if isinstance(v, str))
    bsim = (load_json(rc / "bsim_shadow.json", missing) or {}).get("matches", [])
    bsim_by_addr: dict[str, int] = {}
    bsim_best_same: dict[str, bool] = {}
    bsim_best_prog: dict[str, str] = {}
    for m in bsim:
        cands = [c for c in (m.get("bsim_candidates") or [])
                 if (n := str(c.get("name") or "")) and not n.startswith(("FUN_", "DAT_"))
                 and not ui._ADDR_RE.search(n)]
        bsim_by_addr[str(m.get("function_addr"))] = len(cands)
        if cands:
            # arayüzün seçtiği en iyi aday (ui/server.py _bsim_shadow: en yüksek benzerlik)
            best = max(cands, key=lambda c: c.get("similarity", 0) or 0)
            bsim_best_same[str(m.get("function_addr"))] = (best.get("binary") == binary)
            bsim_best_prog[str(m.get("function_addr"))] = str(best.get("binary"))
    sig = (load_json(rc / "signature_matches.json", missing) or {}).get("matches", [])
    sig_fun = {m["original"] for m in sig if str(m.get("original", "")).startswith("FUN_")}
    clean = (load_json(out / "naming_map.json", missing) or {}).get("mappings", {})

    dec_dir = st / "ghidra_output" / "decompiled"
    com_dir = rc / "commented"

    # Arayüz modeli: arayüzün kendi build_model'i (çağrı bağlamı FUN_ düzeniyle metinden)
    ui._CACHE.clear()
    ui.activate_workspace(str(ws))
    model = ui.build_model()
    if model is None:
        raise SystemExit(f"{ws}: arayüz modeli kurulamadı")
    ui_calls = model["calls"]
    ui_rev: dict[str, set] = collections.defaultdict(set)
    for a, cl in ui_calls.items():
        for c in cl:
            ui_rev[c].add(a)

    # Arayüzün fazladan çizdiği kenarlar (bütün jenerik düğümlerde): arayüz modelinde var, Ghidra
    # çağrı kenarı yok. Her kenarda çağrılan adın metinde '(' ile mi başka biçimde mi geçtiğine bakılır.
    addr_of = {f["name"]: a for a, f in generic.items()}
    extra_edges = collections.Counter()
    for src, cl in ui_calls.items():
        sa = addr_of.get(src)
        if sa is None:
            continue
        gh = {c["address"] for c in xrefs.get(sa, {}).get("functions_called", [])}
        gh |= {c["address"] for c in cg_nodes.get(sa, {}).get("callees", [])}
        extras = [c for c in cl if addr_of.get(c) not in gh]
        if not extras:
            continue
        stext = (dec_dir / f"{src}.c").read_text(errors="ignore")
        for c in extras:
            kinds = set()
            for mm in re.finditer(re.escape(c) + r"(?![0-9a-fA-F])", stext):
                nxt = stext[mm.end():mm.end() + 1]
                kinds.add("cagri" if nxt == "(" else "cagri_disi")
            key = ("ikisi" if len(kinds) == 2 else
                   "yalniz_cagri_sozdizimi" if kinds == {"cagri"} else
                   "yalniz_cagri_disi" if kinds == {"cagri_disi"} else "metinde_yok")
            extra_edges[key] += 1
    extra_edges["toplam"] = sum(v for k, v in extra_edges.items() if k != "toplam")

    ev_counts = collections.Counter()
    empty_counts = collections.Counter()
    ui_counts = collections.Counter()
    verdicts = collections.Counter()
    roles = collections.Counter()
    no_caller_flags = collections.Counter()
    bsim_progs = collections.Counter()  # en iyi BSim adayının geldiği program adı (fonksiyon adı değil)

    for addr, f in unnamed.items():
        name = f["name"]
        ev: set[str] = set()
        # Ada anahtarlı kayıtların anahtarı, kaydı yazan aşamadaki addır: Ghidra adı (FUN_…) ya da
        # ürünün verdiği ad. Yeni üründe adsız fonksiyonun ürün adı yoktur; tabanda eski ürünün adı
        # olabilir. İkisi de denenir.
        pname = global_map.get(name)
        keys = [name] + ([pname] if isinstance(pname, str) and pname and pname != name else [])
        if len(keys) > 1:
            ui_counts["eski_urun_adi_var"] += 1
            if name_counts.get(pname, 0) > 0 or product_name_counts[pname] > 1:
                ui_counts["eski_urun_adi_belirsiz"] += 1

        def has(store) -> bool:
            return any(k in store for k in keys)
        x = xrefs.get(addr, {})
        node = cg_nodes.get(addr, {})
        callers = {c["address"] for c in x.get("called_by", [])} | {c["address"] for c in node.get("callers", [])}
        callers.discard(addr)
        callees = {c["address"]: c.get("name", "") for c in x.get("functions_called", [])}
        for c in node.get("callees", []):
            callees.setdefault(c["address"], c.get("name", ""))
        callees.pop(addr, None)
        if callers:
            ev.add("cagiran")
        imports = []
        internal = 0
        for ca, cname in callees.items():
            cf = by_addr.get(ca)
            cname = (cf or {}).get("name", cname)
            is_imp = bool(cf and (cf["is_thunk"] or cf["is_external"])) and not cname.startswith(("FUN_", "thunk_"))
            if cf is None:
                is_imp = not cname.startswith(("FUN_", "thunk_"))
            if is_imp:
                imports.append(strip_mac_prefix(cname, platform_))
            else:
                internal += 1
        if internal:
            ev.add("cagrilan_ic")
        if imports:
            ev.add("cagrilan_ithal")
            if any(n not in ui._NOISE_CALLS for n in imports):
                ev.add("cagrilan_ithal_ayirt")
            else:
                ev.add("cagrilan_ithal_yalniz_gurultu")
        if x.get("strings_used"):
            ev.add("dizgi_xref")

        dpath = dec_dir / f"{name}.c"
        text = dpath.read_text(errors="ignore") if dpath.is_file() else ""
        if not text:
            ui_counts["decompile_dosyasi_yok"] += 1
        body = decompiled_body(text)
        if ui._STR_LIT_RE.search(body):
            ev.add("dizgi_govde")
        if HEX_CONST_RE.search(body):
            ev.add("sabit_govde")
        if DATA_LABEL_RE.search(body):
            ev.add("veri_etiketi_govde")
        if (f.get("return_type") or "undefined") != "undefined" or f.get("parameters"):
            ui_counts["ghidra_functions_imza_dolu"] += 1
        sig_types = signature_types(body, name)
        if sig_types is None:
            ui_counts["imza_satiri_bulunamadi"] += 1
        else:
            if sig_types["param_sayisi"]:
                ev.add("imza_parametreli")
            if sig_types["adli_tip"]:
                ev.add("imza_adli_tip")
        if _GHIDRA_WARNING_HEAD.search(text):
            ev.add("ghidra_uyari")
            if any(w in text for w in DOUBTFUL_WARNINGS):
                ev.add("ghidra_uyari_kuskulu")
        if f.get("size") is not None and addr in cfg and cfg[addr].get("cyclomatic_complexity") is not None:
            ev.add("boyut_karmasiklik")

        if has(prov_local):
            ev.add("yerel_ad_kaydi")
        if name in prov_global:  # köken kaydının genel bölümü Ghidra adıyla anahtarlı
            ev.add("ad_koken_global")
        pkey = next((k for k in keys if k in pnm), None)
        if pkey is not None:
            ev.add("param_adi")
            if (pnm[pkey] or {}).get("domain") not in (None, "", "unknown"):
                ev.add("param_alan_bilinen")
        if has(blk_names):
            ev.add("blok_aciklama")
        if has(alg_names):
            ev.add("algoritma_etiketi")
        if has(comp_names):
            ev.add("bilesim_asamasi")
        if has(df_names):
            ev.add("veri_akisi")
        if has(struct_names):
            ev.add("struct_kaynagi")
        rec = next((fa[k] for k in keys if k in fa), None)
        if rec:
            parts = [p.strip() for p in str(rec.get("purpose") or "").split(";") if p.strip()]
            if any(p not in FALLBACK_PURPOSES for p in parts):
                ev.add("amac_metni_icerikli")
            if rec.get("algorithms"):
                ev.add("zeka_algoritma")
        cpath = com_dir / f"{name}.c"
        if cpath.is_file():
            ctext = cpath.read_text(errors="ignore")
            if any(w in ctext for w in VULN_WARNINGS):
                ev.add("zafiyet_uyarisi")
        ss = next((subsys[k] for k in keys if k in subsys), None)
        if has(subsys_md):
            ui_counts["alt_sistem_md_listesinde"] += 1
        if ss is None:
            ui_counts["alt_sistem_kaydi_yok"] += 1
        elif GROUP_RE.match(ss):
            ev.add("alt_sistem_grup")
        elif ss != "misc":
            ev.add("alt_sistem_anlamli")
        if bsim_by_addr.get(addr, 0) > 0:
            ev.add("bsim_aday")
            if bsim_best_same.get(addr):
                ui_counts["bsim_en_iyi_aday_ayni_adli_programdan"] += 1
            bsim_progs[bsim_best_prog.get(addr, "?")] += 1
        if name in sig_fun:
            ev.add("imza_adayi_uygulanmamis")

        for k in ev:
            ev_counts[k] += 1
        if not (ev & set(GHIDRA_KEYS)):
            empty_counts["kart_bos_ghidra"] += 1
        if not ({"cagrilan_ithal", "dizgi_xref", "dizgi_govde"} & ev):
            empty_counts["icerik_adsiz"] += 1
        if not callers:
            no_caller_flags["cagirani_yok"] += 1
            if not ({"cagrilan_ithal", "dizgi_xref", "dizgi_govde"} & ev):
                no_caller_flags["cagirani_yok_ve_icerik_adsiz"] += 1

        # --- Arayüz: bugün ne gösteriyor? ---
        hints = ui._external_call_hints(text, clean)
        strs = ui._extract_strings(text)
        diag = ui._naming_diagnosis(name, text, clean, "unnamed")
        ui_callees = set(ui_calls.get(name, []))
        ui_callers = ui_rev.get(name, set())
        if hints:
            ui_counts["ipucu"] += 1
        hint_syms = [h.replace(" çağrılıyor", "") for h in hints]
        if any(s.startswith("FUN_") for s in hint_syms):
            ui_counts["ipucu_FUN_uygulanmamis_imza"] += 1
        if name in hint_syms:
            ui_counts["ipucu_kendisi"] += 1
        if imports and not hints:
            ui_counts["ithal_var_ipucu_yok"] += 1
        if strs:
            ui_counts["dizgi"] += 1
        if ui_callers or ui_callees:
            ui_counts["cagri_baglami"] += 1
        if not hints and not strs and not (ui_callers or ui_callees):
            empty_counts["ui_bos"] += 1
        # Arayüzün çağrı bağlamı ile Ghidra çağrı kenarlarının farkı (yalnız jenerik fonksiyonlar;
        # arayüz modeli yalnız FUN_*.c dosyalarını düğüm sayar)
        gh_fun_callees = {generic[a]["name"] for a in callees if a in generic}
        gh_fun_callers = {generic[a]["name"] for a in callers if a in generic}
        if ui_callees - gh_fun_callees:
            ui_counts["ui_cagrilan_fazla"] += 1
        if gh_fun_callees - ui_callees:
            ui_counts["ui_cagrilan_eksik"] += 1
        if set(ui_callers) - gh_fun_callers:
            # adı başka bir jenerik fonksiyonun gövdesinde çağrı dışı geçiyor (adresi alınıyor:
            # gösterici ataması, geri çağrı argümanı); arayüz bunu "çağıran" diye çiziyor
            ui_counts["ui_cagiran_fazla"] += 1
            ev_counts["adresi_baska_govdede"] += 1
            if not callers:
                ui_counts["ui_cagiran_fazla_ghidra_cagirani_yok"] += 1
            if not (ev & set(GHIDRA_KEYS)):
                ui_counts["kart_bos_ghidra_ama_adresi_alinmis"] += 1
        else:
            if not (ev & set(GHIDRA_KEYS)):
                empty_counts["kart_bos_tam"] += 1
        if not ({"cagiran", "cagrilan_ic"} & ev) and not (set(ui_callers) - gh_fun_callers):
            empty_counts["iliski_yok"] += 1
        if gh_fun_callers - set(ui_callers):
            ui_counts["ui_cagiran_eksik"] += 1
        if callees and not ui_callees and not hints:
            ui_counts["ghidra_cagrilan_var_ui_hicbiri"] += 1
        verdicts[diag.get("verdict")] += 1
        sigs = diag.get("signals") or []
        if any(s.startswith("Bu binary genelinde") for s in sigs):
            ui_counts["teshis_ikili_geneli_satir"] += 1
        if any(s.startswith("BSim:") for s in sigs):
            ui_counts["teshis_bsim_satiri"] += 1
        if "Uygulanabilir imza/parmak izi eşleşmesi yok" in sigs and name in sig_fun:
            ui_counts["teshis_imza_yok_ama_imza_adayi_var"] += 1
        # deriveRole (ui/index.html:899-908) Python'a birebir: prov adsızda None
        if hints:
            roles["cagri"] += 1
        elif strs:
            roles["dizgi"] += 1
        elif diag.get("verdict"):
            roles[diag["verdict"]] += 1
        else:
            roles["bos"] += 1

    # Hiç artmayan sayaçlar da JSON'da 0 olarak görünsün
    for k in UI_COUNTER_KEYS:
        ui_counts[k] += 0
    for k in ("cagirani_yok", "cagirani_yok_ve_icerik_adsiz"):
        no_caller_flags[k] += 0
    n = len(unnamed)

    def ratio(k: int) -> float | None:
        return round(k / n, 4) if n else None

    # İkili geneli: susturma ve eleme sayaçları (fonksiyon başına kayıt yok)
    sil = prov.get("silencing") or {}
    elim = prov.get("eliminated_keys") or {}
    elim_global = {r: sum((v.get("global") or {}).values()) for r, v in elim.items() if isinstance(v, dict)}
    below = prov.get("below_min_confidence_candidates") or {}
    clean_fun_sig = sum(1 for k, v in clean.items()
                        if k.startswith("FUN_") and isinstance(v, dict) and v.get("source") == "signature_db"
                        and k not in global_map)
    report = load_json(ws / "reports" / "report.json", missing) or {}
    rstats = (((report.get("pipeline") or {}).get("stages") or {}).get("reconstruct") or {}).get("stats") or {}

    table = None
    tj = load_json(args.tablo, missing) if args.tablo else None
    if tj:
        tunit = unit if platform_ == "mac" or program != "coreutils" else "debian/coreutils"
        for row in tj.get("ikililer", []):
            if row.get("birim") == tunit and row.get("ikili") == binary:
                table = {k: row.get(k) for k in ("isim_bekleyen", "cagirani_yok", "tablo_kaydinda",
                                                  "gevsek_kayit_dizgili", "gevsek_ust_sinir", "tablo")}
                break

    return {
        "birim": unit,
        "kaynak": paths["kaynak"],
        "yeni_kosu_dizini_var": paths["yeni_dizin_var"],
        "calisma_alani": str(ws),
        "nufus": {
            "ghidra_fonksiyon": len(funcs),
            "jenerik_ad_tumu": generic_all,
            "jenerik_thunk_dis_degil": len(generic),
            "ad_haritasi_global_jenerik_anahtar": sum(1 for a in generic.values() if a["name"] in global_map),
            "adsiz": n,
            "src_iter_haritasinda_ek_anahtar": len(iter_named),
            "ghidra_adi_birden_cok_fonksiyonda": sum(1 for c in name_counts.values() if c > 1),
        },
        "kanit": {k: {"n": ev_counts.get(k, 0), "oran": ratio(ev_counts.get(k, 0))} for k in EVIDENCE_DEFS},
        "bos_kart": {k: {"n": empty_counts.get(k, 0), "oran": ratio(empty_counts.get(k, 0))} for k in EMPTY_DEFS},
        "cagirani_yok": {k: {"n": v, "oran": ratio(v)} for k, v in sorted(no_caller_flags.items())},
        "arayuz": {
            "sayaclar": {k: {"n": v, "oran": ratio(v)} for k, v in sorted(ui_counts.items())},
            "teshis_karari": dict(sorted((str(k), v) for k, v in verdicts.items())),
            "harita_rol_satiri": dict(sorted(roles.items())),
            "bsim_en_iyi_aday_programi": dict(bsim_progs.most_common()),
            "fazla_kenar_sinifi": dict(sorted(extra_edges.items())),
        },
        "ikili_geneli": {
            "susturma_acik": sil.get("enabled"),
            "susturulan_aday_toplam": sum((sil.get("candidates_dropped") or {}).values()),
            "susturulan_aday_sinif_sayisi": len(sil.get("candidates_dropped") or {}),
            "elenen_global_anahtar": elim_global,
            "esik_alti_aday_global": sum((below.get("global") or {}).values()) if isinstance(below, dict) else None,
            "genel_esik": prov.get("global_min_confidence"),
            "temiz_haritada_uygulanmamis_FUN_imza_kaydi": clean_fun_sig,
            "subsystem_map_md_kesilen_ad": subsys_md_cut,
            "subsystem_map_md_listelenen_ad": len(subsys_md),
            "yerlesim_dosya_sayisi": len(subsys),
            "imza_eslesmesi_FUN": len(sig_fun),
            "computation_fusion_matches": rstats.get("computation_fusion_matches"),
            "computation_fusion_accepted": rstats.get("computation_fusion_accepted"),
            "bsim_shadow_functions": rstats.get("bsim_shadow_functions"),
            "comments_added": rstats.get("comments_added"),
        },
        "n4_tablo_yuvasi_sayimi": table,
        "eksik_dosyalar": sorted(set(missing)),
    }


def _tr_int(n) -> str:
    if n is None:
        return "—"
    return f"{int(n):,}".replace(",", " ")


def _tr_pct(x) -> str:
    if x is None:
        return "—"
    return "%" + f"{100 * x:.1f}".replace(".", ",")


def render_tables(result: dict) -> str:
    """JSON'dan belge tabloları (markdown). Belgedeki sayı tabloları bu çıktıdan kopyalanır."""
    rows = result["ikililer"]
    head = "| tür | " + " | ".join(f"{r['birim']} ({r['kaynak']})" for r in rows) + " |"
    sep = "|---|" + "---:|" * len(rows)
    out = []

    def table(title, keys, getter):
        out.append(f"### {title}\n")
        out.append(head)
        out.append(sep)
        for k in keys:
            out.append(f"| `{k}` | " + " | ".join(getter(r, k) for r in rows) + " |")
        out.append("")

    def cell(d):
        return f"{_tr_int(d['n'])} ({_tr_pct(d['oran'])})" if d else "0"

    out.append("### Nüfus\n")
    out.append(head)
    out.append(sep)
    for k in ("ghidra_fonksiyon", "jenerik_thunk_dis_degil", "ad_haritasi_global_jenerik_anahtar", "adsiz",
              "ghidra_adi_birden_cok_fonksiyonda"):
        out.append(f"| `{k}` | " + " | ".join(_tr_int(r["nufus"][k]) for r in rows) + " |")
    out.append("")
    ev = list(result["kunye"]["kanit_tanimlari"].keys())
    ghidra = ev[:ev.index("boyut_karmasiklik") + 1] + ["adresi_baska_govdede"]
    karadul = [k for k in ev if k not in ghidra]
    table("Ghidra kanıtları (adres anahtarlı; adresi_baska_govdede metin vekili)", ghidra,
          lambda r, k: cell(r["kanit"][k]))
    table("Karadul kanıtları (çoğu ada anahtarlı)", karadul, lambda r, k: cell(r["kanit"][k]))
    table("Boş kart tanımları", list(result["kunye"]["bos_kart_tanimlari"].keys()),
          lambda r, k: cell(r["bos_kart"][k]))
    table("Çağıranı olmayanlar", sorted({k for r in rows for k in r["cagirani_yok"]}),
          lambda r, k: cell(r["cagirani_yok"].get(k)))
    table("Arayüz sayaçları (arayüz kodu içe aktarılarak)",
          sorted({k for r in rows for k in r["arayuz"]["sayaclar"]}),
          lambda r, k: cell(r["arayuz"]["sayaclar"].get(k)))
    table("Arayüz teşhis kararı (_naming_diagnosis verdict)",
          sorted({k for r in rows for k in r["arayuz"]["teshis_karari"]}),
          lambda r, k: _tr_int(r["arayuz"]["teshis_karari"].get(k, 0)))
    table("Haritadaki rol satırı (deriveRole dalı)",
          sorted({k for r in rows for k in r["arayuz"]["harita_rol_satiri"]}),
          lambda r, k: _tr_int(r["arayuz"]["harita_rol_satiri"].get(k, 0)))
    table("Arayüzün fazladan çizdiği kenarlar (bütün jenerik düğümler; Ghidra çağrı kenarı yok)",
          ["toplam", "yalniz_cagri_disi", "yalniz_cagri_sozdizimi", "ikisi", "metinde_yok"],
          lambda r, k: _tr_int(r["arayuz"]["fazla_kenar_sinifi"].get(k, 0)))
    ig_keys = [k for k in rows[0]["ikili_geneli"] if k != "elenen_global_anahtar"]
    table("İkili geneli", ig_keys, lambda r, k: str(r["ikili_geneli"].get(k)))
    table("Elenen genel anahtar (naming_provenance eliminated_keys, global; aday stratejisine göre toplam)",
          sorted({k for r in rows for k in (r["ikili_geneli"]["elenen_global_anahtar"] or {})}),
          lambda r, k: _tr_int((r["ikili_geneli"]["elenen_global_anahtar"] or {}).get(k, 0)))
    table("N4 tablo yuvası sayımı (tablo_yuvasi_sayim.json; nüfus geneli, eski koşu)",
          ["isim_bekleyen", "cagirani_yok", "tablo_kaydinda", "gevsek_kayit_dizgili", "gevsek_ust_sinir", "tablo"],
          lambda r, k: _tr_int((r["n4_tablo_yuvasi_sayimi"] or {}).get(k)))
    return "\n".join(out)


def git_head() -> str | None:
    try:
        return subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=10).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--yeni", type=Path, default=DEFAULT_NEW)
    ap.add_argument("--taban-debian", type=Path, default=DEFAULT_BASE_DEBIAN)
    ap.add_argument("--taban-mac", type=Path, default=DEFAULT_BASE_MAC)
    ap.add_argument("--tablo", type=Path, default=DEFAULT_TABLE)
    ap.add_argument("--cikti", type=Path, required=True)
    ap.add_argument("--md-tablolar", type=Path, default=None,
                    help="belge tablolarını bu dosyaya yaz (markdown)")
    args = ap.parse_args(argv)

    rows = [count_binary(args, *b) for b in BINARIES]
    result = {
        "kunye": {
            "betik": str(Path(__file__).resolve().relative_to(REPO)),
            "betik_sha256": sha256_file(Path(__file__).resolve()),
            "ui_server_sha256": sha256_file(REPO / "ui" / "server.py"),
            "ui_index_sha256": sha256_file(REPO / "ui" / "index.html"),
            "git_head": git_head(),
            "zaman": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "python": platform.python_version(),
            "kokler": {"yeni": str(args.yeni), "taban_debian": str(args.taban_debian),
                       "taban_mac": str(args.taban_mac), "tablo": str(args.tablo)},
            "kanit_tanimlari": EVIDENCE_DEFS,
            "bos_kart_tanimlari": EMPTY_DEFS,
            "kuskulu_uyarilar": list(DOUBTFUL_WARNINGS),
        },
        "ikililer": rows,
    }
    args.cikti.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if args.md_tablolar:
        args.md_tablolar.write_text(render_tables(result) + "\n", encoding="utf-8")
    for r in rows:
        print(f"{r['birim']:24s} {r['kaynak']:5s} adsız={r['nufus']['adsiz']:5d} "
              f"kart_bos_ghidra={r['bos_kart']['kart_bos_ghidra']['n']:5d} "
              f"icerik_adsiz={r['bos_kart']['icerik_adsiz']['n']:5d} ui_bos={r['bos_kart']['ui_bos']['n']:5d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
