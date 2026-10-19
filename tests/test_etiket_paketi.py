"""scripts/measurement/etiket_paketi.py — kör etiket paketinin (protokol v2) birim testleri.

Sentetik bir C ağacı ve puanlama satırlarıyla kilitlenen davranışlar:
  (a) karartma (2026-10-19 kararı): yalnız öğenin kendi adı imza, özyineleme,
      yorum ve dizede, ``_`` önekli biçimiyle birlikte FONKSIYON olur; tam sözcük
      eşleşmesi (önek/sonek benzeri tanımlayıcılar kalır); başka öğelerin adları
      görünür kalır ve anahtarda ``capraz_atif`` (kaç başka öğenin gövdesinde
      geçtiği) olarak sayılır; dosya adı yalnız uzantısız hâli öğenin kendi
      adıysa karartılır,
  (b) değerlendirici dosyalarında yalnız beyaz listedeki alanlar var,
  (c) örneklem: yalnız tp + wrong, gövdesi bulunamayan ve belirsiz olanlar dışarıda,
  (d) yem kuralı: %10 ek öğe, başka dosya, boş token kesişimi, hiçbir gövdede
      tanımlayıcı olarak geçmez,
  (e) sızıntı denetimi: yasak alan ve öğenin kendi adı kendi kaydında hata;
      başka öğenin adı uyarı (öğe ve geçiş sayısıyla),
  (f) belirlenimcilik ve ``--gt-goster`` kipinde aynı id'ler.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "measurement" / "etiket_paketi.py"
_spec = importlib.util.spec_from_file_location("etiket_paketi_under_test", _PATH)
ep = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ep
_spec.loader.exec_module(ep)

BASE = 0x100001000

SOURCES = {
    "net.c": (
        "int\n"
        "net_open_socket(const char *host)\n"
        "{\n"
        "\t/* net_open_socket: bir soket açar. */\n"
        "\tint fd = socket_create(host);\n"
        "\tif (fd < 0)\n"
        "\t\tlog_warn(\"net_open_socket failed: %s\", host);\n"
        "\treturn fd;\n"
        "}\n"
        "\n"
        "int\n"
        "net_send_packet(int fd, const char *buf, int len)\n"
        "{\n"
        "\tint net_send_packet_count = 0;\n"
        "\tif (len <= 0)\n"
        "\t\treturn net_send_packet(fd, buf, 1);\n"
        "\tlog_warn(\"net_send_packet: short\");\n"
        "\tnet_send_packet_count += mem_copy_bytes(buf, len);\n"
        "\treturn _net_send_packet(fd) + net_send_packet_count + my_net_send_packet;\n"
        "}\n"
        "\n"
        "void\n"
        "net_close_socket(int fd)\n"
        "{\n"
        "\tcfg_dump_all();\n"
        "\tclose(fd);\n"
        "}\n"
    ),
    "cfg.c": (
        "int\n"
        "cfg_load_file(const char *path)\n"
        "{\n"
        "\treturn cfg_lookup_key(path) + net_open_socket(path);\n"
        "}\n"
        "\n"
        "int\n"
        "cfg_lookup_key(const char *key)\n"
        "{\n"
        "\treturn str_hash_text(key);\n"
        "}\n"
        "\n"
        "void\n"
        "cfg_dump_all(void)\n"
        "{\n"
        "\tprintf(\"dump\\n\");\n"
        "}\n"
        "\n"
        "void\n"
        "cfg_free_tree(void *t)\n"
        "{\n"
        "\tmem_free_block(t);\n"
        "}\n"
    ),
    "ui.c": (
        "void\n"
        "ui_draw_window(int w)\n"
        "{\n"
        "\tui_beep(w);\n"
        "\tnet_open_socket(\"a\");\n"
        "\tnet_open_socket(\"b\");\n"
        "}\n"
        "\n"
        "void\n"
        "ui_resize_window(int w, int h)\n"
        "{\n"
        "\tui_draw_window(w + h);\n"
        "}\n"
        "\n"
        "int\n"
        "ui_handle_key(int k)\n"
        "{\n"
        "\treturn k;\n"
        "}\n"
        "\n"
        "void\n"
        "ui_beep(int n)\n"
        "{\n"
        "\tputchar(7 + n);\n"
        "}\n"
    ),
    "mem.c": (
        "void *\n"
        "mem_alloc_block(int n)\n"
        "{\n"
        "\treturn malloc(n);\n"
        "}\n"
        "\n"
        "void\n"
        "mem_free_block(void *p)\n"
        "{\n"
        "\tfree(p);\n"
        "}\n"
        "\n"
        "int\n"
        "mem_copy_bytes(const char *b, int n)\n"
        "{\n"
        "\treturn n;\n"
        "}\n"
        "\n"
        "void\n"
        "mem_zero_bytes(char *b, int n)\n"
        "{\n"
        "\tmemset(b, 0, n);\n"
        "}\n"
    ),
    "str.c": (
        "unsigned\n"
        "str_hash_text(const char *s)\n"
        "{\n"
        "\treturn s[0] ? 31 * str_hash_text(s + 1) + s[0] : 0;\n"
        "}\n"
        "\n"
        "int\n"
        "str_compare_text(const char *a, const char *b)\n"
        "{\n"
        "\treturn strcmp(a, b);\n"
        "}\n"
        "\n"
        "char *\n"
        "str_trim_space(char *s)\n"
        "{\n"
        "\twhile (*s == ' ')\n"
        "\t\ts++;\n"
        "\treturn s;\n"
        "}\n"
        "\n"
        "void\n"
        "str_upper_case(char *s)\n"
        "{\n"
        "\tfor (; *s; s++)\n"
        "\t\t*s = toupper(*s);\n"
        "}\n"
    ),
    "dup1.c": "static int\nshared_helper(void)\n{\n\treturn 1;\n}\n",
    "dup2.c": "static int\nshared_helper(void)\n{\n\treturn 2;\n}\n",
}

# (gerçek ad, durum, Karadul tahmini)
ROWS = [
    ("net_open_socket", "tp", "net_open_socket"),
    ("net_send_packet", "wrong", "send_data"),
    ("net_close_socket", "wrong", "socket_close"),
    ("cfg_load_file", "wrong", "read_config"),
    ("cfg_lookup_key", "tp", "cfg_lookup_key_2"),
    ("cfg_dump_all", "wrong", "dump"),
    ("cfg_free_tree", "unnamed", None),
    ("ui_draw_window", "wrong", "draw"),
    ("ui_resize_window", "wrong", "window_size"),
    ("ui_handle_key", "unnamed", None),
    ("ui_beep", "unnamed", None),
    ("mem_alloc_block", "wrong", "block_new"),
    ("mem_free_block", "tp", "mem_free_block"),
    ("mem_copy_bytes", "unnamed", None),
    ("mem_zero_bytes", "unnamed", None),
    ("str_hash_text", "wrong", "hash"),
    ("str_compare_text", "wrong", "compare_strings"),
    ("str_trim_space", "unnamed", None),
    ("str_upper_case", "unnamed", None),
    ("shared_helper", "wrong", "helper"),          # iki farklı tanım: belirsiz
    ("tree_RB_NEXT", "wrong", "rb_next"),          # makro: gövde yok
    ("net_send_packet.cold.1", "wrong", "cold_path"),  # parça: gövde yok
]
N_ELIGIBLE = 12  # 15 isimli - 1 belirsiz - 2 gövdesiz


def _rows() -> list[dict]:
    return [{"addr": f"0x{BASE + 0x40 * i:x}", "gt": [f"_{gt}"], "pred": pred, "status": st, "lenient": False}
            for i, (gt, st, pred) in enumerate(ROWS)]


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "src"
    for name, text in SOURCES.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    score = tmp_path / "score.json"
    score.write_text(json.dumps({"summary": {}, "rows": _rows()}), encoding="utf-8")
    return root, score, ep.index_tree(root)


def _build(tree, **kw):
    root, _score, idx = tree
    kw.setdefault("binary", "oyun")
    kw.setdefault("sample_size", 0)
    kw.setdefault("seed", 7)
    return ep.build_package(_rows(), idx, root, **kw)


def _item_by_gt(key: dict, gt: str) -> tuple[str, dict]:
    for iid, v in key["ogeler"].items():
        if v["gt"] == [f"_{gt}"]:
            return iid, v
    raise AssertionError(f"{gt} pakette yok")


def _word(name: str, text: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text) is not None


# --- karartma ---------------------------------------------------------------------------------

def test_mask_own_word_boundaries_and_underscore_form():
    text = "f(); _f(); ff(); f_count; my_f; \"f\"; /* f */ g();"
    out, n = ep.mask_own(text, ep.name_forms(["_f"]))
    assert out == "FONKSIYON(); FONKSIYON(); ff(); f_count; my_f; \"FONKSIYON\"; /* FONKSIYON */ g();"
    assert n == 4


def test_mask_file_only_when_stem_is_own_name():
    own = ep.name_forms(["_xalloc"])
    assert ep.mask_file("lib/xalloc.c", own) == ("lib/FONKSIYON.c", True)
    assert ep.mask_file("_xalloc.h", own) == ("FONKSIYON.h", True)
    assert ep.mask_file("lib/xalloc_util.c", own) == ("lib/xalloc_util.c", False)
    assert ep.mask_file("xalloc/other.c", own) == ("xalloc/other.c", False)  # yalnız dosya adı


def test_own_name_masked_everywhere_in_package(tree):
    amac, _aday, key = _build(tree)
    iid, item = _item_by_gt(key, "net_send_packet")
    body = next(r["govde"] for r in amac if r["id"] == iid)
    assert not _word("net_send_packet", body) and not _word("_net_send_packet", body)
    # imza + özyineleme + dize + _önekli biçim
    assert body.count("FONKSIYON") == 4
    assert item["karartilan_kendi"] == 4
    # benzer ama farklı tanımlayıcılar kalır
    assert body.count("net_send_packet_count") == 3 and "my_net_send_packet" in body
    iid2, _ = _item_by_gt(key, "net_open_socket")
    body2 = next(r["govde"] for r in amac if r["id"] == iid2)
    assert "/* FONKSIYON: bir soket açar. */" in body2
    assert "\"FONKSIYON failed: %s\"" in body2


def test_cross_references_count_items_not_occurrences():
    texts = {"A": "b(); b(); c();", "B": "a(); _a();", "C": "x();"}
    forms = {k: ep.name_forms([k.lower()]) for k in texts}
    seen_in, occ = ep.cross_references(texts, forms)
    assert {k: sorted(v) for k, v in seen_in.items()} == {"A": ["B"], "B": ["A"], "C": ["A"]}
    assert occ == {"A": 3, "B": 2, "C": 0}


def test_other_names_stay_visible_and_capraz_atif_counts_items(tree):
    amac, _aday, key = _build(tree)
    body_of = {r["id"]: r["govde"] for r in amac}
    iid, _ = _item_by_gt(key, "ui_resize_window")
    assert "ui_draw_window(w + h);" in body_of[iid]
    iid, _ = _item_by_gt(key, "cfg_load_file")
    assert "cfg_lookup_key(path) + net_open_socket(path)" in body_of[iid]
    assert "BASKA_FONKSIYON" not in "".join(body_of.values())
    cap = {v["gt"][0][1:]: v["capraz_atif"] for v in key["ogeler"].values()}
    # net_open_socket iki gövdede geçiyor (ui_draw_window'da iki kez): geçiş değil öğe sayılır
    assert cap["net_open_socket"] == 2
    for name in ("cfg_dump_all", "cfg_lookup_key", "str_hash_text", "ui_draw_window"):
        assert cap[name] == 1
    for name in ("net_send_packet", "net_close_socket", "cfg_load_file", "ui_resize_window",
                 "mem_alloc_block", "str_compare_text"):
        assert cap[name] == 0
    # bağımsız sayım: öğenin adının geçtiği BAŞKA gövde sayısı
    for iid, v in key["ogeler"].items():
        names = ep.name_forms(v["gt"])
        expected = sum(1 for j, text in body_of.items() if j != iid and any(_word(n, text) for n in names))
        assert v["capraz_atif"] == expected
    s = key["kunye"]["sayilar"]
    assert s["capraz_atifli_oge"] == sum(1 for v in key["ogeler"].values() if v["capraz_atif"])


def test_file_name_masked_only_for_own_stem(tmp_path):
    root = tmp_path
    defs = [("xalloc", "lib/xalloc.c", "void *\nxalloc(int n)\n{\n\treturn malloc(n);\n}"),
            ("xcalloc", "lib/xalloc.c", "void *\nxcalloc(int n, int m)\n{\n\treturn xalloc(n * m);\n}"),
            ("green_leaf_fold", "y.c", "void\ngreen_leaf_fold(void)\n{\n}"),
            ("stone_wall_build", "z.c", "void\nstone_wall_build(void)\n{\n}"),
            ("paper_cup_fill", "w.c", "void\npaper_cup_fill(void)\n{\n}")]
    rows = _mem_rows([("xalloc", "wrong", "alloc"), ("xcalloc", "wrong", "calloc_like"),
                      ("green_leaf_fold", "wrong", "fold"),
                      ("stone_wall_build", "unnamed", None), ("paper_cup_fill", "unnamed", None)])
    amac, aday, key = ep.build_package(rows, _mem_idx(root, defs), root, binary="t", sample_size=0, seed=4)
    dosya = {key["ogeler"][r["id"]]["gt"][0]: r["dosya"] for r in amac}
    assert dosya["_xalloc"] == "lib/FONKSIYON.c"
    assert dosya["_xcalloc"] == "lib/xalloc.c"  # başka öğenin adı: dosya adı kalır
    flags = {v["gt"][0]: v["dosya_karartildi"] for v in key["ogeler"].values()}
    assert flags["_xalloc"] and not flags["_xcalloc"]
    s = key["kunye"]["sayilar"]
    assert (s["dosya_karartilan"], s["dosya_adi_capraz_atifli_oge"]) == (1, 1)
    errors, warnings = ep.leak_check(amac, aday, key)
    assert errors == [] and any("dosya adlarında geçiyor: 1 öğede" in w for w in warnings)
    gt_amac, _d, _k = ep.build_package(rows, _mem_idx(root, defs), root, binary="t", sample_size=0,
                                       seed=4, show_gt=True)
    assert sorted(r["dosya"] for r in gt_amac if r["dosya"].startswith("lib/")) == ["lib/xalloc.c"] * 2


def test_evaluator_files_have_only_whitelisted_fields(tree):
    amac, aday, key = _build(tree, sample_size=5)
    assert all(set(r) == {"id", "dosya", "govde"} for r in amac)
    assert all(set(r) == {"id", "aday"} for r in aday)
    assert [r["id"] for r in amac] == [r["id"] for r in aday] == sorted(key["ogeler"])
    # dosya adı göreli yol olarak kalır
    assert {r["dosya"] for r in amac} <= set(SOURCES)


# --- örneklem ---------------------------------------------------------------------------------

def test_population_excludes_unnamed_missing_and_ambiguous(tree):
    _amac, _aday, key = _build(tree)
    s = key["kunye"]["sayilar"]
    assert (s["isimli"], s["uygun"], s["govdesi_bulunamayan"], s["govdesi_belirsiz"]) == (15, N_ELIGIBLE, 2, 1)
    assert {tuple(x["gt"]) for x in key["kunye"]["govdesi_bulunamayan"]} == {
        ("_tree_RB_NEXT",), ("_net_send_packet.cold.1",)}
    assert key["kunye"]["govdesi_belirsiz"][0]["dosyalar"] == ["dup1.c", "dup2.c"]
    main = [v for v in key["ogeler"].values() if not v["yem"]]
    assert len(main) == N_ELIGIBLE and all(v["status"] in ("tp", "wrong") for v in main)
    assert all(v["aday"] == v["pred"] for v in main)


def test_sample_size_and_decoy_count(tree):
    _amac, _aday, key = _build(tree, sample_size=5)
    s = key["kunye"]["sayilar"]
    assert (s["ana"], s["yem"], s["toplam"]) == (5, 1, 6)  # %10 yukarı yuvarlanır
    assert key["kunye"]["yem_govde_havuzu"] == "isimli"
    _amac, _aday, key = _build(tree, sample_size=0)
    s = key["kunye"]["sayilar"]
    assert (s["ana"], s["yem"]) == (N_ELIGIBLE, 2)
    assert key["kunye"]["yem_govde_havuzu"] == "isimli+isimsiz"


def test_negative_sample_size_is_an_error(tree):
    with pytest.raises(ep.PaketHatasi):
        _build(tree, sample_size=-1)


@pytest.mark.parametrize("mutate, message", [
    (lambda rows: rows[0].update(addr=4096), "hex metin"),
    (lambda rows: rows[1].update(addr=rows[0]["addr"]), "iki kez"),
    (lambda rows: rows[0].update(gt=[]), "gt boş"),
    (lambda rows: rows[1].update(pred=None), "pred boş"),
    (lambda rows: rows[0].pop("status"), "'status' anahtarı yok"),
])
def test_invalid_rows_are_explicit_errors(mutate, message):
    rows = _rows()
    mutate(rows)
    with pytest.raises(ep.PaketHatasi, match=message):
        ep.validate_rows(rows)


# --- yem ----------------------------------------------------------------------------------------

def test_decoy_rule_holds_for_many_seeds(tree):
    rows = {r["addr"]: r for r in _rows()}
    for seed in range(15):
        amac, aday, key = _build(tree, sample_size=6, seed=seed)
        bodies = "\n".join(r["govde"] for r in amac)
        main_preds = {ep.normalize_name(v["pred"]) for v in key["ogeler"].values() if not v["yem"]}
        decoys = [v for v in key["ogeler"].values() if v["yem"]]
        assert len(decoys) == 1
        for v in decoys:
            src = v["yem_kaynagi"]
            assert src["aday_dosya"] != v["dosya"]
            assert not (ep.name_tokens(v["aday"]) & ep.name_tokens(v["gt"][0]))
            assert rows[src["aday_addr"]]["gt"] == src["aday_gt"] == [f"_{v['aday']}"]
            assert src["aday_addr"] not in {x["addr"] for x in key["ogeler"].values()}
            assert ep.normalize_name(v["aday"]) not in main_preds
            assert not _word(v["aday"], bodies)
            assert v["pred"] is None and v["status"] is None


def _mem_idx(root: Path, defs: list[tuple[str, str, str]]) -> dict:
    """(ad, dosya, gövde) -> index_tree biçiminde bellek içi dizin."""
    idx: dict = {}
    for name, fname, text in defs:
        idx.setdefault(name, []).append({"name": name, "file": str(root / fname), "line": 1, "text": text})
    return idx


def _mem_rows(spec: list[tuple[str, str, str | None]]) -> list[dict]:
    return [{"addr": f"0x{BASE + 0x10 * i:x}", "gt": [f"_{g}"], "status": st, "pred": pred}
            for i, (g, st, pred) in enumerate(spec)]


def test_decoy_candidate_needs_disjoint_tokens(tmp_path):
    root = tmp_path
    defs = [("red_apple_pick", "x.c", "void\nred_apple_pick(void)\n{\n}"),
            ("blue_berry_wash", "y.c", "void\nblue_berry_wash(void)\n{\n}"),
            ("red_berry_count", "z.c", "void\nred_berry_count(void)\n{\n}"),
            ("green_leaf_fold", "z.c", "void\ngreen_leaf_fold(void)\n{\n}")]
    rows = _mem_rows([("red_apple_pick", "wrong", "pick"), ("blue_berry_wash", "wrong", "wash"),
                      ("red_berry_count", "unnamed", None), ("green_leaf_fold", "unnamed", None)])
    for seed in range(20):
        _a, _b, key = ep.build_package(rows, _mem_idx(root, defs), root, binary="t", sample_size=1, seed=seed)
        decoy = next(v for v in key["ogeler"].values() if v["yem"])
        assert decoy["aday"] == "green_leaf_fold"


def test_decoy_candidate_needs_other_file(tmp_path):
    root = tmp_path
    defs = [("red_apple_pick", "x.c", "void\nred_apple_pick(void)\n{\n}"),
            ("blue_berry_wash", "y.c", "void\nblue_berry_wash(void)\n{\n}"),
            ("green_leaf_fold", "x.c", "void\ngreen_leaf_fold(void)\n{\n}"),
            ("stone_wall_build", "y.c", "void\nstone_wall_build(void)\n{\n}")]
    rows = _mem_rows([("red_apple_pick", "wrong", "pick"), ("blue_berry_wash", "wrong", "wash"),
                      ("green_leaf_fold", "unnamed", None), ("stone_wall_build", "unnamed", None)])
    seen = set()
    for seed in range(20):
        _a, _b, key = ep.build_package(rows, _mem_idx(root, defs), root, binary="t", sample_size=1, seed=seed)
        decoy = next(v for v in key["ogeler"].values() if v["yem"])
        assert decoy["yem_kaynagi"]["aday_dosya"] != decoy["dosya"]
        seen.add(decoy["dosya"])
    assert seen == {"x.c", "y.c"}  # iki yön de denendi


def test_decoy_candidate_must_not_appear_in_any_body(tmp_path):
    root = tmp_path
    defs = [("red_apple_pick", "x.c", "void\nred_apple_pick(void)\n{\n\tgreen_leaf_fold();\n}"),
            ("blue_berry_wash", "y.c", "void\nblue_berry_wash(void)\n{\n\tgreen_leaf_fold();\n}"),
            ("green_leaf_fold", "z.c", "void\ngreen_leaf_fold(void)\n{\n}"),
            ("stone_wall_build", "z.c", "void\nstone_wall_build(void)\n{\n}")]
    rows = _mem_rows([("red_apple_pick", "wrong", "pick"), ("blue_berry_wash", "wrong", "wash"),
                      ("green_leaf_fold", "unnamed", None), ("stone_wall_build", "unnamed", None)])
    for seed in range(20):
        _a, _b, key = ep.build_package(rows, _mem_idx(root, defs), root, binary="t", sample_size=1, seed=seed)
        assert next(v for v in key["ogeler"].values() if v["yem"])["aday"] == "stone_wall_build"


def test_no_valid_decoy_candidate_is_an_error(tmp_path):
    root = tmp_path
    defs = [("red_apple_pick", "x.c", "void\nred_apple_pick(void)\n{\n}"),
            ("blue_berry_wash", "x.c", "void\nblue_berry_wash(void)\n{\n}"),
            ("green_leaf_fold", "x.c", "void\ngreen_leaf_fold(void)\n{\n}")]
    rows = _mem_rows([("red_apple_pick", "wrong", "pick"), ("blue_berry_wash", "wrong", "wash"),
                      ("green_leaf_fold", "unnamed", None)])
    with pytest.raises(ep.PaketHatasi, match="yem adayı"):
        ep.build_package(rows, _mem_idx(root, defs), root, binary="t", sample_size=1, seed=1)


def test_decoys_are_mixed_with_main_items(tree):
    _amac, _aday, key = _build(tree, sample_size=0, seed=3)
    order = sorted(key["ogeler"])
    addrs = [int(key["ogeler"][i]["addr"], 16) for i in order]
    assert addrs != sorted(addrs)  # id sırası adres sırası değil
    decoy_pos = [n for n, i in enumerate(order) if key["ogeler"][i]["yem"]]
    assert decoy_pos != list(range(len(order) - len(decoy_pos), len(order)))


# --- gt-goster kipi ve belirlenimcilik -------------------------------------------------------

def test_gt_mode_same_ids_unmasked_with_gt_field(tree):
    a_kor, d_kor, k_kor = _build(tree, sample_size=5, seed=11)
    a_gt, d_gt, k_gt = _build(tree, sample_size=5, seed=11, show_gt=True)
    assert d_kor == d_gt
    assert sorted(k_kor["ogeler"]) == sorted(k_gt["ogeler"])
    for iid, v in k_kor["ogeler"].items():
        w = k_gt["ogeler"][iid]
        fields = ("addr", "gt", "pred", "status", "aday", "yem", "yem_kaynagi", "capraz_atif")
        assert {k: v[k] for k in fields} == {k: w[k] for k in fields}
    assert k_gt["kunye"]["kip"] == "gt_goster" and k_kor["kunye"]["kip"] == "kor"
    for rec in a_gt:
        gt = k_gt["ogeler"][rec["id"]]["gt"][0][1:]
        assert rec["gt"][0] == gt and _word(gt, rec["govde"])
        assert "FONKSIYON" not in rec["govde"]


def test_cli_output_is_byte_identical_for_same_seed(tree, tmp_path, capsys):
    root, score, _idx = tree
    outs = []
    for name, seed in (("p1", 5), ("p2", 5), ("p3", 6)):
        out = tmp_path / name
        rc = ep.main(["uret", "--satirlar", str(score), "--kaynak", str(root), "--ikili", "oyun",
                      "--orneklem", "6", "--tohum", str(seed), "--cikti", str(out)])
        assert rc == 0
        outs.append(out)
    capsys.readouterr()
    for n in ep.PAKET_DOSYALARI:
        assert (outs[0] / n).read_bytes() == (outs[1] / n).read_bytes()
    assert (outs[0] / ep.ANAHTAR_DOSYASI).read_bytes() != (outs[2] / ep.ANAHTAR_DOSYASI).read_bytes()


def test_cli_refuses_to_overwrite_existing_package(tree, tmp_path, capsys):
    root, score, _idx = tree
    args = ["uret", "--satirlar", str(score), "--kaynak", str(root), "--ikili", "oyun",
            "--orneklem", "4", "--tohum", "1", "--cikti", str(tmp_path / "p")]
    assert ep.main(args) == 0
    assert ep.main(args) == 2
    assert ep.main(args + ["--uzerine-yaz"]) == 0
    capsys.readouterr()


# --- sızıntı denetimi ---------------------------------------------------------------------------

def test_leak_check_passes_clean_blind_and_gt_packages(tree):
    for show in (False, True):
        amac, aday, key = _build(tree, sample_size=0, show_gt=show)
        errors, _warnings = ep.leak_check(amac, aday, key)
        assert errors == []


def test_leak_check_flags_forbidden_and_missing_fields(tree):
    amac, aday, key = _build(tree, sample_size=4)
    amac[0]["addr"] = "0x1"
    aday[1]["status"] = "tp"
    del amac[2]["dosya"]
    errors, _ = ep.leak_check(amac, aday, key)
    assert any("yasak alan ['addr']" in e for e in errors)
    assert any("yasak alan ['status']" in e for e in errors)
    assert any("eksik alan ['dosya']" in e for e in errors)


def test_leak_check_flags_gt_field_in_blind_package(tree):
    amac, aday, key = _build(tree, sample_size=4)
    amac[0]["gt"] = ["x"]
    errors, _ = ep.leak_check(amac, aday, key)
    assert any("yasak alan ['gt']" in e for e in errors)


def test_leak_check_own_name_in_own_record_is_error(tree):
    amac, aday, key = _build(tree, sample_size=0)
    iid, _item = _item_by_gt(key, "cfg_dump_all")
    rec = next(r for r in amac if r["id"] == iid)
    rec["govde"] = rec["govde"].replace("FONKSIYON", "cfg_dump_all", 1)
    errors, _ = ep.leak_check(amac, aday, key)
    assert len(errors) == 1 and "kendi adı" in errors[0] and iid in errors[0]
    # aynı ad aday alanında serbest
    amac2, aday2, key2 = _build(tree, sample_size=0)
    next(r for r in aday2 if r["id"] == iid)["aday"] = "cfg_dump_all"
    assert ep.leak_check(amac2, aday2, key2)[0] == []


def test_leak_check_own_name_in_file_field_is_error(tree):
    amac, aday, key = _build(tree, sample_size=0)
    iid, _item = _item_by_gt(key, "net_send_packet")
    next(r for r in amac if r["id"] == iid)["dosya"] = "net_send_packet/net.c"
    errors, _ = ep.leak_check(amac, aday, key)
    assert len(errors) == 1 and "'dosya'" in errors[0] and iid in errors[0]


def test_leak_check_other_item_name_is_warning_with_counts(tree):
    amac, aday, key = _build(tree, sample_size=0)
    s = key["kunye"]["sayilar"]
    errors, warnings = ep.leak_check(amac, aday, key)
    assert errors == []
    assert any(f"gövdelerde geçiyor: {s['baska_ad_gecen_govde']} öğede {s['baska_ad_gecis']} geçiş" in w
               for w in warnings)
    # başka bir öğenin adını bir gövdeye eklemek hata değil; uyarı sayıları artar
    iid, _item = _item_by_gt(key, "mem_alloc_block")
    next(r for r in amac if r["id"] == iid)["govde"] += "\n/* str_compare_text */"
    errors2, warnings2 = ep.leak_check(amac, aday, key)
    assert errors2 == []
    assert any(f"gövdelerde geçiyor: {s['baska_ad_gecen_govde'] + 1} öğede {s['baska_ad_gecis'] + 1} geçiş" in w
               for w in warnings2)


def test_leak_check_flags_decoy_candidate_in_body(tree):
    amac, aday, key = _build(tree, sample_size=0)
    cand = next(v["aday"] for v in key["ogeler"].values() if v["yem"])
    amac[0]["govde"] += f"\n\t{cand}();"
    errors, _ = ep.leak_check(amac, aday, key)
    assert any("yem adayı bir gövdede tanımlayıcı olarak geçiyor" in e for e in errors)


def test_leak_check_flags_id_mismatch(tree):
    amac, aday, key = _build(tree, sample_size=4)
    aday.pop()
    errors, _ = ep.leak_check(amac, aday, key)
    assert any("id kümesi anahtarla aynı değil" in e for e in errors)


def test_leak_check_cli_exit_codes(tree, tmp_path, capsys):
    root, score, _idx = tree
    out = tmp_path / "p"
    assert ep.main(["uret", "--satirlar", str(score), "--kaynak", str(root), "--ikili", "oyun",
                    "--orneklem", "0", "--tohum", "2", "--cikti", str(out)]) == 0
    assert ep.main(["sizinti-denetimi", "--paket", str(out)]) == 0
    lines = (out / ep.AMAC_DOSYASI).read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["otomatik"] = "wrong"
    lines[0] = json.dumps(first, ensure_ascii=False)
    (out / ep.AMAC_DOSYASI).write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert ep.main(["sizinti-denetimi", "--paket", str(out)]) == 1
    assert ep.main(["sizinti-denetimi", "--paket", str(tmp_path / "yok")]) == 2
    capsys.readouterr()


# =============================================================================================
# Çok adaylı kip (G6/G7)
# =============================================================================================

SYSTEMS = ("sys_karadul", "sys_qwen", "sys_gemma")
# gerçek ad -> {sistem: (aday ya da None, güven, durum)}
MULTI = {
    "net_open_socket": {"sys_karadul": ("net_open_socket", None, None), "sys_qwen": ("openSocket", -0.2, None),
                        "sys_gemma": ("NetOpenSocket", -0.1, None)},
    "net_send_packet": {"sys_karadul": ("send_data", None, None), "sys_qwen": ("send_packet", -0.3, None),
                        "sys_gemma": (None, None, "cekimser")},
    "cfg_load_file": {"sys_karadul": ("read_config", None, None), "sys_qwen": ("read_config_2", -0.5, None),
                      "sys_gemma": ("load_config_file", -0.4, None)},
    "cfg_lookup_key": {"sys_karadul": ("FUN_100001100", None, None), "sys_qwen": ("lookup_key", -0.6, None),
                       "sys_gemma": ("lookupKey", -0.9, None)},
    "ui_draw_window": {"sys_karadul": ("draw", None, None), "sys_qwen": ("draw_window", -0.2, None),
                       "sys_gemma": ("render window", -1.0, None)},
    "ui_resize_window": {"sys_karadul": ("window_size", None, None), "sys_qwen": ("resize_window", -0.1, None),
                         "sys_gemma": ("resize_window", -0.3, None)},
    "mem_alloc_block": {"sys_karadul": ("block_new", None, None), "sys_qwen": (None, None, "ret"),
                        "sys_gemma": ("alloc_block", -0.7, None)},
    "mem_free_block": {"sys_karadul": ("mem_free_block", None, None), "sys_qwen": ("free_block", -0.2, None),
                       "sys_gemma": ("release_block", -1.1, None)},
    "str_hash_text": {"sys_karadul": ("hash", None, None), "sys_qwen": ("hash_string", -0.4, None),
                      "sys_gemma": ("compute_hash", -0.8, None)},
    "str_compare_text": {"sys_karadul": ("compare_strings", None, None), "sys_qwen": ("compare_text", -0.3, None),
                         "sys_gemma": ("str_compare_text", -0.2, None)},
    "str_trim_space": {"sys_karadul": (None, None, None), "sys_qwen": ("trim_spaces", -0.5, None),
                       "sys_gemma": ("skip_whitespace", -0.6, None)},
    "ui_beep": {"sys_karadul": (None, None, None), "sys_qwen": ("beep", -0.9, None),
                "sys_gemma": ("ring_bell", -1.2, None)},
}


def _addr_of(gt: str) -> str:
    return next(r["addr"] for r in _rows() if r["gt"] == [f"_{gt}"])


def _cand_records(multi: dict = MULTI) -> list[dict]:
    out = []
    for gt, per in multi.items():
        for system, (name, conf, durum) in per.items():
            rec = {"addr": _addr_of(gt), "sistem": system, "aday": name, "guven": conf}
            if durum:
                rec["durum"] = durum
            out.append(rec)
    return out


def _build_multi(tree, **kw):
    root, _score, idx = tree
    cands, _skipped = ep.parse_candidates(kw.pop("records", _cand_records()))
    kw.setdefault("binary", "oyun")
    kw.setdefault("seed", 5)
    return ep.build_multi_package(_rows(), idx, root, cands, **kw)


def _fn_by_gt(key: dict, gt: str) -> tuple[str, dict]:
    return next((fid, v) for fid, v in key["ogeler"].items() if v["gt"] == [f"_{gt}"])


def _shown_by_system(item: dict) -> dict:
    return {s: (item["adaylar"][e["aday_id"]]["aday"] if e["aday_id"] else None) for s, e in item["sistemler"].items()}


def test_cok_merges_same_normalized_names_and_keeps_systems_in_key(tree):
    _amac, aday, key = _build_multi(tree)
    _fid, item = _fn_by_gt(key, "net_open_socket")
    shown = _shown_by_system(item)
    assert shown == {"sys_karadul": "net_open_socket", "sys_qwen": "open_socket", "sys_gemma": "net_open_socket"}
    merged = item["adaylar"][item["sistemler"]["sys_karadul"]["aday_id"]]
    assert merged["sistemler"] == ["sys_gemma", "sys_karadul"]
    assert merged["ozgun"] == {"sys_gemma": "NetOpenSocket", "sys_karadul": "net_open_socket"}
    assert item["sistemler"]["sys_gemma"]["aday_id"] == item["sistemler"]["sys_karadul"]["aday_id"]
    _fid, item = _fn_by_gt(key, "cfg_load_file")
    assert item["adaylar"][item["sistemler"]["sys_qwen"]["aday_id"]]["sistemler"] == ["sys_karadul", "sys_qwen"]
    # birleşen satır: net_open_socket, cfg_load_file, cfg_lookup_key, ui_resize_window
    s = key["kunye"]["sayilar"]
    assert s["birlesen_satir"] == 4
    assert s["aday"] == len(aday) - s["yem"]


def test_cok_auto_tam_from_normalized_gt(tree):
    _amac, _aday, key = _build_multi(tree)
    tam = {(v["gt"][0][1:], a["aday"]) for v in key["ogeler"].values() for a in v["adaylar"].values() if a["tam"]}
    assert tam == {("net_open_socket", "net_open_socket"), ("mem_free_block", "mem_free_block"),
                   ("str_compare_text", "str_compare_text")}


def test_cok_package_files_hide_systems(tree):
    amac, aday, key = _build_multi(tree)
    assert all(set(r) == {"id", "dosya", "govde"} for r in amac)
    assert all(set(r) == {"id", "aday_id", "aday"} for r in aday)
    text = json.dumps(amac, ensure_ascii=False) + json.dumps(aday, ensure_ascii=False)
    assert "sys_" not in text and not any(s in text for s in SYSTEMS)
    # gösterim normalize: sistem üslubu (büyük harf, _2 eki) görünmez
    assert all(r["aday"] == ep.normalize_name(r["aday"]) for r in aday)
    assert "read_config_2" not in text and "NetOpenSocket" not in text and "openSocket" not in text


def test_cok_abstentions_counted_not_packaged(tree):
    _amac, aday, key = _build_multi(tree)
    reasons = {}
    for v in key["ogeler"].values():
        for system, e in v["sistemler"].items():
            if e["durum"] == "cekimser":
                reasons[(v["gt"][0][1:], system)] = e["neden"]
                assert e["aday_id"] is None
    assert reasons == {
        ("net_send_packet", "sys_gemma"): "cekimser",
        ("cfg_lookup_key", "sys_karadul"): "jenerik",
        ("ui_draw_window", "sys_gemma"): "gecersiz",
        ("mem_alloc_block", "sys_qwen"): "ret",
        ("str_trim_space", "sys_karadul"): "bos",
        ("ui_beep", "sys_karadul"): "bos",
    }
    s = key["kunye"]["sayilar"]
    assert s["cekimser"] == 6 and s["cekimser_nedenleri"] == {"bos": 2, "cekimser": 1, "gecersiz": 1, "jenerik": 1, "ret": 1}
    assert key["kunye"]["sistem_sayilari"]["sys_karadul"] == {"aday": 9, "cekimser": 3, "satir": 12}
    shown = {r["aday"] for r in aday}
    assert not ({"fun_100001100", "render window", "render_window"} & shown)


def test_cok_order_is_seeded_and_mixed_across_functions(tree):
    a1, d1, k1 = _build_multi(tree, seed=5)
    a2, d2, k2 = _build_multi(tree, seed=5)
    assert (a1, d1, k1) == (a2, d2, k2)
    a3, d3, k3 = _build_multi(tree, seed=5, order_seed=99)
    pairs = lambda amac, aday, key: sorted((key["ogeler"][r["id"]]["addr"], r["aday"]) for r in aday)  # noqa: E731
    assert pairs(a1, d1, k1) == pairs(a3, d3, k3)
    assert [r["aday"] for r in d1] != [r["aday"] for r in d3]
    ids = [r["id"] for r in d1]
    assert ids != sorted(ids)  # satırlar fonksiyona göre gruplanmamış
    # fonksiyon id sırası adres sırası değil
    addrs = [int(k1["ogeler"][f]["addr"], 16) for f in sorted(k1["ogeler"])]
    assert addrs != sorted(addrs)


def test_cok_decoys(tree):
    amac, aday, key = _build_multi(tree)
    rows = {r["addr"]: r for r in _rows()}
    bodies = "\n".join(r["govde"] for r in amac)
    decoys = [(fid, a) for fid, v in key["ogeler"].items() for a in v["adaylar"].values() if a["yem"]]
    assert len(decoys) == 2  # 12 fonksiyonun %10'u, yukarı yuvarlanır
    others = {a["aday"] for v in key["ogeler"].values() for a in v["adaylar"].values() if not a["yem"]}
    for fid, a in decoys:
        item = key["ogeler"][fid]
        src = a["yem_kaynagi"]
        assert a["sistemler"] == [] and not a["tam"]
        assert a["aday"] == ep.normalize_name(src["aday_ad"])
        assert src["aday_dosya"] != item["dosya"]
        assert not (ep.name_tokens(src["aday_ad"]) & ep.name_tokens(item["gt"][0]))
        assert rows[src["aday_addr"]]["gt"] == [f"_{src['aday_ad']}"]
        assert src["aday_addr"] not in {v["addr"] for v in key["ogeler"].values()}
        assert not _word(src["aday_ad"], bodies) and a["aday"] not in others
    assert len({a["aday"] for _f, a in decoys}) == 2


def test_cok_decoy_seed_controls_targets(tree):
    seen = set()
    for ys in range(6):
        _a, _d, key = _build_multi(tree, decoy_seed=ys)
        seen.add(tuple(sorted(fid for fid, v in key["ogeler"].items() if any(a["yem"] for a in v["adaylar"].values()))))
    assert len(seen) > 1


def test_cok_address_list_validation(tree):
    root, _score, idx = tree
    cands, _ = ep.parse_candidates(_cand_records())
    ok = [int(_addr_of(g), 16) for g in MULTI]
    amac, _d, key = ep.build_multi_package(_rows(), idx, root, cands, binary="oyun", seed=1, addresses=ok[:5])
    assert len(amac) == 5 and key["kunye"]["orneklem_kaynagi"] == "adres_listesi"
    for bad, msg in ((0xdead, "puanlama satırlarında yok"),
                     (int(_addr_of("shared_helper"), 16), "gövde belirsiz"),
                     (int(_addr_of("tree_RB_NEXT"), 16), "gövde yok"),
                     (int(_addr_of("net_close_socket"), 16), "aday satırı yok")):
        with pytest.raises(ep.PaketHatasi, match=msg):
            ep.build_multi_package(_rows(), idx, root, cands, binary="oyun", seed=1, addresses=ok[:3] + [bad])


def test_cok_load_addresses_formats(tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("# örneklem\n0x100001000\n100001040  # yorum\n\n", encoding="utf-8")
    assert ep.load_addresses(p) == [0x100001000, 0x100001040]
    p.write_text(json.dumps(["0x10", "0x20"]), encoding="utf-8")
    assert ep.load_addresses(p) == [0x10, 0x20]
    p.write_text("0x10\n0x10\n", encoding="utf-8")
    with pytest.raises(ep.PaketHatasi, match="yinelenen"):
        ep.load_addresses(p)
    # G6 yem listesi biçimi: "program-adres"; yalnız eşleşen program alınır
    p.write_text(json.dumps(["oyun-10", "baska-20", "0x30"]), encoding="utf-8")
    assert ep.load_addresses(p, "oyun") == [0x10, 0x30]
    assert ep.load_addresses(p) == [0x10, 0x20, 0x30]


def test_cok_seeded_sample_from_candidate_file(tree):
    recs = _cand_records() + [{"addr": _addr_of("tree_RB_NEXT"), "sistem": "sys_qwen", "aday": "rb_next"},
                              {"addr": _addr_of("shared_helper"), "sistem": "sys_qwen", "aday": "helper_one"},
                              {"addr": "0xdead", "sistem": "sys_qwen", "aday": "ghost"}]
    _a, _d, key = _build_multi(tree, records=recs, sample_size=4)
    s = key["kunye"]
    assert s["sayilar"]["fonksiyon"] == 4 and s["orneklem_kaynagi"] == "tohumlu"
    assert s["sayilar"]["dislanan"] == {"govdesi_belirsiz": 1, "govdesi_bulunamayan": 1, "satirlarda_yok": 1}
    _a, _d, key0 = _build_multi(tree, records=recs, sample_size=0)
    assert key0["kunye"]["sayilar"]["fonksiyon"] == len(MULTI)


def test_cok_g6_aliases_and_program_filter():
    recs = [
        {"program": "tmux", "adres": "0x10", "kosul": "B", "model": "qwen38", "aday": "foo_bar",
         "cekimser": False, "durum": "gecerli", "guven_ort_logprob": -0.25},
        {"program": "tmux", "adres": "0x10", "kosul": "A0", "model": "karadul", "aday": None,
         "cekimser": False, "durum": "isimsiz", "guven_ort_logprob": None},
        {"program": "htop", "adres": "0x10", "kosul": "B", "model": "qwen38", "aday": "x"},
    ]
    cands, skipped = ep.parse_candidates(recs, program="tmux", confidence_field="guven_ort_logprob")
    assert skipped == 1
    assert [(c.addr, c.system, c.name, c.confidence, c.reason) for c in cands] == [
        (0x10, "qwen38/B", "foo_bar", -0.25, None), (0x10, "karadul/A0", None, None, "isimsiz")]


@pytest.mark.parametrize("rec, message", [
    ({"sistem": "s", "aday": "a"}, "adres alanı yok"),
    ({"addr": "0x1", "aday": "a"}, "sistem alanı yok"),
    ({"addr": "0x1", "sistem": "s"}, "'aday' alanı yok"),
    ({"addr": "0x1", "sistem": "s", "aday": 3}, "metin ya da null"),
    ({"addr": "0x1", "sistem": "s", "aday": "a", "cekimser": True}, "hem aday hem çekimser"),
    ({"addr": "0x1", "sistem": "s", "aday": "a", "guven": "yüksek"}, "güven sayı"),
    ({"addr": 16, "sistem": "s", "aday": "a"}, "hex metin"),
])
def test_cok_candidate_row_errors(rec, message):
    with pytest.raises(ep.PaketHatasi, match=message):
        ep.parse_candidates([rec])


def test_cok_duplicate_address_system_is_error():
    rec = {"addr": "0x1", "sistem": "s", "aday": "a"}
    with pytest.raises(ep.PaketHatasi, match="iki kez"):
        ep.parse_candidates([rec, dict(rec)])


def test_cok_leak_check_clean_and_tampered(tree):
    amac, aday, key = _build_multi(tree)
    errors, warnings = ep.leak_check_cok(amac, aday, key)
    assert errors == []
    def copy(x):
        return json.loads(json.dumps(x))

    other = next(r["id"] for r in aday if r["id"] != aday[0]["id"])
    fid, _item = _fn_by_gt(key, "cfg_load_file")
    cases = []
    t = copy(aday)
    t[0]["sistem"] = "sys_qwen"
    cases.append((amac, t, "yasak alan"))
    t = copy(aday)
    t[0]["aday"] = "baska_ad"
    cases.append((amac, t, "anahtarla uyuşmuyor"))
    t = copy(aday)
    t[0]["id"] = other
    cases.append((amac, t, "başka fonksiyona bağlı"))
    a = copy(amac)
    a[0]["id"] = a[0]["id"] + "-sys_qwen"
    cases.append((a, aday, "sistem adı sızıyor"))
    a = copy(amac)
    rec = next(r for r in a if r["id"] == fid)
    rec["govde"] = rec["govde"].replace("FONKSIYON", "cfg_load_file", 1)
    cases.append((a, aday, "kendi adı sızıyor"))
    for am, ad, msg in cases:
        errs, _w = ep.leak_check_cok(am, ad, key)
        assert any(msg in e for e in errs), (msg, errs)


def test_cok_cli_deterministic_and_sizinti_dispatch(tree, tmp_path, capsys):
    root, score, _idx = tree
    cand = tmp_path / "adaylar.jsonl"
    cand.write_text("".join(json.dumps(r) + "\n" for r in _cand_records()), encoding="utf-8")
    addrs = tmp_path / "adresler.txt"
    addrs.write_text("\n".join(_addr_of(g) for g in MULTI) + "\n", encoding="utf-8")
    outs = []
    for name in ("p1", "p2"):
        out = tmp_path / name
        rc = ep.main(["uret-cok", "--satirlar", str(score), "--kaynak", str(root), "--ikili", "oyun",
                      "--adaylar", str(cand), "--adresler", str(addrs), "--tohum", "3", "--cikti", str(out)])
        assert rc == 0
        outs.append(out)
    for n in ep.PAKET_DOSYALARI:
        assert (outs[0] / n).read_bytes() == (outs[1] / n).read_bytes()
    assert ep.main(["sizinti-denetimi", "--paket", str(outs[0])]) == 0
    lines = (outs[0] / ep.ADAY_DOSYASI).read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["sistem"] = "sys_qwen"
    lines[0] = json.dumps(first)
    (outs[0] / ep.ADAY_DOSYASI).write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert ep.main(["sizinti-denetimi", "--paket", str(outs[0])]) == 1
    capsys.readouterr()


def test_cok_decoy_candidate_must_not_appear_in_any_body(tmp_path):
    root = tmp_path
    defs = [("red_apple_pick", "x.c", "void\nred_apple_pick(void)\n{\n\tgreen_leaf_fold();\n}"),
            ("green_leaf_fold", "y.c", "void\ngreen_leaf_fold(void)\n{\n}"),
            ("stone_wall_build", "z.c", "void\nstone_wall_build(void)\n{\n}")]
    rows = _mem_rows([("red_apple_pick", "wrong", "pick"), ("green_leaf_fold", "unnamed", None),
                      ("stone_wall_build", "unnamed", None)])
    cands, _ = ep.parse_candidates([{"addr": rows[0]["addr"], "sistem": "s1", "aday": "pick_fruit"}])
    for seed in range(20):
        _a, _d, key = ep.build_multi_package(rows, _mem_idx(root, defs), root, cands, binary="t", seed=seed)
        (decoy,) = [a for v in key["ogeler"].values() for a in v["adaylar"].values() if a["yem"]]
        assert decoy["aday"] == "stone_wall_build"


def test_cok_explicit_decoy_targets(tree):
    targets = [int(_addr_of("ui_beep"), 16), int(_addr_of("cfg_load_file"), 16), int(_addr_of("str_hash_text"), 16)]
    _a, _d, key = _build_multi(tree, decoy_targets=targets)
    got = sorted(int(v["addr"], 16) for v in key["ogeler"].values() if any(a["yem"] for a in v["adaylar"].values()))
    assert got == sorted(targets) and key["kunye"]["yem_hedefi_kaynagi"] == "liste"
    with pytest.raises(ep.PaketHatasi, match="yem hedefi örneklemde yok"):
        _build_multi(tree, decoy_targets=[int(_addr_of("net_close_socket"), 16)])
