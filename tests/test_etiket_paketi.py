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
