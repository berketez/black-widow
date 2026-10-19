"""scripts/measurement/etiket_puan.py — kör etiket puanlayıcısının birim testleri.

Sentetik anahtar ve etiket dosyalarıyla kilitlenen davranışlar:
  (a) Wilson aralığı bilinen değerleri verir,
  (b) program başına oranlar; ``tam`` anahtardan (tp) gelir, tp olmayana verilen
      ``tam`` doğru tarif sayılır; yemler ana sayılara girmez, kabul oranı ayrı,
  (c) eksik/fazla/yinelenen id, geçersiz etiket, boş amaç ve aday sonrası
      değişen amaç açık hatadır,
  (d) bootstrap aynı tohumla aynı, farklı tohumla farklı sonuç verir,
  (e) cömertlik farkı ve uyuşmazlık çiftleri doğru sayılır; anahtarlar aynı
      öğeleri anlatmıyorsa hata verilir,
  (f) etiket_paketi.py'nin ürettiği anahtar doğrudan okunur,
  (g) ``--capraz-atifsiz``: gerçek adı başka gövdede geçen öğeler (ana ve yem)
      dışarıda bırakılarak oranlar yeniden hesaplanır; ``yem_toplam`` bütün
      paketlerin yemlerini birleştirir.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_MEAS = Path(__file__).resolve().parents[1] / "scripts" / "measurement"


def _load(name: str, fname: str):
    spec = importlib.util.spec_from_file_location(name, _MEAS / fname)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ept = _load("etiket_puan_under_test", "etiket_puan.py")
epk = _load("etiket_paketi_for_puan_test", "etiket_paketi.py")


def _item(status, *, yem=False, n=0, capraz=0):
    return {"addr": f"0x{0x1000 + n:x}", "gt": [f"_fn_{n}"], "pred": None if yem else f"pred_{n}",
            "status": None if yem else status, "aday": f"aday_{n}", "yem": yem, "yem_kaynagi": None,
            "capraz_atif": capraz}


def _key_doc(program: str, items: dict, kip: str = "kor") -> dict:
    return {"kunye": {"sema": epk.PAKET_SEMASI, "program": program, "kip": kip}, "ogeler": items}


def _write_json(path: Path, obj) -> Path:
    path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    return path


def _write_jsonl(path: Path, recs) -> Path:
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in recs), encoding="utf-8")
    return path


def _lab(iid: str, etiket: str, amac: str = "bir şey yapar") -> dict:
    return {"id": iid, "amac": amac, "etiket": etiket, "gerekce": "g"}


# --- Wilson -------------------------------------------------------------------------------------

def test_wilson_known_values():
    lo, hi = ept.wilson(10, 20)
    assert lo == pytest.approx(0.299298, abs=1e-6) and hi == pytest.approx(0.700702, abs=1e-6)
    lo, hi = ept.wilson(1, 10)
    assert lo == pytest.approx(0.017876, abs=1e-6) and hi == pytest.approx(0.404150, abs=1e-6)
    z2 = ept.z_degeri() ** 2
    assert ept.wilson(0, 20) == (0.0, pytest.approx(z2 / (20 + z2)))  # 0/20 -> üst ~%16,1
    assert ept.wilson(20, 20)[0] == pytest.approx(20 / (20 + z2))
    assert ept.wilson(0, 73) == (0.0, pytest.approx(0.049992, abs=1e-6))  # uçlar kesin 0 ve 1
    assert ept.wilson(5, 5)[1] == 1.0
    with pytest.raises(ept.PuanHatasi):
        ept.wilson(0, 0)


# --- puan ---------------------------------------------------------------------------------------

@pytest.fixture
def scored_inputs():
    items = {
        "p-000": _item("tp", n=0),     # tp + yanlis -> tam (tutarsızlık)
        "p-001": _item("tp", n=1),     # tp + dogru_tarif -> tam
        "p-002": _item("wrong", n=2),  # wrong + tam -> dogru_tarif
        "p-003": _item("wrong", n=3),  # dogru_tarif
        "p-004": _item("wrong", n=4),  # yalniz_alan
        "p-005": _item("wrong", n=5),  # yanlis
        "p-006": _item("wrong", n=6),  # yanlis
        "p-007": _item(None, yem=True, n=7),  # yem kabul (dogru_tarif)
        "p-008": _item(None, yem=True, n=8),  # yem ret
    }
    labels = [_lab("p-000", "yanlis"), _lab("p-001", "dogru_tarif"), _lab("p-002", "tam"),
              _lab("p-003", "dogru_tarif"), _lab("p-004", "yalniz_alan"), _lab("p-005", "yanlis"),
              _lab("p-006", "yanlis"), _lab("p-007", "dogru_tarif"), _lab("p-008", "yanlis")]
    return items, labels


def test_score_rates_tam_from_key_and_decoys_separate(tmp_path, scored_inputs):
    items, labels = scored_inputs
    keys = ept.load_keys([_write_json(tmp_path / "k.json", _key_doc("prog", items))])
    res = ept.score(ept.load_labels([_write_jsonl(tmp_path / "e.jsonl", labels)]), keys)
    r = res["programlar"]["prog"]
    assert r["n"] == 7 and r["kip"] == "kor"
    o = r["oranlar"]
    assert (o["tam"]["k"], o["yakin"]["k"], o["yalniz_alan"]["k"], o["yanlis"]["k"]) == (2, 4, 1, 2)
    assert o["yakin"]["oran"] == round(4 / 7, 6)
    lo, hi = ept.wilson(4, 7)
    assert (o["yakin"]["alt"], o["yakin"]["ust"]) == (round(lo, 6), round(hi, 6))
    assert r["ham_etiketler"] == {"tam": 1, "dogru_tarif": 2, "yalniz_alan": 1, "yanlis": 3}
    assert r["tutarlilik"] == {"tp_yakin_disi": ["p-000"], "tam_ama_tp_degil": ["p-002"]}
    assert r["yem"]["n"] == 2 and r["yem"]["kabul"]["k"] == 1 and r["yem"]["kabul_edilen"] == ["p-007"]


def test_capraz_atifsiz_drops_cross_referenced_items(tmp_path):
    items = {
        "p-000": _item("wrong", n=0, capraz=2),     # dışarıda (yakın)
        "p-001": _item("wrong", n=1),               # yanlis
        "p-002": _item("wrong", n=2),               # dogru_tarif
        "p-003": _item("tp", n=3, capraz=1),        # dışarıda (tam)
        "p-004": _item(None, yem=True, n=4, capraz=1),  # dışarıda (kabul)
        "p-005": _item(None, yem=True, n=5),        # ret
    }
    labels = [_lab("p-000", "dogru_tarif"), _lab("p-001", "yanlis"), _lab("p-002", "dogru_tarif"),
              _lab("p-003", "dogru_tarif"), _lab("p-004", "tam"), _lab("p-005", "yanlis")]
    keys = ept.load_keys([_write_json(tmp_path / "k.json", _key_doc("prog", items))])
    lab = ept.load_labels([_write_jsonl(tmp_path / "e.jsonl", labels)])
    full = ept.score(lab, keys)["programlar"]["prog"]
    assert (full["n"], full["oranlar"]["yakin"]["k"], full["yem"]["n"], full["yem"]["kabul"]["k"]) == (4, 3, 2, 1)
    res = ept.score(lab, keys, capraz_atifsiz=True)
    r = res["programlar"]["prog"]
    assert res["capraz_atifsiz"] is True
    assert r["dislanan_capraz_atifli"] == {"ana": 2, "yem": 1}
    assert (r["n"], r["oranlar"]["yakin"]["k"], r["oranlar"]["tam"]["k"]) == (2, 1, 0)
    assert (r["yem"]["n"], r["yem"]["kabul"]["k"]) == (1, 0)
    assert res["yem_toplam"]["n"] == 1


def test_capraz_atifsiz_needs_field_in_key(tmp_path):
    items = {"p-000": _item("wrong", n=0), "p-001": _item(None, yem=True, n=1)}
    del items["p-000"]["capraz_atif"]
    keys = ept.load_keys([_write_json(tmp_path / "k.json", _key_doc("prog", items))])
    lab = ept.load_labels([_write_jsonl(tmp_path / "e.jsonl", [_lab("p-000", "yanlis"), _lab("p-001", "yanlis")])])
    assert ept.score(lab, keys)["programlar"]["prog"]["n"] == 1
    with pytest.raises(ept.PuanHatasi, match="capraz_atif"):
        ept.score(lab, keys, capraz_atifsiz=True)


def test_yem_toplam_pools_all_packages(tmp_path):
    k1 = _write_json(tmp_path / "a.json", _key_doc("a", {
        "a-000": _item("wrong", n=0), "a-001": _item(None, yem=True, n=1), "a-002": _item(None, yem=True, n=2)}))
    k2 = _write_json(tmp_path / "b.json", _key_doc("b", {
        "b-000": _item("wrong", n=3), "b-001": _item(None, yem=True, n=4)}))
    e = _write_jsonl(tmp_path / "e.jsonl", [_lab("a-000", "yanlis"), _lab("a-001", "dogru_tarif"),
                                            _lab("a-002", "yanlis"), _lab("b-000", "yanlis"),
                                            _lab("b-001", "tam")])
    res = ept.score(ept.load_labels([e]), ept.load_keys([k1, k2]))
    assert res["yem_toplam"]["n"] == 3 and res["yem_toplam"]["kabul"]["k"] == 2
    lo, hi = ept.wilson(2, 3)
    assert (res["yem_toplam"]["kabul"]["alt"], res["yem_toplam"]["kabul"]["ust"]) == (round(lo, 6), round(hi, 6))


def test_final_label_rules():
    assert ept.final_label({"yem": False, "status": "tp"}, "yanlis") == "tam"
    assert ept.final_label({"yem": False, "status": "wrong"}, "tam") == "dogru_tarif"
    assert ept.final_label({"yem": False, "status": "wrong"}, "yalniz_alan") == "yalniz_alan"
    assert ept.final_label({"yem": True, "status": None}, "tam") == "tam"


def test_scores_each_program_separately(tmp_path):
    k1 = _write_json(tmp_path / "a.json", _key_doc("a", {"a-000": _item("wrong", n=0), "a-001": _item(None, yem=True, n=1)}))
    k2 = _write_json(tmp_path / "b.json", _key_doc("b", {"b-000": _item("tp", n=2), "b-001": _item(None, yem=True, n=3)}))
    e = _write_jsonl(tmp_path / "e.jsonl", [_lab("a-000", "yanlis"), _lab("a-001", "yanlis"),
                                            _lab("b-000", "yanlis"), _lab("b-001", "tam")])
    res = ept.score(ept.load_labels([e]), ept.load_keys([k1, k2]))
    assert res["programlar"]["a"]["oranlar"]["yanlis"]["k"] == 1
    assert res["programlar"]["b"]["oranlar"]["tam"]["k"] == 1
    assert res["programlar"]["b"]["yem"]["kabul"]["k"] == 1


@pytest.mark.parametrize("mutate, message", [
    (lambda labs: labs.pop(), "eksik 1 id"),
    (lambda labs: labs.append(_lab("p-999", "yanlis")), "fazla 1 id"),
    (lambda labs: labs.append(dict(labs[0])), "iki kez"),
    (lambda labs: labs[0].update(etiket="yanlış"), "geçersiz etiket"),
    (lambda labs: labs[0].update(etiket="Yanlis"), "geçersiz etiket"),
    (lambda labs: labs[0].update(amac="  "), "amaç cümlesi boş"),
    (lambda labs: labs[0].pop("gerekce"), "eksik alan"),
])
def test_label_errors_are_explicit(tmp_path, scored_inputs, mutate, message):
    items, labels = scored_inputs
    mutate(labels)
    keys = ept.load_keys([_write_json(tmp_path / "k.json", _key_doc("prog", items))])
    with pytest.raises(ept.PuanHatasi, match=message):
        ept.score(ept.load_labels([_write_jsonl(tmp_path / "e.jsonl", labels)]), keys)


def test_amac_must_match_stage_one(tmp_path, scored_inputs):
    items, labels = scored_inputs
    stage1 = _write_jsonl(tmp_path / "amac.jsonl", [{"id": x["id"], "amac": x["amac"]} for x in labels])
    lab = ept.load_labels([_write_jsonl(tmp_path / "e.jsonl", labels)])
    ept.check_amac_unchanged(lab, ept.load_stage1([stage1]))
    labels[3]["amac"] = "aday görülünce değişti"
    lab = ept.load_labels([_write_jsonl(tmp_path / "e2.jsonl", labels)])
    with pytest.raises(ept.PuanHatasi, match="değişmiş: p-003"):
        ept.check_amac_unchanged(lab, ept.load_stage1([stage1]))


def test_cli_puan_writes_json_and_fails_on_bad_label(tmp_path, scored_inputs, capsys):
    items, labels = scored_inputs
    k = _write_json(tmp_path / "k.json", _key_doc("prog", items))
    e = _write_jsonl(tmp_path / "e.jsonl", labels)
    out = tmp_path / "puan.json"
    assert ept.main(["puan", "--anahtar", str(k), "--etiket", str(e), "--cikti", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["programlar"]["prog"]["n"] == 7
    labels[0]["etiket"] = "belki"
    e2 = _write_jsonl(tmp_path / "e2.jsonl", labels)
    assert ept.main(["puan", "--anahtar", str(k), "--etiket", str(e2)]) == 2
    assert "geçersiz etiket" in capsys.readouterr().err


# --- bootstrap ve cömertlik -------------------------------------------------------------------

def test_bootstrap_is_deterministic_and_seed_sensitive():
    d = [(1, 0, 0, -1, 1, 1, 0, 0, 1, 0, 0, 1, -1, 0, 1, 0, 1)[i % 17] for i in range(200)]
    a = ept.bootstrap_fark(d, tohum=3, tekrar=999)
    assert a == ept.bootstrap_fark(d, tohum=3, tekrar=999)
    assert len({ept.bootstrap_fark(d, tohum=s, tekrar=999) for s in range(1, 6)}) > 1
    mean = sum(d) / len(d)
    assert a[0] < mean < a[1]
    assert ept.bootstrap_fark([0] * 10, tohum=1, tekrar=100) == (0.0, 0.0)
    with pytest.raises(ept.PuanHatasi):
        ept.bootstrap_fark([], tohum=1)


def test_percentile_interpolates():
    vals = [0.0, 1.0, 2.0, 3.0, 4.0]
    assert ept._yuzdelik(vals, 0.5) == 2.0
    assert ept._yuzdelik(vals, 0.1) == pytest.approx(0.4)


def _pair_keys(tmp_path, items):
    kg = ept.load_keys([_write_json(tmp_path / "kg.json", _key_doc("prog", items, kip="gt_goster"))])
    kk = ept.load_keys([_write_json(tmp_path / "kk.json", _key_doc("prog", items, kip="kor"))])
    return kg, kk


def test_comertlik_difference_and_discordant_pairs(tmp_path):
    items = {f"p-{i:03d}": _item("wrong", n=i) for i in range(10)}
    items["p-010"] = _item(None, yem=True, n=10)
    kg, kk = _pair_keys(tmp_path, items)
    gt_yakin = {0, 1, 2, 3, 4, 5, 6}       # 7/10
    kor_yakin = {0, 1, 2, 7}               # 4/10; 3 ortak, 4 yalnız gt'li, 1 yalnız gt'siz
    lab_gt = [_lab(f"p-{i:03d}", "dogru_tarif" if i in gt_yakin else "yanlis") for i in range(10)]
    lab_kor = [_lab(f"p-{i:03d}", "dogru_tarif" if i in kor_yakin else "yalniz_alan") for i in range(10)]
    lab_gt.append(_lab("p-010", "dogru_tarif"))
    lab_kor.append(_lab("p-010", "yanlis"))
    res = ept.comertlik(ept.load_labels([_write_jsonl(tmp_path / "g.jsonl", lab_gt)]),
                        ept.load_labels([_write_jsonl(tmp_path / "k.jsonl", lab_kor)]),
                        kg, kk, tohum=5, tekrar=3000)
    t = res["toplam"]
    assert t["n"] == 10
    assert t["fark"] == pytest.approx(0.3)
    assert t["ciftler"] == {"ikisi_yakin": 3, "yalniz_gtli_yakin": 4, "yalniz_gtsiz_yakin": 1, "ikisi_yakin_degil": 2}
    assert (t["yakin_gtli"]["k"], t["yakin_gtsiz"]["k"]) == (7, 4)
    assert t["fark_alt"] <= 0.3 <= t["fark_ust"]
    assert (res["yem"]["gtli"]["k"], res["yem"]["gtsiz"]["k"]) == (1, 0)
    again = ept.comertlik(ept.load_labels([tmp_path / "g.jsonl"]), ept.load_labels([tmp_path / "k.jsonl"]),
                          kg, kk, tohum=5, tekrar=3000)
    assert again == res


def test_cli_comertlik_prints_and_writes(tmp_path, capsys):
    items = {f"p-{i:03d}": _item("wrong", n=i) for i in range(6)}
    items["p-006"] = _item(None, yem=True, n=6)
    kg = _write_json(tmp_path / "kg.json", _key_doc("prog", items, kip="gt_goster"))
    kk = _write_json(tmp_path / "kk.json", _key_doc("prog", items, kip="kor"))
    eg = _write_jsonl(tmp_path / "eg.jsonl", [_lab(i, "dogru_tarif") for i in items])
    ek = _write_jsonl(tmp_path / "ek.jsonl", [_lab(i, "yanlis") for i in items])
    out = tmp_path / "c.json"
    rc = ept.main(["comertlik", "--anahtar-gtli", str(kg), "--etiket-gtli", str(eg),
                   "--anahtar-gtsiz", str(kk), "--etiket-gtsiz", str(ek),
                   "--tohum", "3", "--tekrar", "200", "--cikti", str(out)])
    assert rc == 0
    printed = capsys.readouterr().out
    assert "fark (gt'li − gt'siz): +100,0 puan" in printed
    res = json.loads(out.read_text(encoding="utf-8"))
    assert res["toplam"]["fark"] == 1.0 and res["bootstrap"] == {"tohum": 3, "tekrar": 200}
    # kipler ters verilirse açık hata
    assert ept.main(["comertlik", "--anahtar-gtli", str(kk), "--etiket-gtli", str(eg),
                     "--anahtar-gtsiz", str(kg), "--etiket-gtsiz", str(ek)]) == 2


def test_comertlik_capraz_atifsiz(tmp_path):
    items = {f"p-{i:03d}": _item("wrong", n=i, capraz=1 if i < 2 else 0) for i in range(6)}
    items["p-006"] = _item(None, yem=True, n=6)
    kg, kk = _pair_keys(tmp_path, items)
    lab_gt = ept.load_labels([_write_jsonl(tmp_path / "g.jsonl", [_lab(i, "dogru_tarif") for i in items])])
    lab_kor = ept.load_labels([_write_jsonl(tmp_path / "k.jsonl", [_lab(i, "yanlis") for i in items])])
    res = ept.comertlik(lab_gt, lab_kor, kg, kk, tohum=1, tekrar=200, capraz_atifsiz=True)
    assert res["dislanan_capraz_atifli"] == {"ana": 2, "yem": 0}
    assert res["toplam"]["n"] == 4 and res["programlar"]["prog"]["n"] == 4


def test_comertlik_rejects_mismatched_keys(tmp_path):
    items = {f"p-{i:03d}": _item("wrong", n=i) for i in range(4)}
    kg, kk = _pair_keys(tmp_path, items)
    labs = ept.load_labels([_write_jsonl(tmp_path / "e.jsonl", [_lab(i, "yanlis") for i in items])])
    other = dict(items)
    other["p-000"] = {**items["p-000"], "aday": "baska"}
    kg2 = ept.load_keys([_write_json(tmp_path / "kg2.json", _key_doc("prog", other, kip="gt_goster"))])
    with pytest.raises(ept.PuanHatasi, match="öğe farklı"):
        ept.comertlik(labs, labs, kg2, kk)
    with pytest.raises(ept.PuanHatasi, match="gt_goster"):
        ept.comertlik(labs, labs, kk, kk)
    with pytest.raises(ept.PuanHatasi, match="kör kipte"):
        ept.comertlik(labs, labs, kg, kg)


# --- paket anahtarıyla uyum -------------------------------------------------------------------

def test_reads_key_written_by_etiket_paketi(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    names = ["alpha_open_door", "beta_close_gate", "gamma_read_book", "delta_write_note",
             "eps_sort_list", "zeta_hash_word"]
    rows = []
    for i, name in enumerate(names):
        (root / f"m{i}.c").write_text(f"int\n{name}(void)\n{{\n\treturn {i};\n}}\n", encoding="utf-8")
        rows.append({"addr": f"0x{0x2000 + 16 * i:x}", "gt": [f"_{name}"],
                     "pred": name if i < 2 else f"guess_{i}", "status": "tp" if i < 2 else "wrong"})
    amac, aday, key = epk.build_package(rows, epk.index_tree(root), root, binary="mini", sample_size=4, seed=9)
    epk.write_package(tmp_path / "pkg", amac, aday, key)
    keys = ept.load_keys([tmp_path / "pkg" / epk.ANAHTAR_DOSYASI])
    labs = ept.load_labels([_write_jsonl(tmp_path / "e.jsonl", [_lab(r["id"], "yanlis") for r in aday])])
    res = ept.score(labs, keys)["programlar"]["mini"]
    n_tp = sum(1 for v in key["ogeler"].values() if v["status"] == "tp")
    assert res["n"] == 4 and res["yem"]["n"] == 1
    assert res["oranlar"]["tam"]["k"] == n_tp
