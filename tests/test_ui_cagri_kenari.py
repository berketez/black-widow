"""Arayüzün çağrı kenarları Ghidra çağrı grafiğinden; adres başvurusu çağrı sayılmaz.

Envanter (docs/arge/2026-11-11_fonksiyon_karti/envanter.md §2): eski ``build_model`` decompile
metninde geçen her ``FUN_`` adını çağrı sayıyordu; adresi yalnız alınan fonksiyon (geri çağrı kaydı,
tablo) "çağıran" görünüyordu. Bu testler sahte bir çalışma alanında şunları sınar:

* çağrı grafiğinde kenar varsa çağrıdır (metinde adı geçmese de);
* metinde adı geçip grafikte kenarı olmayan başvuru ``addr_refs``'e gider, sayaçlara girmez;
* grafik yok, bozuk ya da başka koşunun grafiğiyse metin yöntemine düşülür ve
  ``calls_source == "text"`` olur (sessiz geri düşüş yok);
* kanıt paketindeki çağıranlar gerçek çağrılardan gelir;
* arayüz metin kipinde listeyi "metinde adı geçenler" diye etiketler.

Ghidra ÇAĞIRMAZ, ağ KULLANMAZ.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
_INDEX_HTML = _ROOT / "ui" / "index.html"

A, B, C, D = "FUN_00101000", "FUN_00102000", "FUN_00103000", "FUN_00104000"


@pytest.fixture(scope="module")
def srv():
    spec = importlib.util.spec_from_file_location("bw_ui_server_cagri", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _graph(edges: list[tuple[str, str]], extra_nodes: tuple[str, ...] = ()) -> dict:
    """Ghidra ``ghidra_call_graph.json`` biçimi: adrese anahtarlı düğümler + kenar listesi."""
    addrs = {a for e in edges for a in e} | set(extra_nodes)
    nodes = {}
    for a in sorted(addrs):
        nodes[a] = {
            "name": f"FUN_{a}", "address": a,
            "callers": [{"name": f"FUN_{s}", "address": s} for s, d in edges if d == a],
            "callees": [{"name": f"FUN_{d}", "address": d} for s, d in edges if s == a],
        }
    return {"program": "t", "total_functions": len(nodes), "total_edges": len(edges),
            "nodes": nodes,
            "edges": [{"from": s, "to": d, "from_name": f"FUN_{s}", "to_name": f"FUN_{d}"}
                      for s, d in edges]}


def _make_ws(root: Path, graph=None, *, raw_graph: str | None = None) -> Path:
    """A: B'yi çağırır, C'nin adresini geri çağrı olarak kaydeder. D: yalnız grafikte A'yı çağırır."""
    src = root / "reconstructed" / "src"
    src.mkdir(parents=True)
    (src / "naming_map.json").write_text(json.dumps({"global": {}}), encoding="utf-8")
    dec = root / "static" / "ghidra_output" / "decompiled"
    dec.mkdir(parents=True)
    (dec / f"{A}.c").write_text(
        f"void {A}(void)\n{{\n  {B}();\n  register_callback({C});\n  return;\n}}\n",
        encoding="utf-8")
    (dec / f"{B}.c").write_text(f"int {B}(void)\n{{\n  return 1;\n}}\n", encoding="utf-8")
    (dec / f"{C}.c").write_text(f"void {C}(int x)\n{{\n  return;\n}}\n", encoding="utf-8")
    # D'nin metninde A geçmiyor (Ghidra kuyruk çağrısını düz atlama olarak yazmış olabilir)
    (dec / f"{D}.c").write_text(f"void {D}(void)\n{{\n  return;\n}}\n", encoding="utf-8")
    if raw_graph is not None:
        (root / "static" / "ghidra_call_graph.json").write_text(raw_graph, encoding="utf-8")
    elif graph is not None:
        (root / "static" / "ghidra_call_graph.json").write_text(
            json.dumps(graph), encoding="utf-8")
    return root


def _model(srv, ws: Path) -> dict:
    srv._CACHE.clear()
    srv.activate_workspace(str(ws))
    m = srv.build_model()
    assert m is not None
    return m


_EDGES = [("00101000", "00102000"), ("00104000", "00101000"),
          # ithale giden kenar: arayüzde düğüm değil, yok sayılır
          ("00101000", "00109000")]


def test_adres_basvurusu_cagri_sayilmaz(srv, tmp_path):
    m = _model(srv, _make_ws(tmp_path / "ws", _graph(_EDGES)))
    assert m["calls_source"] == "ghidra_call_graph"
    assert m["calls"][A] == [B]
    assert m["addr_refs"] == {A: [C]}
    by = {f["addr"]: f for f in m["functions"]}
    assert by[C]["in"] == 0            # adresi alınan C'nin çağıranı yok
    assert by[A]["out"] == 1 and by[A]["in"] == 1
    assert by[B]["in"] == 1


def test_grafikte_olan_kenar_metinde_gecmese_de_cagri(srv, tmp_path):
    m = _model(srv, _make_ws(tmp_path / "ws", _graph(_EDGES)))
    assert m["calls"][D] == [A]
    assert D not in (m["addr_refs"] or {})


def test_kanit_paketinde_caginanlar_gercek_cagri(srv, tmp_path):
    _model(srv, _make_ws(tmp_path / "ws", _graph(_EDGES)))
    ev_c = srv._evidence(C)
    assert ev_c["calls_source"] == "ghidra_call_graph"
    assert ev_c["callers"] == []
    ev_a = srv._evidence(A)
    assert [x["addr"] for x in ev_a["callers"]] == [D]
    assert [x["addr"] for x in ev_a["callees"]] == [B]


def test_yalniz_dugum_bicimi_de_okunur(srv, tmp_path):
    g = _graph(_EDGES)
    del g["edges"]
    m = _model(srv, _make_ws(tmp_path / "ws", g))
    assert m["calls_source"] == "ghidra_call_graph"
    assert m["calls"][A] == [B] and m["calls"][D] == [A]


def test_mac_adres_bicimi(srv, tmp_path):
    """Mac'te adres sıfır dolgusuz 9 hane (100001780); FUN_ dosya adıyla birebir eşleşir."""
    ws = tmp_path / "ws"
    src = ws / "reconstructed" / "src"
    src.mkdir(parents=True)
    (src / "naming_map.json").write_text(json.dumps({"global": {}}), encoding="utf-8")
    dec = ws / "static" / "ghidra_output" / "decompiled"
    dec.mkdir(parents=True)
    (dec / "FUN_100001780.c").write_text("void FUN_100001780(void){ FUN_100001784(); }\n")
    (dec / "FUN_100001784.c").write_text("void FUN_100001784(void){ }\n")
    (ws / "static" / "ghidra_call_graph.json").write_text(
        json.dumps(_graph([("100001780", "100001784")])))
    m = _model(srv, ws)
    assert m["calls_source"] == "ghidra_call_graph"
    assert m["calls"]["FUN_100001780"] == ["FUN_100001784"]


def test_grafik_yoksa_metin_yontemi_isaretli(srv, tmp_path):
    m = _model(srv, _make_ws(tmp_path / "ws", None))
    assert m["calls_source"] == "text"
    assert m["addr_refs"] is None
    assert m["calls"][A] == [B, C]        # eski davranış: metinde geçen her FUN_
    ev = srv._evidence(C)
    assert ev["calls_source"] == "text"
    assert [x["addr"] for x in ev["callers"]] == [A]


def test_bozuk_grafik_metin_yontemine_duser(srv, tmp_path):
    m = _model(srv, _make_ws(tmp_path / "ws", raw_graph="{bozuk"))
    assert m["calls_source"] == "text"
    assert m["calls"][A] == [B, C]


def test_baska_kosunun_grafigi_metin_yontemine_duser(srv, tmp_path):
    """Grafiğin hiçbir düğümü bu decompile dizininin fonksiyonu değilse grafik kullanılmaz."""
    m = _model(srv, _make_ws(tmp_path / "ws", _graph([("00505000", "00506000")])))
    assert m["calls_source"] == "text"


def test_bicimsiz_grafik_metin_yontemine_duser(srv, tmp_path):
    m = _model(srv, _make_ws(tmp_path / "ws", {"program": "t", "nodes": [], "edges": "x"}))
    assert m["calls_source"] == "text"


def test_giris_fonksiyonu_gercek_cagrilardan(srv, tmp_path):
    """En çok çağıran (giriş odağı): metinde A 2 FUN_ anar ama yalnız 1 çağrısı var.

    Grafikte D, B ve C'yi çağırsın: gerçek çağrıda D (2) > A (1).
    """
    edges = [("00101000", "00102000"), ("00104000", "00102000"), ("00104000", "00103000")]
    m = _model(srv, _make_ws(tmp_path / "ws", _graph(edges)))
    assert m["entry"] == D


def test_arayuz_metin_kipini_etiketliyor():
    html = _INDEX_HTML.read_text(encoding="utf-8")
    assert "MODEL.calls_source==='text'" in html
    assert "j.calls_source==='text'" in html
    assert "METİNDE ADI GEÇENLER" in html
    assert "metninde adı geçen" in html


# ---------------------------------------------------------------------------
# Teşhis: "imza eşleşmesi yok" yalnız gerçekten aday yokken (envanter §2, Hata B)
# ---------------------------------------------------------------------------
_NO_SIG = "Uygulanabilir imza/parmak izi eşleşmesi yok"
_WEAK_NO_SIG = "Yalnızca zayıf/adres-sonekli isim — kesin imza eşleşmesi yok"


def _sig_ws(root: Path, originals: list[str] | None) -> Path:
    ws = _make_ws(root, _graph(_EDGES))
    if originals is not None:
        (ws / "reconstructed" / "signature_matches.json").write_text(json.dumps(
            {"total": len(originals),
             "matches": [{"original": o, "matched": "strlen", "library": "libc",
                          "confidence": 0.9, "purpose": ""} for o in originals]}),
            encoding="utf-8")
    return ws


def _diag(srv, ws: Path, addr: str, cls: str = "unnamed") -> dict:
    srv._CACHE.clear()
    srv.activate_workspace(str(ws))
    return srv._naming_diagnosis(addr, "", {}, cls)


def test_imza_adayi_varken_eslesme_yok_yazilmaz(srv, tmp_path):
    d = _diag(srv, _sig_ws(tmp_path / "ws", [C, "entry"]), C)
    assert _NO_SIG not in d["signals"]
    assert not any("imza" in s for s in d["signals"])   # yerine yeni iddia da yok


def test_imza_adayi_yokken_eslesme_yok_yazilir(srv, tmp_path):
    d = _diag(srv, _sig_ws(tmp_path / "ws", ["entry"]), C)
    assert _NO_SIG in d["signals"]


def test_imza_kaydi_okunamiyorsa_eslesme_yok_yazilmaz(srv, tmp_path):
    d = _diag(srv, _sig_ws(tmp_path / "ws", None), C)
    assert _NO_SIG not in d["signals"]


def test_zayif_adda_aday_varken_kesin_eslesme_yok_yazilmaz(srv, tmp_path):
    ws = _sig_ws(tmp_path / "ws", [C])
    assert _diag(srv, ws, C, "weak")["signals"][0] == "Yalnızca zayıf/adres-sonekli isim"
    assert _WEAK_NO_SIG in _diag(srv, ws, B, "weak")["signals"]


def test_imza_adayi_karari_degistirmez(srv, tmp_path):
    with_c = _diag(srv, _sig_ws(tmp_path / "a", [C]), C)
    without = _diag(srv, _sig_ws(tmp_path / "b", []), C)
    assert with_c["verdict"] == without["verdict"]
    assert with_c["reason"] == without["reason"]
