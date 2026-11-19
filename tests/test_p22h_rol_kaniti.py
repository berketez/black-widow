"""P22h kalem 4 — ``get_name_provenance`` P12b'nin ``string_roles``'unu "rol kanıtı, ad değil" etiketiyle gösterir.

Kilitlenen davranışlar:
  (a) satırlar köken dosyasından (``FUN_x`` ve ``FUN_x::yerel`` anahtarları), alan alan; etiket ve
      ``string_role_version`` yazılır; sayısal güven ve ``function_kebab_strings`` dışı alan sızmaz,
  (b) kayıt yoksa alan ``null`` ve ``missing`` nedenini söyler (uydurma yok); satırı olmayan fonksiyonda boş liste,
  (c) tavan ``PROVENANCE_ROLES_MAX`` ve ``truncated`` (sessiz kırpma yok),
  (d) körlük: aday ad sızmaz (dizginin tanımlayıcı biçimi ya da API'si gizli hedefin adıysa satır verilmez),
  (e) D kuralı korunur: rol satırındaki dizgiden kurulan ad önerisi D6 ``dizgiden_ad`` (model bunu ad kanıtı
      sayarsa denetim yakalar).

Gerçek model yok; sentetik çalışma alanı (``tests/test_lm_tools.py``). Mutasyon:
``scripts/measurement/mutation_specs_lm_kesif.json`` (``rk_*``).
"""
from __future__ import annotations

import json

from karadul.lm import guard
from karadul.lm import tools as T
from karadul.lm.tools import read_more as RM
from tests.test_lm_tools import build_ws, fun
from tests.test_lm_tools_v2 import X, call


def _ws(tmp_path, roles=None, version=1, drop_key=False):
    funcs = {X(i): {"calls": []} for i in range(1, 5)}
    names = {X(1): "monitor_activity", X(2): "options_get", X(3): "window_redraw"}
    prov = {X(1): {"new_name": "monitor_activity", "label": "doğrulanmadı", "confidence": 0.8,
                   "strategy": "string_context", "evidence": "monitor-activity"},
            X(2): {"new_name": "options_get", "label": "doğrulanmadı", "strategy": "callee_based"},
            X(3): {"new_name": "window_redraw", "label": "doğrulanmadı", "strategy": "callee_based"}}
    root = build_ws(tmp_path / "w", funcs, names=names, provenance=prov)
    pf = root / "reconstructed" / "src" / "naming_provenance.json"
    data = json.loads(pf.read_text())
    if not drop_key:
        data["string_roles"] = roles if roles is not None else {
            f"FUN_{X(1)}": [{"string": "monitor-activity", "role": "anahtar_erisimi", "api": f"FUN_{X(2)}",
                             "arg_index": 1, "api_distinct_strings": 60, "emitters": 2,
                             "function_kebab_strings": 2, "confidence": 0.9},
                            {"string": "window-renamed", "role": "olay_yayar", "api": "notify_hook",
                             "arg_index": 0, "api_distinct_strings": 12, "emitters": 1,
                             "function_kebab_strings": 2}],
            f"FUN_{X(3)}::param_1": [{"string": "pane-border", "role": "cagri_disi", "api": None,
                                      "arg_index": None, "api_distinct_strings": 0, "emitters": 0,
                                      "function_kebab_strings": 1}]}
        if version is not None:
            data["string_role_version"] = version
    pf.write_text(json.dumps(data), encoding="utf-8")
    return T.Workspace(root)


def prov(ws, a, **ctx):
    return call(ws, "get_name_provenance", {"addr": fun(a)}, **ctx)


def test_rol_kaniti_etiketle_ve_surumle(tmp_path):
    ws = _ws(tmp_path)
    d = prov(ws, X(1)).data
    assert d["string_roles_label"] == RM.STRING_ROLES_LABEL == "rol kanıtı, ad değil"
    assert d["string_role_version"] == 1 and d["string_roles_total"] == 2
    assert d["string_roles"] == [
        {"string": "monitor-activity", "role": "anahtar_erisimi", "api": f"FUN_{X(2)}", "arg_index": 1,
         "api_distinct_strings": 60, "emitters": 2},
        {"string": "window-renamed", "role": "olay_yayar", "api": "notify_hook", "arg_index": 0,
         "api_distinct_strings": 12, "emitters": 1}]
    env = json.dumps(prov(ws, X(1)).envelope(), ensure_ascii=False)
    assert "confidence" not in env and "0.9" not in env and "function_kebab_strings" not in env
    # Sınırlar modelin bunu ad kanıtı sanmamasını söyler.
    assert any("rol kanıtıdır, ad değildir" in s for s in prov(ws, X(1)).limits)
    # Yerel anahtar (``FUN_x::param_1``) fonksiyonun satırıdır; satırı olmayan fonksiyonda boş liste.
    assert prov(ws, X(3)).data["string_roles"][0]["string"] == "pane-border"
    bos = prov(ws, X(2)).data
    assert bos["string_roles"] == [] and bos["string_roles_total"] == 0
    assert bos["string_roles_label"] == "rol kanıtı, ad değil" and bos["missing"] == [
        "reconstructed/param_naming_map.json", "naming_provenance.json: role_evidence (bu çıktıda yok)"]


def test_kayit_yoksa_null_ve_neden(tmp_path):
    d = prov(_ws(tmp_path / "a", drop_key=True), X(1)).data
    assert d["string_roles"] is None and d["string_roles_total"] is None and d["string_roles_label"] is None
    assert d["string_role_version"] is None
    assert "naming_provenance.json: string_roles (bu çıktıda yok)" in d["missing"]
    d2 = prov(_ws(tmp_path / "b", version=None), X(1)).data
    assert d2["string_roles_total"] == 2 and d2["string_role_version"] is None     # sürüm yazılmamışsa uydurulmaz
    ws = _ws(tmp_path / "c")
    (ws.root / "reconstructed" / "src" / "naming_provenance.json").unlink()
    d3 = prov(T.Workspace(ws.root), X(1)).data
    assert d3["string_roles"] is None and d3["string_role_version"] is None


def test_tavan_ve_kirpma(tmp_path):
    rows = [{"string": f"opt-{i:02d}", "role": "anahtar_erisimi", "api": "options_get", "arg_index": 1,
             "api_distinct_strings": 40, "emitters": 0} for i in range(T.PROVENANCE_ROLES_MAX + 3)]
    r = prov(_ws(tmp_path, roles={f"FUN_{X(1)}": rows}), X(1))
    assert len(r.data["string_roles"]) == T.PROVENANCE_ROLES_MAX and r.data["string_roles_total"] == 13
    assert r.truncated == {"omitted": 3, "total": 13, "string_roles": 3}


def test_korluk_aday_ad_sizmaz(tmp_path):
    roles = {f"FUN_{X(2)}": [{"string": "window-redraw", "role": "olay_yayar", "api": "notify",
                              "arg_index": 0, "api_distinct_strings": 9, "emitters": 1},
                             {"string": "status-left", "role": "anahtar_erisimi", "api": "window_redraw",
                              "arg_index": 1, "api_distinct_strings": 40, "emitters": 0},
                             {"string": "status-right", "role": "anahtar_erisimi", "api": "options_get",
                              "arg_index": 1, "api_distinct_strings": 40, "emitters": 0}]}
    ws = _ws(tmp_path, roles=roles)
    acik = prov(ws, X(2)).data["string_roles"]
    assert [x["string"] for x in acik] == ["window-redraw", "status-left", "status-right"]
    kor = prov(ws, X(2), blind_target=X(3)).data          # gizli hedef: window_redraw
    assert [x["string"] for x in kor["string_roles"]] == ["status-right"]
    assert kor["string_roles_total"] == 1
    assert prov(ws, X(3), blind_target=X(3)).error == "arac_kapali"   # hedefin kendisi hâlâ kapalı


def test_d_kurali_rol_dizgisinden_ad_celiski(tmp_path):
    ws = _ws(tmp_path)
    env = prov(ws, X(1)).envelope()
    rep = guard.check_proposal({"isim": "window_renamed", "gerekce": "Olay yayar.", "cekimser": False,
                                "kanit": [env["id"]]}, [env], target=X(1), target_tag=ws.name_tag(X(1)),
                               existing_functions={}, own_ghidra_name=fun(X(1)), assigned_names={},
                               related=[X(1)], empty_content=False, library=frozenset())
    assert rep.verdict == guard.VERDICT_CONFLICT
    assert any(f.rule == "D6" and f.code == guard.CODE_FROM_STRING for f in rep.findings)
