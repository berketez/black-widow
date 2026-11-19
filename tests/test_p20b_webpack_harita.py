"""P20b kalem 1 — webpack modül haritası yalnız çalışma zamanına bağlıysa sayılır.

Önce (39aca9c): `smart-webpack-unpack.mjs` her IIFE'nin nesne / dizi argümanını
"modül haritası" sayıyordu. Electron Fiddle 0.39.0 `.webpack/main/index.js`
(webpack 5, 2,9 MB) üstünde bağımsız sayım (`scripts/measurement/p20b_webpack_say.mjs`)
915 modül buluyor; betik 10 "modül" çıkarıyordu, 10'u da uydurma (bir Prisma
enstrümantasyon nesnesinin `then`, `catch`, `VERSION`, `NAME` … özellikleri),
915'i eksik. `renderer/816` (webpack 5 JSONP öbeği, 1 modül) üstünde 17 "modül"
çıkıyordu: modülün içindeki iki paketlenmiş kütüphanenin dizilerinden, çakışan
kimliklerle birleştirilmiş. JSONP / Node öbekleri tanınmıyor (tek "chunk_0"),
`typescript` eklentisi geçerli JS'i bozduğu için `renderer/main_window`
(904 modül) 0 modül veriyordu.

Sonra: aday ancak webpack çalışma zamanına bağlıysa harita sayılır; iç içe
haritalar dış modülün parçası; seçim ve gerekçesi `module_map_selection`'da;
girdi önce düz JS eklentileriyle ayrıştırılır.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from karadul.config import Config

_SCRIPTS = Config().scripts_dir
_UNPACK = _SCRIPTS / "smart-webpack-unpack.mjs"
_SAY = _SCRIPTS / "measurement" / "p20b_webpack_say.mjs"
_FIDDLE = (
    Path.home() / "karadul_olcum" / "runs" / "onarim-2026-11-18" / "P20" / "ornek"
    / "fiddle_app" / ".webpack"
)


def _node_ok() -> bool:
    return (
        shutil.which("node") is not None
        and _UNPACK.exists()
        and (_SCRIPTS / "node_modules").is_dir()
    )


needs_node = pytest.mark.skipif(not _node_ok(), reason="node ya da scripts/node_modules yok")

# webpack 5 (küçültülmüş) ana paket: harita `e` (çalışma zamanı `n` ona bağlı) +
# aynı kapsamda bir IIFE'ye verilen, modül gibi görünen ama haritayla ilgisiz
# bir nesne (Fiddle'daki Prisma nesnesinin benzeri).
_WP5_MAIN = (
    '(()=>{var e={101(e,t,n){const r=n(202);console.log(r.x)},'
    '202:(e,t)=>{t.x=42}},t={};function n(r){var o=t[r];if(void 0!==o)return o.exports;'
    'var i=t[r]={id:r,loaded:!1,exports:{}};return e[r].call(i.exports,i,i.exports,n),'
    'i.loaded=!0,i.exports}n.m=e;'
    '(function(o){globalThis.inst=o})({then(){return 1},catch(){return 2},'
    'VERSION:function(){return "1.0"},NAME:()=>"x"});'
    'var r=n(101);module.exports=r})();\n'
)

# webpack 5 JSONP öbeği; tek modülün içinde paketlenmiş bir kütüphanenin kendi
# (webpack 4 dizi) çalışma zamanı var. Doğru: 1 modül (77); iç dizi modül değil.
_WP5_CHUNK_NESTED = (
    '(self.webpackChunkapp=self.webpackChunkapp||[]).push([[77],{77(e,t,n){'
    'e.exports=function(m){var c={};function r(i){if(c[i])return c[i].exports;'
    'var o=c[i]={exports:{}};return m[i].call(o.exports,o,o.exports,r),o.exports}'
    'return r(0)}([function(e,t,r){e.exports=r(1)},function(e){e.exports=7}])}}]);\n'
)

# webpack 5 Node öbeği (main/330.index.js biçimi).
_WP5_NODE_CHUNK = (
    'exports.id=330,exports.ids=[330],exports.modules={330(e,t,n){'
    'e.exports=function(){return 1}},331:(e,t)=>{t.y=2}};\n'
)

# typescript eklentisini bozan geçerli JS (Fiddle main_window'dan küçültülmüş
# kalıp: koşullu ifadede parantezli gövdeli iki ok işlevi) + bir webpack 5 haritası.
_TS_TRAP = (
    '(()=>{var e={1(e,t,n){var c=1,s=2;'
    't.f=0===c?t=>({sash:s,start:t.x}):t=>({sash:s,start:t.y})}},t={};'
    'function n(r){var o=t[r];if(void 0!==o)return o.exports;var i=t[r]={exports:{}};'
    'return e[r](i,i.exports,n),i.exports}n(1)})();\n'
)


# Hiçbir webpack çalışma zamanı yok: modül gibi görünen dört yapı da harita DEĞİL.
# (IIFE'ye verilen nesne; kendini geçirmeyen bir dağıtım tablosu; webpack öbek
# dizisi olmayan bir kuyruğa `push([[1],{…}])`; `exports.ids`'siz `exports.modules`.)
_NO_RUNTIME = (
    '(function(o){globalThis.inst=o})({then(){return 1},catch(){return 2},'
    'VERSION:function(){return 3}});\n'
    'var handlers={start(e,t,n){return 1},stop(e,t,n){return 2}};\n'
    'function log(){}\nfunction dispatch(k){return handlers[k](1,2,log)}\n'
    'var queue=[];queue.push([[1],{a(){return 1},b(){return 2}}]);\n'
    'exports.modules={c(){return 1},d(){return 2}};\n'
)
_NO_RUNTIME_FAKE_IDS = {"then", "catch", "VERSION", "start", "stop", "a", "b", "c", "d"}


def _unpack(tmp_path: Path, source: str, name: str = "bundle.js") -> tuple[dict, Path]:
    src = tmp_path / name
    src.write_text(source, encoding="utf-8")
    out = tmp_path / "out"
    proc = subprocess.run(
        ["node", str(_UNPACK), str(src), str(out)],
        capture_output=True, text=True, timeout=600,
    )
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    return payload, out


def _ids(payload: dict) -> set[str]:
    return {m["id"] for m in payload.get("modules", [])}


@needs_node
def test_module_map_must_be_linked_to_webpack_runtime(tmp_path):
    payload, _ = _unpack(tmp_path, _WP5_MAIN)
    assert _ids(payload) == {"101", "202"}
    assert payload["bundle_format"] == "webpack_object"
    assert payload["modules_parse_ok"] == 2
    assert payload["modules_parse_failed"] == 0


@needs_node
def test_unlinked_look_alike_maps_are_not_module_maps(tmp_path):
    payload, _ = _unpack(tmp_path, _NO_RUNTIME)
    assert not (_ids(payload) & _NO_RUNTIME_FAKE_IDS)
    assert not str(payload["bundle_format"]).startswith("webpack")
    sel = payload["module_map_selection"]
    assert sel["chosen"] is None
    assert sel["candidates_linked"] == 0


@needs_node
def test_selection_reason_is_written(tmp_path):
    payload, out = _unpack(tmp_path, _WP5_MAIN)
    sel = payload["module_map_selection"]
    assert sel["chosen"]["module_count"] == 2
    assert "runtime_require_call" in sel["chosen"]["evidence"]
    assert "require_m_assignment" in sel["chosen"]["evidence"]
    # Bağsız IIFE nesnesi gerekçesiyle reddedildi.
    unlinked = [r for r in sel["rejected"] if r["evidence"] == []]
    assert any(r["module_count"] == 4 for r in unlinked)
    assert all("bağı yok" in r["reason"] for r in unlinked)
    # Aynı gerekçe diskteki dependency_graph.json'da da var.
    graph = json.loads((out / "dependency_graph.json").read_text(encoding="utf-8"))
    assert graph["module_map_selection"]["chosen"] == sel["chosen"]


@needs_node
def test_nested_runtime_map_is_not_extracted_as_modules(tmp_path):
    payload, _ = _unpack(tmp_path, _WP5_CHUNK_NESTED)
    assert _ids(payload) == {"77"}
    assert payload["bundle_format"] == "webpack_jsonp_chunk"
    sel = payload["module_map_selection"]
    assert sel["chosen"]["evidence"] == ["jsonp_chunk_push"]
    nested = [r for r in sel["rejected"] if r["reason"].startswith("iç içe")]
    assert len(nested) == 1 and nested[0]["module_count"] == 2


@needs_node
def test_node_chunk_modules_are_extracted(tmp_path):
    payload, _ = _unpack(tmp_path, _WP5_NODE_CHUNK)
    assert _ids(payload) == {"330", "331"}
    assert payload["bundle_format"] == "webpack_node_chunk"
    assert payload["modules_parse_ok"] == 2


@needs_node
def test_valid_js_is_not_broken_by_typescript_plugin(tmp_path):
    payload, _ = _unpack(tmp_path, _TS_TRAP)
    assert payload["parser_plugins"] == "js"
    assert _ids(payload) == {"1"}
    assert payload["modules_parse_ok"] == 1
    assert payload["modules_parse_failed"] == 0


@needs_node
def test_independent_counter_agrees_on_synthetic_inputs(tmp_path):
    """Bağımsız sayım betiği aynı girdilerde aynı kümeyi bulur (iki yöntem)."""
    for i, src in enumerate((_WP5_MAIN, _WP5_CHUNK_NESTED, _WP5_NODE_CHUNK, _TS_TRAP)):
        d = tmp_path / str(i)
        d.mkdir()
        payload, _ = _unpack(d, src)
        f = d / "bundle.js"
        proc = subprocess.run(["node", str(_SAY), str(f)], capture_output=True, text=True, timeout=120)
        say = json.loads(proc.stdout)
        assert set(say["module_ids"]) == _ids(payload), i


_FIDDLE_MAIN = _FIDDLE / "main" / "index.js"


@needs_node
@pytest.mark.skipif(not _FIDDLE_MAIN.is_file(), reason="Fiddle örneği yok (P20 ölçüm kökü)")
def test_real_fiddle_main_matches_independent_count(tmp_path):
    """Gerçek webpack 5 paketi: çıkarılan küme == bağımsız sayım (915), uydurma 0."""
    out = tmp_path / "out"
    proc = subprocess.run(
        ["node", "--max-old-space-size=8192", str(_UNPACK), str(_FIDDLE_MAIN), str(out)],
        capture_output=True, text=True, timeout=900,
    )
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    say_proc = subprocess.run(
        ["node", "--max-old-space-size=8192", str(_SAY), str(_FIDDLE_MAIN)],
        capture_output=True, text=True, timeout=600,
    )
    say = json.loads(say_proc.stdout)
    expected = set(say["module_ids"])
    assert len(expected) == 915
    assert _ids(payload) == expected
    assert payload["modules_parse_ok"] == 915
    assert payload["modules_parse_failed"] == 0
    assert not ({"then", "catch", "VERSION", "NAME"} & _ids(payload))
