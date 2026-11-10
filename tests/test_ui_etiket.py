"""Arayüzde ad etiketi ve gerçek puan (plan v2.2 N1 adım 3, 8. commit).

Kilitlenen davranışlar (tasarım §4.3 "Arayüz", §5.4 8. satır):
  - etiket, puan, kanal ve kanıt temiz haritadaki kayıttan sunucuya geçer;
  - bayat kayıtta (kayıttaki ad != o anki ad) köken "elle"dir; etiket, puan, kanal, kanıt yoktur;
  - kayıtta etiket yoksa rozet verisi yoktur (liste ve kanıt kartı);
  - ``confidence: null`` hata vermez;
  - "kesin" yalnız kayıttaki etiketten gelir, puandan türetilmez;
  - özet satırı etiket sayılarını rapordan ya da temiz haritadan alır, sayı uydurmaz.

KAPSAM: sunucu fonksiyonları sentetik bir çalışma alanıyla doğrudan çağrılır. Tarayıcı, ağ,
Ghidra ve subprocess (isteğe bağlı ``node`` denetimi dışında) yok. ``ui/server.py`` paket modülü
değildir; dosya yolundan yüklenir (``test_ui_security_banner.py`` ile aynı yol).
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from karadul.core.naming_labels import (
    LABEL_CERTAIN,
    LABEL_UNVERIFIED,
    LABEL_VERIFIED,
    NAME_LABELS,
    PRE_NAME_KIND_MANUAL,
    SOURCE_C_NAMER,
)

_UI = Path(__file__).resolve().parent.parent / "ui"
_SERVER_PY = _UI / "server.py"
_INDEX_HTML = _UI / "index.html"

KESIN = "FUN_00401000"
DOGRULANMADI = "FUN_00401100"
ELLE_ON_AD = "FUN_00401200"
YUKSEK_PUAN = "FUN_00401300"
PUANSIZ = "FUN_00401400"
IMZA = "FUN_00401500"
ESKI_BICIM = "FUN_00401600"
ADSIZ = "FUN_00401700"
BOZUK_ETIKET = "FUN_00401800"
KAYITSIZ = "FUN_00401900"

# reconstructed/src/naming_map.json "global": arayüz listesinin okuduğu, o anki adlar
_ADLAR = {
    KESIN: "parse_args",
    DOGRULANMADI: "read_config",
    ELLE_ON_AD: "analist_adi",
    YUKSEK_PUAN: "yuksek_puanli",
    PUANSIZ: "puansiz_ad",
    IMZA: "memcpy",
    ESKI_BICIM: "eski_ad",
    BOZUK_ETIKET: "bozuk_etiketli",
    KAYITSIZ: "kayitsiz_ad",
}


def _c_namer(ad, guven, etiket, kanal, kanit):
    return {"new_name": ad, "source": SOURCE_C_NAMER, "confidence": guven,
            "label": etiket, "channel": kanal, "evidence": kanit}


# clean/naming_map.json "mappings": biçimlendiricinin yazdığı kayıtlar
_KAYITLAR = {
    KESIN: _c_namer("parse_args", 0.95, LABEL_CERTAIN, "ks1:func_kalibi",
                    {"rol": "kendi", "kanit_sayisi": 2}),
    DOGRULANMADI: _c_namer("read_config", 0.62, LABEL_UNVERIFIED, "string_context/oz_ad",
                           "read_config: cannot open %s"),
    # elle verilen ön ad: etiketsiz
    ELLE_ON_AD: _c_namer("analist_adi", 0.95, None, "on_ad:elle", None),
    # puan çok yüksek ama etiket "doğrulanmadı": puan etiketi değiştirmez
    YUKSEK_PUAN: _c_namer("yuksek_puanli", 0.99, LABEL_UNVERIFIED, "string_context/kebap_ad",
                          "yuksek-puanli"),
    # köken kaydı bulunamamış ad: puan null
    PUANSIZ: _c_namer("puansiz_ad", None, LABEL_UNVERIFIED, None, None),
    # c_namer dışı kaynak: etiket anahtarı yok
    IMZA: {"new_name": "memcpy", "source": "signature_db", "confidence": 0.9, "library": "libc"},
    # ce1caf6 öncesi biçim: her ada sabit 1.0, etiket anahtarı yok
    ESKI_BICIM: {"new_name": "eski_ad", "source": SOURCE_C_NAMER, "confidence": 1.0},
    # listede adı olmayan fonksiyonun kaydı (ad yalnız başka bir yinelemede)
    ADSIZ: _c_namer("yalniz_kayitta", 0.95, LABEL_CERTAIN, "ks1:func_kalibi",
                    {"rol": "kendi", "kanit_sayisi": 1}),
    # sözlükte olmayan etiket değeri
    BOZUK_ETIKET: _c_namer("bozuk_etiketli", 1.0, "KESİN", "ks1:func_kalibi", None),
}


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def srv():
    """ui/server.py'yi yalıtılmış modül olarak yükle (sunucu başlatılmaz)."""
    return _load("bw_ui_server_etiket")


def _make_ws(root: Path, *, kayitlar=_KAYITLAR, adlar=_ADLAR, stats=None,
             temiz_harita: bool = True) -> Path:
    """Sentetik çalışma alanı: o anki adlar + decompile dosyaları + temiz çıktı."""
    src = root / "reconstructed" / "src"
    src.mkdir(parents=True)
    (src / "naming_map.json").write_text(
        json.dumps({"global": dict(adlar)}, ensure_ascii=False), encoding="utf-8")
    dec = root / "reconstructed" / "ghidra" / "decompiled"
    dec.mkdir(parents=True)
    for addr in sorted(set(adlar) | set(kayitlar) | {ADSIZ}):
        (dec / f"{addr}.c").write_text(f"void {addr}(void){{ return; }}\n", encoding="utf-8")
    clean = root / "clean"
    clean.mkdir(parents=True)
    report = {"pipeline": {"stages": {"reconstruct": {"stats": stats or {}}}}}
    (clean / "report.json").write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    if temiz_harita:
        (clean / "naming_map.json").write_text(
            json.dumps({"version": "1.0", "mappings": kayitlar}, ensure_ascii=False),
            encoding="utf-8")
    return root


@pytest.fixture
def ws(srv, tmp_path, monkeypatch):
    """Etkin çalışma alanı. Kalıcı elle-ad deposuna (kullanıcının ev dizini) yazılmasın diye ikili
    özeti kapatılır: ``_do_rename`` yalnız geçici dizindeki haritayı günceller."""
    root = _make_ws(tmp_path / "ws")
    monkeypatch.setattr(srv, "_active_binary_hash", lambda ws=None: None)
    srv.activate_workspace(str(root))
    with srv._CACHE_LOCK:
        srv._CACHE.clear()
    yield root
    srv.activate_workspace(None)
    with srv._CACHE_LOCK:
        srv._CACHE.clear()


def _etiketler(srv) -> dict:
    return {f["addr"]: f["label"] for f in srv.build_model()["functions"]}


# -- Kanıt kartı: etiket, puan, kanal, kanıt geçer ---------------------------------------------

def test_kesin_kaydin_alanlari_gecer(srv, ws):
    prov = srv._evidence(KESIN)["provenance"]
    assert prov == {"source": SOURCE_C_NAMER, "confidence": 0.95, "label": LABEL_CERTAIN,
                    "channel": "ks1:func_kalibi",
                    "evidence": {"rol": "kendi", "kanit_sayisi": 2}}


def test_dogrulanmadi_kaydin_alanlari_gecer(srv, ws):
    prov = srv._evidence(DOGRULANMADI)["provenance"]
    assert prov["label"] == LABEL_UNVERIFIED
    assert prov["confidence"] == 0.62
    assert prov["channel"] == "string_context/oz_ad"
    assert prov["evidence"] == "read_config: cannot open %s"
    assert prov["source"] == SOURCE_C_NAMER


def test_kanit_paketi_json_olarak_yazilir(srv, ws):
    """Türkçe etiket ve null puan tel üzerinde bozulmaz (sunucu json.dumps ile yanıtlar)."""
    for addr in (KESIN, DOGRULANMADI, PUANSIZ):
        paket = srv._evidence(addr)
        assert json.loads(json.dumps(paket, ensure_ascii=False)) == paket


def test_imza_kaydi_kendi_puanini_ve_kutuphanesini_tasir(srv, ws):
    """c_namer dışı kaynak: eski alanlar aynen; etiket yok."""
    prov = srv._evidence(IMZA)["provenance"]
    assert prov["source"] == "signature_db"
    assert prov["confidence"] == 0.9
    assert prov["library"] == "libc"
    assert prov["label"] is None and prov["channel"] is None and prov["evidence"] is None


# -- Etiket yoksa rozet verisi yok ---------------------------------------------------------------

@pytest.mark.parametrize("addr", [ELLE_ON_AD, IMZA, ESKI_BICIM, BOZUK_ETIKET])
def test_etiketsiz_kayitta_rozet_verisi_yok(srv, ws, addr):
    assert srv._evidence(addr)["provenance"]["label"] is None
    assert _etiketler(srv)[addr] is None


def test_kayitsiz_adda_koken_ve_etiket_yok(srv, ws):
    assert srv._evidence(KAYITSIZ)["provenance"] is None
    assert _etiketler(srv)[KAYITSIZ] is None


def test_temiz_harita_yoksa_hicbir_etiket_yok(srv, tmp_path, monkeypatch):
    root = _make_ws(tmp_path / "haritasiz", temiz_harita=False)
    monkeypatch.setattr(srv, "_active_binary_hash", lambda ws=None: None)
    srv.activate_workspace(str(root))
    with srv._CACHE_LOCK:
        srv._CACHE.clear()
    try:
        assert set(_etiketler(srv).values()) == {None}
        assert srv._evidence(KESIN)["provenance"] is None
    finally:
        srv.activate_workspace(None)


def test_temiz_harita_nesne_degilse_model_cokmez(srv, tmp_path, monkeypatch):
    root = _make_ws(tmp_path / "bozuk")
    (root / "clean" / "naming_map.json").write_text("[1, 2, 3]", encoding="utf-8")
    monkeypatch.setattr(srv, "_active_binary_hash", lambda ws=None: None)
    srv.activate_workspace(str(root))
    with srv._CACHE_LOCK:
        srv._CACHE.clear()
    try:
        assert set(_etiketler(srv).values()) == {None}
    finally:
        srv.activate_workspace(None)


# -- "kesin" yalnız etiketten --------------------------------------------------------------------

def test_kesin_yalniz_etiketten(srv, ws):
    """Puanı en yüksek kayıtlar "kesin" değildir; "kesin" görünen tek ad etiketi öyle olandır."""
    etiketler = _etiketler(srv)
    assert [a for a, e in etiketler.items() if e == LABEL_CERTAIN] == [KESIN]
    assert etiketler[YUKSEK_PUAN] == LABEL_UNVERIFIED          # puan 0.99
    assert etiketler[BOZUK_ETIKET] is None                      # puan 1.0, etiket sözlükte yok
    assert etiketler[ESKI_BICIM] is None                        # puan 1.0, etiket anahtarı yok
    assert etiketler[ELLE_ON_AD] is None                        # puan 0.95, etiket null
    assert srv._evidence(YUKSEK_PUAN)["provenance"]["label"] == LABEL_UNVERIFIED
    assert srv._evidence(YUKSEK_PUAN)["provenance"]["confidence"] == 0.99


def test_etiket_yazimi_sozlukten(srv, ws):
    """Sunucunun gönderdiği her etiket ya None ya da naming_labels sözlüğünün bir değeridir."""
    assert srv.NAME_LABELS is NAME_LABELS
    gonderilen = {e for e in _etiketler(srv).values() if e is not None}
    assert gonderilen == {LABEL_CERTAIN, LABEL_UNVERIFIED}
    assert gonderilen <= set(NAME_LABELS)


def test_dogrulandi_etiketi_de_tasinir(srv):
    """Üçüncü sözlük değeri bugün üretilmiyor ama alan onu da taşır."""
    kayit = _c_namer("olculmus_ad", 0.8, LABEL_VERIFIED, "string_context/oz_ad", "x")
    assert srv._record_label(kayit) == LABEL_VERIFIED
    assert srv._provenance({KESIN: kayit}, KESIN, "olculmus_ad")["label"] == LABEL_VERIFIED


# -- Liste: her fonksiyonda label alanı -----------------------------------------------------------

def test_listede_her_fonksiyonun_label_alani_var(srv, ws):
    funcs = srv.build_model()["functions"]
    assert len(funcs) == len(_ADLAR) + 1                        # + ADSIZ
    assert all("label" in f for f in funcs)
    etiketler = {f["addr"]: f["label"] for f in funcs}
    assert etiketler[KESIN] == LABEL_CERTAIN
    assert etiketler[DOGRULANMADI] == LABEL_UNVERIFIED
    assert etiketler[PUANSIZ] == LABEL_UNVERIFIED


def test_adsiz_fonksiyon_kaydi_olsa_da_etiket_ve_koken_almaz(srv, ws):
    """Kayıt "kesin" diyor ama listede ad yok (ad yalnız başka yinelemede): gösterilecek ad yok."""
    f = next(x for x in srv.build_model()["functions"] if x["addr"] == ADSIZ)
    assert f["name"] == ADSIZ and f["cls"] == "unnamed"
    assert f["label"] is None
    assert srv._evidence(ADSIZ)["provenance"] is None


# -- confidence: null ------------------------------------------------------------------------------

def test_null_puan_hata_vermez(srv, ws):
    prov = srv._evidence(PUANSIZ)["provenance"]
    assert prov["confidence"] is None
    assert prov["label"] == LABEL_UNVERIFIED
    assert prov["channel"] is None and prov["evidence"] is None


@pytest.mark.parametrize("deger", [None, "0.9", True, [0.9], float("nan"), float("inf")])
def test_sayi_olmayan_puan_gosterilmez(srv, deger):
    kayit = _c_namer("ad", deger, LABEL_UNVERIFIED, None, None)
    assert srv._record_confidence(kayit) is None


def test_eski_bicim_sabit_puan_gosterilmez(srv, ws):
    """Etiket anahtarı taşımayan c_namer kaydı eski biçimdir; 1.0 ölçülmüş güven değildi."""
    prov = srv._evidence(ESKI_BICIM)["provenance"]
    assert prov["source"] == SOURCE_C_NAMER
    assert prov["confidence"] is None
    # yeni biçimde etiket null olsa da puan kayıttaki gerçek değerdir
    assert srv._evidence(ELLE_ON_AD)["provenance"]["confidence"] == 0.95


# -- Bayat kayıt koruması -------------------------------------------------------------------------

def test_elle_degisen_adda_koken_elle_ve_etiket_yok(srv, ws):
    """Ad arayüzden değişir: src haritası güncellenir, temiz harita eski adı anlatır."""
    assert srv._evidence(KESIN)["provenance"]["label"] == LABEL_CERTAIN
    assert _etiketler(srv)[KESIN] == LABEL_CERTAIN

    sonuc = srv._do_rename(KESIN, "benim_adim")
    assert sonuc == {"ok": True, "addr": KESIN, "name": "benim_adim"}
    # temiz haritadaki kayıt gerçekten değişmedi (koruma bu yüzden gerekli)
    temiz = json.loads((ws / "clean" / "naming_map.json").read_text(encoding="utf-8"))
    assert temiz["mappings"][KESIN]["new_name"] == "parse_args"
    assert temiz["mappings"][KESIN]["label"] == LABEL_CERTAIN

    paket = srv._evidence(KESIN)
    assert paket["current_name"] == "benim_adim"
    assert paket["provenance"] == {"source": PRE_NAME_KIND_MANUAL}
    assert paket["provenance"]["source"] == "elle"
    etiketler = _etiketler(srv)
    assert etiketler[KESIN] is None
    # öbür adlar etkilenmez
    assert etiketler[DOGRULANMADI] == LABEL_UNVERIFIED


def test_eski_ada_geri_donunce_kayit_yeniden_gecerli(srv, ws):
    srv._do_rename(KESIN, "gecici_ad")
    assert _etiketler(srv)[KESIN] is None
    srv._do_rename(KESIN, "parse_args")
    assert _etiketler(srv)[KESIN] == LABEL_CERTAIN
    assert srv._evidence(KESIN)["provenance"]["channel"] == "ks1:func_kalibi"


def test_bayat_kayit_dogrudan(srv):
    """Yardımcı düzeyinde: ad uyuşmazsa kayıt yok sayılır; adres hâlâ ad ise köken yok."""
    cmap = {KESIN: _KAYITLAR[KESIN]}
    assert srv._name_record(cmap, KESIN, "parse_args") is _KAYITLAR[KESIN]
    assert srv._name_record(cmap, KESIN, "baska_ad") is None
    assert srv._name_record(cmap, KESIN, KESIN) is None
    # kayıt adresin kendisini "ad" diye taşısa bile adsız fonksiyon etiket almaz
    kendine = {KESIN: dict(_KAYITLAR[KESIN], new_name=KESIN)}
    assert srv._name_record(kendine, KESIN, KESIN) is None
    assert srv._provenance(kendine, KESIN, KESIN) is None
    assert srv._provenance(cmap, KESIN, "baska_ad") == {"source": "elle"}
    assert srv._provenance(cmap, KESIN, KESIN) is None
    assert srv._provenance(cmap, DOGRULANMADI, "read_config") is None      # kayıt yok
    assert srv._provenance({KESIN: "bozuk"}, KESIN, "parse_args") is None  # kayıt nesne değil


# -- Özet satırı ----------------------------------------------------------------------------------

def _ozet(srv, root: Path) -> list[dict]:
    return srv._report_substages(str(root))


def test_ozet_rapordaki_etiket_sayilariyla(srv, tmp_path):
    """Raporda naming_by_label varsa sayılar oradan (temiz haritadaki sayım kullanılmaz)."""
    root = _make_ws(tmp_path / "r", stats={
        "naming_by_label": {LABEL_CERTAIN: 7, LABEL_UNVERIFIED: 41},
        "naming_high_confidence": 48,
    })
    satirlar = _ozet(srv, root)
    assert satirlar == [
        {"label": f"etiket: {LABEL_CERTAIN}", "count": 7, "unit": "ad",
         "name_label": LABEL_CERTAIN},
        {"label": f"etiket: {LABEL_UNVERIFIED}", "count": 41, "unit": "ad",
         "name_label": LABEL_UNVERIFIED},
    ]


def test_ozet_sifir_sayiyi_da_tasir(srv, tmp_path):
    root = _make_ws(tmp_path / "r", stats={
        "naming_by_label": {LABEL_CERTAIN: 0, LABEL_UNVERIFIED: 12}})
    assert [(s["name_label"], s["count"]) for s in _ozet(srv, root)] == [
        (LABEL_CERTAIN, 0), (LABEL_UNVERIFIED, 12)]


def test_ozet_rapor_yoksa_temiz_haritadan_sayar(srv, tmp_path):
    """naming_by_label yok: etiketli kayıtlar haritadan sayılır (2 kesin, 3 doğrulanmadı)."""
    root = _make_ws(tmp_path / "r", stats={"naming_high_confidence": 48})
    assert [(s["name_label"], s["count"], s["unit"]) for s in _ozet(srv, root)] == [
        (LABEL_CERTAIN, 2, "ad"), (LABEL_UNVERIFIED, 3, "ad")]


def test_ozet_gecersiz_rapor_degerleri_sayilmaz(srv, tmp_path):
    """Sözlükte olmayan anahtar, bool, eksi sayı ve dizgi atılır; kalan geçerli sayı gösterilir."""
    root = _make_ws(tmp_path / "r", stats={"naming_by_label": {
        "emin": 9, LABEL_CERTAIN: True, LABEL_VERIFIED: -1, LABEL_UNVERIFIED: 5}})
    assert [(s["name_label"], s["count"]) for s in _ozet(srv, root)] == [(LABEL_UNVERIFIED, 5)]
    # hiç geçerli değer kalmazsa temiz haritadaki sayıma düşülür
    root2 = _make_ws(tmp_path / "r2", stats={"naming_by_label": {LABEL_CERTAIN: "7"}})
    assert [(s["name_label"], s["count"]) for s in _ozet(srv, root2)] == [
        (LABEL_CERTAIN, 2), (LABEL_UNVERIFIED, 3)]


def test_ozet_etiket_verisi_yoksa_satir_yok(srv, tmp_path):
    """Eski koşu: ne raporda sayı ne haritada etiket. Eski "yüksek-güven isim" satırı da yok."""
    kayitlar = {IMZA: _KAYITLAR[IMZA], ESKI_BICIM: _KAYITLAR[ESKI_BICIM]}
    root = _make_ws(tmp_path / "r", kayitlar=kayitlar,
                    stats={"naming_high_confidence": 48, "gnulib_recovered": 3})
    satirlar = _ozet(srv, root)
    assert satirlar == [{"label": "gnulib string-fingerprint", "count": 3}]
    root2 = _make_ws(tmp_path / "r2", temiz_harita=False,
                     stats={"naming_high_confidence": 48})
    assert _ozet(srv, root2) == []


# -- index.html: sözlük, metinler, rozet işlevleri ------------------------------------------------

def _html() -> str:
    return _INDEX_HTML.read_text(encoding="utf-8")


def _etiket_blogu() -> str:
    m = re.search(r"/\* ETIKET-BASLA \*/(.*?)/\* ETIKET-BITIS \*/", _html(), re.S)
    assert m, "index.html'de etiket bloğu işaretleri yok"
    return m.group(1)


def test_arayuz_sozlugu_naming_labels_ile_ayni():
    """Arayüzün rozet çizdiği etiket kümesi sözlükle aynı yazılır (eksik de fazla da olmaz)."""
    m = re.search(r"const NAME_LABEL=\{(.*?)\n\};", _etiket_blogu(), re.S)
    assert m
    anahtarlar = re.findall(r"^\s*'([^']+)':\{cls:'([a-z])'", m.group(1), re.M)
    assert [a for a, _ in anahtarlar] == list(NAME_LABELS)
    assert len({c for _, c in anahtarlar}) == len(NAME_LABELS)      # her etikete ayrı biçem


def test_ayar_paneli_metni_yaniltmaz():
    html = _html()
    assert "Emin değilsen isim verme" not in html
    assert "Bu güvenin altında fonksiyon isimsiz (FUN_) bırakılır" not in html
    m = re.search(r'<div class="n">İsim güven eşiği</div><div class="d">([^<]*)</div>', html)
    assert m
    # "aç"tan (1.21.1) beri ürün eşiği genel adlara uygulanır; metin bunu söyler
    assert "fonksiyon adlarına uygulanmaz" not in m.group(1)
    assert "fonksiyon ve veri adları" in m.group(1)
    assert "Ghidra adıyla kalır" in m.group(1)
    assert "Yerel değişken adlarına uygulanmaz" in m.group(1)
    # ayar düğmeleri yerinde: davranış değişmedi
    assert 'id="cfgConf"' in html and 'id="cfgUnk"' in html


def test_kanit_karti_puani_kosulsuz_yazmaz():
    """Eski satır puanı etiketten bağımsız basıyordu; artık rozet ve puan yardımcılardan gelir."""
    html = _html()
    assert "labelBadge(prov.label,false,tip)" in html
    assert "provScore(prov)" in html
    assert "labelBadge(f.label,true)" in html
    assert "f.label=null" in html                    # elle değişen adın liste işareti silinir


_NODE = shutil.which("node")

_NODE_KOSUM = r"""
const out = {
  kesin: labelBadge('kesin', false, ''),
  kesinMini: labelBadge('kesin', true),
  dogrulanmadi: labelBadge('doğrulanmadı', false, 'kanal: string_context/oz_ad'),
  dogrulanmadiMini: labelBadge('doğrulanmadı', true),
  yok: [null, undefined, '', 'certain', 'KESİN', 0.99, 1, true, {}, 'toString', '__proto__']
         .map(x => labelBadge(x, false, 'kanal: x')),
  yokMini: [null, undefined, 'toString'].map(x => labelBadge(x, true)),
  kacis: labelBadge('kesin', false, 'kanıt: "<img src=x onerror=1>"'),
  puan: provScore({confidence: 0.62}),
  puanYok: [null, undefined, {}, {confidence: null}, {confidence: '0.9'}, {confidence: NaN},
            {source: 'elle'}].map(provScore),
  puanTam: provScore({confidence: 1, label: null}),
  ipucuDizgi: provTip({channel: 'string_context/oz_ad', evidence: 'read_config: cannot open %s'}),
  ipucuKs1: provTip({channel: 'ks1:func_kalibi', evidence: {rol: 'kendi', kanit_sayisi: 2}}),
  ipucuBos: [null, {}, {channel: null, evidence: null}, {source: 'elle'}].map(provTip),
};
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(_NODE is None, reason="node yok: rozet işlevleri çalıştırılarak sınanamaz")
def test_rozet_islevleri_node_ile(tmp_path):
    """index.html'deki rozet işlevleri çalıştırılır: etiket yoksa çıktı boş, puandan rozet doğmaz."""
    html = _html()
    yardimcilar = []
    for imza in ("function esc(", "function trunc(", "function _fmtConf("):
        satir = next(s for s in html.splitlines() if s.startswith(imza))
        yardimcilar.append(satir)
    betik = tmp_path / "rozet.js"
    betik.write_text("\n".join(yardimcilar) + _etiket_blogu() + _NODE_KOSUM, encoding="utf-8")
    proc = subprocess.run([_NODE, str(betik)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)

    assert out["kesin"] == (
        '<span class="lbadge k" title="kesin: ad ikilinin kendi ad yuvasından okundu; bu kanalın '
        'tam ad kesinliği ön kayıtlı ölçümde hedefi tuttu">kesin</span>')
    assert out["kesinMini"].endswith(">kesin</span>") and 'class="lbadge k"' in out["kesinMini"]
    assert 'class="lbadge u"' in out["dogrulanmadi"]
    assert out["dogrulanmadi"].endswith(">doğrulanmadı</span>")
    assert "kanal: string_context/oz_ad" in out["dogrulanmadi"]
    assert out["dogrulanmadiMini"].endswith(">?</span>")
    # etiket yoksa ya da sözlükte değilse hiçbir şey çizilmez (sayı, bool, nesne, yabancı dizgi)
    assert out["yok"] == [""] * 11
    assert out["yokMini"] == [""] * 3
    # ikiliden gelen kanıt dizgisi nitelik içinde kaçırılır
    assert "<img" not in out["kacis"] and "&lt;img" in out["kacis"]
    assert "&quot;" in out["kacis"]
    # puan: yalnız sayıysa; puandan etiket doğmaz
    assert out["puan"] == '<span class="iv-cconf">0.62</span>'
    assert out["puanYok"] == [""] * 7
    assert out["puanTam"] == '<span class="iv-cconf">1.00</span>'
    assert "kesin" not in out["puanTam"] and "lbadge" not in out["puanTam"]
    assert out["ipucuDizgi"] == (
        'kanal: string_context/oz_ad\nkanıt: "read_config: cannot open %s"')
    assert out["ipucuKs1"] == "kanal: ks1:func_kalibi\nkanıt: rol kendi, 2 kanıt"
    assert out["ipucuBos"] == [""] * 4
