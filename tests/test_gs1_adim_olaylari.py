"""GS-1 (A-36): Ghidra sonrası adımların ve aşama sınırlarının ``ILERLEME`` olayları.

Eskiden olay yalnız Ghidra köprüsünden geliyordu; yeniden kurma aşaması (Ollama'da 26–44 dk) ve
aşama sınırları tek olay üretmiyordu. Şimdi adım koşucusu (``karadul/pipeline/runner.py``) koşan her
adım için baş ve bitiş olayı, boru hattı (``karadul/core/pipeline.py``) her aşama için baş ve son
olayı üretir; üretici ``karadul/core/ilerleme.py``'de (köprünün üreticisiyle aynı biçim).
Sahte ilerleme yok: adım içi ``suruyor`` olayı ve zamanlayıcıyla basılan satır yok.
"""
from __future__ import annotations

import logging
import threading
import time
from types import SimpleNamespace

import pytest

from karadul.config import Config
from karadul.core.ilerleme import (
    ASAMALAR,
    GOSTERILEN_ALANLAR,
    gosterim_alanlari,
    ilerleme_ayristir,
    olay_satiri,
    olay_yaz,
)
from karadul.core.pipeline import Pipeline, Stage
from karadul.core.result import StageResult
from karadul.ghidra.headless import ILERLEME_GUNLUKCU, ilerleme_satiri
from karadul.pipeline.registry import Step, _REGISTRY, register_step
from karadul.pipeline.runner import NEDEN_EN_COK, PipelineRunner, _IzlenenHatalar


class _Toplayici(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.satirlar: list[str] = []
        self.kilit = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        with self.kilit:
            self.satirlar.append(record.getMessage())


@pytest.fixture()
def olaylar():
    gunlukcu = logging.getLogger(ILERLEME_GUNLUKCU)
    tut = _Toplayici()
    eski = gunlukcu.level
    gunlukcu.setLevel(logging.INFO)
    gunlukcu.addHandler(tut)
    try:
        yield tut
    finally:
        gunlukcu.removeHandler(tut)
        gunlukcu.setLevel(eski)


def _ayr(tut: _Toplayici) -> list[dict]:
    out = [ilerleme_ayristir(s) for s in tut.satirlar]
    assert all(o is not None for o in out), tut.satirlar  # her satır sözleşme biçiminde
    return out


# --- üretici ------------------------------------------------------------------------------

_DEGERLER = [
    {}, {"gecen_sn": 1.5}, {"islenen": 3, "toplam": 10, "gecen_sn": 0.001},
    {"neden": 'iki "tırnak" ve \\ ters bölü'}, {"neden": "a=b"}, {"neden": "satır\nsonu\r\nvar"},
    {"neden": ""}, {"neden": "çğıİöşü Türkçe"}, {"cozumleyici": "Objective-C Message Analyzer"},
    {"bilesen": "x", "neden": None}, {"islenen": 0, "toplam": 0},
]


@pytest.mark.parametrize("alanlar", _DEGERLER)
@pytest.mark.parametrize("durum", ["basladi", "suruyor", "bitti", "kismi", "atlandi"])
def test_iki_uretici_ayni_bicim(alanlar, durum):
    """Köprünün üreticisi (hep ``asama=static``) ile yeni üretici aynı satırı verir."""
    for adim in ("ghidra.cfg", "reconstruct.c_naming", "ad boşluklu", 'tırnak"li'):
        assert olay_satiri("static", adim, durum, **alanlar) == ilerleme_satiri(adim, durum, **alanlar)


def test_uretici_sozlesme_disini_reddeder():
    with pytest.raises(ValueError):
        olay_satiri("dynamic", "dynamic", "basladi")          # sözleşmede olmayan aşama
    with pytest.raises(ValueError):
        olay_satiri("reconstruct", "reconstruct.x", "hata")   # sözleşmede olmayan durum
    with pytest.raises(ValueError):
        olay_satiri("reconstruct", "reconstruct.x", "bitti", sure=1)  # sözleşmede olmayan alan
    assert ASAMALAR == ("identify", "static", "deobfuscate", "reconstruct", "report", "paket")


def test_uretici_ayristiriciyla_gidis_donus():
    s = olay_satiri("reconstruct", "reconstruct.engineering_annotation", "kismi", gecen_sn=12.5,
                    neden='blok: "x" = 1')
    assert ilerleme_ayristir(s) == {"asama": "reconstruct", "adim": "reconstruct.engineering_annotation",
                                    "durum": "kismi", "gecen_sn": 12.5, "neden": 'blok: "x" = 1'}


def test_gosterim_alanlari_asama_tasir():
    """Arayüz olayı kendi aşamasının satırına yazar: ``asama`` gösterilen alanlarda."""
    assert GOSTERILEN_ALANLAR[0] == "asama"
    g = gosterim_alanlari(ilerleme_ayristir(olay_satiri("reconstruct", "reconstruct.c_naming", "basladi")))
    assert g["asama"] == "reconstruct" and g["adim"] == "reconstruct.c_naming" and g["gecen_sn"] is None


def test_olay_yaz_info_duzeyinde_karadul_ilerleme(olaylar):
    olay_yaz("report", "report", "basladi")
    assert olaylar.satirlar == ["ILERLEME asama=report adim=report durum=basladi"]


# --- adım koşucusu ------------------------------------------------------------------------

def _pc(paralel: bool, asama: str | None = "reconstruct"):
    extra = {} if asama is None else {"_current_stage": asama}
    return SimpleNamespace(metadata={}, extra=extra, config=SimpleNamespace(pipeline=SimpleNamespace(
        parallel_steps=paralel, parallel_max_workers=None)))


@pytest.fixture()
def adimlar():
    olusan: list[str] = []

    def kaydet(ad, **kw):
        olusan.append(ad)
        return register_step(name=ad, **kw)

    @kaydet("gs1_a", produces=["gs1_x"])
    class _A(Step):
        def run(self, ctx):
            time.sleep(0.05)
            return {"gs1_x": 1}

    @kaydet("gs1_b", requires=["gs1_x"], produces=["gs1_y"])
    class _B(Step):
        def run(self, ctx):
            time.sleep(0.02)  # paralel düzeyde gs1_c koşarken eklesin
            ctx.errors.append("gs1_b: bir hata")
            return {"gs1_y": 2}

    @kaydet("gs1_c", requires=["gs1_x"], produces=["gs1_z", "gs1_status"])
    class _C(Step):
        def run(self, ctx):
            time.sleep(0.05)
            return {"gs1_z": 3, "gs1_status": "disabled"}

    @kaydet("gs1_d", requires=["gs1_y", "gs1_z"], produces=["gs1_w", "gs1d_status"])
    class _D(Step):
        def run(self, ctx):
            ctx.errors.extend(["d1", "d2"])
            return {"gs1_w": 4, "gs1d_status": "not_pe_target"}

    @kaydet("gs1_e", requires=["gs1_w"], produces=["gs1_v"])
    class _E(Step):
        def run(self, ctx):
            return {"gs1_v": 5, "gs1e_status": "disabled"}  # produces dışı: koşucu hata verir

    @kaydet("gs1_f", requires=["gs1_w"], produces=["gs1_u"])
    class _F(Step):
        def run(self, ctx):
            raise KeyError("eksik anahtar")

    @kaydet("gs1_g", produces=["gs1_t", "gs1g_status"])
    class _G(Step):
        def run(self, ctx):
            ctx.errors.append("g: " + "uzun " * 100)
            return {"gs1_t": 1, "gs1g_status": "disabled"}  # hata da var: kismi önce gelir

    try:
        yield
    finally:
        for ad in olusan:
            _REGISTRY.pop(ad, None)


def _adim_olaylari(tut):
    return [o for o in _ayr(tut) if o["asama"] == "reconstruct"]


@pytest.mark.parametrize("paralel", [False, True], ids=["sirali", "paralel"])
def test_kosan_her_adim_bir_bas_bir_bitis(olaylar, adimlar, paralel):
    runner = PipelineRunner(["gs1_a", "gs1_b", "gs1_c", "gs1_d"])
    ctx = runner.run(_pc(paralel))
    ol = _adim_olaylari(olaylar)
    assert len(ol) == 2 * 4                                 # olay sayısı = 2 × koşan adım
    for ad in ("gs1_a", "gs1_b", "gs1_c", "gs1_d"):
        kendi = [o for o in ol if o["adim"] == "reconstruct." + ad]
        assert [o["durum"] for o in kendi][0] == "basladi" and len(kendi) == 2
        assert kendi[1]["durum"] in ("bitti", "kismi", "atlandi")
        assert isinstance(kendi[1]["gecen_sn"], float) and "gecen_sn" not in kendi[0]
    son = {o["adim"]: o for o in ol if o["durum"] != "basladi"}
    assert son["reconstruct.gs1_a"]["durum"] == "bitti"
    assert son["reconstruct.gs1_a"]["gecen_sn"] >= 0.04       # gerçek süre (adım 0,05 sn uyudu)
    assert son["reconstruct.gs1_b"] == {"asama": "reconstruct", "adim": "reconstruct.gs1_b",
                                        "durum": "kismi", "gecen_sn": son["reconstruct.gs1_b"]["gecen_sn"],
                                        "neden": "gs1_b: bir hata"}
    assert son["reconstruct.gs1_c"]["durum"] == "atlandi"
    assert son["reconstruct.gs1_c"]["neden"] == "gs1_status=disabled"
    assert son["reconstruct.gs1_d"]["durum"] == "kismi"     # not_pe_target atlama değil; hata var
    assert son["reconstruct.gs1_d"]["neden"] == "2 hata; ilki: d1"
    # çıktı değişmedi: hata listesi aynı içerik, yapıtlar aynı
    assert list(ctx.errors) == ["gs1_b: bir hata", "d1", "d2"]
    assert ctx.errors == ["gs1_b: bir hata", "d1", "d2"]
    assert {k: ctx.artifacts[k] for k in ("gs1_x", "gs1_y", "gs1_z", "gs1_w")} == {
        "gs1_x": 1, "gs1_y": 2, "gs1_z": 3, "gs1_w": 4}


def test_paralel_duzeyde_hata_baska_adima_yazilmaz(olaylar, adimlar):
    """gs1_b (hata ekler) ve gs1_c aynı düzeyde paralel koşar: gs1_c'nin olayı kismi olmaz."""
    PipelineRunner(["gs1_a", "gs1_b", "gs1_c"]).run(_pc(True))
    son = {o["adim"]: o["durum"] for o in _adim_olaylari(olaylar) if o["durum"] != "basladi"}
    assert son == {"reconstruct.gs1_a": "bitti", "reconstruct.gs1_b": "kismi",
                   "reconstruct.gs1_c": "atlandi"}


def test_izlenen_hatalar_ekleyen_adima_yazar():
    h = _IzlenenHatalar(["eski"])
    h.append("sahipsiz")
    h._yerel.adim = "x"
    h.append(1)
    h += ["2"]
    h.extend(iter(["3"]))
    h.insert(0, "4")
    h._yerel.adim = None
    h.append("sahipsiz2")
    assert h == ["4", "eski", "sahipsiz", 1, "2", "3", "sahipsiz2"]
    assert h.adim_hatalari == {"x": ["1", "2", "3", "4"]}
    assert h + ["z"] == ["4", "eski", "sahipsiz", 1, "2", "3", "sahipsiz2", "z"]


@pytest.mark.parametrize("paralel", [False, True], ids=["sirali", "paralel"])
def test_istisna_atan_adim_kismi_ve_hata_yukselir(olaylar, adimlar, paralel):
    from karadul.pipeline.runner import StepFailedError
    with pytest.raises(StepFailedError):
        PipelineRunner(["gs1_a", "gs1_b", "gs1_c", "gs1_d", "gs1_f"]).run(_pc(paralel))
    son = [o for o in _adim_olaylari(olaylar) if o["adim"] == "reconstruct.gs1_f"]
    assert [o["durum"] for o in son] == ["basladi", "kismi"]
    assert son[1]["neden"].startswith("istisna: KeyError:") and "eksik anahtar" in son[1]["neden"]


def test_produces_disi_yapit_hatasi_da_kapanis_olayi_alir(olaylar, adimlar):
    with pytest.raises(RuntimeError):
        PipelineRunner(["gs1_a", "gs1_b", "gs1_c", "gs1_d", "gs1_e"]).run(_pc(False))
    son = [o for o in _adim_olaylari(olaylar) if o["adim"] == "reconstruct.gs1_e"]
    assert [o["durum"] for o in son] == ["basladi", "kismi"]
    assert "produces disinda" in son[1]["neden"]


def test_hata_atlamadan_once_gelir_ve_neden_kisaltilir(olaylar, adimlar):
    PipelineRunner(["gs1_g"]).run(_pc(False))
    son = _adim_olaylari(olaylar)[-1]
    assert son["durum"] == "kismi"
    assert len(son["neden"]) == NEDEN_EN_COK and son["neden"].endswith("…")


@pytest.mark.parametrize("asama", [None, "dynamic", "bilinmeyen"])
def test_asama_bilinmiyorsa_olay_yok(olaylar, adimlar, asama):
    PipelineRunner(["gs1_a", "gs1_b"]).run(_pc(False, asama=asama))
    assert olaylar.satirlar == []


@pytest.mark.parametrize("asama", ["deobfuscate", "static"])
def test_adim_adi_asamayla_oneklenir(olaylar, adimlar, asama):
    PipelineRunner(["gs1_a"]).run(_pc(False, asama=asama))
    assert [o["adim"] for o in _ayr(olaylar)] == [asama + ".gs1_a"] * 2


def test_uzun_adimda_zamanlayici_olayi_yok(olaylar):
    """Adım 0,6 sn sürse de yalnız iki olay (sürüyor / "hâlâ çalışıyor" satırı yok)."""
    try:
        @register_step(name="gs1_uzun", produces=["gs1_uzun_x"])
        class _U(Step):
            def run(self, ctx):
                time.sleep(0.6)
                return {"gs1_uzun_x": 1}

        PipelineRunner(["gs1_uzun"]).run(_pc(False))
    finally:
        _REGISTRY.pop("gs1_uzun", None)
    assert [o["durum"] for o in _ayr(olaylar)] == ["basladi", "bitti"]


def test_basladi_adim_koşarken_gunlukte(olaylar):
    """Baş olayı adım koşmaya başlamadan yazılır (takılan adım günlükte görünür)."""
    goruldu: list[list[str]] = []
    try:
        @register_step(name="gs1_gozle", produces=["gs1_gozle_x"])
        class _G(Step):
            def run(self, ctx):
                goruldu.append(list(olaylar.satirlar))
                return {"gs1_gozle_x": 1}

        PipelineRunner(["gs1_gozle"]).run(_pc(False))
    finally:
        _REGISTRY.pop("gs1_gozle", None)
    assert goruldu == [["ILERLEME asama=reconstruct adim=reconstruct.gs1_gozle durum=basladi"]]


# --- aşama sınırları ----------------------------------------------------------------------

class _Asama(Stage):
    def __init__(self, ad: str, sonuc=None, istisna: Exception | None = None) -> None:
        self.name = ad
        self._sonuc = sonuc
        self._istisna = istisna

    def execute(self, context):
        if self._istisna is not None:
            raise self._istisna
        return self._sonuc


def _sonuc(**kw) -> StageResult:
    base = {"stage_name": "x", "success": True, "duration_seconds": 0.0}
    base.update(kw)
    return StageResult(**base)


@pytest.fixture()
def boru():
    return Pipeline(Config())


def test_asama_basi_ve_sonu(olaylar, boru):
    r = boru._execute_stage(_Asama("reconstruct", _sonuc()), SimpleNamespace())
    ol = _ayr(olaylar)
    assert [(o["asama"], o["adim"], o["durum"]) for o in ol] == [
        ("reconstruct", "reconstruct", "basladi"), ("reconstruct", "reconstruct", "bitti")]
    assert ol[1]["gecen_sn"] == round(r.duration_seconds, 3)


def test_asama_hatali_kismi(olaylar, boru):
    boru._execute_stage(_Asama("static", _sonuc(errors=["ghidra: adım bütçesi doldu", "ikinci"])),
                        SimpleNamespace())
    son = _ayr(olaylar)[-1]
    assert son["durum"] == "kismi" and son["neden"] == "2 neden; ilki: ghidra: adım bütçesi doldu"


def test_asama_kismi_isaretli(olaylar, boru):
    boru._execute_stage(_Asama("reconstruct", _sonuc(stats={"partial": True,
                                                             "partial_reasons": ["ad katmanı kapalı"]})),
                        SimpleNamespace())
    son = _ayr(olaylar)[-1]
    assert son["durum"] == "kismi" and son["neden"] == "ad katmanı kapalı"


def test_asama_atlandi(olaylar, boru):
    boru._execute_stage(_Asama("deobfuscate", _sonuc(success=False, skipped=True,
                                                      stats={"skip_reason": "JS değil"})),
                        SimpleNamespace())
    son = _ayr(olaylar)[-1]
    assert son["durum"] == "atlandi" and son["neden"] == "JS değil"


def test_asama_istisnasi_kismi_basarisiz(olaylar, boru):
    r = boru._execute_stage(_Asama("report", istisna=KeyError("rapor")), SimpleNamespace())
    assert r.success is False
    son = _ayr(olaylar)[-1]
    assert son["durum"] == "kismi" and son["neden"].startswith("aşama başarısız: KeyError")


def test_asama_basarisiz_nedensiz(olaylar, boru):
    boru._execute_stage(_Asama("identify", _sonuc(success=False)), SimpleNamespace())
    assert _ayr(olaylar)[-1]["neden"] == "aşama başarısız: neden bildirilmedi"


def test_sozlesme_disi_asama_olay_yok(olaylar, boru):
    boru._execute_stage(_Asama("dynamic", _sonuc()), SimpleNamespace())
    assert olaylar.satirlar == []


# --- arayüz sunucusu: son çıktının yaşı ---------------------------------------------------

import base64  # noqa: E402
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_NODE = shutil.which("node")


@pytest.fixture()
def srv():
    spec = importlib.util.spec_from_file_location("bw_ui_server_gs1_olay", _ROOT / "ui" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod._JOBS.clear()


class _Bitmis:
    pid = 99_999_999
    returncode = 0

    def poll(self):
        return 0


def _is_kaydi(srv, tmp_path, log):
    srv._JOBS["y"] = {"proc": _Bitmis(), "log": str(log or tmp_path / "yok.log"),
                      "ws_out": str(tmp_path / "ws"), "run_dir": str(tmp_path), "binary": "hedef",
                      "started": time.time(), "lf": None, "closed": True, "cancelled": False,
                      "activated": False}
    return "y"


def test_son_cikti_yasi_gunlugun_degisme_zamanindan(srv, tmp_path):
    log = tmp_path / "analyze.log"
    log.write_text("ILERLEME asama=reconstruct adim=reconstruct.c_naming durum=basladi\n")
    simdi = time.time()
    os.utime(log, (simdi - 1860, simdi - 1860))  # 31 dk önce yazılmış
    p = srv._job_progress(_is_kaydi(srv, tmp_path, log))
    assert 1859.0 <= p["son_cikti_yasi_sn"] <= 1870.0
    assert p["ilerleme"]["asama"] == "reconstruct"


def test_son_cikti_yasi_dosya_yoksa_null(srv, tmp_path):
    p = srv._job_progress(_is_kaydi(srv, tmp_path, None))
    assert p["son_cikti_yasi_sn"] is None


def test_son_cikti_yasi_yeni_yazilan_gunlukte_kucuk(srv, tmp_path):
    log = tmp_path / "analyze.log"
    log.write_text("x\n")
    p = srv._job_progress(_is_kaydi(srv, tmp_path, log))
    assert 0.0 <= p["son_cikti_yasi_sn"] < 5.0


# --- arayüz (index.html): yeni satırlar ---------------------------------------------------

def _betik() -> str:
    html = (_ROOT / "ui" / "index.html").read_text(encoding="utf-8")
    return re.search(r"<script>(.*?)</script>", html, re.S).group(1)


def _render_stages_kaynagi() -> str:
    betik = _betik()
    bas = betik.index("function renderStages(p){")
    son = betik.index("\nfunction ", bas + 1)
    return betik[bas:son]


_HARNESS_BASI = r"""
const kutu={k:[],set innerHTML(v){this.k=[]},appendChild(x){this.k.push(x)}};
const ogeler={anStages:kutu,anEl:{},anTail:{}};
function $(id){return ogeler[id]}
const document={createElement(){return {style:{},className:'',textContent:'',innerHTML:'',title:''}}};
function esc(s){return String(s)}
function labelInfo(){return null}
"""
_HARNESS_SONU = r"""
renderStages(JSON.parse(process.argv[1]));
console.log(JSON.stringify(kutu.k.map(x=>({cls:x.className,text:x.textContent,html:x.innerHTML,css:x.style.cssText||''}))));
"""


def _ciz(p: dict) -> list[dict]:
    """Gerçek ``renderStages``'i node'da sahte DOM ile koşar; kutuya eklenen öğeleri döner."""
    kod = _HARNESS_BASI + _render_stages_kaynagi() + _HARNESS_SONU
    r = subprocess.run([_NODE, "-e", kod, json.dumps(p)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _p(**kw) -> dict:
    base = {"elapsed": 12, "finished": False, "substages": [], "tail": "", "ilerleme": None,
            "son_cikti_yasi_sn": None,
            "stages": [{"key": "static", "label": "Statik", "status": "done", "time": 3.0},
                       {"key": "reconstruct", "label": "Yeniden kurma", "status": "running",
                        "time": None}]}
    base.update(kw)
    return base


_YOK_NODE = pytest.mark.skipif(_NODE is None, reason="node yok")


@_YOK_NODE
def test_olay_kendi_asamasinin_altinda():
    e = {"asama": "reconstruct", "adim": "reconstruct.c_naming", "durum": "basladi", "islenen": None,
         "toplam": None, "gecen_sn": None, "cozumleyici": None, "neden": None}
    k = _ciz(_p(ilerleme=e))
    metinler = [x["text"] for x in k]
    assert "reconstruct.c_naming · basladi" in metinler
    i = metinler.index("reconstruct.c_naming · basladi")
    assert "Yeniden kurma" in k[i - 1]["html"]  # yeniden kurma satırının hemen altında


@_YOK_NODE
def test_bitmis_asamanin_olayi_baska_asamada_gosterilmez():
    """Köprü bitince son olay ``asama=static``; yeniden kurma sürerken gösterilmez (yanıltırdı)."""
    e = {"asama": "static", "adim": "ghidra.kapatma", "durum": "bitti", "islenen": None,
         "toplam": None, "gecen_sn": 0.3, "cozumleyici": None, "neden": None}
    assert not any("ghidra.kapatma" in x["text"] for x in _ciz(_p(ilerleme=e)))


@_YOK_NODE
def test_statik_olayi_statik_surerken():
    e = {"asama": "static", "adim": "ghidra.decompile", "durum": "suruyor", "islenen": 500,
         "toplam": 13559, "gecen_sn": 45.25, "cozumleyici": None, "neden": None}
    stages = [{"key": "static", "label": "Statik", "status": "running", "time": None}]
    k = _ciz(_p(ilerleme=e, stages=stages))
    assert "ghidra.decompile · suruyor · 500 / 13559 · 45.3 sn" in [x["text"] for x in k]


@_YOK_NODE
def test_kismi_olay_alanlari():
    e = {"asama": "reconstruct", "adim": "reconstruct.engineering_annotation", "durum": "kismi",
         "islenen": None, "toplam": None, "gecen_sn": 61.04, "cozumleyici": None, "neden": "1 hata"}
    k = _ciz(_p(ilerleme=e))
    assert "reconstruct.engineering_annotation · kismi · 61.0 sn · 1 hata" in [x["text"] for x in k]


@_YOK_NODE
@pytest.mark.parametrize("yas,metin", [(0.4, "son çıktı 0 sn önce"), (42.6, "son çıktı 43 sn önce"),
                                        (59.4, "son çıktı 59 sn önce"), (1860.0, "son çıktı 31 dk önce"),
                                        (7200.0, "son çıktı 120 dk önce")])
def test_son_cikti_satiri_oldugu_gibi(yas, metin):
    k = _ciz(_p(son_cikti_yasi_sn=yas))
    satir = [x for x in k if x["text"].startswith("son çıktı")]
    assert [x["text"] for x in satir] == [metin]
    assert "animation" not in satir[0]["css"] and satir[0]["cls"] == "sonyas"


@_YOK_NODE
def test_son_cikti_yoksa_ya_da_is_bittiyse_satir_yok():
    assert not any(x["text"].startswith("son çıktı") for x in _ciz(_p()))
    assert not any(x["text"].startswith("son çıktı")
                   for x in _ciz(_p(son_cikti_yasi_sn=12.0, finished=True)))


def test_yeni_satirlarda_animasyon_ve_ilerliyor_metni_yok():
    kaynak = _render_stages_kaynagi()
    yeni = kaynak[kaynak.index("ÖL-4 / GS-1"):]
    for yasak in ("animation", "@keyframes", "spinner", "ilerliyor", "setInterval", "setTimeout"):
        assert yasak not in yeni
    html = (_ROOT / "ui" / "index.html").read_text(encoding="utf-8")
    assert ".sonyas" not in html  # sınıfın stil kuralı (animasyon) yok


def test_csp_karmasi_betikle_ayni():
    html = (_ROOT / "ui" / "index.html").read_text(encoding="utf-8")
    karma = base64.b64encode(hashlib.sha256(_betik().encode("utf-8")).digest()).decode()
    assert "script-src 'sha256-%s'" % karma in html
