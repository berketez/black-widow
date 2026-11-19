"""P22c2 — KaradulLM terminal paneli, ajan imleci ve öneri kartı (``ui/index.html``; KaradulLM v2 tasarımı §4.4,
§4.5, §4.7; §8.1 U-1…U-3).

Bölümler:
  (a) satır biçimi: ``lmLines`` (JS) ``karadul/lm/repl.py::render`` (Python) ile aynı metni üretir; yalnız metin.
  (b) uzun yoklama istemcisi: kaçırılan olay tek satırla ve doğru sayıyla yazılır (yineleme yok).
  (c) imleç: yalnız olayla; düğüm yoksa yer değiştirmez ve "haritada yok" der; takip; dokunulan ışınlar.
  (d) öneri kartı: RET hükmünde kabul yok; denetim ayrıntısı yoksa bu söylenir; koşmayan kurallar görünür.
  (e) U-2 / U-3 durağan + durum satırı: panel ve imleç seçicilerinde süresiz / kendiliğinden animasyon yok;
      zamanlayıcıyla hareket yok; hız ölçülmeden "beklenen" süre yok.
  (f) güvenlik: CSP (betik karması, 'unsafe-inline' yok, connect-src 'self'); panel metni yalnız textContent.
  (g) U-1 tarayıcıda (Playwright + yerel Chromium; yoksa atlanır): olay yokken 10 sn imleç yerinde, animasyon yok.

JS işlevleri ``index.html``'den çıkarılıp node ile çalıştırılır (P22C2-LM bloğu; P17'nin yöntemi). Gerçek model yok.
Mutasyon koruması: ``scripts/measurement/mutation_specs_ui_lm_panel.json``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from karadul.lm import repl as R
from karadul.lm.events import EventStream

_ROOT = Path(__file__).resolve().parent.parent
_INDEX = _ROOT / "ui" / "index.html"
_NODE = shutil.which("node")
nodeli = pytest.mark.skipif(_NODE is None, reason="node yok")


def _html() -> str:
    return _INDEX.read_text(encoding="utf-8")


def _blok(ad: str) -> str:
    m = re.search(rf"/\* {ad}-BASLA:.*?\*/(.*?)/\* {ad}-BITIS \*/", _html(), re.S)
    assert m, f"{ad} bloğu yok"
    return m.group(1)


def _script() -> str:
    m = re.search(r"<script>(.*?)</script>", _html(), re.S)
    assert m
    return m.group(1)


def _lm_dom() -> str:
    """Panelin DOM kodu: saf bloğun sonundan ``init();``'e kadar."""
    s = _script()
    i = s.index("/* P22C2-LM-BITIS */")
    j = s.rindex("init();")
    return s[i:j]


def _run(tmp_path, body: str):
    p = tmp_path / "lm.js"
    p.write_text(_blok("P17-GOSTERIM") + _blok("P22C2-LM") + body, encoding="utf-8")
    proc = subprocess.run([_NODE, str(p)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


# --------------------------------------------------------------------------------------------
# (a) satır biçimi: repl.render ile aynı


def _ornek_olaylar() -> list[dict]:
    s = EventStream("oTEST")
    h = {"fn": "FUN_00001000", "adres": "00001000"}
    s.emit("oturum_basladi", kip="kesif", model="m.gguf · 0123456789ab", arka_uc="yerel_llama_server", baglam=10240,
           ag="kapalı", hiz=None)
    s.emit("oturum_basladi", kip="adlandir", model=None, arka_uc="yok", baglam=None, ag="kapalı", hiz=None)
    s.emit("arka_uc_durumu", durum="hazir", bellek_gib=None)
    s.emit("gorev_basladi", gorev="g1", gorev_turu="ad_oner", kip="adlandir", hedef=h,
           butce={"arac": 8, "jeton": 256, "sure_sn": 900})
    s.emit("arac_basladi", gorev="g1", sonuc="r1", arac="get_evidence", cagiran="sunucu", hedef=h,
           arguman={"addr": "FUN_00001000"})
    s.emit("arac_bitti", gorev="g1", sonuc="r1", arac="get_evidence", tamam=True, hata=None, calistirildi=True,
           tur_kind="olgu", bayt=812, kirpma=False, sure_ms=3, dokunulan=["FUN_00002000"], dokunulan_toplam=1,
           icerik_saklandi=True)
    s.emit("arac_bitti", gorev="g1", sonuc="r2", arac="get_decompiled", tamam=False, hata="veri_bayat",
           calistirildi=False, tur_kind=None, bayt=None, kirpma=True, sure_ms=None, dokunulan=[], dokunulan_toplam=0,
           icerik_saklandi=False)
    s.emit("model_istegi", gorev="g1", amac="k0", istem_kestirim=900)
    s.emit("jeton", gorev="g1", parca=4, karakter=31)
    s.emit("model_cevabi", gorev="g1", amac="k0", durum="tamam", bitis_nedeni="stop", istem_jeton=912,
           uretim_jeton=41, onbellek_jeton=None, sure_ms=3100, niyet="çağrılanlara bak <b>", hata=None)
    s.emit("model_cevabi", gorev="g1", amac="k0", durum="arka_uc_hatasi", bitis_nedeni=None, istem_jeton=None,
           uretim_jeton=None, onbellek_jeton=None, sure_ms=None, niyet=None, hata="bağlantı koptu")
    s.emit("denetim", gorev="g1", nesne="g1", hukum="celiski",
           bulgular=[{"kural": "D7", "kod": "kutuphane_adi", "etki": "celiski", "dayanak": []}], bayraklar=["D12"],
           toplu_kabul=False, sinanan=["D1", "D7"], sinanmayan=["D5", "D4"])
    s.emit("denetim", gorev="g1", nesne="g1", hukum="sinanamadi", bulgular=[], bayraklar=[], toplu_kabul=False,
           sinanan=[], sinanmayan=[])
    s.emit("ozet", gorev="g1", hedef=h, metin="Ağ bağlantısı açar.", belirsiz=True, kanit=["r1", "r2"],
           hukum="sinandi_celiski_yok", kaynak="model")
    s.emit("ozet", gorev="g1", hedef={"fn": None, "adres": "9000"}, metin="x", belirsiz=False, kanit=[],
           hukum=None, kaynak="olgu")
    s.emit("oneri", gorev="g1", oneri_kimligi="p1", hedef=h, oneri_turu="ad", deger="open_connection",
           gerekce="Bağlantı açar.", kanit=["r1"], hukum="sinandi_celiski_yok")
    s.emit("gorev_bitti", gorev="g1", durum="tamam",
           sayaclar={"tool_calls": 2, "model_calls": 1}, sure_ms=3300, hata=None, ad_durumu=None, cevap=None,
           hukum=None, toplu_kabul=None)
    s.emit("iptal", kaynak="analist")
    for duzey in ("bilgi", "uyari", "hata"):
        s.emit("satir", metin=f"{duzey} <script>alert(1)</script>\x1b[2J", duzey=duzey)
    s.emit("oturum_bitti", neden="cik")
    return s.since(0)["olaylar"]


@nodeli
def test_satirlar_repl_render_ile_ayni(tmp_path):
    olaylar = _ornek_olaylar()
    beklenen = [R.render(e) for e in olaylar]
    out = _run(tmp_path, "const E=" + json.dumps(olaylar, ensure_ascii=False) + ";\n"
               "console.log(JSON.stringify(E.map(e=>lmLines(e).map(l=>l.t))));")
    assert out == beklenen
    # satırı olmayan türler: jeton, model_istegi, arac_basladi (sayaç ayrı); ESC ve HTML metin olarak kalır
    turler = {e["tur"]: r for e, r in zip(olaylar, out)}
    assert turler["jeton"] == [] and turler["model_istegi"] == [] and turler["arac_basladi"] == []
    satir = [r for e, r in zip(olaylar, out) if e["tur"] == "satir"]
    assert satir[2] == ["✗ hata <script>alert(1)</script>\\x1b[2J"]     # sunucuda kaçışlanmış, yorumlanmaz
    assert any("niyet (model metni)" in x for r in out for x in r)          # karar 5 (b): satır açık, işaretli


# --------------------------------------------------------------------------------------------
# (b) uzun yoklama istemcisi


# --------------------------------------------------------------------------------------------
# (c) imleç


# --------------------------------------------------------------------------------------------
# (d) öneri kartı


# --------------------------------------------------------------------------------------------
# (e) U-2 / U-3


def _lm_css_kurallari() -> list[tuple[str, str]]:
    css = re.search(r"<style>(.*?)</style>", _html(), re.S).group(1)
    i = css.index("/* ===================== KARADULLM")
    blok = re.sub(r"/\*.*?\*/", "", css[i:], flags=re.S)
    return re.findall(r"([^{}]+)\{([^{}]*)\}", blok)


@nodeli
def test_u3_hiz_olculmeden_beklenen_sure_yok(tmp_path):
    out = _run(tmp_path, r"""
const b={oturum:'o1',kip:'kesif',arka_uc:'hazir',model:'m',ag:'kapalı',takip:true,calisan:null,kuyruk:0,onay_bekleyen:null,hiz:null};
console.log(JSON.stringify([lmStatusText(b), lmStatusText(Object.assign({},b,{hiz:{P:210.4,G:10.9,T:35.62,zaman:'z'}})),
  lmStatusText({oturum:null,model_ayari:null}), lmStatusText({oturum:null,model_ayari:'q4.gguf'}),
  lmStatusText(Object.assign({},b,{hiz:{P:null,G:null,T:null,zaman:'z'}}))]));
""")
    olcmeden, olculmus, yok, ayarli, olculemedi = out
    assert "hız: ölçülmedi" in olcmeden and "beklenen" not in olcmeden and not re.search(r"\d+(\.\d+)? sn", olcmeden)
    assert "beklenen görev ≈ 35.6 sn" in olculmus and "önek 210.4 · üretim 10.9" in olculmus
    assert "hız: ölçülmedi" in olculemedi and "beklenen" not in olculemedi
    assert yok.startswith("oturum yok") and "model yapılandırılmamış" in yok and "q4.gguf" in ayarli


# --------------------------------------------------------------------------------------------
# (f) güvenlik


def test_panel_metni_yalniz_textcontent():
    blok = _blok("P22C2-LM") + _lm_dom()
    for yasak in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert yasak not in blok, yasak
    assert "d.textContent=text" in blok


def test_cekmece_haritanin_altinda_ve_tek_komut_ipucu():
    html = _html()
    sonuc = html[html.index('<section id="result"'):html.index("<!-- ===================== AYARLAR")]
    i_main, i_dr, i_ft = sonuc.index('<div class="rmain">'), sonuc.index('id="lmDrawer"'), sonuc.index("<footer>")
    assert i_main < i_dr < i_ft                                          # karar 4 (a): alt çekmece
    assert "kabuk değildir" in sonuc


