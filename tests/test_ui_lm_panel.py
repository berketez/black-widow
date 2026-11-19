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


@nodeli
def test_yoklama_kacan_olay_tek_satir_dogru_sayi(tmp_path):
    out = _run(tmp_path, r"""
const ev=n=>({seq:n,tur:'satir',metin:'x',duzey:'bilgi'});
const r1=lmPollApply(0,{olaylar:[ev(1),ev(2)],son:2,tasma:false,kacan:0,kapali:false});
const r2=lmPollApply(2,{olaylar:[ev(10),ev(11)],son:11,tasma:true,kacan:7,kapali:false});   // sunucu sayar + boşluk 7
const r3=lmPollApply(11,{olaylar:[ev(12),ev(15)],son:15,tasma:false,kacan:0,kapali:false}); // yalnız boşluk 2
const r4=lmPollApply(15,{olaylar:[],son:15,tasma:false,kacan:0,kapali:true});
console.log(JSON.stringify({r1:[r1.pre,r1.son,r1.stop],r2:[r2.pre,r2.son,r2.lost],r3:[r3.pre,r3.lost],r4:[r4.pre,r4.son,r4.stop]}));
""")
    assert out["r1"] == [[], 2, False]
    assert out["r2"] == [[{"t": "! 7 olay kaçırıldı", "c": "warn"}], 11, 7]
    assert out["r3"] == [[{"t": "! 2 olay kaçırıldı", "c": "warn"}], 2]
    assert out["r4"] == [[], 15, True]


# --------------------------------------------------------------------------------------------
# (c) imleç


@nodeli
def test_imlec_yalniz_olayla_ve_dugum_yoksa_yer_degistirmez(tmp_path):
    out = _run(tmp_path, r"""
const BY={FUN_1:{},FUN_2:{},FUN_3:{}}, DRAWN={FUN_1:{x:1,y:2},FUN_2:{x:3,y:4}};
const g=(fn,adres)=>({tur:'gorev_basladi',hedef:{fn:fn,adres:adres}});
const a=(fn)=>({tur:'arac_basladi',hedef:fn===undefined?null:{fn:fn,adres:'9'}});
const R=[
  lmSpiderAct(g('FUN_2','2'),BY,DRAWN,true),           // takip açık → odak
  lmSpiderAct(g('FUN_2','2'),BY,DRAWN,false),          // takip kapalı, çizili → taşı
  lmSpiderAct(a('FUN_3'),BY,DRAWN,false),              // takip kapalı, çizili değil → haritadan kalk
  lmSpiderAct(g('FUN_9','9'),BY,DRAWN,true),           // modelde yok → yer değiştirmez
  lmSpiderAct(g(null,'9000'),BY,DRAWN,true),           // dosyasız adres (fn null) → yer değiştirmez
  lmSpiderAct(a(undefined),BY,DRAWN,true),             // reddedilen çağrı (hedef null) → hiçbir şey
  lmSpiderAct({tur:'arac_bitti',dokunulan:['FUN_1','FUN_9','FUN_3']},BY,DRAWN,true),
  lmSpiderAct({tur:'jeton',parca:3,karakter:9},BY,DRAWN,true),   // jeton: imleç oynamaz
  lmSpiderAct({tur:'model_cevabi'},BY,DRAWN,true),
  lmSpiderAct({tur:'oneri',oneri_kimligi:'p1',deger:'f',hukum:'celiski',hedef:{fn:'FUN_1'}},BY,DRAWN,true),
  lmSpiderAct({tur:'gorev_bitti'},BY,DRAWN,true),
  lmSpiderAct({tur:'oturum_bitti'},BY,DRAWN,true),
];
console.log(JSON.stringify(R));
""")
    assert out[0] == {"act": "focus", "fn": "FUN_2"}
    assert out[1] == {"act": "move", "fn": "FUN_2"}
    assert out[2]["act"] == "off_map" and out[2]["fn"] == "FUN_3" and "takip kapalı" in out[2]["line"]
    assert out[3]["act"] == "not_on_map" and out[3]["line"].startswith("FUN_9: haritada yok")
    assert "yer değiştirmedi" in out[3]["line"]
    assert out[4]["act"] == "not_on_map" and out[4]["line"].startswith("adres 9000: haritada yok")
    assert out[5] == {"act": "none"}
    assert out[6] == {"act": "touch", "list": ["FUN_1", "FUN_3"]}
    assert out[7] == {"act": "none"} and out[8] == {"act": "none"}
    assert out[9]["act"] == "label" and out[9]["text"] == "öneri p1: f · ÇELİŞKİ"
    assert out[10] == {"act": "idle"} and out[11] == {"act": "remove"}


def test_imlec_yalniz_olay_isleyicisinden_cagrilir():
    """İmleci yerleştiren tek yol olay işleyicisi (lmHandle → lmSpider) ve harita yeniden çizimi (drawRadial →
    lmReanchor; analistin kendi eylemi ya da sahne boyu). Zamanlayıcı / döngüyle hareket yok."""
    s = _script()
    assert s.count("lmSpider(e);") == 1 and s.count("lmSpider(") == 2 and "function lmHandle(e){" in s
    assert re.findall(r"\blmPlace\(", s).__len__() == 4                     # tanım + focus/move + reanchor
    assert len(re.findall(r"\blmReanchor\(\)", s)) == 2                     # tanım + drawRadial sonu
    dom = _lm_dom()
    for yasak in ("setInterval", "requestAnimationFrame", "animate(", ".animation", "infinite"):
        assert yasak not in dom, yasak
    # setTimeout yalnız girişe odak ve ağ yeniden denemesi (ikisi de imleç / satır üretmez)
    st = [ln for ln in dom.splitlines() if "setTimeout" in ln]
    assert len(st) == 2 and all("lmSpider" not in ln and "lmPlace" not in ln and "lmAdd" not in ln for ln in st)


# --------------------------------------------------------------------------------------------
# (d) öneri kartı


@nodeli
def test_oneri_karti_dugmeler_ve_denetim_satirlari(tmp_path):
    out = _run(tmp_path, r"""
const den={hukum:'celiski',bulgular:[{kural:'D7',kod:'kutuphane_adi',etki:'celiski'}],bayraklar:['D12'],
  toplu_kabul:false,sinanan:['D1'],sinanmayan:['D5','D4']};
const p=(o)=>Object.assign({oneri_kimligi:'p1',adres:'1000',oneri_turu:'ad',deger:'open_conn',gerekce:'g',
  hukum:'celiski',durum:'bekleyen',fn:'FUN_00001000',denetim:den},o);
console.log(JSON.stringify([lmCard(p({})), lmCard(p({hukum:'ret'})), lmCard(p({hukum:null,denetim:null})),
  lmCard(p({oneri_turu:'yorum',hukum:null,denetim:null})), lmCard(p({durum:'kabul'})),
  lmCard(p({durum:'ret',neden:'yanlış'})), lmCard(p({fn:null,hukum:'sinandi_celiski_yok',denetim:null}))]));
""")
    c, ret, yok, yorum, kabul, red, fnsiz = out
    assert (c["canAccept"], c["canReject"], c["conflict"]) == (True, True, True)
    assert c["rows"] == ["denetim: ÇELİŞKİ", "  D7 kutuphane_adi (celiski)", "  bayrak: D12",
                         "  bu kurallar koşmadı: D4, D5", "  toplu kabule girmez"]
    assert (c["kind"], c["target"], c["value"]) == ("ad önerisi", "FUN_00001000", "open_conn")
    assert ret["canAccept"] is False and ret["canReject"] is True               # RET: kabul düğmesi yok
    assert yok["canAccept"] is False and yok["rows"][0] == "denetim: hüküm yok"   # hükümsüz ad önerisi
    assert yok["rows"][1].startswith("  denetim ayrıntısı bu oturumun akışında yok")
    assert yorum["canAccept"] is True and yorum["kind"] == "yorum önerisi"
    assert kabul["canAccept"] is False and kabul["canReject"] is False
    assert red["status"] == "ret" and red["why"] == "yanlış" and not red["canReject"]
    assert fnsiz["target"] == "adres 1000"


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


@nodeli
def test_model_adi_ayri_katman_gosterimi(tmp_path):
    out = _run(tmp_path, r"""
const f={addr:'FUN_1',name:'FUN_1',cls:'unnamed'}, g={addr:'FUN_2',name:'parse_x',cls:'named'};
const mn={FUN_1:{name:'open_connection',oneri_kimligi:'p1',hukum:'celiski'}};
console.log(JSON.stringify([lmShownName(f,mn),lmShownName(g,mn),lmShownName(f,null),lmShownName(f,{})]));
""")
    assert out == ["open_connection", "parse_x", "FUN_1", "FUN_1"]
    s = _script()
    # listede model adı "model" rozetiyle; elle ad rozeti öncelikli; sayaçlar (recount / nameCounts) model adını görmez
    assert "iv-mtag lm-model" in s and "model_names" not in s[s.index("function recount"):s.index("async function loadOverrides")]


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
    assert 'id="lmSpider"' in sonuc[sonuc.index('<section class="stage">'):sonuc.index('<section class="code"')]
    assert "kabuk değildir" in sonuc


