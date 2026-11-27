"""P-ÜV6c: Go üst verisinin tutarlılık damgası, okuyucu düzeltmeleri ve yanıltıcı "kısmi" durumu.

Önce: Go adlarının köken kaydında her zaman ``ust_veri_dogrulama: olculmedi`` (P-ÜV7'nin denetimi
çağrılmıyordu); ``GoSonuc`` okuyucu nesnesini taşımıyordu; ``paket`` alanı alıcının ardında ``/``
olan adlarda (yükseltilmiş dışa kapalı yöntem, adsız tip sarmalayıcısı) yanlıştı; ``FUNC_ID`` tablosu
yalnız ``tutarlilik.py``'deydi; evrensel ikilide eski Go çözümleyicisinin iletisi yeni okuyucu adları
okuduğunda da aşama hatası sayılıyordu (koşu kısmi). Şimdi (bayrak ``enable_go_metadata_integrity``,
öntanım kapalı): damga köken kaydına geçer; ``tutarsiz`` adı yazılmaz (kanıt satırı); ikili
``ust_veri_supheli`` ise bütün Go adları kanıt satırı; ``uyari`` raporda gerçek sayılarla; etiket
her zaman ``üst veriden``. Testler sentetik görüntü (``tests/test_puv7_tutarlilik.kur``) ve sahte
yapıtlarla; gerçek ikili yok.
"""
from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from karadul.analyzers.ustveri import go_pclntab as G
from karadul.analyzers.ustveri import tutarlilik as T
from karadul.config import Config
from karadul.core import naming_labels as nl
from karadul.pipeline.context import StepContext
from karadul.pipeline.steps import _feedback_naming_candidates as FC
from karadul.pipeline.steps import _feedback_naming_merger as FM
from karadul.pipeline.steps import go_metadata_recovery as A
from tests.test_puv7_tutarlilik import ANA, F_GOGO, F_PT_AD, F_T_AD, kur

_KOK = Path(__file__).resolve().parents[1]
GO = nl.SOURCE_GO_PCLNTAB
RAN = {"durum": "calisti", "neden": ""}


# =============================================================================================
# 1. Okuyucu düzeltmeleri (hüküm 4)
# =============================================================================================

@pytest.mark.parametrize("ad, paket", [
    # yükseltilmiş dışa kapalı yöntem: son "/" yöntem adının içinde
    ("a/b.(*T).golang.org/x/net/http2.streamEnded", "a/b"),
    ("github.com/docker/cli/cli/command.(*cliReader).github.com/docker/cli/vendor/go.opentelemetry.io"
     "/otel/sdk/metric.register", "github.com/docker/cli/cli/command"),
    # satır içi kapanış: alıcı fonksiyon adından sonra; paket eski kuralla aynı
    ("crypto/x509.policiesValid.(*policyGraph).parents.func1", "crypto/x509"),
    ("net/http.logf.(*Logger).Printf.func1", "net/http"),
    # adsız tip sarmalayıcısı (derleyici): paket yolu yok → önek
    ("go:(*struct { io.Reader; io.WriterTo }).Read", "go:"),
    ("go:struct { io.Reader; io.Closer }.Close", "go:"),
    ("go:interface { ForceFlush(context.Context) error }.ForceFlush-fm", "go:"),
    # değişmeyenler
    ("main.main", "main"),
    ("runtime.(*mheap).alloc", "runtime"),
    ("github.com/a/b.F", "github.com/a/b"),
    ("pkg.(*T[go.shape.int,a/b.X]).M", "pkg"),
    ("gopkg.in/yaml%2ev3.(*decoder).unmarshal", "gopkg.in/yaml%2ev3"),
    ("type:.eq.[2]interface {}", "type:"),
    ("go:(**mSpanList).runtime.init", "go:"),
])
def test_fonksiyon_paketi_alicili_adlar(ad: str, paket: str) -> None:
    assert G.fonksiyon_paketi(ad) == paket


def test_eski_kural_arastirma_tanimi_icin_degismedi() -> None:
    # P-ÜV7'nin araştırma T2p / T3 / T4 sayaçları ve ustveri_bozma örneklemi eski kurala bağlı.
    assert G.paket_adi("a/b.(*T).golang.org/x/net/http2.streamEnded") == "a/b.(*T).golang.org/x/net/http2"
    assert G.paket_adi("go:(*struct { io.Reader }).Read") == "go:(*struct { io"
    assert G.paket_adi("type:.eq.struct { a.b int }") == G.fonksiyon_paketi("type:.eq.struct { a.b int }")


def test_oku_paket_alani_yeni_kuralla_ad_degismez() -> None:
    ad = f"{ANA}/p.(*T).golang.org/x/net/http2.akis"
    g, b = kur(adlar={F_T_AD: ad})
    s = G.oku(g)
    assert s.durum == G.DURUM_CALISTI
    f = next(f for f in s.fonksiyonlar if f.giris == b["girisler"][F_T_AD])
    assert f.ad == ad                       # ozgun_ad değişmez
    assert f.paket == f"{ANA}/p"            # eskisi: …(*T).golang.org/x/net/http2
    assert f.sinif == G.SINIF_KENDI
    assert "pcln" not in f.kayit()


def test_gosonuc_okuyucu_nesnesini_tasir_serilestirilmez() -> None:
    g, _b = kur()
    s = G.oku(g)
    assert isinstance(s.pcln, G.GoPclntab)
    alan = next(f for f in dataclasses.fields(G.GoSonuc) if f.name == "pcln")
    assert alan.repr is False and alan.compare is False
    assert "GoPclntab" not in repr(s)
    assert G.GoSonuc(durum=G.DURUM_VERI_YOK).pcln is None


def test_denetle_sonuc_ile_okuyucuyu_yeniden_kurmaz(monkeypatch: pytest.MonkeyPatch) -> None:
    g, _b = kur(adlar={F_GOGO: "runtime.gogo2"})
    s = G.oku(g)
    beklenen = T.denetle(g)

    def kurma(*_a, **_k):
        raise AssertionError("okuyucu yeniden kuruldu")

    monkeypatch.setattr(T, "GoPclntab", kurma)
    t = T.denetle(g, sonuc=s)
    assert t.durum == G.DURUM_CALISTI
    assert t.damgalar == beklenen.damgalar and t.karar == beklenen.karar


def test_func_id_tek_tanim() -> None:
    assert T.FUNC_ID is G.FUNC_ID and T.FUNC_ID_ADI is G.FUNC_ID_ADI
    assert T.FUNC_ID_SARMALAYICI == G.FUNC_ID_SARMALAYICI == len(G.FUNC_ID) - 1
    kaynak = (_KOK / "karadul/analyzers/ustveri/tutarlilik.py").read_text(encoding="utf-8")
    assert not re.search(r"^FUNC_ID\w*\s*=", kaynak, re.M)


# =============================================================================================
# 2. Üretici adım: damga (hüküm 1)
# =============================================================================================

def _baglam(tmp_path: Path, *, kurtar: object = True, damga: object = False,
            static: object = None) -> StepContext:
    hedef = tmp_path / "ikili"
    hedef.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 60)
    pc = MagicMock()
    pc.config = Config()
    pc.config.binary_reconstruction.enable_go_metadata_recovery = kurtar
    pc.config.binary_reconstruction.enable_go_metadata_integrity = damga
    pc.results = {} if static is None else {"static": static}
    yazilan: dict = {}

    def kaydet(asama, ad, veri):
        yazilan["veri"] = json.loads(json.dumps(veri, default=str))
        return tmp_path / f"{ad}.json"

    pc.workspace.save_json = kaydet
    ctx = StepContext(pipeline_context=pc)
    ctx._write_artifacts({"binary_for_byte_match": hedef})
    ctx.yazilan = yazilan  # type: ignore[attr-defined]
    return ctx


def _kos(ctx: StepContext, g) -> dict:
    import karadul.pipeline.steps.go_metadata_recovery as mod
    eski = mod._goruntu_ac
    mod._goruntu_ac = lambda _y: g
    try:
        return A.GoMetadataRecoveryStep().run(ctx)
    finally:
        mod._goruntu_ac = eski


def test_bayrak_kapaliyken_kayit_ve_dosya_bugunkuyle_ayni(tmp_path) -> None:
    g, _b = kur(adlar={F_GOGO: "runtime.gogo2"})
    ctx = _baglam(tmp_path, damga=False)
    out = _kos(ctx, g)
    assert out["go_status"] == {"durum": "calisti", "neden": ""}
    assert all("dogrulama" not in k for k in out["go_functions"])
    assert out["go_functions"] == [f.kayit() for f in G.oku(g).fonksiyonlar]
    assert "go_metadata_integrity" not in ctx.stats
    assert "tutarlilik" not in ctx.yazilan["veri"]["durum"]


@pytest.mark.parametrize("deger", ["true", 1, None])
def test_bayrak_yalniz_gercek_true_acar(tmp_path, deger) -> None:
    g, _b = kur()
    out = _kos(_baglam(tmp_path, damga=deger), g)
    assert "tutarlilik" not in out["go_status"]


def test_bayrak_ontanimi_kapali() -> None:
    assert Config().binary_reconstruction.enable_go_metadata_integrity is False


def test_bayrak_acikken_damga_ve_ozet(tmp_path) -> None:
    g, b = kur(adlar={F_GOGO: "runtime.gogo2"}, ek_duz=200)
    ctx = _baglam(tmp_path, damga=True)
    out = _kos(ctx, g)
    by = {int(k["giris"], 16): k for k in out["go_functions"]}
    bozuk = by[b["girisler"][F_GOGO]]
    assert bozuk["dogrulama"] == T.DAMGA_TUTARSIZ and bozuk["dogrulama_isaretleri"] == ["T5"]
    assert by[b["girisler"][F_PT_AD]]["dogrulama"] == T.DAMGA_CIFT_KAYNAK
    ozet = out["go_status"]["tutarlilik"]
    assert ozet["karar"] == T.KARAR_UYARI and ozet["guclu_isaretli_fonksiyon"] == 1
    assert ozet["guclu_isaret_dagilimi"] == {"T5": 1}          # T4 zayıf: özete girmez
    assert ctx.stats["go_metadata_integrity"] == ozet
    assert ctx.yazilan["veri"]["durum"]["tutarlilik"]["karar"] == T.KARAR_UYARI


# =============================================================================================
# 3. Ad kanalı: tutarsız ad yazılmaz, şüpheli ikili, uyarı (hüküm 1–3)
# =============================================================================================

def _index(*addrs: int) -> FC.GhidraFunctionIndex:
    by_addr = {a: f"FUN_{a:08x}" for a in addrs}
    return FC.GhidraFunctionIndex(by_addr=by_addr, names=frozenset(by_addr.values()))


def _flags(**on: bool) -> dict[str, bool]:
    return {src: bool(on.get(src)) for src in FC.K4_CHANNEL_FLAGS}


def _go(addr: int, ad: str, damga: str | None = None, **kw) -> dict:
    r = {"giris": hex(addr), "bitis": hex(addr + 0x40), "ad": ad, "paket": ad.split(".")[0],
         "pcsp_kapsama": "tam"}
    if damga is not None:
        r["dogrulama"] = damga
    r.update(kw)
    return r


def _status(karar: str | None) -> dict:
    if karar is None:
        return dict(RAN)
    return {**RAN, "tutarlilik": {"durum": "calisti", "karar": karar,
                                  "karar_nedeni": "güçlü işaretli 3 / 208 fonksiyon"}}


def _run(index, go, status, flags=None, **kw) -> SimpleNamespace:
    cands: dict = {}
    stats: dict = {}
    recs: dict = {}
    ev: list = []
    FC.add_k4_channels(flags=flags or _flags(**{GO: True}), index=index, binary_path=kw.pop("binary_path", None),
                       pdb_symbols=[], pdb_status=None, bn_functions=[], bn_status=None,
                       trex_structs=[], trex_status=None, go_functions=go, go_status=status,
                       metadata_records=recs, metadata_evidence=ev, candidates=cands, stats=stats)
    return SimpleNamespace(cands=cands, ch=stats["naming_channels"], recs=recs, ev=ev)


def test_tutarsiz_damgali_ad_yazilmaz_kanit_satiri_olur() -> None:
    r = _run(_index(0x1000, 0x1100), [
        _go(0x1000, "main.main", T.DAMGA_CIFT_KAYNAK),
        _go(0x1100, "a.F", T.DAMGA_TUTARSIZ, dogrulama_isaretleri=["T2"]),
    ], _status(T.KARAR_UYARI))
    assert set(r.cands) == {"FUN_00001000"}
    assert r.ev == [{"kaynak": GO, "adres": "0x1100", "ozgun_ad": "a.F", "nedenler": ["tutarsiz"],
                     "isaretler": ["T2"]}]
    assert r.ch[GO]["tutarsiz_elendi"] == 1 and r.ch[GO]["aday"] == 1
    assert r.ch[GO]["dogrulama"] == {"cift_kaynak": 1, "tutarsiz": 1}
    assert r.ch[GO]["ikili_karari"] == T.KARAR_UYARI
    assert r.recs["FUN_00001000"][nl.METADATA_CHECK_FIELD] == T.DAMGA_CIFT_KAYNAK


def test_supheli_ikilide_butun_go_adlari_kanit_satiri() -> None:
    r = _run(_index(0x1000, 0x1100), [
        _go(0x1000, "main.main", T.DAMGA_CIFT_KAYNAK), _go(0x1100, "a.G", T.DAMGA_TEK_KAYNAK)],
        _status(T.KARAR_UST_VERI_SUPHELI))
    assert r.cands == {} and r.recs == {}
    assert [e["nedenler"] for e in r.ev] == [["ust_veri_supheli"], ["ust_veri_supheli"]]
    assert r.ev[0]["ikili_karari_nedeni"] == "güçlü işaretli 3 / 208 fonksiyon"
    assert r.ch[GO]["ust_veri_supheli_elendi"] == 2


def test_uyari_ikilide_adlar_yazilir_damgasiz_kayit_bugunku_gibi() -> None:
    r = _run(_index(0x1000), [_go(0x1000, "main.main", T.DAMGA_TEK_KAYNAK)], _status(T.KARAR_UYARI))
    assert [c.name for c in r.cands["FUN_00001000"]] == ["main_main"]
    r0 = _run(_index(0x1000), [_go(0x1000, "main.main")], _status(None))
    assert nl.METADATA_CHECK_FIELD not in r0.recs["FUN_00001000"]
    assert "dogrulama" not in r0.ch[GO] and "ikili_karari" not in r0.ch[GO]


def test_iki_go_kanali_ayni_adrese_iki_aday_uretmez(monkeypatch) -> None:
    # hüküm 6: go_demangler (nm) go_pclntab açıkken aynı adrese ikinci aday üretmez.
    monkeypatch.setattr(FC, "_extract_binary_symbols", lambda _p: [("main.main", 0x1000)])
    r = _run(_index(0x1000), [_go(0x1000, "main.main", T.DAMGA_CIFT_KAYNAK)], _status(T.KARAR_TEMIZ),
             flags=_flags(**{GO: True, "go_demangler": True}), binary_path=Path("x"))
    assert [c.source for c in r.cands["FUN_00001000"]] == [GO]
    assert r.ch["go_demangler"]["ust_veri_onde"] == 1 and "aday" not in r.ch["go_demangler"]


# =============================================================================================
# 4. Köken kaydı: damga taşınır, etiket değişmez (hüküm 3, H6)
# =============================================================================================

@pytest.mark.parametrize("damga, beklenen", [
    (T.DAMGA_CIFT_KAYNAK, "cift_kaynak"), (T.DAMGA_TEK_KAYNAK, "tek_kaynak"), (None, "olculmedi")])
def test_koken_kaydi_damga_tasir_etiket_kesin_olmaz(damga, beklenen) -> None:
    meta = {"kaynak": GO, "adres": "0x1000", "ozgun_ad": "main.main", "ad": "main_main"}
    if damga is not None:
        meta[nl.METADATA_CHECK_FIELD] = damga
    karar = FM.metadata_decision(meta, "main_main")
    assert karar[nl.METADATA_CHECK_FIELD] == beklenen
    assert karar["label"] == nl.LABEL_METADATA != nl.LABEL_CERTAIN
    assert karar["confidence"] == nl.MEASURED_METADATA_PRECISION[GO][2]


# =============================================================================================
# 5. Rapor uyarısı (hüküm 2)
# =============================================================================================

def _rapor(gi: dict | None, ch: dict | None = None):
    from karadul.reporting import report_data as rd
    st = {"naming_by_label": {nl.LABEL_CERTAIN: 1}, "name_merger_by_label": {nl.LABEL_METADATA: 5}}
    if gi is not None:
        st["go_metadata_integrity"] = gi
    if ch is not None:
        st["naming_channels"] = {GO: ch}
    res = SimpleNamespace(stages={"reconstruct": SimpleNamespace(stats=st)})
    return rd._naming(res, None)


def _gi(karar: str, guclu: int = 66, tutarsiz: int = 66) -> dict:
    return {"durum": "calisti", "karar": karar, "karar_nedeni": f"güçlü işaretli {guclu} / 40384 fonksiyon",
            "fonksiyon": 40384, "guclu_isaretli_fonksiyon": guclu,
            "guclu_isaret_dagilimi": {"T1": 20, "T2": 66}, "adli_damga": {"tutarsiz": tutarsiz}}


def test_rapor_uyari_gercek_sayilarla() -> None:
    sec = _rapor(_gi(T.KARAR_UYARI), {"tutarsiz_elendi": 66})
    w = sec.extra["go_metadata_warning"]
    assert w["verdict"] == "uyari" and w["strong_signal_functions"] == 66 and w["functions"] == 40384
    assert w["strong_checks"] == {"T1": 20, "T2": 66} and w["withheld"] == 66
    assert "WARNING: Go metadata integrity check verdict 'uyari'" in sec.summary
    assert "66 of 40384 Go functions" in sec.summary and "T1: 20, T2: 66" in sec.summary
    assert "(66)" in sec.summary


def test_rapor_supheli_butun_adlar_kanit() -> None:
    sec = _rapor(_gi(T.KARAR_UST_VERI_SUPHELI, 900, 900), {"ust_veri_supheli_elendi": 40000})
    assert sec.extra["go_metadata_warning"]["withheld"] == 40000
    assert "all Go metadata names withheld as evidence rows (40000)" in sec.summary


@pytest.mark.parametrize("gi", [None, {"durum": "calisti", "karar": "temiz"}, {"durum": "hata", "karar": None}])
def test_rapor_temiz_ya_da_damgasiz_uyari_yok(gi) -> None:
    sec = _rapor(gi)
    assert "go_metadata_warning" not in sec.extra and "WARNING" not in sec.summary


# =============================================================================================
# 6. Yanıltıcı "kısmi" (hüküm 5)
# =============================================================================================

def _statik_sonuc() -> SimpleNamespace:
    from karadul.stages import _note_universal_special_slices
    hedef = SimpleNamespace(metadata={"go_slice": True})
    sr = SimpleNamespace(stats={}, errors=["başka bir hata"])
    _note_universal_special_slices(hedef, sr)
    return sr


def test_evrensel_ileti_yeni_okuyucu_calistiysa_bilgi_satirina_iner(tmp_path) -> None:
    from karadul.core.pipeline import analysis_outcome
    sr = _statik_sonuc()
    assert len(sr.errors) == 2 and sr.stats["go_hatti_status"] == "desteklenmiyor"
    g, _b = kur()
    ctx = _baglam(tmp_path, static=sr)
    _kos(ctx, g)
    assert sr.errors == ["başka bir hata"]
    assert sr.stats["go_hatti_status"] == A.EVRENSEL_DURUM_BILGI
    assert sr.stats["go_hatti_bilgi"] == A.EVRENSEL_BILGI and "go_hatti_error" not in sr.stats
    assert ctx.stats["go_universal_note"] == A.EVRENSEL_DURUM_BILGI
    # yalnız bu ileti vardıysa analiz durumu "tam" olur
    sr2 = _statik_sonuc()
    sr2.errors.remove("başka bir hata")
    _kos(_baglam(tmp_path, static=sr2), g)
    sonuc = SimpleNamespace(stages={"static": SimpleNamespace(skipped=False, success=True,
                                                               errors=sr2.errors, stats=sr2.stats)})
    assert analysis_outcome(sonuc)["status"] == "tam"


def test_evrensel_ileti_okuyucu_kapali_ya_da_okuyamadiysa_hata_kalir(tmp_path) -> None:
    sr = _statik_sonuc()
    _kos(_baglam(tmp_path, kurtar=False, static=sr), kur()[0])
    assert len(sr.errors) == 2 and sr.stats["go_hatti_status"] == "desteklenmiyor"
    sr = _statik_sonuc()
    g = MagicMock()
    import karadul.pipeline.steps.go_metadata_recovery as mod
    eski = mod.go_pclntab.oku
    mod.go_pclntab.oku = lambda _g: G.GoSonuc(durum=G.DURUM_VERI_YOK, neden="Go pclntab yok")
    try:
        A.GoMetadataRecoveryStep().run(_baglam(tmp_path, static=sr))
    finally:
        mod.go_pclntab.oku = eski
    assert len(sr.errors) == 2 and any("evrensel ikilide go dilimi" in e for e in sr.errors)
    del g


def test_evrensel_ileti_bun_dilimine_dokunulmaz(tmp_path) -> None:
    from karadul.stages import _note_universal_special_slices
    sr = SimpleNamespace(stats={}, errors=[])
    _note_universal_special_slices(SimpleNamespace(metadata={"bun_slice": True}), sr)
    _kos(_baglam(tmp_path, static=sr), kur()[0])
    assert len(sr.errors) == 1 and sr.stats["bun_hatti_status"] == "desteklenmiyor"
