"""P22e — KaradulLM oturumu: tekrar anahtarı, defter, oturum yaşam döngüsü, plan, iptal / devam.

Bölümler:
  (0) ``Agent._call_key``: ``find_path``'in ``to``'su da tek yazıma (P22d bulgusu; tekrar yakalanır).

Gerçek model yok: sahte arka uç (``FakeBackend``) ve sentetik çalışma alanı (``tests/test_lm_tools.py``).
Mutasyon koruması: ``scripts/measurement/mutation_specs_lm_oturum.json``.
"""
from __future__ import annotations

import json

from karadul.lm import agent as G
from karadul.lm import backend as B
from karadul.lm import tools as T
from tests.test_lm_tools import A, D, default_ws, fun


def _cagri(tool: str, **args) -> B.FakeReply:
    return B.FakeReply(content=json.dumps({"kind": "call", "tool": tool, "args": args}))


_CEKIMSER = B.FakeReply(content=json.dumps({"kind": "final", "isim": None, "gerekce": "Eksik.", "cekimser": True,
                                            "kanit": []}))


# --------------------------------------------------------------------------------------------
# (0) tekrar anahtarı: bütün adres argümanları tek yazıma


def test_tekrar_anahtari_find_path_hedefini_de_tek_yaziya_cevirir(tmp_path):
    ws = T.Workspace(default_ws(tmp_path / "ws"))
    arka = B.FakeBackend([
        _cagri("find_path", addr=fun(D), to="FUN_1000"),            # çalışır
        _cagri("find_path", addr=fun(D), to=fun(A)),                 # aynı çağrı, dolgulu yazım → tekrar
        _cagri("find_path", addr="FUN_4000", to="FUN_00001000"),     # iki uç da başka yazım → tekrar
        _cagri("find_path", addr=fun(D), to=fun(A), max_depth=2),    # başka argüman → yeni çağrı
        _CEKIMSER])
    ajan = G.Agent(arka, ws, registry=T.full_registry(), enabled_modes=("K0", "K2"))
    r = ajan.run_loop(fun(A))
    c = r.counters
    assert r.status == "tamam"
    assert (c.call_requests, c.tool_calls, c.repeats) == (4, 2, 2)
    # anahtar: iki adres alanı da ``FUN_<çalışma alanı yazımı>``; tanınmayan adres olduğu gibi kalır
    k1 = ajan._call_key("find_path", {"addr": "FUN_4000", "to": "FUN_1000"})
    k2 = ajan._call_key("find_path", {"addr": fun(D), "to": fun(A)})
    assert k1 == k2 and json.loads(k1[1])["to"] == fun(A)
    assert json.loads(ajan._call_key("find_path", {"addr": fun(D), "to": "FUN_fffff"})[1])["to"] == "FUN_fffff"


# --------------------------------------------------------------------------------------------
# (1) defter (``notebook.py``)

import os  # noqa: E402

import pytest  # noqa: E402

from karadul.lm import BUDGET_SESSION_TOKENS  # noqa: E402
from karadul.lm import context as C  # noqa: E402
from karadul.lm import notebook as N  # noqa: E402

SHA = "ab" * 32


def _izin(p) -> int:
    return os.stat(p).st_mode & 0o777


def _oneri(nb, adres="1000", deger="parse_table", tur="ad", kimlik=None):
    return nb.append(N.NoteRecord("oneri", "2026-11-18T20:00:00+03:00", "o1", adres=adres,
                                  oneri_kimligi=kimlik or nb.next_proposal_id(), oneri_turu=tur, deger=deger,
                                  gerekce="Tabloyu ayrıştırır.", hukum="sinandi_celiski_yok", gorev="g1"))


def test_defter_izinler_oneri_durumu_ve_kararlar(tmp_path):
    nb = N.Notebook(SHA, root=tmp_path)
    assert nb.records() == [] and not (tmp_path / SHA).exists()        # okumak dosya açmaz
    nb.note("o1", "1000", "ağ kodu burada olabilir")
    assert _izin(tmp_path / SHA) == 0o700 and _izin(nb.path) == 0o600
    assert nb.next_proposal_id() == "p1"
    _oneri(nb)
    _oneri(nb, adres="2000", deger="Ağ bağlantısını açar.", tur="yorum")
    assert nb.next_proposal_id() == "p3"
    assert [p["durum"] for p in nb.pending()] == ["bekleyen", "bekleyen"]
    nb.append(N.NoteRecord("ret", "z", "o1", oneri_kimligi="p1", neden="yanlış: tabloyu değil başlığı okuyor"))
    nb.append(N.NoteRecord("kabul", "z", "o1", oneri_kimligi="p2"))
    durum = {p["oneri_kimligi"]: (p["durum"], p.get("neden")) for p in nb.proposals()}
    assert durum == {"p1": ("ret", "yanlış: tabloyu değil başlığı okuyor"), "p2": ("kabul", None)}
    assert nb.pending() == [] and nb.rejected_names() == {"1000": {"parse_table"}}
    _oneri(nb, adres="1000", deger="bekleyen_ad")                            # bekleyen ad D10'a girmez
    assert nb.rejected_names() == {"1000": {"parse_table"}}
    # yeniden okunan defter aynı; hiçbir şey silinmez, satır sayısı = kayıt sayısı
    yeni = N.Notebook(SHA, root=tmp_path)
    assert [r.as_dict() for r in yeni.records()] == [r.as_dict() for r in nb.records()]
    assert len(nb.path.read_text(encoding="utf-8").splitlines()) == 6 and yeni.last_time() == "2026-11-18T20:00:00+03:00"
    # kurallar
    for kotu, ileti in [
        (N.NoteRecord("ret", "z", "o1", oneri_kimligi="p1", neden="x"), "zaten"),
        (N.NoteRecord("kabul", "z", "o1", oneri_kimligi="p9"), "yok"),
        (N.NoteRecord("ret", "z", "o1", oneri_kimligi="p2"), "neden"),
        (N.NoteRecord("sil", "z", "o1"), "bilinmeyen"),
        (N.NoteRecord("analist_notu", "z", "o1", adres="0x1000", metin="x"), "adres"),
        (N.NoteRecord("analist_notu", "z", "o1", adres="1000", metin="a\x1b[2Jb"), "U\\+001B"),
        (N.NoteRecord("analist_notu", "z", "o1", adres="1000", metin="a‮b"), "U\\+202E"),
        (N.NoteRecord("analist_notu", "z", "../x", adres="1000", metin="x"), "oturum"),
        (N.NoteRecord("oneri", "z", "o1", adres="1000", oneri_kimligi="p1", oneri_turu="ad", deger="x"), "yineleniyor"),
        (N.NoteRecord("oneri", "z", "o1", adres="1000", oneri_kimligi="q1", oneri_turu="ad", deger="x"), "p<sayı>"),
        (N.NoteRecord("oneri", "z", "o1", adres="1000", oneri_kimligi="p7", oneri_turu="kabuk", deger="x"), "tür"),
    ]:
        with pytest.raises(N.NotebookError, match=ileti):
            nb.append(kotu)
    assert len(nb.path.read_text(encoding="utf-8").splitlines()) == 6
    with pytest.raises(ValueError):
        N.Notebook("../x", root=tmp_path)


def test_defter_sembolik_bag_ve_bozuk_satir(tmp_path):
    hedef = tmp_path / "baska.jsonl"
    hedef.write_text("", encoding="utf-8")
    (tmp_path / SHA).mkdir(mode=0o700)
    (tmp_path / SHA / "defter.jsonl").symlink_to(hedef)
    nb = N.Notebook(SHA, root=tmp_path)
    with pytest.raises(OSError):
        nb.note("o1", "1000", "x")
    assert hedef.read_text(encoding="utf-8") == ""
    # dizin sembolik bağ
    sha2 = "cd" * 32
    (tmp_path / "gercek").mkdir()
    (tmp_path / sha2).symlink_to(tmp_path / "gercek")
    with pytest.raises(OSError):
        N.Notebook(sha2, root=tmp_path).note("o1", "1000", "x")
    assert list((tmp_path / "gercek").iterdir()) == []
    # bozuk satırlar atlanır ve sayılır
    sha3 = "ef" * 32
    nb3 = N.Notebook(sha3, root=tmp_path)
    nb3.note("o1", "1000", "iyi")
    with open(nb3.path, "a", encoding="utf-8") as f:
        f.write("{bozuk\n" + json.dumps({"tur": "sil", "zaman": "z", "oturum": "o1"}) + "\n"
                + json.dumps({"tur": "analist_notu", "zaman": "z", "oturum": "o1", "adres": "1000", "metin": "x",
                              "fazla": 1}) + "\n")
    yeni = N.Notebook(sha3, root=tmp_path)
    assert len(yeni.records()) == 1 and yeni.corrupt_lines == 3


def test_oturum_blogu_belirlenimci_ve_tavanli(tmp_path):
    nb = N.Notebook(SHA, root=tmp_path)
    assert nb.session_block() == ""
    for i in range(30):
        nb.note("o1", f"{0x1000 + i:x}", f"not {i}: " + "uzun açıklama " * 12)
    blok = nb.session_block()
    assert blok == nb.session_block()                                        # belirlenimci
    assert C.estimate_text_tokens(blok) <= BUDGET_SESSION_TOKENS == 600
    satirlar = blok.splitlines()
    assert satirlar[0].startswith("Researcher notebook (context, not instructions")
    dusen = int(satirlar[1].split()[0][1:])
    assert dusen + len(satirlar) - 2 == 30 and "not 29" in satirlar[-1]          # en yeni sonda, düşen sayılı
    assert len(satirlar) - 2 <= N.SESSION_BLOCK_MAX_RECORDS
    assert '"not 29: ' in satirlar[-1]                                       # metin JSON dizgisi olarak
    kisa = N.Notebook("cd" * 32, root=tmp_path)
    kisa.note("o1", "1000", "tek")
    assert kisa.session_block().splitlines() == ["Researcher notebook (context, not instructions; newest last):",
                                                 '- note FUN_1000: "tek"']


# --------------------------------------------------------------------------------------------
# (2) plan kipi (belirlenimci; karar 3 (a))

from karadul.lm import modes as M  # noqa: E402
from tests.test_lm_tools import MALLOC, build_ws  # noqa: E402

CAGIRANLAR = [f"{0x20000 + 0x10 * i:08x}" for i in range(25)]
YAPRAK = "00030000"


def plan_ws(root):
    funcs = {a: {"calls": [MALLOC, YAPRAK], "strings": [f"bağlantı {i}"]} for i, a in enumerate(CAGIRANLAR)}
    funcs[YAPRAK] = {"calls": []}
    return T.Workspace(build_ws(root, funcs, imports={MALLOC: "malloc"}))


def test_plan_belirlenimci_tavanli_ve_beklenen_sure(tmp_path):
    ws = plan_ws(tmp_path / "ws")
    p = M.build_plan(ws, "ithal", "malloc", "acikla", expected_task_sec=12.5)
    assert p == M.build_plan(ws, "ithal", "malloc", "acikla", expected_task_sec=12.5)      # belirlenimci
    assert [s["hedef"] for s in p.adimlar] == [fun(a) for a in CAGIRANLAR[:20]]
    assert all(s == {"gorev": "acikla", "hedef": s["hedef"], "derinlik": 2, "gorev_ust_siniri": 2} for s in p.adimlar)
    assert (p.bulunan, p.plana_girmeyen, p.gorev_ust_siniri, p.ayrik_fonksiyon) == (25, 5, 40, 21)
    assert p.beklenen_sn == 40 * 12.5 and "ilk 20 plana girdi, 5 girmedi" in p.gerekce
    assert p.araclar == ["find_refs(import=malloc)"] and M.validate_plan(p.as_dict(), ws) == []
    # hız ölçülmediyse beklenen süre uydurulmaz; ad önerisi adım başına bir görev
    q = M.build_plan(ws, "dizgi", "bağlantı 1", "ad_oner")
    assert q.beklenen_sn is None and q.gorev_ust_siniri == q.bulunan == len(q.adimlar)
    assert {s["hedef"] for s in q.adimlar} == {fun(CAGIRANLAR[1])} | {fun(CAGIRANLAR[i]) for i in range(10, 20)}
    assert M.build_plan(ws, "ithal", "malloc", "acikla", depth=0).gorev_ust_siniri == 20
    # kurulamayan plan: ithal adı yok, eşleşme yok
    with pytest.raises(M.PlanError, match="ithal listesinde yok"):
        M.build_plan(ws, "ithal", "connect", "acikla")
    with pytest.raises(M.PlanError, match="eşleşen"):
        M.build_plan(ws, "dizgi", "yok böyle", "acikla")
    for kotu in (dict(kind="kabuk"), dict(task="sil"), dict(depth=3)):
        args = {"kind": "ithal", "value": "malloc", "task": "acikla", **kotu}
        with pytest.raises(ValueError):
            M.build_plan(ws, args.pop("kind"), args.pop("value"), args.pop("task"), **args)


def test_plan_dogrulama_adresleri_ve_semayi_sinar(tmp_path):
    ws = plan_ws(tmp_path / "ws")
    iyi = {"adimlar": [{"gorev": "acikla", "hedef": fun(CAGIRANLAR[0]), "derinlik": 1}], "gerekce": "x"}
    assert M.validate_plan(iyi, ws) == []
    def adim(**k):
        return {"adimlar": [{"gorev": "acikla", "hedef": fun(CAGIRANLAR[0]), "derinlik": 1, **k}], "gerekce": "x"}
    for plan, ileti in [
        ([], "alanlarını"), ({"adimlar": []}, "alanlarını"), ({"adimlar": [], "gerekce": "x", "fazla": 1}, "alanlarını"),
        ({"adimlar": [], "gerekce": "x"}, "adım sayısı"),
        ({"adimlar": [iyi["adimlar"][0]] * 21, "gerekce": "x"}, "adım sayısı"),
        (adim(gorev="sil"), "görev"), (adim(hedef="FUN_99999"), "hedef"), (adim(hedef=f"FUN_{MALLOC}"), "hedef"),
        (adim(derinlik=3), "derinlik"), (adim(derinlik=True), "derinlik"), (adim(komut="ls"), "alanlar"),
        ({"adimlar": iyi["adimlar"] * 2, "gerekce": "x"}, "yineleniyor"),
    ]:
        hatalar = M.validate_plan(plan, ws)
        assert hatalar and any(ileti in h for h in hatalar), (plan, hatalar)


# --------------------------------------------------------------------------------------------
# (3) oturum: yaşam döngüsü, kipler ve öneriler, analizle dışlama, iptal / devam, plan yürütme

import threading  # noqa: E402

from karadul.lm import session as S  # noqa: E402
from karadul.lm.audit import AuditLog  # noqa: E402
from tests.test_lm_summaries import R as ZR, X as ZX, ZINCIR_METIN, OzetArka, zincir_ws  # noqa: E402

BEKLE = 20.0


@pytest.fixture(autouse=True)
def _oturumu_kapat():
    yield
    s = S.current_session()
    if s is not None:
        s.close()


def ac(root, arka, *, ws_root=None, **kw):
    if ws_root is None:
        ws_root = root / "ws" if (root / "ws").exists() else zincir_ws(root / "ws").root
    return S.open_session(ws_root, backend=arka, binary_sha256=SHA, store_root=root / "depo", **kw)


def olay(s, tur=None):
    return [e for e in s.stream.since(0)["olaylar"] if tur is None or e["tur"] == tur]


def satir(s) -> list[str]:
    return [e["metin"] for e in olay(s, "satir")]


AD_CEVAP = {"isim": "open_connection", "gerekce": "Bağlantı açar.", "cekimser": False, "kanit": ["r1"]}


def _kanit_kimlikleri(sema) -> list[str]:
    """Şemadaki ilk ``kanit`` kimlik listesi (o istekte verilen sonuç kimlikleri)."""
    if isinstance(sema, dict):
        k = sema.get("properties", {}).get("kanit", {}).get("items", {}).get("enum")
        if k:
            return list(k)
        for v in sema.values():
            r = _kanit_kimlikleri(v)
            if r:
                return r
    if isinstance(sema, list):
        for v in sema:
            r = _kanit_kimlikleri(v)
            if r:
                return r
    return []


class AdArka(B.FakeBackend):
    """"Ad öner" cevabını istekten kuran sahte arka uç: ``kanit`` o istekte verilen ilk kimlik."""

    def __init__(self, n: int = 1, isim: str = AD_CEVAP["isim"], **kw):
        super().__init__([], **kw)
        self.kalan = n
        self.isim = isim

    def _chat(self, messages, schema, stream, max_tokens, on_token):
        c = json.dumps({**AD_CEVAP, "isim": self.isim, "kanit": _kanit_kimlikleri(schema)[:1]}, ensure_ascii=False)
        self.replies = [B.FakeReply(content=c, chunks=[c[:5], c[5:]])] if self.kalan > 0 else []
        self.kalan -= 1
        return super()._chat(messages, schema, stream, max_tokens, on_token)


def test_oturum_yasam_dongusu_tek_oturum(tmp_path):
    arka = OzetArka(dict(ZINCIR_METIN), audit=AuditLog())
    with pytest.raises(S.SessionError):
        S.open_session(tmp_path / "yok", backend=arka, binary_sha256=SHA)
    with pytest.raises(S.SessionError):
        ac(tmp_path, arka, ws_root=zincir_ws(tmp_path / "w0").root, session_id="../x")
    assert S.current_session() is None                                       # başarısız açılış yuvayı tutmaz
    s = ac(tmp_path, arka)
    assert S.current_session() is s
    ilk = olay(s)[0]
    assert ilk["tur"] == "oturum_basladi" and ilk["seq"] == 1 and ilk["oturum"] == s.id
    assert (ilk["kip"], ilk["arka_uc"], ilk["baglam"], ilk["ag"], ilk["hiz"]) == ("kesif", "sahte", 10240, "kapalı",
                                                                                   None)
    assert satir(s)[:2] == ["kip: keşif (salt okur · uygula yok · çalıştır yok · ağ kapalı)",
                            "bu ikili için defter ve özet deposu boş"]
    assert olay(s, "arka_uc_durumu")[0]["durum"] == "kapali"
    with pytest.raises(S.SessionExists, match="zaten açık"):
        ac(tmp_path, OzetArka({}))
    assert s.submit("/yardim")["kabul"] and any("kabuk değildir" in x for x in satir(s))
    r = s.submit("/ls -la")
    assert r == {"kabul": False, "is": None, "hata": "bilinmeyen komut: /ls (/yardim)"}
    assert olay(s)[-1] == {**olay(s)[-1], "tur": "satir", "duzey": "hata"}
    assert s.submit("bu ne?")["kabul"] is False and "sorusu görevi henüz bağlı değil" in satir(s)[-1]
    # denetim kaydı içeriksiz: girdi metni yazılmaz
    girdiler = [k for k in arka.audit.records if k["olay"] == "girdi"]
    assert len(girdiler) == 3 and all("-la" not in json.dumps(k) and "bu ne" not in json.dumps(k) for k in girdiler)
    s.submit("/cik")
    assert s.closed and S.current_session() is None and arka.stops == ["cikis"]
    son = s.stream.since(0)
    assert son["olaylar"][-1]["tur"] == "oturum_bitti" and son["olaylar"][-1]["neden"] == "cik" and son["kapali"]
    s.close()                                                                # ikinci kapanış etkisiz
    assert s.submit("/yardim") == {"kabul": False, "is": None, "hata": "oturum kapalı"}
    ikinci = ac(tmp_path, OzetArka({}))                                      # yuva boşaldı
    assert ikinci.id != s.id
    with pytest.raises(S.SessionError):
        S.Session(zincir_ws(tmp_path / "w2").root, backend=None, binary_sha256="kisa")


def test_kip_izinleri_yorum_ve_ad_onerisi(tmp_path):
    arka = OzetArka(dict(ZINCIR_METIN))
    s = ac(tmp_path, arka)
    # keşif: açıklar ama öneri açmaz; /ad keşifte yok
    assert s.submit(f"/acikla {fun(ZR)} 0")["kabul"] and s.wait_idle(BEKLE)
    assert olay(s, "oneri") == [] and "keşif kipinde yorum önerisi yok" in satir(s)[-1]
    assert s.submit(f"/ad {fun(ZX)}")["hata"] == "ad önerisi adlandır kipinde: /kip adlandir"
    # açıkla: kökün özeti yorum önerisi olur (defterde bekleyen)
    s.submit("/kip açıkla")
    assert satir(s)[-1].startswith("kip: açıkla (öneri: yorum")
    assert s.submit(f"/acikla {fun(ZX)} 0")["is"] == "i2" and s.wait_idle(BEKLE)
    o = olay(s, "oneri")
    assert len(o) == 1 and (o[0]["oneri_kimligi"], o[0]["oneri_turu"], o[0]["deger"]) == ("p1", "yorum",
                                                                                         "X işini yapar.")
    assert o[0]["hedef"] == {"fn": fun(ZX), "adres": ZX} and o[0]["gorev"] is not None
    assert [p["oneri_kimligi"] for p in s.notebook.pending()] == ["p1"]
    # uzun iş: hız ölçülmedi → kapanışı 5 olan zincir onay bekler; /onayla başlatır
    r = s.submit(f"/acikla {fun(ZR)}")
    assert r["kabul"] and "en çok 5 görev" in satir(s)[-1] and "hız ölçülmedi" in satir(s)[-1]
    assert s.status()["onay_bekleyen"] == {"is": r["is"], "tur": "acikla"} and s.status()["kuyruk"] == 0
    assert s.submit("/onayla")["is"] == r["is"] and s.wait_idle(BEKLE)
    assert [e["gorev_turu"] for e in olay(s, "gorev_basladi")][-5:] == ["ozet_alt"] * 4 + ["acikla"]
    assert s.submit("/onayla")["hata"] == "onay bekleyen iş yok"
    # adlandır: ad önerisi
    s.submit("/kip adlandir")
    arka.metinler = {}
    s.agent.backend = AdArka()
    assert s.submit(f"/ad {fun(ZX)}")["kabul"] and s.wait_idle(BEKLE)
    o = olay(s, "oneri")[-1]
    assert (o["oneri_turu"], o["deger"]) == ("ad", "open_connection") and o["hukum"] is not None
    assert len(o["kanit"]) == 1 and o["kanit"][0].startswith("r")
    # denetim RET veren ad önerisi açılmaz (C anahtar sözcüğü: D1)
    s.agent.backend = AdArka(isim="while")
    assert s.submit(f"/ad {fun(ZR)}")["kabul"] and s.wait_idle(BEKLE)
    assert olay(s, "oneri")[-1] == o and "denetim RET" in satir(s)[-1]
    # plan kipinde görev komutu yok; kip değişikliği görev sürerken yok
    s.submit("/kip plan")
    assert "plan kipinde işler /plan" in s.submit(f"/acikla {fun(ZX)}")["hata"]


def test_karar_ret_nedeni_d10_ve_kabulde_yeniden_denetim(tmp_path):
    from tests.test_lm_tools import B as FB
    s = ac(tmp_path, B.FakeBackend([]), ws_root=default_ws(tmp_path / "ws"))
    nb = s.notebook
    for adres, deger in ((A, "parse_input_line"), (A, "malloc"), (FB, "read_header"), (A, "yorum metni")):
        _oneri(nb, adres=adres, deger=deger, tur="yorum" if " " in deger else "ad")
    assert s.decide("p1", "ret")["hata"] == "ret için neden zorunlu"
    assert s.decide("p1", "ret", "   ")["hata"] == "ret için neden zorunlu"
    assert "U+001B" in s.decide("p1", "ret", "kötü\x1b")["hata"]
    assert s.decide("p1", "sil")["hata"] == "karar kabul ya da ret olmalı"
    assert s.decide("p9", "kabul")["hata"] == "böyle bir öneri yok"
    r = s.decide("p1", "ret", "tabloyu değil satırı okuyor")
    assert r["tamam"] and r["oneri"]["durum"] == "ret" and "parse_input_line" in s.agent.rejected_names[A]
    assert "zaten" in s.decide("p1", "kabul")["hata"]
    # kabulde D1 (ikilide başka fonksiyonun adı) ve D2 (kesin etiketli hedef) yeniden koşar
    assert "D1" in s.decide("p2", "kabul")["hata"]
    assert "D2" in s.decide("p3", "kabul")["hata"]
    assert s.decide("p4", "kabul")["tamam"]                                  # yorum: ad denetimi yok
    assert [p["durum"] for p in nb.proposals()] == ["ret", "bekleyen", "bekleyen", "kabul"]


def test_analizle_dislama_model_ve_yazma_yok(tmp_path):
    analiz = {"suruyor": True}
    arka = OzetArka(dict(ZINCIR_METIN))
    s = ac(tmp_path, arka, analysis_running=lambda: analiz["suruyor"], mode="acikla")
    for komut in (f"/acikla {fun(ZX)} 0", f"/not {fun(ZX)} not", "/hiz"):
        assert "analiz sürüyor" in s.submit(komut)["hata"], komut
    _ = s.submit("/oneriler")                                                # okuma çalışır
    assert arka.calls == [] and not (tmp_path / "depo").exists()             # model yok, yazma yok
    analiz["suruyor"] = False
    assert s.submit(f"/not {fun(ZX)} artık yazılır")["kabul"] and (tmp_path / "depo" / SHA / "defter.jsonl").exists()
    # kuyruktaki iş başlamadan önce de bakılır
    kapi = threading.Event()
    giris = threading.Event()

    class Bekleyen(OzetArka):
        def _chat(self, *a, **k):
            giris.set()
            kapi.wait(BEKLE)
            return super()._chat(*a, **k)
    s.agent.backend = Bekleyen(dict(ZINCIR_METIN))
    s.submit(f"/acikla {fun(ZX)} 0")
    assert giris.wait(BEKLE)
    s.submit(f"/acikla {fun(ZR)} 0")
    analiz["suruyor"] = True
    kapi.set()
    assert s.wait_idle(BEKLE)
    assert "iş i2 başlatılmadı: analiz sürüyor" in " ".join(satir(s))
    assert [e["hedef"]["fn"] for e in olay(s, "gorev_basladi")] == [fun(ZX)]
    assert "öneri deftere yazılmadı" in " ".join(satir(s))                  # sürerken başlayan analiz: yazma yok


class BloklananArka(AdArka):
    """İlk isteği ``kapi`` açılana kadar bekleten sahte arka uç (parça parça akış: iptal parçada denetlenir)."""

    def __init__(self, n):
        super().__init__(n)
        self.kapi = threading.Event()
        self.giris = threading.Event()

    def _chat(self, *a, **k):
        self.giris.set()
        self.kapi.wait(BEKLE)
        return super()._chat(*a, **k)


def test_iptal_kuyrugu_bosaltir_sonraki_gorev_tamam(tmp_path):
    arka = BloklananArka(2)
    s = ac(tmp_path, arka, mode="adlandir")
    assert s.cancel() is False and satir(s)[-1] == "durdurulacak iş yok" and olay(s, "iptal") == []
    s.submit(f"/ad {fun(ZX)}")
    assert arka.giris.wait(BEKLE)
    s.submit(f"/ad {fun(ZR)}")
    assert s.status()["calisan"]["hedef"] == fun(ZX) and s.status()["kuyruk"] == 1
    assert "görev sürerken kip değişmez" in s.submit("/kip kesif")["hata"] and s.mode == "adlandir"
    assert s.submit("/durdur")["kabul"]
    iptal = olay(s, "iptal")
    assert len(iptal) == 1 and iptal[0]["kaynak"] == "analist" and iptal[0]["gorev"] is None
    assert "süren iş var, kuyruktan düşen 1" in satir(s)[-1]
    arka.kapi.set()
    assert s.wait_idle(BEKLE)
    bitti = olay(s, "gorev_bitti")
    assert [e["durum"] for e in bitti] == ["iptal"] and olay(s, "oneri") == []
    assert "iptal sonrası sunucu durumu" in " ".join(satir(s))
    # iptal görev başınadır: sonraki görev tamam (LM-06)
    s.submit(f"/ad {fun(ZR)}")
    assert s.wait_idle(BEKLE) and olay(s, "gorev_bitti")[-1]["durum"] == "tamam"
    assert olay(s, "oneri")[-1]["hedef"]["fn"] == fun(ZR)


def test_kapanis_suren_isi_iptal_eder(tmp_path):
    arka = BloklananArka(1)
    s = ac(tmp_path, arka, mode="adlandir")
    s.submit(f"/ad {fun(ZX)}")
    assert arka.giris.wait(BEKLE)
    t = threading.Timer(0.3, arka.kapi.set)
    t.start()
    s.close(S.CLOSE_UI)
    t.join()
    tur = [e["tur"] for e in s.stream.since(0)["olaylar"]]
    assert tur[-1] == "oturum_bitti" and olay(s, "oturum_bitti")[0]["neden"] == "arayuz_kapandi"
    assert olay(s, "iptal")[0]["kaynak"] == "kapanis" and "cikis" in arka.stops
    assert olay(s, "gorev_bitti")[0]["durum"] == "iptal" and tur.index("gorev_bitti") < tur.index("oturum_bitti")


def test_devam_defter_ve_ozet_deposundan(tmp_path):
    s = ac(tmp_path, OzetArka(dict(ZINCIR_METIN)), mode="acikla")
    s.submit(f"/acikla {fun(ZX)} 1")
    s.submit("/onayla")
    assert s.wait_idle(BEKLE)
    s.submit(f"/not {fun(ZX)} incelenecek")
    assert len(s.notebook.pending()) == 1
    s.close()
    ikinci_arka = OzetArka(dict(ZINCIR_METIN))
    s2 = ac(tmp_path, ikinci_arka, mode="acikla")
    devam = [x for x in satir(s2) if x.startswith("devam:")]
    assert devam and devam[0].startswith("devam: 1 bekleyen öneri, 2 özet kaydı, 2 defter kaydı, son defter kaydı ")
    assert s2.decide("p1", "kabul")["tamam"]
    # aynı zincir yeniden: özetler depodan, model çağrısı 0; yeni öneri p2
    s2.submit(f"/acikla {fun(ZX)} 1")
    s2.submit("/onayla")
    assert s2.wait_idle(BEKLE) and ikinci_arka.calls == []
    assert olay(s2, "oneri")[-1]["oneri_kimligi"] == "p2"
    s2.close()
    # reddedilen ad bir sonraki oturumun ajanına (D10) geçer
    s3 = ac(tmp_path, B.FakeBackend([]), mode="adlandir")
    _oneri(s3.notebook, adres=ZX, deger="bad_name")
    s3.decide("p3", "ret", "yanlış")
    s3.close()
    s4 = ac(tmp_path, B.FakeBackend([]))
    assert s4.agent.rejected_names == {ZX: {"bad_name"}}


def test_plan_onayla_yurut_ve_sonuc_ac(tmp_path):
    ws = plan_ws(tmp_path / "ws")
    metin = {a: f"{a} bağlantı kurar." for a in CAGIRANLAR}
    s = ac(tmp_path, OzetArka(metin), ws_root=ws.root)
    assert "plan kipinde kurulur" in s.submit("/plan dizgi bağlantı 1")["hata"]
    s.submit("/kip plan")
    assert "kurulamadı" in s.submit("/plan ithal connect")["hata"]
    r = s.submit("/plan dizgi bağlantı 1")
    assert r["kabul"] and s.status()["onay_bekleyen"]["tur"] == "plan"
    sat = satir(s)
    assert any(x.startswith("plan: find_refs(string=bağlantı 1): 11 fonksiyon") for x in sat)
    assert "toplam: 11 adım, en çok 22 görev, 12 ayrık fonksiyon" in sat and "hız ölçülmedi" in sat[-1]
    assert s.submit("/onayla")["kabul"] and s.wait_idle(BEKLE)
    assert satir(s)[-1] == "plan bitti: 11/11 adım"
    assert len(olay(s, "oneri")) == 11 and {e["oneri_turu"] for e in olay(s, "oneri")} == {"yorum"}
    # yaprak D0: modelsiz; her çağıran bir model çağrısı
    assert len(s.agent.backend.calls) == 11
    # sonuç açma: içerik deposundan, görüntü biçiminde
    s.submit("/ac r1")
    assert json.loads(satir(s)[-1])["tool"] == "get_evidence"
    assert "deposunda yok" in s.submit("/ac r999")["hata"]
    assert s.result_content("r1")["id"] == "r1"


def test_hiz_olcumu_gercek_degerle(tmp_path):
    s = ac(tmp_path, None)
    assert "model yok" in s.submit("/hiz")["hata"] and "model yok" in satir(s)[1]
    s.close()
    arka = B.FakeBackend([B.FakeReply(content="a"), B.FakeReply(content="b")])
    s = ac(tmp_path, arka)
    assert s.submit("/hiz")["kabul"] and s.wait_idle(BEKLE)
    assert "hız ölçülemedi" in satir(s)[-1] and s.agent.expected_task_sec is None
    h = s.status()["hiz"]
    assert (h["P"], h["G"], h["T"]) == (None, None, None) and h["zaman"]          # ölçüm yapıldı, değer yok



def test_plan_durdurulunca_kalan_adimlar_acilmaz(tmp_path):
    ws = plan_ws(tmp_path / "ws")
    kapi, giris = threading.Event(), threading.Event()

    class Bekleyen(OzetArka):
        def _chat(self, *a, **k):
            giris.set()
            kapi.wait(BEKLE)
            return super()._chat(*a, **k)
    arka = Bekleyen({a: "Bağlantı kurar." for a in CAGIRANLAR})
    s = ac(tmp_path, arka, ws_root=ws.root, mode="plan")
    s.submit("/plan dizgi bağlantı 1")
    s.submit("/onayla")
    assert giris.wait(BEKLE)
    assert s.cancel() is True
    kapi.set()
    assert s.wait_idle(BEKLE)
    assert "plan durdu: 1/11 adım bitti" in satir(s) and len(arka.calls) == 1
    assert olay(s, "gorev_bitti")[-1]["durum"] == "iptal" and olay(s, "oneri") == []


def test_ayni_oneriye_eszamanli_kararlar_tek_kayit(tmp_path):
    """Arayüzün istek iş parçacıkları aynı öneriye aynı anda karar gönderirse defterde tek karar kalır
    (defter kilidi). Yarış belirlenimci değildir: bu sınama gerileme koruması, mutasyon kanıtı değil."""
    s = ac(tmp_path, B.FakeBackend([]), ws_root=default_ws(tmp_path / "ws"))
    _oneri(s.notebook, adres=A, deger="parse_input_line")
    sonuc: list[bool] = []
    bariyer = threading.Barrier(8)

    def karar(i):
        bariyer.wait()
        sonuc.append(s.decide("p1", "ret" if i % 2 else "kabul", f"neden {i}")["tamam"])
    ts = [threading.Thread(target=karar, args=(i,)) for i in range(8)]
    for t_ in ts:
        t_.start()
    for t_ in ts:
        t_.join(BEKLE)
    assert sorted(sonuc) == [False] * 7 + [True]
    assert len([r for r in N.Notebook(SHA, root=tmp_path / "depo").records() if r.tur in ("kabul", "ret")]) == 1
