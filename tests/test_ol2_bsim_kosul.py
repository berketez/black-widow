"""ÖL-2: BSim'in boş depoda sorguyu atlaması, ingest bütçesi ve sorgu bütçesi.

Ghidra / JVM gerekmez: P16c'nin sahte BSim dünyası (``tests/test_p16c_bsim_toplu.py``) ve elle
ilerleyen saat. Sözleşme (gönderim hükümleri 5–7):
- "depoda başka program var mı" ingest'ten ÖNCE köken kaydından cevaplanır; programın kendisi
  ve aynı kimlikli kopyaları (``_Exclusion.classify`` ölçütü) dışarıda tutulur; köken kaydı
  okunamıyorsa / karantinadaysa sorgu ATLANMAZ, neden durumda;
- boş depoda (ayar açıkken) sorgu çağrılmaz; ``bsim_matches.json`` aynı şemada, 0 eşleşme,
  ``bsim_status: atlandi``; dolu depoda durum alanları bugünküyle aynı (yeni alan yok);
- ingest bütçesi tarama döngüsünde: dolunca taranan kısım eklenir, durum ``kismi``;
- sorgu bütçesi: fonksiyon başına yolda parça sınırında, toplu yolda tarama döngüsünde ve
  ``QueryNearest`` çağrısından önce (çağrının kendisi kesilmez).
"""

from __future__ import annotations

import json
import logging
import shlex
import types
from pathlib import Path

import pytest

import karadul.ghidra.bsim as bsim_mod
import karadul.ghidra.headless as headless_mod
from karadul.config import Config
from karadul.ghidra.bsim import (
    BOS_DEPO_NEDENI,
    STATUS_ATLANDI,
    STATUS_KISMI,
    BSimDatabase,
    ExeIdentity,
    _BSimNativeWrapper,
    _ProvenanceStore,
)
from karadul.ghidra.headless import _AdimDenetcisi
from tests.test_p16c_bsim_toplu import (
    BUILD_OWN,
    DB,
    FUNCS,
    MD5_OTHER,
    MD5_OWN,
    MD5_SYM,
    SHA_OWN,
    _exclusion,
    _FakeNative,
    _Prog,
    _World,
)

DBN = "karadul_bsim"


class _Saat:
    def __init__(self) -> None:
        self.t = 50.0

    def monotonic(self) -> float:
        return self.t

    def ilerle(self, sn: float) -> None:
        self.t += sn

    @staticmethod
    def time() -> float:
        return 0.0


@pytest.fixture
def saat(monkeypatch):
    s = _Saat()
    monkeypatch.setattr(headless_mod, "time", s)
    return s


def _db(tmp_path: Path, monkeypatch, native, atla: bool | None = True,
        batch: bool | None = None) -> BSimDatabase:
    monkeypatch.setattr(bsim_mod, "_BSIM_AVAILABLE", True)
    cfg = Config()
    cfg.bsim.db_path = str(tmp_path / "bsim")
    cfg.bsim.lock_timeout_s = 0.3
    if atla is not None:
        cfg.bsim.bos_depoda_sorgu_atla = atla
    if batch is not None:
        cfg.bsim.batch_query = batch
    db = BSimDatabase(cfg)
    db._native = native  # type: ignore[assignment]
    return db


def _kaydet(db: BSimDatabase, *kimlikler: ExeIdentity) -> None:
    store = _ProvenanceStore(db.db_path, DBN)
    for k in kimlikler:
        store.record(k, "native")


OWN = ExeIdentity(MD5_OWN, SHA_OWN, BUILD_OWN, "prog")
SYM = ExeIdentity(MD5_SYM, "2" * 64, BUILD_OWN, "prog")          # aynı yapı (dışlanır)
OTHER = ExeIdentity(MD5_OTHER, "3" * 64, ("elf:" + "cd" * 20,), "lib")


# ---------------------------------------------------------------------------
# bos_depo_durumu
# ---------------------------------------------------------------------------

def test_taze_depo_bos(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path, monkeypatch, _FakeNative())
    assert db.bos_depo_durumu(_Prog(), DBN) == {"bos": True, "kayit": 0, "baska": 0}


def test_ayni_ikili_ikinci_kez_bos_sayilir(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path, monkeypatch, _FakeNative())
    _kaydet(db, OWN)
    assert db.bos_depo_durumu(_Prog(), DBN) == {"bos": True, "kayit": 1, "baska": 0}


def test_ayni_yapinin_kopyasi_baska_program_sayilmaz(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path, monkeypatch, _FakeNative())
    _kaydet(db, OWN, SYM)
    # sahte programın dosyası yok: derleme kimliği dosyadan okunamaz; kimlik elle verilir
    db._identity = OWN
    assert db.bos_depo_durumu(_Prog(), DBN) == {"bos": True, "kayit": 2, "baska": 0}
    db._identity = ExeIdentity(MD5_OWN, SHA_OWN, (), "prog")   # derleme kimliği yoksa: başka
    assert db.bos_depo_durumu(_Prog(), DBN) == {"bos": False, "kayit": 2, "baska": 1}


def test_baska_program_varsa_bos_degil(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path, monkeypatch, _FakeNative())
    _kaydet(db, OWN, OTHER)
    assert db.bos_depo_durumu(_Prog(), DBN) == {"bos": False, "kayit": 2, "baska": 1}


def test_bozuk_koken_kaydi_atlanmaz_neden_yazilir(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path, monkeypatch, _FakeNative())
    yol = db.db_path / f"{DBN}.provenance.json"
    yol.write_text("{bozuk", encoding="utf-8")
    karar = db.bos_depo_durumu(_Prog(), DBN)
    assert karar["bos"] is False and "okunamadı" in karar["neden"]
    assert yol.read_text(encoding="utf-8") == "{bozuk"     # dosyaya dokunulmadı


def test_karantinadaki_koken_kaydi_atlanmaz(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path, monkeypatch, _FakeNative())
    (db.db_path / f"{DBN}.provenance.json.bozuk-20261123-1-2").write_text("x", encoding="utf-8")
    karar = db.bos_depo_durumu(_Prog(), DBN)
    assert karar["bos"] is False and "karantina" in karar["neden"]


def test_koken_kaydi_yok_ama_depo_dosyasi_var_atlanmaz(tmp_path, monkeypatch) -> None:
    db = _db(tmp_path, monkeypatch, _FakeNative())
    (db.db_path / f"{DBN}.mv.db").write_bytes(b"h2")
    karar = db.bos_depo_durumu(_Prog(), DBN)
    assert karar["bos"] is False and "depo dosyası var" in karar["neden"]


# ---------------------------------------------------------------------------
# query_all_functions: sorgu atlama
# ---------------------------------------------------------------------------

class _Fm:
    def __init__(self, funcs) -> None:
        self._f = list(funcs)

    def getFunctions(self, ileri):  # noqa: N802
        it = iter(self._f)
        nxt = [None]

        class J:
            def hasNext(self_):  # noqa: N802, N805
                try:
                    nxt[0] = next(it)
                    return True
                except StopIteration:
                    return False

            def next(self_):  # noqa: N805
                return nxt[0]
        return J()


class _ProgF(_Prog):
    def getFunctionManager(self):  # noqa: N802
        return _Fm(FUNCS)


def test_bos_depoda_sorgu_cagrilmaz_ayni_sema(tmp_path, monkeypatch) -> None:
    nat = _FakeNative()
    db = _db(tmp_path, monkeypatch, nat)
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert nat.batch_calls == 0 and nat.single_calls == 0
    p = res.to_payload()
    assert p["total_matches"] == 0 and p["matches"] == [] and p["total_queries"] == 0
    assert p["bsim_status"] == STATUS_ATLANDI
    assert p["bsim_detail"]["sorgu_atlandi"] is True
    assert p["bsim_detail"]["neden"] == BOS_DEPO_NEDENI
    # şema: sorgu koşulan yolun anahtarlarıyla aynı
    nat2 = _FakeNative()
    db2 = _db(tmp_path / "b", monkeypatch, nat2, atla=False)
    p2 = db2.query_all_functions(_ProgF(), 0.7, db_name=DBN).to_payload()
    assert list(p) == list(p2)
    json.loads(json.dumps(p))


def test_ayar_kapaliyken_bos_depoda_da_sorgu_kosar(tmp_path, monkeypatch) -> None:
    nat = _FakeNative()
    db = _db(tmp_path, monkeypatch, nat, atla=False)
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert nat.batch_calls == 1
    assert res.status["status"] == "ok"
    assert not {"sorgu_atlandi", "neden", "bos_depo_denetimi"} & set(res.status)


def test_dolu_depoda_sorgu_kosar_durum_alanlari_bugunkuyle_ayni(tmp_path, monkeypatch) -> None:
    nat = _FakeNative()
    db = _db(tmp_path, monkeypatch, nat, atla=True)
    _kaydet(db, OWN, OTHER)
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    nat2 = _FakeNative()
    db2 = _db(tmp_path / "b", monkeypatch, nat2, atla=False)
    _kaydet(db2, OWN, OTHER)
    res2 = db2.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert nat.batch_calls == 1 == nat2.batch_calls
    zamansiz = lambda s: {k: v for k, v in s.items() if k not in ("query_s", "lock_wait_s")}  # noqa: E731
    assert list(res.status) == list(res2.status)
    assert zamansiz(res.status) == zamansiz(res2.status)


def test_okunamayan_koken_kaydinda_sorgu_kosar_neden_durumda(tmp_path, monkeypatch) -> None:
    nat = _FakeNative()
    db = _db(tmp_path, monkeypatch, nat)
    (db.db_path / f"{DBN}.provenance.json").write_text("[]", encoding="utf-8")
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert nat.batch_calls == 1
    assert res.status["status"] == "ok"
    assert "okunamadı" in res.status["bos_depo_denetimi"]


class _IngestNative(_FakeNative):
    """Ingest sırasında depoya BAŞKA bir programın kaydı düşer (eşzamanlı koşu benzetimi)."""

    def __init__(self, db_path: Path) -> None:
        super().__init__()
        self.db_path = db_path

    def ingest_program(self, program, db_name, database=None):
        _ProvenanceStore(self.db_path, db_name).record(OTHER, "native")
        return 3


def test_karar_ingestten_once_verilir(tmp_path, monkeypatch) -> None:
    nat = _IngestNative(tmp_path / "bsim")
    db = _db(tmp_path, monkeypatch, nat)
    db.ingest_program(_ProgF(), DBN)
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    # ingest'ten önce depo boştu: sorgu atlandı (ingest sonrası köken kaydı 2 program gösterse de)
    assert nat.batch_calls == 0
    assert res.status["status"] == STATUS_ATLANDI
    assert res.status["known_executables"] == 2


def test_ingestsiz_sorguda_karar_sorgu_aninda(tmp_path, monkeypatch) -> None:
    nat = _FakeNative()
    db = _db(tmp_path, monkeypatch, nat)
    _kaydet(db, OTHER)
    db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert nat.batch_calls == 1


def test_mesgul_depoda_atlama_yolu_devreye_girmez(tmp_path, monkeypatch) -> None:
    nat = _FakeNative()
    db = _db(tmp_path, monkeypatch, nat)
    db.status["status"] = "skipped_busy"
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert res.status["status"] == "skipped_busy"
    assert "sorgu_atlandi" not in res.status


# ---------------------------------------------------------------------------
# Ingest bütçesi (gerçek _BSimNativeWrapper.ingest_program, sahte Ghidra)
# ---------------------------------------------------------------------------

class _IngestDunyasi:
    def __init__(self, saat: _Saat) -> None:
        self.taranan: list[str] = []
        self.eklenen: list[list[str]] = []
        self.saat = saat

    def kur(self, monkeypatch) -> None:
        import sys
        d = self

        class Manager:
            def __init__(self) -> None:
                self.funcs: list = []

            def listAllFunctions(self):  # noqa: N802
                return [types.SimpleNamespace(sortCallgraph=lambda: None) for _ in self.funcs]

        class Gen:
            def __init__(self, _b) -> None:
                self.m = Manager()

            def setVectorFactory(self, _f):  # noqa: N802
                pass

            def openProgram(self, *a):  # noqa: N802
                pass

            def scanFunction(self, f):  # noqa: N802
                d.saat.ilerle(1.0)
                d.taranan.append(f.getName())
                self.m.funcs.append(f)

            def getDescriptionManager(self):  # noqa: N802
                return self.m

            def dispose(self):
                pass

        class InsertRequest:
            def __init__(self) -> None:
                self.manage = None

            def execute(self, db):
                d.eklenen.append([f.getName() for f in self.manage.funcs])
                return object()

        for ad in ("ghidra", "ghidra.features", "ghidra.features.bsim",
                   "ghidra.features.bsim.query", "ghidra.features.bsim.query.protocol"):
            monkeypatch.setitem(sys.modules, ad, types.ModuleType(ad))
        sys.modules["ghidra.features.bsim.query"].GenSignatures = Gen
        sys.modules["ghidra.features.bsim.query.protocol"].InsertRequest = InsertRequest


class _GercekProg(_ProgF):
    pass


def test_ingest_butcesi_dolunca_taranan_kisim_eklenir(tmp_path, monkeypatch, saat) -> None:
    dunya = _IngestDunyasi(saat)
    dunya.kur(monkeypatch)
    w = _BSimNativeWrapper(tmp_path)
    w.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 2.5, 0, saat.t)
    n = w.ingest_program(_GercekProg(), DBN, database=DB)
    # 0, 1, 2 sn'de denetim geçer; 3 sn'de dolar → 3 fonksiyon taranır ve eklenir
    assert n == 3 and dunya.taranan == ["FUN_1000", "FUN_2000", "FUN_3000"]
    assert dunya.eklenen == [["FUN_1000", "FUN_2000", "FUN_3000"]]
    assert w.last_ingest_kismi == {"islenen": 3, "toplam": len(FUNCS)}
    assert w.denetci.sayac() == {"islenen": 3, "toplam": len(FUNCS)}


def test_ingest_butcesiz_hepsi_taranir_kismi_yok(tmp_path, monkeypatch, saat) -> None:
    dunya = _IngestDunyasi(saat)
    dunya.kur(monkeypatch)
    w = _BSimNativeWrapper(tmp_path)
    w.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 0, 0, saat.t)
    assert w.ingest_program(_GercekProg(), DBN, database=DB) == len(FUNCS)
    assert w.last_ingest_kismi is None
    w.denetci = None
    assert w.ingest_program(_GercekProg(), DBN, database=DB) == len(FUNCS)


class _KismiNative(_FakeNative):
    def ingest_program(self, program, db_name, database=None):
        assert self.denetci is not None and self.denetci.adim == "ghidra.bsim.ingest"
        self.last_ingest_kismi = {"islenen": 4, "toplam": 9}
        return 4


def test_veritabani_ingest_kismi_durumu_ve_sayilar(tmp_path, monkeypatch, saat) -> None:
    nat = _KismiNative()
    db = _db(tmp_path, monkeypatch, nat)
    db.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 900, 0, saat.t)
    assert db.ingest_program(_ProgF(), DBN) == 4
    st = db.status
    assert st["status"] == STATUS_KISMI and st["ingested_functions"] == 4
    assert st["ingest_islenen"] == 4 and st["ingest_toplam"] == 9
    assert st["neden"] == "ingest: adım bütçesi (900 sn) doldu"
    # boş depo: sorgu yine atlanır ama durum kısmi kalır, iki neden birlikte
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert res.status["status"] == STATUS_KISMI and res.status["sorgu_atlandi"] is True
    assert res.status["neden"] == "ingest: adım bütçesi (900 sn) doldu; " + BOS_DEPO_NEDENI


# ---------------------------------------------------------------------------
# Sorgu bütçesi
# ---------------------------------------------------------------------------

class _YavasNative(_FakeNative):
    def __init__(self, saat: _Saat, **kw) -> None:
        super().__init__(**kw)
        self.saat = saat

    def query_function(self, database, program, func, mn, mx, sig, exclusion, slots):
        self.saat.ilerle(1.0)
        return super().query_function(database, program, func, mn, mx, sig, exclusion, slots)


def test_fonksiyon_basina_sorgu_parca_sinirinda_kesilir(tmp_path, monkeypatch, saat) -> None:
    nat = _YavasNative(saat)
    db = _db(tmp_path, monkeypatch, nat, atla=False, batch=False)
    db.denetci = _AdimDenetcisi("ghidra.bsim.query", 2.5, 0, saat.t)
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert nat.single_calls == 3
    assert res.total_queries == 3
    assert res.status["status"] == STATUS_KISMI
    assert res.status["sorgu_islenen"] == 3 and res.status["sorgu_toplam"] == len(FUNCS)
    assert res.status["neden"] == "sorgu: adım bütçesi (2.5 sn) doldu"


def test_fonksiyon_basina_sorgu_butce_dolmazsa_alan_yok(tmp_path, monkeypatch, saat) -> None:
    nat = _YavasNative(saat)
    db = _db(tmp_path, monkeypatch, nat, atla=False, batch=False)
    db.denetci = _AdimDenetcisi("ghidra.bsim.query", 100, 0, saat.t)
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert nat.single_calls == len(FUNCS) and res.total_queries == len(FUNCS)
    assert res.status["status"] == "ok"
    assert not {"sorgu_islenen", "sorgu_toplam", "neden"} & set(res.status)


class _SayacliDunya(_World):
    def __init__(self, saat: _Saat) -> None:
        super().__init__()
        self.saat = saat

    def install(self, monkeypatch) -> None:
        super().install(monkeypatch)
        import sys
        gen = sys.modules["ghidra.features.bsim.query"].GenSignatures
        eski = gen.scanFunction
        s = self.saat

        def tara(self_, f):
            s.ilerle(1.0)
            return eski(self_, f)
        gen.scanFunction = tara


def test_toplu_sorgu_taramada_dolarsa_cagri_yapilmaz(tmp_path, monkeypatch, saat) -> None:
    world = _SayacliDunya(saat)
    world.install(monkeypatch)
    w = _BSimNativeWrapper(tmp_path)
    w.denetci = _AdimDenetcisi("ghidra.bsim.query", 1.5, 0, saat.t)
    ex = _exclusion()
    out, failed = w.query_functions(DB, object(), FUNCS, 0.7, 5, 0.0, ex, ex.extra_slots())
    assert out == [] and failed == 0
    assert world.queries == []                       # QueryNearest kurulmadı / koşmadı
    assert w.last_query_kismi == {"islenen": 0, "toplam": len(FUNCS)}
    assert w.denetci.sayac() == {"islenen": 0, "toplam": len(FUNCS)}
    assert w.denetci.neden() == ("adım bütçesi (1.5 sn) doldu; toplu sorgu çağrılmadı "
                                 "(2 / 5 fonksiyon tarandı)")


def test_toplu_sorgu_cagri_oncesi_bütce_denetlenir(tmp_path, monkeypatch, saat) -> None:
    world = _SayacliDunya(saat)
    world.install(monkeypatch)
    w = _BSimNativeWrapper(tmp_path)
    # tarama 5 sn sürer; bütçe 4,5: son denetim (4 sn) geçer, çağrıdan önceki denetim (5 sn) dolar
    w.denetci = _AdimDenetcisi("ghidra.bsim.query", 4.5, 0, saat.t)
    ex = _exclusion()
    out, _ = w.query_functions(DB, object(), FUNCS, 0.7, 5, 0.0, ex, ex.extra_slots())
    assert out == [] and world.queries == []
    assert "(5 / 5 fonksiyon tarandı)" in w.denetci.neden()


def test_toplu_sorgu_butce_icinde_eski_yolla_ayni(tmp_path, monkeypatch, saat) -> None:
    world = _SayacliDunya(saat)
    world.install(monkeypatch)
    w = _BSimNativeWrapper(tmp_path)
    w.denetci = _AdimDenetcisi("ghidra.bsim.query", 100, 0, saat.t)
    ex = _exclusion()
    out, _ = w.query_functions(DB, object(), FUNCS, 0.7, 5, 0.0, ex, ex.extra_slots())
    w2 = _BSimNativeWrapper(tmp_path)
    ex2 = _exclusion()
    out2, _ = w2.query_functions(DB, object(), FUNCS, 0.7, 5, 0.0, ex2, ex2.extra_slots())
    assert [m.to_dict() for m in out] == [m.to_dict() for m in out2] and len(out) > 0
    assert w.last_query_kismi is None and len(world.queries) == 2


class _KismiTopluNative(_FakeNative):
    def query_functions(self, database, program, funcs, mn, mx, sig, exclusion, slots):
        self.batch_calls += 1
        self.last_query_kismi = {"islenen": 0, "toplam": len(funcs)}
        return [], 0


def test_veritabani_toplu_kismi_tekli_yola_dusmez(tmp_path, monkeypatch, saat) -> None:
    nat = _KismiTopluNative()
    db = _db(tmp_path, monkeypatch, nat, atla=False)
    db.denetci = _AdimDenetcisi("ghidra.bsim.query", 10, 0, saat.t)
    res = db.query_all_functions(_ProgF(), 0.7, db_name=DBN)
    assert nat.batch_calls == 1 and nat.single_calls == 0
    assert res.status["status"] == STATUS_KISMI and res.total_queries == 0
    assert nat.denetci is db.denetci                 # denetçi toplu yola iletildi


# ---------------------------------------------------------------------------
# Adım içi olay (BSim döngüsünde gerçek sayaçla)
# ---------------------------------------------------------------------------

def test_ingest_dongusunde_suruyor_olayi(tmp_path, monkeypatch, saat, caplog) -> None:
    caplog.set_level(logging.INFO, logger="karadul.ilerleme")
    dunya = _IngestDunyasi(saat)
    dunya.kur(monkeypatch)
    w = _BSimNativeWrapper(tmp_path)
    w.denetci = _AdimDenetcisi("ghidra.bsim.ingest", 0, 2, saat.t)
    w.ingest_program(_GercekProg(), DBN, database=DB)
    ol = [dict(p.split("=", 1) for p in shlex.split(r.getMessage())[1:])
          for r in caplog.records if r.name == "karadul.ilerleme"]
    assert [(o["durum"], o["islenen"], o["toplam"], o["gecen_sn"]) for o in ol] == [
        ("suruyor", "2", "5", "2.0"), ("suruyor", "4", "5", "4.0")]
