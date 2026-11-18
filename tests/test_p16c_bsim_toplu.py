"""P16c kalem 3: toplu BSim sorgusu.

Eski yol her fonksiyon için ayrı ``GenSignatures`` + ``QueryNearest`` kuruyordu
(Debian ``cat``'te 107 fonksiyon 26,5 sn). Toplu yol tek ``GenSignatures`` ve tek
``QueryNearest`` kullanır; sonuçlar ``SimilarityResult.getBase()`` adresiyle fonksiyona
eşlenir. Kabul ölçütü: eşleşme kümesi, sırası, dışlama sayaçları eski yolla AYNI.

Ghidra / JVM gerekmez: sahte ``GenSignatures`` / ``QueryNearest`` sorgu fonksiyonlarının
taranmış olup olmadığına bakarak yanıt üretir (gerçek BSim gibi: yanıt yöneticideki
fonksiyonlar için gelir).
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

import karadul.ghidra.bsim as bsim_mod
from karadul.config import Config
from karadul.ghidra.bsim import (
    BSimDatabase,
    ExeIdentity,
    _BSimNativeWrapper,
    _Exclusion,
)

MD5_OWN = "a" * 32
MD5_SYM = "b" * 32      # aynı yapının sembollü kopyası (dışlanır)
MD5_OTHER = "c" * 32    # başka yapı (aday)
MD5_LEGACY = "d" * 32   # kaynak kaydı yok (etiketli aday)
SHA_OWN = "1" * 64
BUILD_OWN = ("elf:" + "ab" * 20,)


class _Addr:
    def __init__(self, off: int) -> None:
        self._off = off

    def getOffset(self) -> int:  # noqa: N802
        return self._off

    def __str__(self) -> str:
        return "%08x" % self._off


class _Func:
    def __init__(self, name: str, off: int) -> None:
        self._name, self._addr = name, _Addr(off)

    def getName(self) -> str:  # noqa: N802
        return self._name

    def getEntryPoint(self) -> _Addr:  # noqa: N802
        return self._addr

    def isThunk(self) -> bool:  # noqa: N802
        return False

    def isExternal(self) -> bool:  # noqa: N802
        return False


class _Exe:
    def __init__(self, md5: str, prog: str) -> None:
        self._md5, self._prog = md5, prog

    def getMd5(self) -> str:  # noqa: N802
        return self._md5

    def getNameExec(self) -> str:  # noqa: N802
        return self._prog


class _Fdesc:
    def __init__(self, md5: str, prog: str, name: str, addr: int) -> None:
        self._e, self._n, self._a = _Exe(md5, prog), name, addr

    def getExecutableRecord(self):  # noqa: N802
        return self._e

    def getFunctionName(self):  # noqa: N802
        return self._n

    def getAddress(self):  # noqa: N802
        return self._a


class _Note:
    def __init__(self, fdesc: _Fdesc, sim: float, sig: float) -> None:
        self._f, self._s, self._g = fdesc, sim, sig

    def getFunctionDescription(self):  # noqa: N802
        return self._f

    def getSimilarity(self):  # noqa: N802
        return self._s

    def getSignificance(self):  # noqa: N802
        return self._g


class _SimResult:
    def __init__(self, base: _Fdesc, notes: list[_Note]) -> None:
        self._base, self._notes = base, notes

    def getBase(self):  # noqa: N802
        return self._base

    def __iter__(self):
        return iter(self._notes)


# Depodaki adaylar: sorgu fonksiyonunun giriş adresi -> [(md5, program, ad, benzerlik)]
CANDIDATES: dict[int, list[tuple[str, str, str, float]]] = {
    0x1000: [(MD5_OWN, "prog", "FUN_1000", 1.0), (MD5_OTHER, "prog", "parse_args", 0.95),
             (MD5_LEGACY, "libx", "legacy_a", 0.91)],
    0x2000: [(MD5_SYM, "prog", "gt_name", 1.0), (MD5_OTHER, "prog", "read_cfg", 0.9)],
    0x3000: [],  # adayı yok
    0x4000: [(MD5_OTHER, "lib", "n%d" % i, 0.99 - i / 100) for i in range(9)],  # kırpma
    0x5000: [(MD5_OWN, "prog", "FUN_5000", 1.0)],  # yalnız kendisi
}


class _World:
    """Sahte Ghidra BSim: kurulan ``GenSignatures`` ve koşulan sorguları sayar."""

    def __init__(self, scan_fail: set[int] | None = None, reverse: bool = True,
                 execute_none: bool = False) -> None:
        self.gens: list[Any] = []
        self.queries: list[Any] = []
        self.scan_fail = scan_fail or set()
        self.reverse = reverse
        self.execute_none = execute_none

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        world = self

        class Manager:
            def __init__(self) -> None:
                self.funcs: list[_Func] = []

        class Gen:
            def __init__(self, _b) -> None:
                self.manager = Manager()
                world.gens.append(self)

            def setVectorFactory(self, _f):  # noqa: N802
                pass

            def openProgram(self, *a):  # noqa: N802
                pass

            def scanFunction(self, f):  # noqa: N802
                if f.getEntryPoint().getOffset() in world.scan_fail:
                    raise RuntimeError("DecompileException")
                self.manager.funcs.append(f)

            def getDescriptionManager(self):  # noqa: N802
                return self.manager

            def dispose(self):
                pass

        class QueryNearest:
            def __init__(self) -> None:
                self.max = None
                self.manage = None
                world.queries.append(self)

            def execute(self, db):
                if world.execute_none:
                    return None
                results = []
                for f in self.manage.funcs:
                    off = f.getEntryPoint().getOffset()
                    base = _Fdesc(MD5_OWN, "prog", f.getName(), off)
                    notes = [_Note(_Fdesc(m, p, n, 0x9000 + i), s, 10.0 + i)
                             for i, (m, p, n, s) in enumerate(CANDIDATES.get(off, []))]
                    results.append(_SimResult(base, notes[: self.max]))
                if world.reverse:
                    # Gerçek yanıtın sırası garanti değil: eşleme konuma değil adrese bağlı olmalı.
                    results.reverse()
                return types.SimpleNamespace(result=results)

        mods = {}
        for name in ("ghidra", "ghidra.features", "ghidra.features.bsim",
                     "ghidra.features.bsim.query", "ghidra.features.bsim.query.protocol"):
            mods[name] = types.ModuleType(name)
            monkeypatch.setitem(sys.modules, name, mods[name])
        mods["ghidra.features.bsim.query"].GenSignatures = Gen
        mods["ghidra.features.bsim.query.protocol"].QueryNearest = QueryNearest
        mods["ghidra.features.bsim.query"].protocol = mods["ghidra.features.bsim.query.protocol"]


FUNCS = [_Func("FUN_1000", 0x1000), _Func("FUN_2000", 0x2000), _Func("FUN_3000", 0x3000),
         _Func("FUN_4000", 0x4000), _Func("FUN_5000", 0x5000)]


def _exclusion() -> _Exclusion:
    own = ExeIdentity(MD5_OWN, SHA_OWN, BUILD_OWN, "prog")
    prov = {
        MD5_OWN: {"sha256": SHA_OWN, "build_ids": list(BUILD_OWN)},
        MD5_SYM: {"sha256": "2" * 64, "build_ids": list(BUILD_OWN)},
        MD5_OTHER: {"sha256": "3" * 64, "build_ids": ["elf:" + "cd" * 20]},
    }
    return _Exclusion(own, prov)


DB = types.SimpleNamespace(getLSHVectorFactory=lambda: object(), getLastError=lambda: None)


def _per_function(tmp_path: Path, monkeypatch, funcs=FUNCS, scan_fail=None):
    world = _World(scan_fail=scan_fail)
    world.install(monkeypatch)
    ex = _exclusion()
    w = _BSimNativeWrapper(tmp_path)
    out = []
    for f in funcs:
        out.extend(w.query_function(DB, object(), f, 0.7, 5, 0.0, ex, ex.extra_slots()))
    return out, ex, world


def _batch(tmp_path: Path, monkeypatch, funcs=FUNCS, scan_fail=None):
    world = _World(scan_fail=scan_fail)
    world.install(monkeypatch)
    ex = _exclusion()
    w = _BSimNativeWrapper(tmp_path)
    out, failed = w.query_functions(DB, object(), funcs, 0.7, 5, 0.0, ex, ex.extra_slots())
    return out, failed, ex, world


def _key(m) -> tuple:
    return tuple(sorted(m.to_dict().items()))


def test_toplu_sorgu_eski_yolla_ayni_eslesme_sira_ve_sayac(tmp_path, monkeypatch) -> None:
    old, ex_old, w_old = _per_function(tmp_path, monkeypatch)
    new, failed, ex_new, w_new = _batch(tmp_path, monkeypatch)
    assert failed == 0
    assert [_key(m) for m in new] == [_key(m) for m in old]
    assert ex_new.counts == ex_old.counts == {"self": 2, "same_file": 0, "same_build": 1}
    assert ex_new.unrecorded_candidates == ex_old.unrecorded_candidates == 1
    # kırpma: 0x4000'in 9 adayından 5'i
    assert sum(1 for m in new if m.query_address == "00004000") == 5
    # sorgu adresi doğru fonksiyona eşlendi (yanıt sırası ters verildi)
    assert {m.query_function for m in new if m.matched_function == "parse_args"} == {"FUN_1000"}
    assert {m.query_function for m in new if m.matched_function == "read_cfg"} == {"FUN_2000"}


def test_toplu_sorgu_tek_imza_uretimi_tek_sorgu(tmp_path, monkeypatch) -> None:
    _old, _ex, w_old = _per_function(tmp_path, monkeypatch)
    assert len(w_old.gens) == len(FUNCS) and len(w_old.queries) == len(FUNCS)
    _new, _f, ex, w_new = _batch(tmp_path, monkeypatch)
    assert len(w_new.gens) == 1 and len(w_new.queries) == 1
    assert w_new.queries[0].max == 5 + ex.extra_slots()
    assert [f.getName() for f in w_new.gens[0].manager.funcs] == [f.getName() for f in FUNCS]


def test_toplu_sorgu_taranamayan_fonksiyon_sayilir(tmp_path, monkeypatch) -> None:
    old, ex_old, _ = _per_function(tmp_path, monkeypatch, scan_fail={0x1000})
    new, failed, ex_new, _ = _batch(tmp_path, monkeypatch, scan_fail={0x1000})
    assert failed == 1
    assert [_key(m) for m in new] == [_key(m) for m in old]
    assert ex_new.counts == ex_old.counts
    assert not any(m.query_function == "FUN_1000" for m in new)


def test_toplu_sorgu_none_yanit_hata(tmp_path, monkeypatch) -> None:
    world = _World(execute_none=True)
    world.install(monkeypatch)
    w = _BSimNativeWrapper(tmp_path)
    with pytest.raises(RuntimeError, match="toplu"):
        w.query_functions(DB, object(), FUNCS, 0.7, 5, 0.0, _exclusion(), 2)


# ---------------------------------------------------------------------------
# BSimDatabase: toplu yol öntanım, düşerse tekli yola geçiş (sayaçlar çift sayılmaz)
# ---------------------------------------------------------------------------

class _FakeNative:
    def __init__(self, batch_error: Exception | None = None) -> None:
        self.batch_error = batch_error
        self.batch_calls = 0
        self.single_calls = 0
        self.last_ingest_already = False

    def open_client(self, name: str) -> Any:
        return types.SimpleNamespace(close=lambda: None)

    def query_functions(self, database, program, funcs, mn, mx, sig, exclusion, slots):
        self.batch_calls += 1
        exclusion.counts["self"] += 7  # düşmeden önce yarım sayılmış olsun
        if self.batch_error is not None:
            raise self.batch_error
        return [], 0

    def query_function(self, database, program, func, mn, mx, sig, exclusion, slots):
        self.single_calls += 1
        exclusion.counts["self"] += 1
        return []

    def release(self, name: str) -> bool:
        return True

    def close(self) -> None:
        pass


class _Prog:
    def getName(self):  # noqa: N802
        return "prog"

    def getExecutableMD5(self):  # noqa: N802
        return MD5_OWN

    def getExecutableSHA256(self):  # noqa: N802
        return SHA_OWN

    def getExecutablePath(self):  # noqa: N802
        return ""


def _db(tmp_path: Path, monkeypatch, native: _FakeNative, batch: bool | None = None) -> BSimDatabase:
    monkeypatch.setattr(bsim_mod, "_BSIM_AVAILABLE", True)
    cfg = Config()
    cfg.bsim.db_path = str(tmp_path / "bsim")
    cfg.bsim.lock_timeout_s = 0.3
    if batch is not None:
        cfg.bsim.batch_query = batch  # BSimConfig'de alan yok (yama); getattr ile okunur
    db = BSimDatabase(cfg)
    db._native = native  # type: ignore[assignment]
    return db


def test_veritabani_toplu_yolu_kullanir(tmp_path, monkeypatch) -> None:
    nat = _FakeNative()
    db = _db(tmp_path, monkeypatch, nat)
    res = db._query_functions(_Prog(), FUNCS, 0.7, 5, "karadul_bsim")
    assert nat.batch_calls == 1 and nat.single_calls == 0
    assert res.status["query_mode"] == "batch"
    assert res.status["excluded"]["self"] == 7


def test_veritabani_toplu_duserse_tekli_yol_sayac_cift_sayilmaz(tmp_path, monkeypatch) -> None:
    nat = _FakeNative(batch_error=RuntimeError("QueryNearest bellek"))
    db = _db(tmp_path, monkeypatch, nat)
    res = db._query_functions(_Prog(), FUNCS, 0.7, 5, "karadul_bsim")
    assert nat.batch_calls == 1 and nat.single_calls == len(FUNCS)
    assert res.status["query_mode"] == "per_function"
    assert "QueryNearest bellek" in res.status["batch_query_error"]
    assert res.status["excluded"]["self"] == len(FUNCS)  # toplu yolun yarım sayımı atıldı


def test_veritabani_toplu_ayarla_kapatilir(tmp_path, monkeypatch) -> None:
    nat = _FakeNative()
    db = _db(tmp_path, monkeypatch, nat, batch=False)
    res = db._query_functions(_Prog(), FUNCS, 0.7, 5, "karadul_bsim")
    assert nat.batch_calls == 0 and nat.single_calls == len(FUNCS)
    assert res.status["query_mode"] == "per_function"
    assert "batch_query_error" not in res.status
