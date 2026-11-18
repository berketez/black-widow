"""P16b: BSim deposunda kilit, aday kaynağı ve atomik lite dizini.

GHIDRA-01: eşzamanlı koşuda H2 kilidi → sessiz lite yedeği yerine süreçler arası
kilit + bekleme + açık durum. GHIDRA-02: kendisi / aynı dosya / aynı yapı (build-id,
LC_UUID) aday olamaz, kalan aday kaynağını taşır. GHIDRA-03: lite dizini kilit
altında birleştirilerek atomik yazılır, bozuk dizin ezilmez. GHIDRA-12: doğru depoyu
dışa açan API (db_name, kipten bağımsız salt okur listeleme, değişiklik yoksa yazmama).

Ghidra / JVM gerekmez: Ghidra modülleri sahte modüllerle, program nesnesi sahte
sınıfla taklit edilir.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import subprocess
import sys
import textwrap
import threading
import time
import types
from pathlib import Path
from typing import Any

import pytest

import karadul.ghidra.bsim as bsim_mod
from karadul.config import Config
from karadul.ghidra._bsim_shadow import build_shadow_payload
from karadul.ghidra.bsim import (
    BSimDatabase,
    BSimMatch,
    BSimResult,
    ExeIdentity,
    _BSimLiteIndex,
    _BSimNativeWrapper,
    _DirLock,
    _Exclusion,
    read_build_ids,
)

# ---------------------------------------------------------------------------
# Sahte Ghidra nesneleri
# ---------------------------------------------------------------------------

MD5_OWN = "a" * 32
MD5_SYM = "b" * 32      # aynı yapının sembollü kopyası
MD5_OTHER = "c" * 32    # başka bir yapı (aynı adlı olabilir)
MD5_LEGACY = "d" * 32   # kaynak kaydı olmayan eski kayıt
SHA_OWN = "1" * 64
BUILD_OWN = ("elf:" + "ab" * 20,)


class _Iter:
    def __init__(self, items: list[Any]) -> None:
        self._items = list(items)
        self._i = 0

    def hasNext(self) -> bool:  # noqa: N802
        return self._i < len(self._items)

    def next(self) -> Any:  # noqa: A003
        v = self._items[self._i]
        self._i += 1
        return v


class FakeFunc:
    def __init__(self, name: str, addr: str, thunk: bool = False) -> None:
        self._name, self._addr, self._thunk = name, addr, thunk

    def getName(self) -> str:  # noqa: N802
        return self._name

    def getEntryPoint(self) -> str:  # noqa: N802
        return self._addr

    def isThunk(self) -> bool:  # noqa: N802
        return self._thunk

    def isExternal(self) -> bool:  # noqa: N802
        return False

    def getBody(self) -> object:  # noqa: N802
        return object()


class _Instr:
    def __init__(self, m: str) -> None:
        self._m = m

    def getMnemonicString(self) -> str:  # noqa: N802
        return self._m


class FakeProgram:
    """Her çağrıda taze yineleyici veren program taklidi."""

    def __init__(self, name: str = "prog", md5: str = "", sha256: str = "",
                 path: str = "", funcs: list[FakeFunc] | None = None,
                 mnemonics: list[str] | None = None) -> None:
        self._name, self._md5, self._sha, self._path = name, md5, sha256, path
        self._funcs = funcs if funcs is not None else [
            FakeFunc("f1", "1000"), FakeFunc("f2", "2000"), FakeFunc("t", "3000", thunk=True)]
        self._mn = mnemonics or ["MOV", "ADD", "RET"]

    def getName(self) -> str:  # noqa: N802
        return self._name

    def getExecutableMD5(self) -> str:  # noqa: N802
        return self._md5

    def getExecutableSHA256(self) -> str:  # noqa: N802
        return self._sha

    def getExecutablePath(self) -> str:  # noqa: N802
        return self._path

    def getFunctionManager(self) -> Any:  # noqa: N802
        funcs = self._funcs
        return types.SimpleNamespace(getFunctions=lambda _fwd: _Iter(funcs))

    def getListing(self) -> Any:  # noqa: N802
        mn = self._mn
        return types.SimpleNamespace(getInstructions=lambda _b, _f: _Iter([_Instr(m) for m in mn]))


class FakeNative:
    """``_BSimNativeWrapper`` yerine: istemci açılışını ve çağrıları sayar."""

    def __init__(self, open_errors: list[Exception] | None = None) -> None:
        self.open_errors = list(open_errors or [])
        self.open_calls = 0
        self.ingest_calls = 0
        self.query_calls = 0
        self.last_ingest_already = False
        self.clients: list[Any] = []
        self.released: list[str] = []

    def open_client(self, name: str) -> Any:
        self.open_calls += 1
        if self.open_errors:
            raise self.open_errors.pop(0)
        c = types.SimpleNamespace(closed=False)
        c.close = lambda c=c: setattr(c, "closed", True)
        self.clients.append(c)
        return c

    def ingest_program(self, program: Any, db_name: str, database: Any = None) -> int:
        self.ingest_calls += 1
        return 2

    def query_function(self, database, program, func, *a, **k) -> list[BSimMatch]:
        self.query_calls += 1
        return [BSimMatch(str(func.getName()), str(func.getEntryPoint()), "lib_f", "libx",
                          0.9, 5.0, "10", MD5_OTHER, "", bsim_mod.SOURCE_UNRECORDED)]

    @staticmethod
    def _iter_real_functions(program: Any) -> list[Any]:
        return _BSimNativeWrapper._iter_real_functions(program)

    def release(self, name: str) -> bool:
        self.released.append(name)
        return True

    def close(self) -> None:
        pass


def _cfg(tmp_path: Path, lock_timeout: float = 0.3) -> Config:
    cfg = Config()
    cfg.bsim.db_path = str(tmp_path / "bsim")
    cfg.bsim.lock_timeout_s = lock_timeout  # BSimConfig'de alan yok; getattr ile okunur
    return cfg


@pytest.fixture
def native_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def make(open_errors: list[Exception] | None = None, lock_timeout: float = 0.3):
        monkeypatch.setattr(bsim_mod, "_BSIM_AVAILABLE", True)
        db = BSimDatabase(_cfg(tmp_path, lock_timeout))
        fake = FakeNative(open_errors)
        db._native = fake  # type: ignore[assignment]
        return db, fake
    return make


@pytest.fixture
def lite_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bsim_mod, "_BSIM_AVAILABLE", False)


def _hold_lock_in_thread(path: Path, hold_s: float) -> threading.Thread:
    """Başka bir iplikte (ayrı fd) kilidi tut: süreçler arası çakışmanın süreç içi taklidi."""
    ready = threading.Event()

    def run() -> None:
        lk = _DirLock(path)
        assert lk.acquire(5.0)
        ready.set()
        time.sleep(hold_s)
        lk.release()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert ready.wait(5.0)
    return t


# ---------------------------------------------------------------------------
# GHIDRA-01: kilit, bekleme, açık durum, lite'a sessiz düşüş yok
# ---------------------------------------------------------------------------

class TestGhidra01Kilit:
    def test_kilit_alinamazsa_atlanir_lite_yok(self, native_db, tmp_path) -> None:
        db, fake = native_db(lock_timeout=0.2)
        t = _hold_lock_in_thread(tmp_path / "bsim", 1.5)
        n = db.ingest_program(FakeProgram(md5=MD5_OWN), "karadul_bsim")
        assert n == 0
        assert fake.ingest_calls == 0 and fake.open_calls == 0
        assert db.mode == "native" and db._lite is None  # yedeğe düşmedi
        assert db.status["status"] == bsim_mod.STATUS_SKIPPED_BUSY
        assert "kilidi" in db.status["reason"]
        res = db.query_all_functions(FakeProgram(md5=MD5_OWN), 0.7)
        assert res.total_matches == 0 and fake.query_calls == 0
        p = res.to_payload()
        assert p["bsim_status"] == "skipped_busy" and p["bsim_mode"] == "native"
        assert p["bsim_detail"]["lock_wait_s"] >= 0.2
        db.close()
        t.join()

    def test_kilit_bosalinca_bekleyip_calisir(self, native_db, tmp_path) -> None:
        db, fake = native_db(lock_timeout=5.0)
        t = _hold_lock_in_thread(tmp_path / "bsim", 0.4)
        n = db.ingest_program(FakeProgram(md5=MD5_OWN), "karadul_bsim")
        assert n == 2 and fake.ingest_calls == 1
        assert db.status["status"] == bsim_mod.STATUS_OK
        assert db.status["lock_wait_s"] >= 0.3
        db.close()
        t.join()

    def test_h2_mesgul_yeniden_dener_sonra_atlar_lite_yok(self, native_db, monkeypatch) -> None:
        monkeypatch.setattr(bsim_mod, "_BUSY_RETRY_S", 0.05)
        busy = [RuntimeError("BSim DB initialize basarisiz (karadul_bsim): "
                             "Database already in use by another process")] * 100
        db, fake = native_db(open_errors=busy, lock_timeout=0.3)
        assert db.ingest_program(FakeProgram(md5=MD5_OWN), "karadul_bsim") == 0
        assert db._lite is None and db.mode == "native"
        assert db.status["status"] == bsim_mod.STATUS_SKIPPED_BUSY
        assert db.status["busy_retries"] >= 2
        assert fake.ingest_calls == 0
        # Oturum bitti: kilit başkasına açık
        other = _DirLock(db.db_path)
        assert other.acquire(0.0)
        other.release()
        db.close()

    def test_h2_mesgul_sonra_bosalir(self, native_db, monkeypatch) -> None:
        monkeypatch.setattr(bsim_mod, "_BUSY_RETRY_S", 0.05)
        busy = [RuntimeError("Database already in use by another process")]
        db, fake = native_db(open_errors=busy, lock_timeout=5.0)
        assert db.ingest_program(FakeProgram(md5=MD5_OWN), "karadul_bsim") == 2
        assert db.status["status"] == bsim_mod.STATUS_OK and db.status["busy_retries"] == 1
        db.close()

    def test_baska_native_hata_lite_yedegi_acikca(self, native_db, caplog) -> None:
        db, _fake = native_db(open_errors=[RuntimeError("Invalid absolute file path")])
        with caplog.at_level(logging.WARNING, logger="karadul.ghidra.bsim"):
            n = db.ingest_program(FakeProgram(md5=MD5_OWN), "karadul_bsim")
        assert n == 2  # lite yolu iki gerçek fonksiyonu işledi
        assert db.mode == "lite"
        assert db.status["status"] == bsim_mod.STATUS_FALLBACK_LITE
        assert "Invalid absolute file path" in db.status["reason"]
        # sağlamlık denetiminin B-B9 sayacı bu metni arıyor
        assert any("BSim native ingest basarisiz" in r.getMessage() for r in caplog.records)
        res = db.query_all_functions(FakeProgram(md5=MD5_OWN), 0.7)
        assert res.mode == "lite" and res.status["status"] == bsim_mod.STATUS_FALLBACK_LITE
        db.close()

    def test_oturum_kilidi_ingestten_sorgu_sonuna_kadar(self, native_db) -> None:
        db, fake = native_db()
        prog = FakeProgram(md5=MD5_OWN)
        db.ingest_program(prog, "karadul_bsim")
        other = _DirLock(db.db_path)
        got: list[bool] = []
        th = threading.Thread(target=lambda: got.append(other.acquire(0.0)))
        th.start()
        th.join()
        assert got == [False]  # ingest ile sorgu arasında kilit tutuluyor
        res = db.query_all_functions(prog, 0.7)
        assert res.total_queries == 2 and fake.query_calls == 2
        assert fake.open_calls == 1  # istemci oturumda bir kez açıldı
        assert fake.clients[0].closed is True
        got.clear()
        th = threading.Thread(target=lambda: got.append(other.acquire(0.0)))
        th.start()
        th.join()
        assert got == [True]  # sorgu bitti, kilit bırakıldı
        db.close()

    def test_oturum_sonunda_h2_havuzu_kapatilir(self, native_db) -> None:
        # Ghidra'nın H2 havuzu açık kalırsa dosya süreç bitene dek kilitli kalır.
        db, fake = native_db()
        prog = FakeProgram(md5=MD5_OWN)
        db.ingest_program(prog, "karadul_bsim")
        assert fake.released == []  # oturum sürüyor
        res = db.query_all_functions(prog, 0.7)
        assert fake.released == ["karadul_bsim"]
        assert res.status["h2_released"] is True
        db.close()

    def test_release_yalniz_bu_deponun_havuzunu_kapatir(self, monkeypatch, tmp_path) -> None:
        disposed: list[str] = []

        class Ds:
            def __init__(self, path: str) -> None:
                self._p = path

            def getServerInfo(self):  # noqa: N802
                return types.SimpleNamespace(getDBName=lambda: self._p)

            def dispose(self) -> None:
                disposed.append(self._p)

        d = tmp_path / "bsim"
        d.mkdir()
        mine = str(d / "karadul_bsim.mv.db")
        other = str(tmp_path / "baska" / "karadul_bsim.mv.db")
        mgr = types.SimpleNamespace(getAllDataSources=lambda: [Ds(other), Ds(mine)])
        for name in ("ghidra", "ghidra.features", "ghidra.features.bsim",
                     "ghidra.features.bsim.query", "ghidra.features.bsim.query.file"):
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        sys.modules["ghidra.features.bsim.query.file"].BSimH2FileDBConnectionManager = mgr
        w = _BSimNativeWrapper(d)
        assert w.release("karadul_bsim") is True
        assert disposed == [mine]
        assert w.release("yok") is False

    def test_surecler_arasi_gercek_kilit(self, tmp_path) -> None:
        d = tmp_path / "bsim"
        d.mkdir()
        code = textwrap.dedent(f"""
            import fcntl, os, sys, time
            fd = os.open({str(d / bsim_mod._LOCK_FILE_NAME)!r}, os.O_RDWR | os.O_CREAT, 0o644)
            fcntl.flock(fd, fcntl.LOCK_EX)
            print("tutuyor", flush=True)
            time.sleep(1.5)
        """)
        proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        try:
            assert proc.stdout.readline().strip() == "tutuyor"
            lk = _DirLock(d)
            assert lk.acquire(0.2) is False
            assert lk.acquire(10.0) is True  # çocuk süreç bitince
            lk.release()
        finally:
            proc.wait(10)

    def test_payload_eski_alanlar_ve_durum(self) -> None:
        r = BSimResult(1, 1, [BSimMatch("f", "10", "g", "p", 0.9, 1.0)], "db", 0.1,
                       mode="native", status={"status": "ok", "mode": "native"})
        p = r.to_payload()
        assert set(p["matches"][0]) >= {"query_function", "query_address", "matched_function",
                                         "matched_program", "similarity", "matched_exe_md5",
                                         "matched_source"}
        assert p["bsim_status"] == "ok" and p["bsim_mode"] == "native"
        # durum bilinmiyorsa "ok" uydurulmaz
        q = BSimResult(0, 0, [], "db", 0.0).to_payload()
        assert q["bsim_status"] is None and q["bsim_detail"] is None


# ---------------------------------------------------------------------------
# GHIDRA-02: kimlik, kaynak kaydı, dışlama
# ---------------------------------------------------------------------------

def _elf64_with_build_id(build_id: bytes) -> bytes:
    name = b"GNU\0"
    note = struct.pack("<III", len(name), len(build_id), 3) + name + build_id
    ehdr_size, phdr_size = 64, 56
    note_off = ehdr_size + phdr_size
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 3, 0xB7, 1, 0, ehdr_size, 0, 0,
                               ehdr_size, phdr_size, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 4, 4, note_off, 0, 0, len(note), len(note), 4)
    return ehdr + phdr + note


def _macho64_with_uuid(uuid: bytes) -> bytes:
    lc = struct.pack("<II", 0x1B, 24) + uuid
    hdr = struct.pack("<IiiIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(lc), 0) + b"\0" * 4
    return hdr + lc


class TestGhidra02Kimlik:
    def test_elf_build_id(self, tmp_path) -> None:
        bid = bytes(range(20))
        f = tmp_path / "a.elf"
        f.write_bytes(_elf64_with_build_id(bid))
        assert read_build_ids(f) == ("elf:" + bid.hex(),)

    def test_macho_uuid_ve_evrensel(self, tmp_path) -> None:
        u1, u2 = bytes(range(16)), bytes(range(16, 32))
        f = tmp_path / "m"
        f.write_bytes(_macho64_with_uuid(u1))
        assert read_build_ids(f) == ("macho:" + u1.hex(),)
        s1, s2 = _macho64_with_uuid(u1), _macho64_with_uuid(u2)
        off1, off2 = 4096, 8192
        fat = struct.pack(">II", 0xCAFEBABE, 2)
        fat += struct.pack(">iiIII", 0x0100000C, 0, off1, len(s1), 12)
        fat += struct.pack(">iiIII", 0x01000007, 3, off2, len(s2), 12)
        blob = bytearray(fat.ljust(off2 + len(s2), b"\0"))
        blob[off1:off1 + len(s1)] = s1
        blob[off2:off2 + len(s2)] = s2
        g = tmp_path / "fat"
        g.write_bytes(bytes(blob))
        assert read_build_ids(g) == ("macho:" + u1.hex(), "macho:" + u2.hex())

    def test_bozuk_ve_baska_bicim_bos(self, tmp_path) -> None:
        for i, data in enumerate([b"", b"\x7fELF\x02\x01", b"MZ" + b"\0" * 100,
                                  b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 64]):
            f = tmp_path / f"x{i}"
            f.write_bytes(data)
            assert read_build_ids(f) == ()
        assert read_build_ids(tmp_path / "yok") == ()
        assert read_build_ids("") == ()

    def test_gercek_strip_uuid_korunur(self) -> None:
        orig = Path("/Users/apple/Black_Widow/workspaces/2026-10-15_oturum_scratchpad/macho/orig/htop")
        strp = Path("/Users/apple/Black_Widow/workspaces/olcum_mac/corpus/htop/bin/htop")
        if not (orig.is_file() and strp.is_file()):
            pytest.skip("ölçüm korpusu yok")
        a, b = read_build_ids(orig), read_build_ids(strp)
        assert a and a == b

    def test_dislama_siniflari(self) -> None:
        own = ExeIdentity(MD5_OWN, SHA_OWN, BUILD_OWN, "htop")
        prov = {
            MD5_OWN: {"sha256": SHA_OWN, "build_ids": list(BUILD_OWN)},
            MD5_SYM: {"sha256": "2" * 64, "build_ids": list(BUILD_OWN)},
            MD5_OTHER: {"sha256": "3" * 64, "build_ids": ["elf:" + "cd" * 20]},
        }
        ex = _Exclusion(own, prov)
        assert ex.classify(MD5_OWN) == "self"
        assert ex.classify(MD5_SYM) == "same_build"
        assert ex.classify(MD5_OTHER) == ""
        assert ex.classify(MD5_LEGACY) == ""
        assert ex.classify("e" * 32, sha256=SHA_OWN) == "same_file"
        assert ex.extra_slots() == 2  # kendisi + sembollü kopya

    def _fake_ghidra(self, monkeypatch, notes: list[tuple[str, str, str, float]]):
        created: list[Any] = []

        class Exe:
            def __init__(self, md5: str, prog: str) -> None:
                self._md5, self._prog = md5, prog

            def getMd5(self) -> str:  # noqa: N802
                return self._md5

            def getNameExec(self) -> str:  # noqa: N802
                return self._prog

        class Fdesc:
            def __init__(self, md5, prog, name, i) -> None:
                self._e, self._n, self._i = Exe(md5, prog), name, i

            def getExecutableRecord(self):  # noqa: N802
                return self._e

            def getFunctionName(self):  # noqa: N802
                return self._n

            def getAddress(self):  # noqa: N802
                return 0x1000 + self._i

        class Note:
            def __init__(self, md5, prog, name, sim, i) -> None:
                self._f, self._s = Fdesc(md5, prog, name, i), sim

            def getFunctionDescription(self):  # noqa: N802
                return self._f

            def getSimilarity(self):  # noqa: N802
                return self._s

            def getSignificance(self):  # noqa: N802
                return 12.0

        class QueryNearest:
            def __init__(self) -> None:
                self.max = None
                created.append(self)

            def execute(self, db):
                return types.SimpleNamespace(result=[[Note(*n, i) for i, n in enumerate(notes)]])

        class Gen:
            def __init__(self, _b) -> None:
                pass

            def setVectorFactory(self, _f):  # noqa: N802
                pass

            def openProgram(self, *a):  # noqa: N802
                pass

            def scanFunction(self, _f):  # noqa: N802
                pass

            def getDescriptionManager(self):  # noqa: N802
                return object()

            def dispose(self):
                pass

        mods = {}
        for name in ("ghidra", "ghidra.features", "ghidra.features.bsim",
                     "ghidra.features.bsim.query", "ghidra.features.bsim.query.protocol"):
            mods[name] = types.ModuleType(name)
            monkeypatch.setitem(sys.modules, name, mods[name])
        mods["ghidra.features.bsim.query"].GenSignatures = Gen
        mods["ghidra.features.bsim.query.protocol"].QueryNearest = QueryNearest
        mods["ghidra.features.bsim.query"].protocol = mods["ghidra.features.bsim.query.protocol"]
        return created

    def test_native_sorgu_kendisini_ve_ayni_yapiyi_dislar(self, monkeypatch, tmp_path) -> None:
        notes = [
            (MD5_OWN, "htop", "FUN_1000", 1.0),            # kendisi
            (MD5_SYM, "htop", "real_name_gt", 1.0),        # sembollü kopya (aynı UUID)
            (MD5_OTHER, "htop", "other_build_name", 0.93),  # başka yapı: aday kalır
            (MD5_LEGACY, "libx", "legacy_name", 0.91),     # kaynak kaydı yok: etiketli kalır
        ]
        created = self._fake_ghidra(monkeypatch, notes)
        own = ExeIdentity(MD5_OWN, SHA_OWN, BUILD_OWN, "htop")
        prov = {
            MD5_OWN: {"sha256": SHA_OWN, "build_ids": list(BUILD_OWN)},
            MD5_SYM: {"sha256": "2" * 64, "build_ids": list(BUILD_OWN)},
            MD5_OTHER: {"sha256": "3" * 64, "build_ids": ["elf:" + "cd" * 20]},
        }
        ex = _Exclusion(own, prov)
        db = types.SimpleNamespace(getLSHVectorFactory=lambda: object())
        w = _BSimNativeWrapper(tmp_path)
        out = w.query_function(db, FakeProgram(), FakeFunc("FUN_1000", "1000"), 0.7, 5,
                               0.0, ex, ex.extra_slots())
        assert [m.matched_function for m in out] == ["other_build_name", "legacy_name"]
        assert created[0].max == 5 + 2
        assert ex.counts == {"self": 1, "same_file": 0, "same_build": 1}
        assert out[0].matched_source == "recorded" and out[0].matched_exe_sha256 == "3" * 64
        assert out[1].matched_source == "unrecorded" and out[1].matched_exe_md5 == MD5_LEGACY
        assert ex.unrecorded_candidates == 1

    def _lite_with(self, tmp_path: Path) -> _BSimLiteIndex:
        lite = _BSimLiteIndex(tmp_path)
        code = "int f(int a) { return a + 1; }"
        ins = [{"mnemonic": "ADD"}, {"mnemonic": "RET"}]
        progs = [
            ("htop", ExeIdentity(MD5_OWN, SHA_OWN, BUILD_OWN, "htop")),
            ("htop.sym", ExeIdentity(MD5_SYM, "2" * 64, BUILD_OWN, "htop.sym")),
            ("htop", ExeIdentity(MD5_OTHER, "3" * 64, ("elf:" + "cd" * 20,), "htop")),
        ]
        for i, (name, ident) in enumerate(progs):
            lite.ingest_function("db", name, f"name_{i}", "1000", code, ins, identity=ident)
        lite.save()
        return lite

    def test_lite_kimlikle_dislar_adla_degil(self, tmp_path) -> None:
        lite = self._lite_with(tmp_path)
        code = "int f(int a) { return a + 1; }"
        sh = _BSimLiteIndex._compute_structural_hash(code)
        oh = _BSimLiteIndex._compute_opcode_hash([{"mnemonic": "ADD"}, {"mnemonic": "RET"}])
        ex = _Exclusion(ExeIdentity(MD5_OWN, SHA_OWN, BUILD_OWN, "htop"), {})
        out = lite.query_function("db", "1000", sh, oh, exclude_program="htop",
                                  min_similarity=0.5, query_name="FUN_1000", exclusion=ex)
        # aynı adlı başka yapı (Debian htop ↔ Mac htop) aday; kendisi ve sembollü kopya değil
        assert [m.matched_exe_md5 for m in out] == [MD5_OTHER]
        assert out[0].query_function == "FUN_1000" and out[0].matched_source == "recorded"
        assert ex.counts["self"] == 1 and ex.counts["same_build"] == 1
        # toplu sorgu yolu (ters dizin) aynı sonucu verir
        ex2 = _Exclusion(ExeIdentity(MD5_OWN, SHA_OWN, BUILD_OWN, "htop"), {})
        out2 = lite.query_function("db", "1000", sh, oh, exclude_program="htop", min_similarity=0.5,
                                   query_name="FUN_1000", exclusion=ex2,
                                   lookup=lite.build_lookup("db"))
        assert [m.matched_exe_md5 for m in out2] == [MD5_OTHER]

    def test_lite_ayni_adli_iki_ikili_birbirini_ezmez(self, tmp_path) -> None:
        lite = self._lite_with(tmp_path)
        disk = json.loads((tmp_path / "bsim_lite_index.json").read_text())
        keys = set(disk["databases"]["db"]["programs"])
        assert {MD5_OWN, MD5_OTHER, MD5_SYM} <= keys
        assert lite.list_databases()[0]["program_count"] == 3

    def test_ingest_kaynak_kaydi_yazar(self, tmp_path, lite_mode) -> None:
        elf = tmp_path / "bin.elf"
        bid = bytes(range(20))
        elf.write_bytes(_elf64_with_build_id(bid))
        cfg = _cfg(tmp_path)
        db = BSimDatabase(cfg)
        prog = FakeProgram(name="bin.elf", md5=MD5_OWN, sha256=SHA_OWN, path=str(elf))
        assert db.ingest_program(prog, "karadul_bsim") == 2
        prov = json.loads((db.db_path / "karadul_bsim.provenance.json").read_text())
        rec = prov["executables"][MD5_OWN]
        assert rec["sha256"] == SHA_OWN and rec["build_ids"] == ["elf:" + bid.hex()]
        assert "path" not in rec  # başka vakanın yolu kayda girmez
        res = db.query_all_functions(prog, 0.5)
        # kendi fonksiyonları kendisine aday olmadı
        assert res.total_matches == 0
        assert res.status["excluded"]["self"] >= 2
        assert res.status["own_identity"]["build_ids"] == ["elf:" + bid.hex()]
        db.close()

    def test_shadow_durum_ve_kaynak_tasir(self) -> None:
        raw = {"database": "db", "bsim_mode": "native", "bsim_status": "ok",
               "bsim_detail": {"excluded": {"self": 3}},
               "matches": [{"query_function": "FUN_1", "query_address": "1",
                            "matched_function": "g", "matched_program": "p", "similarity": 0.9,
                            "matched_exe_md5": MD5_OTHER, "matched_exe_sha256": "3" * 64,
                            "matched_source": "recorded"}]}
        p = build_shadow_payload(raw_data=raw, shadow_mode=True)
        assert p["bsim_status"] == "ok" and p["bsim_mode"] == "native"
        assert p["bsim_detail"] == {"excluded": {"self": 3}}
        c = p["matches"][0]["bsim_candidates"][0]
        assert c["exe_md5"] == MD5_OTHER and c["source"] == "recorded"
        old = build_shadow_payload(raw_data={"database": "db", "matches": []}, shadow_mode=True)
        assert old["bsim_status"] is None and old["bsim_mode"] is None


# ---------------------------------------------------------------------------
# GHIDRA-03: lite dizini kilitli, birleştirerek ve atomik yazılır
# ---------------------------------------------------------------------------

class TestGhidra03LiteDizini:
    def test_eszamanli_iki_yazici_ikisi_de_kalir(self, tmp_path) -> None:
        a = _BSimLiteIndex(tmp_path)   # iki süreç dizini aynı anda okudu
        b = _BSimLiteIndex(tmp_path)
        a.ingest_function("db", "pa", "fa", "1", "int a;", identity=ExeIdentity(MD5_OWN, name="pa"))
        b.ingest_function("db", "pb", "fb", "2", "int b;", identity=ExeIdentity(MD5_OTHER, name="pb"))
        a.save()
        b.save()
        disk = json.loads((tmp_path / "bsim_lite_index.json").read_text())
        assert set(disk["databases"]["db"]["programs"]) == {MD5_OWN, MD5_OTHER}

    def test_bozuk_dizin_ezilmez_yedege_tasinir(self, tmp_path, lite_mode) -> None:
        d = tmp_path / "bsim"
        d.mkdir()
        bozuk = b'{"version": 1, "databases": {"x": {"progr'
        (d / "bsim_lite_index.json").write_bytes(bozuk)
        db = BSimDatabase(_cfg(tmp_path))
        db.ingest_program(FakeProgram(md5=MD5_OWN), "karadul_bsim")
        db.close()
        yedekler = list(d.glob("bsim_lite_index.json.bozuk-*"))
        assert len(yedekler) == 1 and yedekler[0].read_bytes() == bozuk
        yeni = json.loads((d / "bsim_lite_index.json").read_text())
        assert MD5_OWN in yeni["databases"]["karadul_bsim"]["programs"]

    def test_yazim_gecici_dosya_ve_replace(self, tmp_path, monkeypatch) -> None:
        calls: list[tuple[str, str]] = []
        real = os.replace

        def spy(src, dst):
            calls.append((str(src), str(dst)))
            return real(src, dst)

        monkeypatch.setattr(bsim_mod.os, "replace", spy)
        lite = _BSimLiteIndex(tmp_path)
        lite.ingest_function("db", "p", "f", "1", "int a;")
        lite.save()
        target = str(tmp_path / "bsim_lite_index.json")
        assert any(dst == target and src != target and Path(src).parent == tmp_path
                   for src, dst in calls)
        assert not list(tmp_path.glob("*.tmp"))

    def test_degisiklik_yoksa_kapanista_yazmaz(self, tmp_path, lite_mode) -> None:
        d = tmp_path / "bsim"
        d.mkdir()
        f = d / "bsim_lite_index.json"
        f.write_text(json.dumps({"version": 1, "databases": {"x": {"programs": {}}}}))
        os.utime(f, (1_000_000, 1_000_000))
        db = BSimDatabase(_cfg(tmp_path))
        db.list_databases()
        db.close()
        assert f.stat().st_mtime == 1_000_000


# ---------------------------------------------------------------------------
# GHIDRA-12: analizin kullandığı depoyu dışa açan API
# ---------------------------------------------------------------------------

class TestGhidra12API:
    def test_list_lite_kipte_native_dosyayi_gosterir(self, tmp_path, lite_mode) -> None:
        d = tmp_path / "bsim"
        d.mkdir()
        (d / "karadul_bsim.mv.db").write_bytes(b"\0" * 2048)
        db = BSimDatabase(_cfg(tmp_path))
        names = {(x["name"], x["mode"]) for x in db.list_databases()}
        assert ("karadul_bsim", "native") in names
        info = db.storage_info()
        assert info["native_databases"] == [str(d / "karadul_bsim.mv.db")]
        assert info["db_path"] == str(d)
        db.close()
        assert not (d / "bsim_lite_index.json").exists()  # salt okur

    def test_query_all_functions_db_adini_kullanir(self, tmp_path, lite_mode) -> None:
        db = BSimDatabase(_cfg(tmp_path))
        prog = FakeProgram(name="q", md5=MD5_OWN)
        sh = ""
        oh = _BSimLiteIndex._compute_opcode_hash([{"mnemonic": m} for m in ["MOV", "ADD", "RET"]])
        assert db._lite is not None
        db._lite.ingest_function("b", "other", "lib_f", "10", "", [{"mnemonic": m} for m in
                                                                    ["MOV", "ADD", "RET"]],
                                 identity=ExeIdentity(MD5_OTHER, name="other"))
        db._lite.save()
        assert sh == "" and oh
        res_a = db.query_all_functions(prog, 0.6, db_name="a")
        res_b = db.query_all_functions(prog, 0.6, db_name="b")
        assert res_a.total_matches == 0 and res_a.database_name == "a"
        assert res_b.total_matches == 2 and res_b.database_name == "b"
        assert {m.matched_function for m in res_b.matches} == {"lib_f"}
        db.close()
