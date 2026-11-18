"""P15c kalem 6: simge eşleşmesinin kitaplık iddiası ikilinin kendi bağlanma kanıtına bağlı.

- ELF sürüm gereksinimi içe aktarımı dosyaya bağlar (``__cxa_finalize@GLIBC_2.17`` →
  ``libc.so.6``); veritabanı ``libc++abi`` dese de iddia ikilinin söylediğidir.
- Sürümsüz içe aktarımda veritabanının ailesi ``DT_NEEDED``'da yoksa iddia geri çekilir.
- ``_`` önek geri düşüşü yalnız Mach-O / bilinmeyen hedefte (ELF'te ``acl_*`` → libc yok).
Fikstür: depodaki gerçek Debian ``cat`` (aarch64, soyulmuş).
"""

from __future__ import annotations

import json
from pathlib import Path

from karadul.analyzers.signature_db import (
    SignatureDB,
    SignatureMatch,
    apply_import_bindings,
    elf_import_bindings,
)

CAT = Path(__file__).resolve().parent / "fixtures" / "coreutils" / "binaries" / "stripped" / "cat"


def _clean_db() -> SignatureDB:
    db = SignatureDB()
    with db._lock:
        db._string_sigs = {}
        db._call_sigs = []
        db._byte_signatures = []
        db._symbol_db = {}
        db._lmdb_backend = None
        db._string_sigs_version += 1
    return db


def test_elf_baglanma_kaniti_okunur():
    b = elf_import_bindings(CAT)
    assert b is not None
    assert b["needed"] == ["libc.so.6", "ld-linux-aarch64.so.1"]
    assert b["versioned"]["__cxa_finalize"] == ("libc.so.6", "GLIBC_2.17")
    assert "__gmon_start__" in b["unversioned"]
    assert elf_import_bindings(Path(__file__)) is None   # ELF değil


def test_surumlu_ice_aktarim_ikilinin_kitapligina_baglanir():
    m = SignatureMatch("__cxa_finalize", "__cxa_finalize", "libc++abi", 0.98, "symbol")
    say = apply_import_bindings([m], elf_import_bindings(CAT))
    assert m.library == "libc.so.6" and m.libraries is None
    assert m.evidence == ["bağlanma: __cxa_finalize@GLIBC_2.17 → libc.so.6 (ELF sürüm gereksinimi)"]
    assert say["surumlu"] == 1 and say["surumlu_duzeltilen"] == 1
    assert m.claim == "kimlik"


def test_surumsuz_ice_aktarim_needed_disi_iddia_geri_cekilir():
    bag = {"needed": ["libc.so.6"], "versioned": {}, "unversioned": ["weak_x", "weak_y"]}
    disarida = SignatureMatch("weak_x", "weak_x", "rust_std", 0.98, "symbol")
    icerde = SignatureMatch("weak_y", "weak_y", "glibc", 0.98, "symbol")
    davranis = SignatureMatch("weak_x", "read_env_var", "config", 0.014, "string_ref")
    say = apply_import_bindings([disarida, icerde, davranis], bag)
    assert disarida.library == "" and disarida.libraries == ["rust_std"]
    assert disarida.evidence[0].startswith("kitaplık iddiası ikilinin DT_NEEDED listesinde yok")
    assert icerde.library == "glibc"            # aile (c) DT_NEEDED'da: iddia kalır
    assert davranis.library == "config"         # yalnız simge kayıtları
    assert say == {"surumlu": 0, "surumlu_duzeltilen": 0, "surumsuz": 2,
                   "surumsuz_geri_cekilen": 1}


def test_alt_cizgi_geri_dususunun_kitapligi_baglanmayla_duzelir():
    """ELF'te ``acl_set_fd`` → Mach-O ``_acl_set_fd`` kaydı (libc): ad kimliği kalır (geri düşüş
    kapatılmadı: 119 ikilide 4 269 doğru içe aktarımı siliyordu), kitaplık ikilinin sürüm
    gereksiniminden gelir."""
    db = _clean_db()
    db.add_symbol("_acl_set_fd", {"lib": "libc", "purpose": "acl"})
    m = db._match_by_symbol("acl_set_fd", target_platform="elf")
    assert m is not None and m.library == "libc" and m.matched_name == "acl_set_fd"
    bag = {"needed": ["libacl.so.1", "libc.so.6"],
           "versioned": {"acl_set_fd": ("libacl.so.1", "ACL_1.0")}, "unversioned": []}
    apply_import_bindings([m], bag)
    assert m.library == "libacl.so.1"


def test_match_all_ikili_yoluyla(tmp_path):
    db = _clean_db()
    db.add_symbol("__cxa_finalize", {"lib": "libc++abi", "purpose": "dtor"})
    fj = tmp_path / "f.json"
    fj.write_text(json.dumps({"functions": [{"name": "__cxa_finalize", "address": "00001000"}]}))
    (tmp_path / "s.json").write_text("[]")
    (tmp_path / "c.json").write_text("{}")
    (tmp_path / "dec").mkdir()
    once = db.match_all(fj, tmp_path / "s.json", tmp_path / "c.json", tmp_path / "dec",
                        target_platform="elf")
    assert once[0].library == "libc++abi"
    assert db.import_binding_info == {"durum": "ikili verilmedi"}
    sonra = db.match_all(fj, tmp_path / "s.json", tmp_path / "c.json", tmp_path / "dec",
                         target_platform="elf", binary_path=CAT)
    assert sonra[0].library == "libc.so.6"
    assert db.import_binding_info["durum"] == "uygulandi"
    assert db.import_binding_info["surumlu_duzeltilen"] == 1
