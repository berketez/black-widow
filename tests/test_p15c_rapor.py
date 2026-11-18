"""P15c kalem 4 + 8: raporda imza kayıtlarının iddia türü ve veritabanı künyesi.

- Dizgi / çağrı deseni (davranış tahmini) IOC bölümünde "kimlik" gibi sayılmaz; özet kimlik
  ve davranış kayıtlarını ayrı yazar; davranış kaydı aile / kademe / kategori taşısa bile
  bilinen zararlı simge (KRDL006) değildir.
- IOC özeti veritabanı künyesini (build_id, şema, ad sayısı, yol kaynağı, veri kökü) ve şema
  uyarısını yazar (P15b'den beri istatistikte; raporda yoktu).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from karadul.reporting import report_data as rd

SLIVER = "github.com/bishopfox/sliver/implant/sliver/handlers"


class _WS:
    def __init__(self, data: dict[str, Any] | None) -> None:
        self.data = data

    def load_json(self, stage: str, name: str):
        return self.data if (stage, name) == ("reconstructed", "signature_matches") else None


def _result(stats: dict[str, Any]):
    return SimpleNamespace(stages={"reconstruct": SimpleNamespace(stats=stats, errors=[])})


def _kayit(method: str, **ek: Any) -> dict[str, Any]:
    d = {"original": "FUN_00104920", "matched": "read_env_var", "library": "config",
         "libraries": None, "confidence": 0.014, "purpose": "env", "category": "",
         "family": "", "tier": "", "address": "00104920", "method": method}
    d.update(ek)
    return d


DB = {"sigdb_build_id": "s2-b32ee9f65b1a-20261118", "sigdb_schema_version": "2",
      "sigdb_lmdb_symbol_count": 9092473, "sigdb_path_source": "data_root:signatures.lmdb",
      "sigdb_data_root": "/veri", "sigdb_data_root_source": "paket kökü",
      "sigdb_schema_warning": None}


def test_davranis_tahmini_kimlikten_ayri_sayilir():
    data = {"schema": 2, "database": DB, "matches": [
        _kayit("string_ref"), _kayit("call_pattern", matched="copy_buffer"),
        _kayit("symbol", original="SSL_CTX_new", matched="SSL_CTX_new")]}
    sec = rd._ioc(_result({"sigdb_status": "matched"}), _WS(data))
    assert sec.status == rd.SECTION_CLEAN
    assert sec.extra["claims"] == {"kimlik": 1, "davranis": 2}
    assert "1 identity" in sec.summary and "2 behaviour guess(es)" in sec.summary
    assert "not which function it is" in sec.summary


def test_davranis_kaydi_ioc_olamaz_kimlik_kaydi_olur():
    sahte = _kayit("string_ref", family="sliver", tier="1", category="malware")
    gercek = _kayit("symbol", original=SLIVER, matched=SLIVER, family="sliver", tier="1",
                    category="malware")
    sec = rd._ioc(_result({"sigdb_status": "matched"}),
                  _WS({"schema": 2, "database": DB, "matches": [sahte]}))
    assert sec.status == rd.SECTION_CLEAN and sec.count == 0
    sec2 = rd._ioc(_result({"sigdb_status": "matched"}),
                   _WS({"schema": 2, "database": DB, "matches": [sahte, gercek]}))
    assert sec2.status == rd.SECTION_FINDINGS and sec2.count == 1
    assert [m["original"] for m in sec2.items] == [SLIVER]
    # Kayıtta yazılı iddia yöntemden önce gelir.
    assert rd._is_ioc(dict(gercek, claim="davranis")) is False


def test_kunye_sema_ve_veri_koku_raporda():
    sec = rd._ioc(_result({"sigdb_status": "matched"}),
                  _WS({"schema": 2, "database": DB, "matches": [_kayit("symbol")]}))
    for parca in ("s2-b32ee9f65b1a-20261118", "schema 2", "9092473 names",
                  "data_root:signatures.lmdb", "data root /veri (paket kökü)"):
        assert parca in sec.summary, parca
    assert sec.extra["database"]["sigdb_schema_version"] == "2"
    assert "WARNING" not in sec.summary


def test_eski_sema_uyarisi_istatistikten_raporda():
    st = {"sigdb_status": "no_match", "sigdb_schema_version": None,
          "sigdb_schema_warning": "eski şema (1 (künyesiz))",
          "sigdb_path_source": "default:~/.karadul/signatures.lmdb"}
    sec = rd._ioc(_result(st), _WS(None))
    assert sec.status == rd.SECTION_CLEAN
    assert "WARNING: eski şema (1 (künyesiz))" in sec.summary
    assert "default:~/.karadul/signatures.lmdb" in sec.summary
    assert sec.extra["database"]["sigdb_schema_warning"].startswith("eski şema")
