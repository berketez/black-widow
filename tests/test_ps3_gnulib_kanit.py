"""P-S3 (AD-03, B-A3): gnulib ön ad kanalı kanıta bağlı.

1. **Varlık kanıtı (AD-03):** kanal yalnız ikilide en az ``MIN_PRESENCE_MODULES`` bağımsız gnulib
   modülünün işareti varsa ad yazar. Eskiden gnulib'siz programlarda da ateşleniyordu: "write
   error" taşıyan tek fonksiyon ``close_stdout`` (tmux, Mach-O tmux, zstd), ``write`` çağıran
   2-4 dallı tek fonksiyon ``full_write`` (redis-cli, openssl).
2. **LTO yerleşimi (B-A3):** ``version_etc`` / ``hard_locale`` / ``full_write`` ateşlendiği
   fonksiyonun bütün çağıranları ince sarmalayıcıysa (≤ 2 çağrı) ad yazılmaz (LTO'suz yapıda
   dizgi / çağrı iç fonksiyonda kalır; geliştirme setinde bu üç girdinin 217 adının hepsi yanlıştı).
3. **Kanıt kaybolmaz (K-2):** yazılmayan aday, kanıt satırı ve nedeniyle
   ``static/gnulib_candidates.json``'a yazılır.

Ölçüm ve ön kayıt: ``docs/arge/2026-11-18_onarim/P-S3.md``, ``P-S3_on_kayit.md``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.stages import ReconstructionStage

GNULIB_LIB = Path(__file__).resolve().parents[1] / "vendor" / "gnulib-ref" / "lib"

# gnulib varlık işaretleri (upstream kaynakta birebir geçen dizgiler)
PROGNAME = "A NULL argv[0] was passed through an exec system call.\n"
VERSION_ETC = "General help using GNU software: <%s>\n"


def _write_c(decompiled: Path, stem: str, body: str) -> None:
    (decompiled / f"{stem}.c").write_text(
        f"void {stem}(void)\n{{\n{body}\n}}\n", encoding="utf-8")


def _static(tmp_path: Path, *, gnulib: bool, nodes: dict | None = None) -> Path:
    """Decompile çıktısı + çağrı çizgesi. ``gnulib``: progname ve version-etc işaretleri.

    İşaretler adlı (FUN_ olmayan) fonksiyonlarda: parmak izi adayı olmazlar, yalnız varlık
    kanıtına girerler (gerçek ikilide set_program_name / emit_bug_reporting_address gibi).
    """
    static_dir = tmp_path / "static"
    decompiled = static_dir / "decompiled"
    decompiled.mkdir(parents=True)
    # Ürün decompile dizinini en az bir FUN_*.c ile tanır (_find_decompiled_dir).
    _write_c(decompiled, "FUN_00100000", "  return;")
    if gnulib:
        _write_c(decompiled, "set_program_name", f'  fputs("{PROGNAME.encode("unicode_escape").decode()}",stderr);')
        _write_c(decompiled, "emit_bug_reporting_address",
                 f'  printf("{VERSION_ETC.encode("unicode_escape").decode()}","https://www.gnu.org/gethelp/");')
    (static_dir / "call_graph.json").write_text(json.dumps({"nodes": nodes or {}}),
                                                encoding="utf-8")
    return static_dir


def _node(addr: str, callees: list[str], callers: list[str] = ()) -> dict:
    return {"name": f"FUN_{addr}", "address": addr, "callee_count": len(callees),
            "callees": [{"name": c} for c in callees],
            "callers": [{"name": f"FUN_{c}", "address": c} for c in callers]}


def _kayit(static_dir: Path) -> dict:
    return json.loads((static_dir / "gnulib_candidates.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. Varlık kanıtı


class TestVarlikKaniti:
    def test_gnulibsiz_ikilide_write_error_close_stdout_olmaz(self, tmp_path):
        """tmux / Mach-O tmux / zstd durumu: tek "write error" fonksiyonu ad almaz, aday kalır."""
        static_dir = _static(tmp_path, gnulib=False)
        _write_c(static_dir / "decompiled", "FUN_00101000", '  error(0,0,"write error");')
        names: dict[str, str] = {}
        stats: dict = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, stats)
        assert names == {}
        assert "gnulib_recovered" not in stats
        assert stats["gnulib_evidence"]["sufficient"] is False
        assert stats["gnulib_withheld"] == 1
        k = _kayit(static_dir)
        assert k["presence"]["sufficient"] is False and k["presence"]["found"] == []
        [karar] = k["decisions"]
        assert karar["key"] == "FUN_00101000" and karar["name"] == "close_stdout"
        assert karar["decision"] == "withheld" and karar["reason"] == "gnulib_kaniti_yetersiz"
        assert "write error" in karar["evidence"]

    def test_gnulibsiz_ikilide_write_cagrisi_full_write_olmaz(self, tmp_path):
        """redis-cli / openssl durumu: write çağıran 2 dallı tek fonksiyon ad almaz."""
        nodes = {"00102000": _node("00102000", ["write", "__errno_location"], ["00109000"]),
                 "00109000": _node("00109000", [f"x{i}" for i in range(20)] + ["FUN_00102000"])}
        static_dir = _static(tmp_path, gnulib=False, nodes=nodes)
        _write_c(static_dir / "decompiled", "FUN_00102000", "  return;")
        names: dict[str, str] = {}
        stats: dict = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, stats)
        assert names == {}
        [karar] = _kayit(static_dir)["decisions"]
        assert (karar["name"], karar["channel"], karar["reason"]) == (
            "full_write", "cagri_bicimi", "gnulib_kaniti_yetersiz")

    def test_gnulibli_ikilide_ad_yazilir(self, tmp_path):
        """İki bağımsız modül (progname + version-etc): kanal eskisi gibi ad yazar."""
        static_dir = _static(tmp_path, gnulib=True)
        _write_c(static_dir / "decompiled", "FUN_00101000", '  error(0,0,"write error");')
        names: dict[str, str] = {}
        stats: dict = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, stats)
        assert names == {"FUN_00101000": "close_stdout"}
        assert stats["gnulib_recovered"] == 1
        assert stats["gnulib_evidence"] == {"sufficient": True, "min_modules": 2,
                                            "modules": ["progname", "version-etc"]}
        k = _kayit(static_dir)
        assert k["presence"]["sufficient"] is True
        assert [d["decision"] for d in k["decisions"]] == ["applied"]

    def test_tek_modul_yetmez(self, tmp_path):
        """Tek bağımsız modül (yalnız progname) yetersiz: tek dizgi kanıt değildir."""
        static_dir = _static(tmp_path, gnulib=False)
        d = static_dir / "decompiled"
        _write_c(d, "set_program_name", f'  fputs("{PROGNAME.encode("unicode_escape").decode()}",stderr);')
        _write_c(d, "FUN_00101000", '  error(1,0,"memory exhausted");')
        names: dict[str, str] = {}
        stats: dict = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, stats)
        assert names == {}
        assert stats["gnulib_evidence"]["modules"] == ["progname"]
        assert stats["gnulib_evidence"]["sufficient"] is False

    def test_genel_dizgiler_kanit_sayilmaz(self, tmp_path):
        """"write error", "memory exhausted", "Usage: %s" gnulib'e özgü değil: kanıt sayılmaz."""
        static_dir = _static(tmp_path, gnulib=False)
        d = static_dir / "decompiled"
        _write_c(d, "FUN_00101000", '  error(0,0,"write error");')
        _write_c(d, "FUN_00102000", '  error(1,0,"memory exhausted");')
        _write_c(d, "FUN_00103000", '  printf("Usage: %s [OPTION]...");')
        names: dict[str, str] = {}
        stats: dict = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, stats)
        assert names == {}
        assert stats["gnulib_evidence"]["modules"] == []
        assert stats["gnulib_withheld"] == 3

    def test_cagri_isaretleri_kanit_sayilir(self, tmp_path):
        """__fpending (close-stream) + __freading (freading) iki bağımsız modül: yeterli."""
        nodes = {"00103000": _node("00103000", ["__fpending", "fclose"]),
                 "00104000": _node("00104000", ["fclose", "__freading", "fileno"])}
        static_dir = _static(tmp_path, gnulib=False, nodes=nodes)
        _write_c(static_dir / "decompiled", "FUN_00101000", '  error(0,0,"write error");')
        names: dict[str, str] = {}
        stats: dict = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, stats)
        assert stats["gnulib_evidence"]["modules"] == ["close-stream", "freading"]
        assert names["FUN_00101000"] == "close_stdout"
        assert names["FUN_00103000"] == "close_stream"
        assert names["FUN_00104000"] == "rpl_fclose"

    def test_ikinci_cagri_degistirmez(self, tmp_path):
        """Tohum iki kez çağrılır: adlar, sayaçlar ve aday kaydı aynı kalır."""
        static_dir = _static(tmp_path, gnulib=True)
        _write_c(static_dir / "decompiled", "FUN_00101000", '  error(0,0,"write error");')
        _write_c(static_dir / "decompiled", "FUN_00102000", '  error(0,errno,"error closing file");')
        stage = ReconstructionStage()
        names: dict[str, str] = {}
        stats: dict = {}
        stage._recover_gnulib_from_fingerprints(names, static_dir, stats)
        ilk_ad, ilk_sayac, ilk_kayit = dict(names), dict(stats), _kayit(static_dir)
        stage._recover_gnulib_from_fingerprints(names, static_dir, stats)
        assert names == ilk_ad and stats == ilk_sayac and _kayit(static_dir) == ilk_kayit


# ---------------------------------------------------------------------------
# 2. LTO yerleşimi


def _lto_static(tmp_path: Path, caller_callees: list[int]) -> Path:
    """version_etc ("Written by") ve hard_locale (setlocale) adayı; çağıranların çağrı sayıları."""
    cagiranlar = [f"0020{i}000" for i in range(len(caller_callees))]
    nodes = {
        "00105000": _node("00105000", ["fputs_unlocked", "fprintf"], cagiranlar),
        "00108000": _node("00108000", ["setlocale", "strcmp"], cagiranlar),
    }
    for addr, n in zip(cagiranlar, caller_callees):
        nodes[addr] = _node(addr, ["FUN_00105000"] + [f"c{j}" for j in range(n - 1)])
    static_dir = _static(tmp_path, gnulib=True, nodes=nodes)
    _write_c(static_dir / "decompiled", "FUN_00105000", '  fprintf(stream,"Written by %s.\\n",a);')
    return static_dir


class TestLtoYerlesimi:
    def test_ince_cagiranlarda_ad_yazilmaz(self, tmp_path):
        """LTO'suz yerleşim: version_etc_arn'ın çağıranları ince (2, 2, 1) -> ad yok, aday kalır."""
        static_dir = _lto_static(tmp_path, [2, 2, 1])
        names: dict[str, str] = {}
        stats: dict = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, stats)
        # P-S3b yaması: version_etc dış adı yazılmaz, iç ad (version_etc_arn) yazılır; hard_locale tutulur.
        assert names.get("FUN_00105000") == "version_etc_arn" and "FUN_00108000" not in names
        nedenler = {d["key"]: d for d in _kayit(static_dir)["decisions"]}
        assert nedenler["FUN_00105000"]["reason"] == "lto_yerlesimi_ic_ad"
        assert nedenler["FUN_00105000"]["outer_name"] == "version_etc"
        assert nedenler["FUN_00105000"]["caller_callee_counts"] == [2, 2, 1]
        assert nedenler["FUN_00108000"]["reason"] == "lto_yerlesimi"
        assert stats["gnulib_withheld"] == 1

    def test_genis_cagiranda_ad_yazilir(self, tmp_path):
        """LTO'lu yerleşim: çağıran main gibi geniş (40 çağrı) -> ad yazılır."""
        static_dir = _lto_static(tmp_path, [40])
        names: dict[str, str] = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, {})
        assert names["FUN_00105000"] == "version_etc"
        assert names["FUN_00108000"] == "hard_locale"

    def test_bir_genis_cagiran_yeter(self, tmp_path):
        """Çağıranlardan biri geniş (2 ve 32; Ubuntu pr hard_locale) -> yerleşim kanıtı yok, ad yazılır."""
        static_dir = _lto_static(tmp_path, [2, 32])
        names: dict[str, str] = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, {})
        assert names["FUN_00105000"] == "version_etc"

    def test_cagirani_yoksa_eski_davranis(self, tmp_path):
        """Çağıranı olmayan ateşlemede kural karar veremez: ad yazılır (eski davranış)."""
        static_dir = _lto_static(tmp_path, [])
        names: dict[str, str] = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, {})
        assert names["FUN_00105000"] == "version_etc"

    def test_tutulan_aday_baska_gnulib_adi_almaz(self, tmp_path):
        """Yerleşim kuralıyla tutulan dizgi adayı, sonraki çağrı şekli katmanında başka bir gnulib
        adı (close_stream) almaz: bir katmanın önerdiği anahtar sonrakilere aday değildir."""
        nodes = {"00105000": _node("00105000", ["__fpending", "fclose"], ["00201000"]),
                 "00201000": _node("00201000", ["FUN_00105000"])}
        static_dir = _static(tmp_path, gnulib=True, nodes=nodes)
        _write_c(static_dir / "decompiled", "FUN_00105000", '  fprintf(stream,"Written by %s.\\n",a);')
        names: dict[str, str] = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, {})
        # P-S3b yaması: iç ad (version_etc_arn) yazılır; close_stream adı yine verilmez.
        assert names.get("FUN_00105000") == "version_etc_arn"
        [karar] = [d for d in _kayit(static_dir)["decisions"] if d["key"] == "FUN_00105000"]
        assert (karar["name"], karar["reason"]) == ("version_etc_arn", "lto_yerlesimi_ic_ad")

    def test_kural_yalniz_uc_girdiye(self, tmp_path):
        """Yerleşime bağlı olmayan girdi (close_stream) ince çağıranda da ad alır."""
        nodes = {"00103000": _node("00103000", ["__fpending", "fclose"], ["00109000"]),
                 "00109000": _node("00109000", ["FUN_00103000"])}
        static_dir = _static(tmp_path, gnulib=True, nodes=nodes)
        names: dict[str, str] = {}
        ReconstructionStage()._recover_gnulib_from_fingerprints(names, static_dir, {})
        assert names["FUN_00103000"] == "close_stream"


# ---------------------------------------------------------------------------
# 3. Saf fonksiyonlar ve kaynak denetimi


def test_presence_evidence_ve_lto_less_layout():
    from karadul.analyzers.gnulib_fingerprints import (
        MIN_PRESENCE_MODULES, lto_less_layout, presence_evidence)
    assert MIN_PRESENCE_MODULES == 2
    p = presence_evidence(["x " + PROGNAME, VERSION_ETC], ["write"])
    assert p.sufficient and [m for m, *_ in p.found] == ["progname", "version-etc"]
    assert "yeterli" in p.evidence_line()
    assert not presence_evidence(["write error", "memory exhausted"], ["write"]).sufficient
    assert presence_evidence([], ["__fpending", "__freading"]).sufficient
    assert not presence_evidence([], ["__fpending"]).sufficient
    assert lto_less_layout([2, 2, 1]) and lto_less_layout([1])
    assert not lto_less_layout([2, 3]) and not lto_less_layout([]) and not lto_less_layout(None)


@pytest.mark.skipif(not GNULIB_LIB.is_dir(), reason="vendor/gnulib-ref yok")
def test_varlik_isaretleri_upstream_kaynakta():
    """Her işaret gnulib upstream lib/<source>'da birebir geçer (GT'den değil; leakage-safe)."""
    from karadul.analyzers.gnulib_fingerprints import GNULIB_PRESENCE_MARKERS
    eksik = []
    for m in GNULIB_PRESENCE_MARKERS:
        kaynak = (GNULIB_LIB / m.source).read_text(encoding="utf-8", errors="ignore")
        eksik += [f"{m.module}: {a}" for a in m.anchors if a not in kaynak]
    assert eksik == []
