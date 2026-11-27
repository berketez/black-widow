"""ÖL-4: ``karadul.ilerleme`` olaylarının CLI'da ve arayüz sunucusunda gösterimi.

Gönderim: ``docs/arge/2026-11-23_dalga1/gonderim/OL4.md`` (hükümler 1–6). Olayı ÖL-1 üretir
(``karadul/ghidra/headless.py``); bu testler yalnız gösterimi sınar (Ghidra yok):

- tek ayrıştırıcı (``karadul.core.ilerleme``): üreticinin satırıyla gidiş-dönüş, ``--verbose`` öneki,
  sözleşme dışı satır ``None``;
- CLI kipleri (``karadul.cli_common``): ``--quiet`` / ``--json`` olay basmaz, ``--verbose`` satırı tam
  bir kez, öntanımda stderr terminal değilse satır, terminalde yalnız çubuk açıklaması; stdout'a olay
  yazılmaz; sahte boru hattıyla uçtan uca (``CliRunner``);
- sunucu (``ui/server.py`` ``_job_progress``): artımlı okuma ↔ tam okuma eşdeğerliği (rastgele
  parçalar), yarım satır, ``\\r\\n`` bölünmesi, dosya kısalması, yalnız yeni baytların taranması,
  10 MB günlükte ikinci ve sonraki çağrılar < 50 ms, ``ilerleme`` alanı (olay yoksa ``null``).
"""

from __future__ import annotations

import gc
import importlib.util
import io
import json
import logging
import random
import time
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

import karadul.cli as cli
from karadul.cli_common import (
    ILERLEME_KIP_CUBUK,
    ILERLEME_KIP_SATIR,
    ILERLEME_KIP_YOK,
    IlerlemeGosterici,
    ilerleme_aciklamasi,
    ilerleme_gosterimi,
    ilerleme_kipi,
)
from karadul.config import Config
from karadul.core.ilerleme import (
    GOSTERILEN_ALANLAR,
    ILERLEME_GUNLUKCU,
    gosterim_alanlari,
    ilerleme_ayristir,
)
from karadul.core.result import PipelineResult, StageResult
from karadul.ghidra.headless import _ilerleme, ilerleme_satiri

_ROOT = Path(__file__).resolve().parent.parent
_SERVER_PY = _ROOT / "ui" / "server.py"
# Bugünkü (ÖL-4 öncesi) _job_progress'in döndürdüğü anahtarlar: değişmez, yalnız ``ilerleme`` eklenir.
_ESKI_ANAHTARLAR = {"stages", "substages", "finished", "workspace", "elapsed", "binary", "rc",
                    "cancelled", "outcome", "clean_dir", "tail"}


# =============================================================================
# 1) Ayrıştırıcı
# =============================================================================


def test_uretici_satiri_gidis_donus_tirnak_ve_kacis():
    s = ilerleme_satiri("ghidra.otomatik_analiz", "suruyor", islenen=3, toplam=10, gecen_sn=12.5,
                        cozumleyici='Objective-C "Message" a\\b=c',
                        neden="600 sn tepede (eşik 600 sn);\nkapatılıyor")
    olay = ilerleme_ayristir(s)
    assert olay == {"asama": "static", "adim": "ghidra.otomatik_analiz", "durum": "suruyor",
                    "islenen": 3, "toplam": 10, "gecen_sn": 12.5,
                    "cozumleyici": 'Objective-C "Message" a\\b=c',
                    "neden": "600 sn tepede (eşik 600 sn); kapatılıyor"}
    assert isinstance(olay["islenen"], int) and isinstance(olay["gecen_sn"], float)


def test_verbose_oneki_ve_yalin_satir():
    s = ilerleme_satiri("ghidra.bsim.query", "atlandi", neden="depoda başka program yok")
    for satir in (s, "13:00:01 INFO    [karadul.ilerleme] " + s, s + "\r\n"):
        assert ilerleme_ayristir(satir) == {"asama": "static", "adim": "ghidra.bsim.query",
                                            "durum": "atlandi", "neden": "depoda başka program yok"}


@pytest.mark.parametrize("satir", [
    "",
    "INFO [karadul] OK static: 1.0s",
    "XILERLEME asama=static adim=a durum=bitti",          # başka sözcüğün parçası
    "ILERLEME adim=a durum=bitti",                         # asama yok
    "ILERLEME asama=static durum=bitti",                   # adim yok
    "ILERLEME asama=static adim=a",                        # durum yok
    "ILERLEME asama=static adim=a durum=ilerliyor",        # sözleşmede olmayan durum
    "ILERLEME asama=static adim=a durum=bitti renk=mavi",  # sözleşmede olmayan alan
    "ILERLEME asama=static adim=a durum=bitti yalin",      # '=' yok
    'ILERLEME asama=static adim=a durum=kismi neden="yarım',  # kapanmamış tırnak (yarım satır)
    "ILERLEME asama=static adim=a durum=suruyor islenen=x",  # sayı değil
    "ILERLEME asama=static adim=a durum=bitti gecen_sn=1,5",
    "ILERLEME asama=static adim=a durum=bitti adim=b",     # yinelenen alan
])
def test_sozlesme_disi_satir_olay_degil(satir):
    assert ilerleme_ayristir(satir) is None


def test_gosterim_alanlari_uydurmaz():
    assert gosterim_alanlari(None) is None
    g = gosterim_alanlari(ilerleme_ayristir("ILERLEME asama=static adim=ghidra.cfg durum=basladi"))
    assert list(g) == list(GOSTERILEN_ALANLAR)
    assert g == {"asama": "static", "adim": "ghidra.cfg", "durum": "basladi", "islenen": None, "toplam": None,
                 "gecen_sn": None, "cozumleyici": None, "neden": None}


# =============================================================================
# 2) CLI kipleri (birim)
# =============================================================================


@pytest.mark.parametrize(("quiet", "verbose", "tty", "cubuk", "beklenen"), [
    (True, False, False, False, ILERLEME_KIP_YOK),
    (True, False, True, True, ILERLEME_KIP_YOK),
    (False, True, False, False, ILERLEME_KIP_YOK),
    (False, True, True, True, ILERLEME_KIP_YOK),
    (False, False, False, False, ILERLEME_KIP_SATIR),
    (False, False, False, True, ILERLEME_KIP_SATIR),   # stderr dosyada, çubuk terminalde
    (False, False, True, False, ILERLEME_KIP_SATIR),   # çubuk çizilmiyor: satır terminale
    (False, False, True, True, ILERLEME_KIP_CUBUK),
])
def test_ilerleme_kipi(quiet, verbose, tty, cubuk, beklenen):
    assert ilerleme_kipi(quiet=quiet, verbose=verbose, stderr_tty=tty,
                         cubuk_cizilir=cubuk) == beklenen


def test_cubuk_aciklamasi_yalniz_olaydaki_alanlar():
    etiket = {"static": "Static Analysis"}
    a = ilerleme_aciklamasi(ilerleme_ayristir(
        "ILERLEME asama=static adim=ghidra.decompile durum=suruyor islenen=500 toplam=13559 "
        "gecen_sn=45.25"), etiket)
    assert a == "[cyan]Static Analysis[/cyan] [dim]ghidra.decompile 500/13559 45.2 sn[/dim]"
    b = ilerleme_aciklamasi(ilerleme_ayristir(
        "ILERLEME asama=static adim=ghidra.strings durum=suruyor islenen=7 gecen_sn=2"), etiket)
    assert b == "[cyan]Static Analysis[/cyan] [dim]ghidra.strings 7 2.0 sn[/dim]"
    c = ilerleme_aciklamasi(ilerleme_ayristir(
        'ILERLEME asama=static adim="[bold]x" durum=basladi'), etiket)
    assert c == "[cyan]Static Analysis[/cyan] [dim]\\[bold]x[/dim]"   # Rich biçimlemesi kaçırılır


class _SahteCubuk:
    def __init__(self):
        self.aciklamalar = []

    def update(self, task_id, **kw):
        self.aciklamalar.append((task_id, kw.get("description")))


@pytest.fixture
def gunlukcu_durumu():
    """Kök ve ``karadul.ilerleme`` günlükçülerinin durumunu test sonunda geri yükle."""
    kok, g = logging.getLogger(), logging.getLogger(ILERLEME_GUNLUKCU)
    eski = (list(kok.handlers), kok.level, list(g.handlers), g.level, g.propagate)
    yield
    kok.handlers[:] = eski[0]
    kok.setLevel(eski[1])
    g.handlers[:] = eski[2]
    g.setLevel(eski[3])
    g.propagate = eski[4]


def test_satir_kipi_tek_satir_akima_ve_cubuga(gunlukcu_durumu):
    akim, cubuk = io.StringIO(), _SahteCubuk()
    g = logging.getLogger(ILERLEME_GUNLUKCU)
    onceki = (list(g.handlers), g.level, g.propagate)
    with ilerleme_gosterimi(ILERLEME_KIP_SATIR, akim=akim, progress=cubuk, task_id=7,
                            stage_labels={"static": "Static Analysis"}) as isleyici:
        assert isinstance(isleyici, IlerlemeGosterici)
        _ilerleme("ghidra.decompile", "suruyor", islenen=5, toplam=10, gecen_sn=1.5)
    assert akim.getvalue() == ilerleme_satiri("ghidra.decompile", "suruyor", islenen=5, toplam=10,
                                              gecen_sn=1.5) + "\n"
    assert cubuk.aciklamalar == [
        (7, "[cyan]Static Analysis[/cyan] [dim]ghidra.decompile 5/10 1.5 sn[/dim]")]
    # çıkışta günlükçü eski hâlinde: işleyici yok, düzey ve yayılım geri
    assert (list(g.handlers), g.level, g.propagate) == onceki
    _ilerleme("ghidra.cfg", "basladi")
    assert akim.getvalue().count("\n") == 1


def test_cubuk_kipi_satir_basmaz(gunlukcu_durumu):
    akim, cubuk = io.StringIO(), _SahteCubuk()
    with ilerleme_gosterimi(ILERLEME_KIP_CUBUK, akim=akim, progress=cubuk, task_id=1):
        _ilerleme("ghidra.xref", "suruyor", islenen=100, toplam=200, gecen_sn=3.0)
        _ilerleme("ghidra.xref", "bitti", gecen_sn=4.0)
    assert akim.getvalue() == ""
    assert [a for _, a in cubuk.aciklamalar] == [
        "[cyan]Static[/cyan] [dim]ghidra.xref 100/200 3.0 sn[/dim]",
        "[cyan]Static[/cyan] [dim]ghidra.xref 4.0 sn[/dim]"]


def test_yok_kipi_isleyici_kurmaz(gunlukcu_durumu):
    g = logging.getLogger(ILERLEME_GUNLUKCU)
    onceki = list(g.handlers)
    with ilerleme_gosterimi(ILERLEME_KIP_YOK, akim=io.StringIO()) as isleyici:
        assert isleyici is None and list(g.handlers) == onceki


def test_kokteki_eski_isleyici_satiri_yinelemez(gunlukcu_durumu):
    """Kökte (önceki bir --verbose koşusundan kalan) işleyici varsa satır yine tek kez çıkar."""
    kok_akim, akim = io.StringIO(), io.StringIO()
    kok = logging.getLogger()
    kok.addHandler(logging.StreamHandler(kok_akim))
    kok.setLevel(logging.INFO)
    with ilerleme_gosterimi(ILERLEME_KIP_SATIR, akim=akim):
        _ilerleme("ghidra.pcode", "basladi")
    assert akim.getvalue().count("ILERLEME") == 1 and kok_akim.getvalue() == ""


# =============================================================================
# 3) CLI uçtan uca (sahte boru hattı; olaylar gerçek üreticiden)
# =============================================================================

_OLAYLAR = [
    ("ghidra.otomatik_analiz", "basladi", {}),
    ("ghidra.otomatik_analiz", "suruyor", {"gecen_sn": 15.0, "cozumleyici": "Stack Analyzer"}),
    ("ghidra.otomatik_analiz", "bitti", {"gecen_sn": 19.1}),
    ("ghidra.decompile", "basladi", {}),
    ("ghidra.decompile", "bitti", {"islenen": 296, "toplam": 296, "gecen_sn": 11.6}),
    ("ghidra.bsim.query", "atlandi", {"neden": "depoda başka program yok"}),
]
_SATIRLAR = [ilerleme_satiri(a, d, **k) for a, d, k in _OLAYLAR]


class _OlayliBoruHatti:
    registered_stages = ["identify"]

    def __init__(self, kok: Path) -> None:
        self._kok = kok

    def run(self, target_path, **kwargs):
        for adim, durum, alanlar in _OLAYLAR:
            _ilerleme(adim, durum, **alanlar)
        ws = self._kok / "workspaces" / "hedef" / "20260101_000000"
        ws.mkdir(parents=True, exist_ok=True)
        sonuc = PipelineResult(target_name="hedef", target_hash="0" * 64, workspace_path=ws)
        sonuc.add_stage_result(StageResult(stage_name="identify", success=True,
                                           duration_seconds=0.0))
        return sonuc


@pytest.fixture
def analyze_cagir(tmp_path, monkeypatch, gunlukcu_durumu):
    monkeypatch.setattr(cli, "build_pipeline", lambda cfg, **kw: _OlayliBoruHatti(tmp_path))
    monkeypatch.setattr(cli, "_load_config", lambda _yol: Config())
    hedef = tmp_path / "hedef.bin"
    hedef.write_bytes(b"\x00" * 64)

    def cagir(*on, sonra=()):
        return CliRunner().invoke(cli.main, [*on, "analyze", str(hedef), *sonra],
                                  catch_exceptions=False)

    return cagir


def _ilerleme_satirlari(metin: str) -> list[str]:
    return [s for s in metin.splitlines() if "ILERLEME" in s]


def test_e2e_ontanim_tty_degil_satirlar_stderr_de(analyze_cagir):
    r = analyze_cagir()
    assert r.exit_code == 0, r.output
    assert _ilerleme_satirlari(r.stderr) == _SATIRLAR       # her olay bir satır, sözleşme biçimi
    assert _ilerleme_satirlari(r.stdout) == []              # stdout'a olay yazılmaz


@pytest.mark.parametrize("bayrak", [(("--quiet",), ()), ((), ("--json",))],
                         ids=["quiet", "json"])
def test_e2e_quiet_ve_json_olay_basmaz(analyze_cagir, bayrak):
    r = analyze_cagir(*bayrak[0], sonra=bayrak[1])
    assert r.exit_code == 0, r.output
    assert _ilerleme_satirlari(r.output) == []
    if bayrak[1]:
        json.loads(r.stdout)                                  # makine-okur çıktı bozulmadı


def test_e2e_verbose_satir_tam_bir_kez(analyze_cagir):
    r = analyze_cagir(sonra=("--verbose",))
    assert r.exit_code == 0, r.output
    satirlar = _ilerleme_satirlari(r.output)
    assert len(satirlar) == len(_SATIRLAR)                    # yineleme yok
    assert [ilerleme_ayristir(s) for s in satirlar] == [ilerleme_ayristir(s) for s in _SATIRLAR]
    assert all("[karadul.ilerleme]" in s for s in satirlar)  # kök işleyicinin biçimi


def test_e2e_cubuk_terminalde_satir_stderr_e_gider(analyze_cagir, monkeypatch):
    """stdout terminal (çubuk çiziliyor), stderr dosya: Rich Live sys.stderr'i konsola yönlendirse
    de satırlar gerçek stderr'e gider; çubuk çıktısına (stdout) olay satırı karışmaz."""
    ekran = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=ekran, force_terminal=True, width=120))
    r = analyze_cagir()
    assert r.exit_code == 0, r.output
    assert _ilerleme_satirlari(r.stderr) == _SATIRLAR
    assert "ILERLEME" not in ekran.getvalue()


def test_e2e_cubuk_kipi_stderr_terminal_satir_yok(analyze_cagir, monkeypatch):
    ekran = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=ekran, force_terminal=True, width=120))
    monkeypatch.setattr(cli, "akim_tty", lambda akim: True)
    goruler = []
    gercek = cli.ilerleme_gosterimi

    def izle(kip, **kw):
        goruler.append(kip)
        return gercek(kip, **kw)

    monkeypatch.setattr(cli, "ilerleme_gosterimi", izle)
    r = analyze_cagir()
    assert r.exit_code == 0, r.output
    assert goruler == [ILERLEME_KIP_CUBUK]
    assert _ilerleme_satirlari(r.stderr) == [] and "ILERLEME" not in ekran.getvalue()


# =============================================================================
# 4) Sunucu: artımlı okuma
# =============================================================================


@pytest.fixture
def srv():
    spec = importlib.util.spec_from_file_location("bw_ui_server_ol4", _SERVER_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod._JOBS.clear()


class _Surec:
    def __init__(self):
        self.rc = None

    def poll(self):
        return self.rc


def _is(srv, tmp_path: Path, ad: str = "j") -> tuple[Path, _Surec]:
    kok = tmp_path / ad
    kok.mkdir(parents=True, exist_ok=True)
    log = kok / "analyze.log"
    log.write_bytes(b"")
    proc = _Surec()
    # eski biçimli iş kaydı (``gunluk`` alanı yok): sunucu kendisi kurar
    srv._JOBS[ad] = {"proc": proc, "log": str(log), "ws_out": str(kok / "ws"),
                     "run_dir": str(kok), "binary": "hedef", "started": time.time(),
                     "lf": None, "closed": True, "cancelled": False, "activated": False}
    return log, proc


def _tam_okuma(srv, log: Path) -> dict:
    """ÖL-4 öncesi _job_progress'in tam okuması (aynı ayrıştırıcılar) + son olay."""
    metin = log.read_text(errors="ignore")
    alt = []
    for pat, label, grp in srv.SUBSTAGE_PATTERNS:
        m = pat.search(metin)
        if m:
            alt.append({"label": label, "count": m.group(grp) if grp else None})
    son = None
    for satir in metin.split("\n"):
        olay = ilerleme_ayristir(satir)
        if olay is not None:
            son = olay
    return {"stages": srv._parse_stage_log(metin), "substages": alt,
            "tail": "\n".join(metin.splitlines()[-6:]), "ilerleme": gosterim_alanlari(son)}


def _secili(p: dict) -> dict:
    return {k: p[k] for k in ("stages", "substages", "tail", "ilerleme")}


def _ornek_gunluk() -> bytes:
    olay = [ilerleme_satiri("ghidra.otomatik_analiz", "suruyor", gecen_sn=15.0,
                            cozumleyici="Objective-C Message Analyzer"),
            ilerleme_satiri("ghidra.xref", "kismi", islenen=1144, toplam=1144, gecen_sn=1.023,
                            neden="xrefs: adım bütçesi (1 sn) doldu; genel sembol sayımı yarıda")]
    satirlar = [
        "13:00:00 INFO    [karadul] başlıyor — Türkçe ğüşiöç ✓",
        "13:00:01 INFO    [karadul] OK identify: 0.10s",
        "13:00:02 INFO    [karadul.ilerleme] " + olay[0],
        "satır\x0ciçinde form besleme",
        "13:00:03 INFO    [karadul.naming] gnulib fingerprint: 12 fonksiyon kurtarıldı",
        "13:00:03 INFO    [karadul.naming] gnulib fingerprint: 99 fonksiyon (ikinci, sayılmaz)",
        "13:00:04 ERROR   [karadul] FAIL deobfuscate: beklenmeyen",
        "13:00:05 INFO    [karadul.ilerleme] " + olay[1],
        "13:00:06 INFO    [karadul] OK static: 12.50s",
        "13:00:06 INFO    [karadul] SKIP deobfuscate: 0.00s -- Python hedefi uygulanamaz",
        "ELF boilerplate: 3 fonksiyon",
        'ILERLEME asama=static adim=ghidra.cfg durum=suruyor neden="kapanmamış',  # olay değil
        "",
        "main kurtarildi",
    ]
    govde = "\r\n".join(satirlar[:5]) + "\r" + "\n".join(satirlar[5:]) + "\n"
    return govde.encode("utf-8") + b"\xff\xfe bozuk bayt\n" + "son yarım satır é".encode("utf-8")


@pytest.mark.parametrize("tohum", range(8))
def test_parcali_okuma_tek_seferlik_tam_okumayla_ayni(srv, tmp_path, tohum):
    veri = _ornek_gunluk()
    rnd = random.Random(tohum)
    kesimler = sorted(rnd.sample(range(1, len(veri)), 25))
    # \r ile \n arasından ve çok baytlı UTF-8 karakterinin ortasından bölme de olsun
    kesimler = sorted(set(kesimler) | {veri.index(b"\r\n") + 1, veri.index("ğ".encode()) + 1})
    log, proc = _is(srv, tmp_path)
    onceki = 0
    with open(log, "ab") as f:
        for k in kesimler + [len(veri)]:
            f.write(veri[onceki:k])
            f.flush()
            onceki = k
            srv._job_progress("j")
    proc.rc = 0
    p = srv._job_progress("j")
    assert _secili(p) == _tam_okuma(srv, log)
    assert set(p) == _ESKI_ANAHTARLAR | {"ilerleme", "son_cikti_yasi_sn"}
    # bitmiş işte yeniden yoklama aynı sonucu verir
    assert _secili(srv._job_progress("j")) == _secili(p)


def test_tek_seferde_okuma_da_ayni_ve_beklenen_degerler(srv, tmp_path):
    log, proc = _is(srv, tmp_path)
    log.write_bytes(_ornek_gunluk())
    proc.rc = 0
    p = srv._job_progress("j")
    assert _secili(p) == _tam_okuma(srv, log)
    durum = {s["key"]: s["status"] for s in p["stages"]}
    assert durum == {"identify": "done", "static": "done", "deobfuscate": "skipped",
                     "reconstruct": "running", "report": "pending"}
    assert p["substages"] == [
        {"label": "main entry recovery", "count": None},
        {"label": "gnulib string-fingerprint", "count": "12"},
        {"label": "ELF/CRT boilerplate", "count": "3"}]
    assert p["ilerleme"] == {"asama": "static", "adim": "ghidra.xref", "durum": "kismi", "islenen": 1144,
                             "toplam": 1144, "gecen_sn": 1.023, "cozumleyici": None,
                             "neden": "xrefs: adım bütçesi (1 sn) doldu; genel sembol sayımı yarıda"}
    assert p["tail"].endswith("son yarım satır é")


def test_yarim_satir_sonraki_yoklamaya_kalir(srv, tmp_path):
    log, proc = _is(srv, tmp_path)
    with open(log, "ab") as f:
        f.write(b"OK identify: 0.1s\nOK stat")
        f.flush()
        p = srv._job_progress("j")
        assert [s["status"] for s in p["stages"]][:2] == ["done", "running"]
        assert p["tail"] == "OK identify: 0.1s"
        f.write(b"ic: 2.0s\nILERLEME asama=static adim=ghidra.cfg durum=basladi")
        f.flush()
        p = srv._job_progress("j")
        assert [s["status"] for s in p["stages"]][:2] == ["done", "done"]
        assert p["ilerleme"] is None                 # yarım olay satırı henüz işlenmedi
    proc.rc = 0
    p = srv._job_progress("j")                       # iş bitti: son yarım satır da işlenir
    assert p["ilerleme"]["adim"] == "ghidra.cfg" and p["ilerleme"]["durum"] == "basladi"


def test_cr_lf_parca_sinirinda_tek_satir_sonu(srv, tmp_path):
    log, proc = _is(srv, tmp_path)
    with open(log, "ab") as f:
        for parca in (b"a\r", b"\nb\r", b"\nc"):
            f.write(parca)
            f.flush()
            srv._job_progress("j")
    proc.rc = 0
    assert srv._job_progress("j")["tail"] == "a\nb\nc" == _tam_okuma(srv, log)["tail"]


def test_dosya_kisalinca_bastan_okunur(srv, tmp_path):
    log, proc = _is(srv, tmp_path)
    log.write_text("OK identify: 0.1s\nOK static: 1.0s\nOK deobfuscate: 1.0s\nuzun bir satır\n")
    srv._job_progress("j")
    log.write_text("OK identify: 0.1s\n")            # aynı dosya, kısaldı
    p = srv._job_progress("j")
    assert _secili(p) == _tam_okuma(srv, log)
    assert [s["status"] for s in p["stages"]][:2] == ["done", "running"]


def test_gunluk_yoksa_bos_gunluk_gibi(srv, tmp_path):
    log, proc = _is(srv, tmp_path)
    log.unlink()
    p = srv._job_progress("j")
    assert p["tail"] == "" and p["substages"] == [] and p["ilerleme"] is None
    assert [s["status"] for s in p["stages"]] == ["running"] + ["pending"] * 4


def test_olay_yoksa_ilerleme_null(srv, tmp_path):
    log, proc = _is(srv, tmp_path)
    log.write_text("OK identify: 0.1s\nILERLEME ama sözleşme dışı\n")
    p = srv._job_progress("j")
    assert p["ilerleme"] is None
    json.dumps(p)


def test_ayni_parcada_son_olay_alinir(srv, tmp_path):
    log, _ = _is(srv, tmp_path)
    log.write_text("\n".join([
        ilerleme_satiri("ghidra.decompile", "basladi"),
        ilerleme_satiri("ghidra.decompile", "suruyor", islenen=10, toplam=20, gecen_sn=5.0),
        ilerleme_satiri("ghidra.decompile", "suruyor", islenen=20, toplam=20, gecen_sn=9.0),
        "ILERLEME asama=static adim=x durum=yanlis",
    ]) + "\n")
    p = srv._job_progress("j")
    assert p["ilerleme"]["islenen"] == 20 and p["ilerleme"]["gecen_sn"] == 9.0


def test_ikinci_yoklama_yalniz_yeni_satirlari_tarar(srv, tmp_path, monkeypatch):
    log, _ = _is(srv, tmp_path)
    log.write_text("".join("satır %d\n" % i for i in range(1000)))
    srv._job_progress("j")
    taranan = []
    gercek = srv._scan_stage_lines
    monkeypatch.setattr(srv, "_scan_stage_lines",
                        lambda metin, e, h: (taranan.append(metin), gercek(metin, e, h)))
    with open(log, "a") as f:
        f.write("OK identify: 0.5s\nyeni\n")
    p = srv._job_progress("j")
    assert taranan == ["OK identify: 0.5s", "yeni"]
    assert p["stages"][0]["status"] == "done"
    assert srv._JOBS["j"]["gunluk"].ofset == log.stat().st_size


def _buyuk_gunluk(log: Path, hedef_bayt: int) -> None:
    satirlar, n, i = [], 0, 0
    while n < hedef_bayt:
        i += 1
        if i % 5 == 0:
            s = "12:00:00 INFO    [karadul.ilerleme] " + ilerleme_satiri(
                "ghidra.decompile", "suruyor", islenen=i, toplam=10 ** 6, gecen_sn=i / 10)
        else:
            s = "12:00:00 INFO    [karadul.naming] satır %d gnulib fingerprint: %d fonksiyon" % (i, i)
        satirlar.append(s)
        n += len(s.encode()) + 1
    log.write_text("\n".join(satirlar) + "\n")


def test_10mb_gunlukte_ikinci_ve_sonraki_yoklamalar_50ms_alti(srv, tmp_path, capsys):
    log, _ = _is(srv, tmp_path)
    _buyuk_gunluk(log, 10 * 1024 * 1024)
    assert log.stat().st_size >= 10 * 1024 * 1024
    gc.collect()
    t0 = time.perf_counter()
    srv._job_progress("j")
    ilk = time.perf_counter() - t0
    sureler = []
    for k in range(5):
        with open(log, "a") as f:
            f.write("".join("ek satır %d-%d\n" % (k, i) for i in range(200)))
            f.write(ilerleme_satiri("ghidra.cfg", "suruyor", islenen=k, toplam=5) + "\n")
        t0 = time.perf_counter()
        p = srv._job_progress("j")
        sureler.append(time.perf_counter() - t0)
        assert p["ilerleme"]["adim"] == "ghidra.cfg" and p["ilerleme"]["islenen"] == k
    with capsys.disabled():
        print("\n[OL4] 10 MB günlük: ilk yoklama %.1f ms, sonrakiler %s ms" % (
            ilk * 1e3, ", ".join("%.2f" % (s * 1e3) for s in sureler)))
    assert max(sureler) < 0.050
