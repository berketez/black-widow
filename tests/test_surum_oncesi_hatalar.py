"""Sürüm öncesi hata düzeltmelerini kilitleyen testler (belge denetimi, 2026-11-10).

Her bölüm, belge denetiminde bulunup yeniden üretilen bir hatayı kilitler:

1. ``karadul.analyze()`` aşama kaydetmeden koşuyordu.
2. ``--online`` ağı açmıyor, kapalı bırakıyordu.
3. ``analyze --json`` verilince ``--output`` yok sayılıyordu.
4. ``pyahocorasick`` yalnız ``perf`` ekindeydi; ``import karadul.reconstruction``
   temel kurulumda düşüyordu.
5. ``karadul-hack``, ``pyfiglet`` yokken içe aktarmada çöküyordu.
6. Uçtan uca test CLI'ı PATH'ten buluyor, başka kurulumun kodunu koşturabiliyordu.
7. n-gram duman testi veri yokken atlamıyor, düşüyordu.
8. ``docs/quickstart.md`` var olmayan seçenek, aşama adı ve öznitelik anlatıyordu.

Hiçbir test Ghidra, ağ ya da hedef ikilinin çalıştırılmasını gerektirmez.
CLI testlerinde boru hattı sahtesiyle değiştirilir; gerçek aşama koşan tek
test ``identify`` aşamasını geçici dizindeki bir metin dosyasında çalıştırır.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import click
import pytest
from click.testing import CliRunner

import karadul
import karadul.cli as cli
from karadul.cli_common import DEFAULT_STAGE_ORDER, build_pipeline
from karadul.config import GHIDRA_PINNED_VERSION, Config
from karadul.core.pipeline import Pipeline
from karadul.core.result import PipelineResult, StageResult

REPO_ROOT = Path(__file__).resolve().parent.parent

# Alt süreçte .pyc yazılmasın (mutasyon koşularında bayat bytecode tuzağı).
_ALT_SUREC_ORTAMI = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")


def _hedef_dosya(tmp_path: Path) -> Path:
    """Analiz hedefi olarak verilen, çalıştırılmayan küçük bir dosya."""
    hedef = tmp_path / "hedef.bin"
    hedef.write_bytes(b"\x00" * 64)
    return hedef


# ---------------------------------------------------------------------------
# 1) karadul.analyze() aşamaları CLI ile aynı kurucudan alır
# ---------------------------------------------------------------------------


class TestAnalyzeAsamaKaydi:
    def test_asama_listesi_dolu_ve_cli_ile_ayni(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """analyze(), `run` çağrılırken CLI'ın varsayılan aşamalarını kaydetmiş olmalı."""
        gorulen: dict = {}
        nobetci = object()

        def sahte_run(self, target_path, stages=None, **kwargs):
            gorulen["kayitli"] = self.registered_stages
            gorulen["stages"] = stages
            gorulen["hedef"] = Path(target_path)
            return nobetci

        monkeypatch.setattr(Pipeline, "run", sahte_run)
        cfg = Config()
        hedef = _hedef_dosya(tmp_path)

        sonuc = karadul.analyze(hedef, config=cfg)

        assert sonuc is nobetci
        assert gorulen["hedef"] == hedef
        assert gorulen["stages"] is None
        # CLI'ın bayraksız çağrısı: build_pipeline(cfg, stop_after=None, skip_dynamic=False)
        cli_asamalari = build_pipeline(
            cfg, stop_after=None, skip_dynamic=False,
        ).registered_stages
        assert gorulen["kayitli"], "analyze() hiçbir aşama kaydetmedi"
        assert gorulen["kayitli"] == cli_asamalari
        # Kayıtlı aşamalar varsayılan sıranın alt dizisi; ilk ve son uçlar yerinde.
        assert gorulen["kayitli"][0] == DEFAULT_STAGE_ORDER[0] == "identify"
        assert gorulen["kayitli"][-1] == DEFAULT_STAGE_ORDER[-1] == "report"

    def test_stages_parametresi_run_a_iletilir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        gorulen: dict = {}

        def sahte_run(self, target_path, stages=None, **kwargs):
            gorulen["stages"] = stages
            return None

        monkeypatch.setattr(Pipeline, "run", sahte_run)
        karadul.analyze(
            _hedef_dosya(tmp_path), config=Config(), stages=["identify", "static"],
        )
        assert gorulen["stages"] == ["identify", "static"]

    def test_gercek_kosuda_asama_sonucu_doner(self, tmp_path: Path) -> None:
        """Sahtesiz: yalnız `identify` aşaması bir metin dosyasında gerçekten koşar.

        Hata varken sonuç aşama kaydı olmadan, `stages == {}` ile dönüyordu.
        """
        hedef = tmp_path / "ornek.js"
        hedef.write_text("console.log(1);\n", encoding="utf-8")
        cfg = Config()
        cfg.project_root = tmp_path  # çalışma alanı depoya değil geçici dizine

        sonuc = karadul.analyze(hedef, config=cfg, stages=["identify"])

        assert list(sonuc.stages) == ["identify"]
        assert sonuc.stages["identify"].success is True
        assert sonuc.success is True
        assert tmp_path in sonuc.workspace_path.parents


# ---------------------------------------------------------------------------
# 2) ve 3) için ortak: boru hattı sahtesiyle `karadul analyze`
# ---------------------------------------------------------------------------


class _SahteBoruHatti:
    """`build_pipeline` yerine geçer; hiçbir aşama koşmaz, boş bir sonuç döner."""

    registered_stages = ["identify"]

    def __init__(self, calisma_koku: Path) -> None:
        self._calisma_koku = calisma_koku

    def run(self, target_path, **kwargs) -> PipelineResult:
        ws = self._calisma_koku / "workspaces" / "hedef" / "20260101_000000"
        ws.mkdir(parents=True, exist_ok=True)
        sonuc = PipelineResult(
            target_name="hedef", target_hash="0" * 64, workspace_path=ws,
        )
        sonuc.add_stage_result(
            StageResult(stage_name="identify", success=True, duration_seconds=0.0),
        )
        return sonuc


@pytest.fixture
def sahte_analyze(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """`karadul analyze`'ı sahte boru hattıyla çağıran yardımcı.

    Dönen işlev `(click sonucu, build_pipeline'a verilen Config)` verir.
    Yapılandırma `Config()` ile sabitlenir: çalışma dizinindeki bir
    `karadul.yaml` testin sonucunu değiştirmesin.
    """
    gorulen: dict = {}

    def sahte_build(cfg, **kwargs):
        gorulen["cfg"] = cfg
        return _SahteBoruHatti(tmp_path)

    monkeypatch.setattr(cli, "build_pipeline", sahte_build)
    monkeypatch.setattr(cli, "_load_config", lambda _yol: Config())
    hedef = _hedef_dosya(tmp_path)

    def cagir(*bayraklar: str):
        sonuc = CliRunner().invoke(
            cli.main, ["analyze", str(hedef), *bayraklar], catch_exceptions=False,
        )
        return sonuc, gorulen.get("cfg")

    return cagir


# ---------------------------------------------------------------------------
# 2) --online ağı açar
# ---------------------------------------------------------------------------


class TestAgBayraklari:
    @pytest.mark.parametrize(
        ("bayraklar", "beklenen"),
        [
            ((), False),
            (("--enable-network",), True),
            (("--online",), True),
        ],
        ids=["bayraksiz", "enable-network", "online"],
    )
    def test_ag_anahtari(self, sahte_analyze, bayraklar, beklenen) -> None:
        sonuc, cfg = sahte_analyze("--json", *bayraklar)
        assert sonuc.exit_code == 0, sonuc.output
        assert cfg.network.enabled is beklenen
        assert cfg.source_match.enabled is beklenen

    def test_iki_bayrak_da_yardimda_ve_kapatan_bayrak_yok(self) -> None:
        """`--online` yardımda görünür; ağ seçeneğinin "kapalı" tarafı yoktur."""
        ag_secenegi = next(
            p for p in cli.analyze.params if p.name == "enable_network"
        )
        assert set(ag_secenegi.opts) == {"--enable-network", "--online"}
        assert list(ag_secenegi.secondary_opts) == []


# ---------------------------------------------------------------------------
# 3) --json ile --output birlikte
# ---------------------------------------------------------------------------


class TestJsonIleOutput:
    def test_json_ve_output_birlikte(self, sahte_analyze, tmp_path: Path) -> None:
        cikti = tmp_path / "temiz"
        sonuc, _cfg = sahte_analyze("--json", "--output", str(cikti))

        assert sonuc.exit_code == 0, sonuc.output
        # stdout'un TAMAMI tek bir JSON nesnesi olmalı (başka satır karışmamalı).
        yuk = json.loads(sonuc.stdout)
        assert yuk["success"] is True
        assert "identify" in yuk["stages"]
        # Temiz çıktı gerçekten yazılmış olmalı (gerçek OutputFormatter koşar).
        assert cikti.is_dir(), "--json verilince --output yok sayıldı"
        assert any(cikti.iterdir()), "temiz çıktı dizini boş"
        # Sessiz kip: biçimleme iletileri stderr'e de dökülmez (yalnız hata yazılır).
        assert "Output Formatting" not in sonuc.stderr

    def test_json_tek_basina_cikti_dizini_yazmaz(
        self, sahte_analyze, tmp_path: Path,
    ) -> None:
        sonuc, _cfg = sahte_analyze("--json")
        assert sonuc.exit_code == 0, sonuc.output
        json.loads(sonuc.stdout)
        assert not (tmp_path / "temiz").exists()

    def test_tablo_dalinda_output_yazilir(self, sahte_analyze, tmp_path: Path) -> None:
        """`--json` olmadan eski davranış korunur: çıktı yazılır, özet stdout'ta."""
        cikti = tmp_path / "temiz"
        sonuc, _cfg = sahte_analyze("--no-compute-recovery", "--output", str(cikti))

        assert sonuc.exit_code == 0, sonuc.output
        assert cikti.is_dir() and any(cikti.iterdir())
        assert "Output Formatting" in sonuc.stdout


# ---------------------------------------------------------------------------
# 4) pyahocorasick temel bağımlılık
# ---------------------------------------------------------------------------


def _temel_bagimlilik_adlari() -> set[str]:
    veri = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    adlar = set()
    for gereksinim in veri["project"]["dependencies"]:
        ad = re.split(r"[\s<>=!~\[;]", gereksinim, maxsplit=1)[0]
        adlar.add(ad.lower().replace("_", "-"))
    return adlar


def _kosulsuz_ust_duzey_ice_aktarimlar(dosya: Path) -> set[str]:
    """Modül gövdesinde, try/if/işlev dışında içe aktarılan üst düzey paket adları."""
    agac = ast.parse(dosya.read_text(encoding="utf-8"))
    adlar: set[str] = set()
    for dugum in agac.body:
        if isinstance(dugum, ast.Import):
            adlar.update(takma.name.split(".")[0] for takma in dugum.names)
        elif isinstance(dugum, ast.ImportFrom) and dugum.module and dugum.level == 0:
            adlar.add(dugum.module.split(".")[0])
    return adlar


class TestAhocorasickBagimliligi:
    def test_kosulsuz_ice_aktarilan_paket_temel_bagimlilikta(self) -> None:
        """`aho_replacer` ahocorasick'i koşulsuz içe aktardığı sürece paket temel
        bağımlılık olmalı; yoksa `import karadul.reconstruction` temel kurulumda düşer.
        """
        aho = REPO_ROOT / "karadul" / "reconstruction" / "aho_replacer.py"
        if "ahocorasick" not in _kosulsuz_ust_duzey_ice_aktarimlar(aho):
            pytest.skip("aho_replacer artık ahocorasick'i koşulsuz içe aktarmıyor")
        assert "pyahocorasick" in _temel_bagimlilik_adlari()

    def test_reconstruction_paketi_aho_replacer_i_kosulsuz_yukler(self) -> None:
        """Üstteki testin dayandığı zincir: paket -> c_namer -> aho_replacer."""
        c_namer = REPO_ROOT / "karadul" / "reconstruction" / "c_namer.py"
        paket = REPO_ROOT / "karadul" / "reconstruction" / "__init__.py"
        assert "karadul.reconstruction.aho_replacer" in c_namer.read_text(encoding="utf-8")
        assert "karadul.reconstruction.c_namer" in paket.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 5) karadul-hack pyfiglet olmadan
# ---------------------------------------------------------------------------


_PYFIGLET_YOK_BETIGI = """
import sys
sys.modules["pyfiglet"] = None  # `import pyfiglet` ImportError versin
import karadul.hacker_cli as h
assert h.pyfiglet is None
logo = h._build_logo().plain
assert h._PLAIN_TITLE.strip() in logo, "sade başlık yok"
assert "██" in logo, "örümcek çizimi yok"
sys.argv = ["karadul-hack", "--help"]
h.main()
"""


class TestHackerCliPyfigletsiz:
    def test_pyfiglet_yokken_ice_aktarilir_ve_yardim_basar(self) -> None:
        surec = subprocess.run(
            [sys.executable, "-c", _PYFIGLET_YOK_BETIGI],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            env=_ALT_SUREC_ORTAMI,
        )
        assert surec.returncode == 0, surec.stderr[-2000:]
        assert "Usage: karadul-hack" in surec.stdout

    def test_pyfiglet_varken_suslu_baslik_kullanilir(self) -> None:
        pytest.importorskip("pyfiglet")
        import karadul.hacker_cli as h

        assert h.pyfiglet is not None
        baslik = h._title_art()
        assert baslik != h._PLAIN_TITLE
        assert len(baslik.splitlines()) > 3

    def test_yardim_bayragi_analiz_baslatmaz(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
    ) -> None:
        import karadul.hacker_cli as h

        def cagrilmamali(*_a, **_k):
            raise AssertionError("--help analiz ya da etkileşimli mod başlattı")

        monkeypatch.setattr(h, "analyze_with_live_output", cagrilmamali)
        monkeypatch.setattr(h, "run_interactive", cagrilmamali)
        monkeypatch.setattr(sys, "argv", ["karadul-hack", "--help"])

        h.main()

        assert "Usage: karadul-hack" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 6) Uçtan uca test CLI'ı testi koşturan yorumlayıcıyla çağırır
# ---------------------------------------------------------------------------


class TestE2eCliYalitimi:
    def test_komut_oneki_sys_executable_ile_modul_cagrisi(self) -> None:
        from tests import test_pipeline_e2e_real_binary as e2e

        assert e2e._karadul_cli() == [sys.executable, "-m", "karadul"]
        kaynak = Path(e2e.__file__).read_text(encoding="utf-8")
        assert "shutil.which(" not in kaynak

    def test_komut_oneki_bu_agacin_kodunu_kosturur(self) -> None:
        """Önek, uçtan uca testin verdiği `cwd` ile bu ağaçtaki CLI'ı çalıştırır."""
        from tests import test_pipeline_e2e_real_binary as e2e

        assert e2e.REPO_ROOT == REPO_ROOT
        yorumlayici = e2e._karadul_cli()[0]
        konum = subprocess.run(
            [yorumlayici, "-c", "import karadul; print(karadul.__file__)"],
            cwd=str(e2e.REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            env=_ALT_SUREC_ORTAMI,
        )
        assert konum.returncode == 0, konum.stderr[-2000:]
        assert Path(konum.stdout.strip()).resolve() == (
            REPO_ROOT / "karadul" / "__init__.py"
        ).resolve()

        surum = subprocess.run(
            [*e2e._karadul_cli(), "--version"],
            cwd=str(e2e.REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            env=_ALT_SUREC_ORTAMI,
        )
        assert surum.returncode == 0, surum.stderr[-2000:]
        assert karadul.__version__ in surum.stdout


# ---------------------------------------------------------------------------
# 7) n-gram duman testi veri yokken atlar
# ---------------------------------------------------------------------------


def _ngram_testini_kopyada_kos(kok: Path) -> subprocess.CompletedProcess:
    """Duman testini `kok/tests/` altına kopyalayıp orada koşar.

    Test dosyası veri dizinini kendi konumuna göre arar (`<kök>/sigs/...`);
    kopya sayesinde sonuç bu makinede verinin bulunup bulunmamasına bağlı kalmaz.
    """
    hedef_dizin = kok / "tests"
    hedef_dizin.mkdir(parents=True)
    kopya = hedef_dizin / "test_ngram_db_v2_smoke.py"
    shutil.copyfile(REPO_ROOT / "tests" / "test_ngram_db_v2_smoke.py", kopya)
    return subprocess.run(
        [
            sys.executable, "-m", "pytest", str(kopya),
            "-q", "-p", "no:cacheprovider", "-o", "addopts=", "-rs",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
        env=_ALT_SUREC_ORTAMI,
    )


class TestNgramDumanTestiVeriYokken:
    def test_veri_dizini_yokken_gerekceyle_atlar(self, tmp_path: Path) -> None:
        surec = _ngram_testini_kopyada_kos(tmp_path / "depo")
        cikti = surec.stdout + surec.stderr

        assert surec.returncode == 0, cikti[-2000:]
        assert re.search(r"\b\d+ skipped\b", cikti), cikti[-2000:]
        assert " failed" not in cikti and " passed" not in cikti
        assert "sigs/ngram_name_db/" in cikti  # atlama gerekçesi veri yolunu söyler

    def test_veri_dizini_bos_ise_atlamaz_duser(self, tmp_path: Path) -> None:
        """Dizin var ama içi eksikse testler düşmeli: yarım veri sessizce geçmesin."""
        kok = tmp_path / "depo"
        (kok / "sigs" / "ngram_name_db").mkdir(parents=True)
        surec = _ngram_testini_kopyada_kos(kok)
        cikti = surec.stdout + surec.stderr

        assert surec.returncode != 0
        assert re.search(r"\b\d+ failed\b", cikti), cikti[-2000:]


# ---------------------------------------------------------------------------
# 8) docs/quickstart.md bugünkü CLI ve API ile uyumlu
# ---------------------------------------------------------------------------

_QUICKSTART = REPO_ROOT / "docs" / "quickstart.md"


def _kod_bloklari(dil: str) -> list[str]:
    metin = _QUICKSTART.read_text(encoding="utf-8")
    return re.findall(rf"```{dil}\n(.*?)```", metin, flags=re.DOTALL)


def _belgedeki_karadul_komutlari() -> list[str]:
    komutlar = []
    for blok in _kod_bloklari("bash"):
        for satir in blok.splitlines():
            if satir.strip().startswith("karadul "):
                komutlar.append(satir.strip())
    return komutlar


def _click_ile_ayristir(komut_satiri: str) -> None:
    """Komut satırını CLI'ın kendi ayrıştırıcısından geçirir; komut ÇALIŞTIRILMAZ.

    `make_context` yalnız seçenekleri ve argümanları ayrıştırır, komutun
    gövdesini çağırmaz. Tanınmayan seçenek, geçersiz seçim ya da eksik argüman
    click hatası olarak yükselir.
    """
    parcalar = shlex.split(komut_satiri, comments=True)
    assert parcalar[0] == "karadul"
    komut: click.Command = cli.main
    i = 1
    while isinstance(komut, click.Group) and i < len(parcalar) and not parcalar[i].startswith("-"):
        alt = komut.get_command(click.Context(komut), parcalar[i])
        assert alt is not None, f"böyle bir alt komut yok: {parcalar[i]!r} ({komut_satiri})"
        komut = alt
        i += 1
    try:
        with komut.make_context(parcalar[i - 1], parcalar[i:]):
            pass
    except click.exceptions.Exit:
        pass  # --help / --version: ayrıştırma başarılı, erken çıkış
    except click.BadParameter as hata:
        # Belgedeki yollar yer tutucudur; "var olmalı" denetimi ayrıştırma hatası sayılmaz.
        yol_tipi = isinstance(getattr(hata.param, "type", None), click.Path)
        if not (yol_tipi and "does not exist" in hata.format_message()):
            raise


class TestQuickstartBelgesi:
    def test_belgede_komut_var(self) -> None:
        assert len(_belgedeki_karadul_komutlari()) >= 8

    @pytest.mark.parametrize("komut_satiri", _belgedeki_karadul_komutlari())
    def test_her_komut_cli_ayristiricisindan_gecer(self, komut_satiri: str) -> None:
        _click_ile_ayristir(komut_satiri)

    def test_ayristirma_denetimi_olmayan_secenegi_yakalar(self) -> None:
        """Denetimin kendisi çalışıyor mu: eski belgedeki `-o` reddedilmeli."""
        with pytest.raises(click.UsageError):
            _click_ile_ayristir("karadul analyze /bin/ls -o /tmp/karadul-ls")
        with pytest.raises(click.UsageError):
            _click_ile_ayristir("karadul analyze /bin/ls --stage decompile")

    def test_tablodaki_komutlar_var(self) -> None:
        metin = _QUICKSTART.read_text(encoding="utf-8")
        tablo_komutlari = re.findall(r"^\| `karadul (\w+)", metin, flags=re.MULTILINE)
        assert len(tablo_komutlari) >= 5
        for ad in tablo_komutlari:
            assert cli.main.get_command(click.Context(cli.main), ad) is not None, ad

    def test_python_ornekleri_derlenir_ve_gercek_adlari_kullanir(self) -> None:
        bloklar = _kod_bloklari("python")
        assert bloklar, "belgede Python örneği yok"
        sonuc_ozellikleri = set(PipelineResult.__dataclass_fields__) | {
            ad for ad in dir(PipelineResult) if not ad.startswith("_")
        }
        for blok in bloklar:
            compile(blok, str(_QUICKSTART), "exec")
            for ad in re.findall(r"\bresult\.([A-Za-z_]\w*)", blok):
                assert ad in sonuc_ozellikleri, f"PipelineResult.{ad} yok"
            for liste in re.findall(r"stages=\[([^\]]*)\]", blok):
                for asama in re.findall(r"[\"']([^\"']+)[\"']", liste):
                    assert asama in DEFAULT_STAGE_ORDER, f"aşama adı yok: {asama}"
            # Config.load bir Path bekler; düz dizgi AttributeError verir.
            assert not re.search(r"Config\.load\(\s*[\"']", blok)

    def test_ghidra_surumu_sabitlenen_surumle_ayni(self) -> None:
        metin = _QUICKSTART.read_text(encoding="utf-8")
        surumler = set(re.findall(r"Ghidra (\d+(?:\.\w+)+)", metin))
        assert surumler == {GHIDRA_PINNED_VERSION}

    def test_anilan_belge_yollari_var(self) -> None:
        metin = _QUICKSTART.read_text(encoding="utf-8")
        yollar = set(re.findall(r"`((?:docs|tests|karadul)/[\w./-]+|README\.md|pyproject\.toml)`", metin))
        assert yollar
        for yol in yollar:
            assert (REPO_ROOT / yol).exists(), f"belgede anılan yol yok: {yol}"
