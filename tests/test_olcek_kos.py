"""scripts/measurement/olcek_kos.py — ÖLÇ-A ölçek koşucusunun testleri (Ghidra yok).

Koşucu her testte gerçek bir alt süreç olarak çalışır (sinyaller ana iş parçacığında, ``/usr/bin/time -l``
gerçek); analiz komutunun yerine ``--komut`` test kancasıyla sahte bir Python betiği verilir. Ürün ağacı
denetimi (``urun_kos.agac_kunyesi``) sarmalayıcıda sahte künyeyle değiştirilir; geri kalan her şey üründeki
yoldur.

Kilitlenen davranışlar:
  (a) duvar: süre dolunca karadul sürecine SIGTERM (``time``'a değil: ``time -l`` satırları kalır),
      ``BITTI`` = ``zaman_asimi``; SIGTERM'i yok sayan süreç ``--kill-bekle-sn`` sonra SIGKILL ile ölür;
  (b) örnekleyici: ``ornekler.csv`` satırları; tepe RSS süreç AĞACININ (torunlar dahil) en büyüğü;
  (c) künye: çıkış kodu / durum, ``time -l`` alanları, ortam (``PYTHONHASHSEED``, ``KARADUL_CACHE_DIR``,
      ``JAVA_TOOL_OPTIONS`` gc günlüğü), Ghidra adım süreleri ve kaynağı (``ghidra_status.adim_sureleri``
      önce, yoksa dosya zamanı), yarıda kalan köprüde "nerede kaldı", aşama süreleri, ilk rapor zamanı,
      GC duraklama özeti, paket bileşenleri;
  (d) yanlış ağaç denetimi koşuyu başlatmaz; ``BITTI`` olan köke yeniden koşulmaz;
  (e) PLAN kabulü: varsayılan aralıklarla 30 sn'lik sahte koşuda ``ornekler.csv`` ≥ 3 satır.

Mutasyon koruması: ``scripts/measurement/mutation_specs_olcek_kos.json``.
"""
from __future__ import annotations

import csv
import importlib.util
import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

_KOK = Path(__file__).resolve().parents[1]
_PATH = _KOK / "scripts" / "measurement" / "olcek_kos.py"
_spec = importlib.util.spec_from_file_location("olcek_kos_under_test", _PATH)
ok = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ok
_spec.loader.exec_module(ok)

pytestmark = pytest.mark.skipif(not os.access("/usr/bin/time", os.X_OK) or sys.platform != "darwin",
                                reason="macOS /usr/bin/time -l gerekir")

# Koşucuyu ayrı süreçte, sahte ağaç künyesiyle çalıştıran sarmalayıcı.
_SARMAL = textwrap.dedent(f"""
    import importlib.util, json, os, sys
    spec = importlib.util.spec_from_file_location("olcek_kos", {str(_PATH)!r})
    ok = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ok)
    def sahte_kunye(agac):
        if os.environ.get("SAHTE_AGAC_HATALI"):
            raise SystemExit("karadul başka ağaçtan yükleniyor")
        return {{"agac": str(agac), "commit": "sahte", "kirli": [], "karadul_dosyasi": "x",
                "karadul_surumu": "0"}}
    ok.agac_kunyesi = sahte_kunye
    sys.exit(ok.main(sys.argv[1:]))
""")

# Sahte analiz komutu: kip ve süre argümanla. JAVA_TOOL_OPTIONS'tan gc günlüğü yolunu okur.
_SAHTE = textwrap.dedent("""
    import json, os, re, signal, subprocess, sys, time
    kip, sure = sys.argv[1], float(sys.argv[2])
    kok = os.environ["SAHTE_KOK"]
    if kip == "inatci":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if kip == "bellek":
        time.sleep(1.2)
        cocuk = subprocess.Popen([sys.executable, "-c",
            "import time; b = bytearray(80 * 1024 * 1024)\\n"
            "for i in range(0, len(b), 4096): b[i] = 1\\n"
            "time.sleep(%f)" % sure])
        cocuk.wait()
        sys.exit(0)
    if kip == "ws":
        time.sleep(1.0)  # pid.json'nin karadul sürecini görmesi için
        m = re.search(r"file=(\\S+?):time", os.environ["JAVA_TOOL_OPTIONS"])
        with open(m.group(1), "w") as f:
            f.write("[2026-11-20T01:00:00.000+0300][0.100s] Using G1\\n")
            f.write("[2026-11-20T01:00:00.200+0300][0.200s] GC(0) Pause Young (Normal) "
                    "(G1 Evacuation Pause) 24M->4M(260M) 3.250ms\\n")
            f.write("[2026-11-20T01:00:00.300+0300][0.300s] GC(0) User=0.01s Sys=0.00s Real=0.00s\\n")
            f.write("[2026-11-20T01:00:01.000+0300][1.000s] GC(1) Pause Remark 40M->40M(260M) 1.750ms\\n")
        ws = os.path.join(kok, "ws", "workspaces", "hedef", "20261120_000000")
        go = os.path.join(ws, "static", "ghidra_output")
        os.makedirs(os.path.join(go, "decompiled"))
        os.makedirs(os.path.join(ws, "reports"))
        t = time.time() - 100
        for ad, dt in (("functions.json", 10), ("strings.json", 12), ("decompiled.json", 40),
                       ("combined_results.json", 50)):
            p = os.path.join(go, ad)
            open(p, "w").write("{}")
            os.utime(p, (t + dt, t + dt))
        for i in range(3):
            open(os.path.join(go, "decompiled", "f%d.c" % i), "w").write("int f(void);")
        json.dump({"duration_seconds": 45.0, "success": True, "functions": {"total": 7}},
                  open(os.path.join(ws, "static", "ghidra_status.json"), "w"))
        json.dump({"total_duration": 60.5, "success": True,
                   "stages": {"static": {"duration_seconds": 50.0},
                              "reconstruct": {"duration_seconds": 9.0,
                                              "stats": {"timing_c_naming": 2.5, "baska": 1}}}},
                  open(os.path.join(ws, "reports", "pipeline_result.json"), "w"))
        open(os.path.join(ws, "reports", "report.json"), "w").write("{}")
        print("sahte analiz bitti")
        sys.exit(3)
    time.sleep(sure)
""")


def _hazirla(tmp_path: Path) -> tuple[Path, Path, Path]:
    sarmal = tmp_path / "sarmal.py"
    sarmal.write_text(_SARMAL, encoding="utf-8")
    sahte = tmp_path / "sahte.py"
    sahte.write_text(_SAHTE, encoding="utf-8")
    hedef = tmp_path / "hedef.bin"
    hedef.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 60)
    (tmp_path / "agac").mkdir()
    return sarmal, sahte, hedef


def _kos(tmp_path: Path, kip: str, sure: float, *ek: str, zaman_asimi: float = 60,
         ortam_ek: dict | None = None) -> tuple[int, Path, float]:
    sarmal, sahte, hedef = _hazirla(tmp_path)
    kok = tmp_path / "kok"
    komut = [sys.executable, str(sarmal), "--agac", str(tmp_path / "agac"), "--hedef", str(hedef),
             "--kok", str(kok), "--etiket", "test",
             "--komut", f"{sys.executable} {sahte} {kip} {sure}", *ek]
    if "--duvar-sn" not in ek:
        komut += ["--duvar-sn", "120"]
    ortam = dict(os.environ, SAHTE_KOK=str(kok), **(ortam_ek or {}))
    t0 = time.monotonic()
    p = subprocess.Popen(komut, env=ortam, start_new_session=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        p.communicate(timeout=zaman_asimi)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        _oldur_sahteler(kok)
        p.communicate()
        pytest.fail(f"koşucu {zaman_asimi} sn içinde bitmedi")
    return p.returncode, kok, time.monotonic() - t0


def _oldur_sahteler(kok: Path) -> None:
    pj = ok._oku_json(kok / "pid.json") or {}
    for pid in (pj.get("karadul_pid"), pj.get("time_pid")):
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def _kunye(kok: Path) -> dict:
    return json.loads((kok / "kunye.json").read_text(encoding="utf-8"))


def _satirlar(kok: Path) -> list[dict]:
    with open(kok / "ornekler.csv", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _yasiyor(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


# --------------------------------------------------------------------------------------------
# (a) duvar


def test_duvar_sigterm_karadula_gider_time_l_kalir(tmp_path):
    kod, kok, sure = _kos(tmp_path, "uyku", 120, "--duvar-sn", "5")
    assert kod == 4
    assert (kok / "BITTI").read_text().strip() == "zaman_asimi"
    k = _kunye(kok)
    assert k["durum"] == "zaman_asimi" and k["sonlandirma"] == "sigterm"
    # PLAN kabulü: duvar 5 sn → süre ≤ 5 + 60 + 2
    assert 5.0 <= k["sure_sn"] <= 5 + 60 + 2
    assert sure <= 5 + 60 + 2 + 5
    # SIGTERM'e hemen ölen süreçte bekleme payı kullanılmaz: duvar + birkaç saniye
    assert k["sure_sn"] < 12
    # time'a SIGTERM gitmediği için rusage satırları yazıldı
    assert k["time_l"].get("real_sn", 0) > 0
    assert k["time_l"].get("maximum_resident_set_size", 0) > 0


def test_duvar_sigterm_yok_sayan_surec_sigkill_ile_olur(tmp_path):
    kod, kok, sure = _kos(tmp_path, "inatci", 120, "--duvar-sn", "2", "--kill-bekle-sn", "2",
                          zaman_asimi=25)
    k = _kunye(kok)
    assert (kok / "BITTI").read_text().strip() == "zaman_asimi"
    assert k["sonlandirma"] == "sigkill"
    assert k["sure_sn"] <= 2 + 2 + 3
    pj = json.loads((kok / "pid.json").read_text())
    assert pj["karadul_pid"] and not _yasiyor(pj["karadul_pid"])


# --------------------------------------------------------------------------------------------
# (b) örnekleyici


def test_ornekleyici_agac_rss_tepesi_torunlari_icerir(tmp_path):
    kod, kok, _ = _kos(tmp_path, "bellek", 2.5, "--ornek-aralik", "0.4", "--disk-aralik", "1")
    assert kod == 0
    satir = _satirlar(kok)
    assert len(satir) >= 3
    k = _kunye(kok)
    assert k["ornek_sayisi"] == len(satir)
    # 80 MiB'ı sahte komutun ÇOCUĞU ayırıyor: tepe ağaç toplamı olmalı
    assert k["tepe_rss_bayt"] >= 60 * 1024 * 1024
    ilk = int(satir[0]["rss_kib"])
    assert ilk * 1024 < k["tepe_rss_bayt"]
    # tepe, örneklerin en büyüğüdür (ilk ya da son değil)
    assert k["tepe_rss_bayt"] == max(int(s["rss_kib"]) for s in satir if s["rss_kib"]) * 1024
    disk = [s for s in satir if s["disk_ayrilan_bayt"]]
    assert disk and all(int(s["disk_ayrilan_bayt"]) > 0 for s in disk)
    assert k["tepe_disk_bayt"] == max(int(s["disk_ayrilan_bayt"]) for s in disk)
    assert all(float(s["yuk1"]) >= 0 for s in satir)


def test_kabul_30sn_varsayilan_araliklarla_en_az_uc_ornek(tmp_path):
    kod, kok, _ = _kos(tmp_path, "uyku", 30, zaman_asimi=90)
    assert kod == 0
    assert len(_satirlar(kok)) >= 3


# --------------------------------------------------------------------------------------------
# (c) künye


def test_kunye_alanlari_kismi_koşu(tmp_path):
    kod, kok, _ = _kos(tmp_path, "ws", 0)
    assert kod == 0  # kısmi (3) koşu bitmiş sayılır
    assert (kok / "BITTI").read_text().strip() == "kismi"
    assert (kok / "CIKIS").read_text().strip() == "3"
    k = _kunye(kok)
    assert k["durum"] == "kismi" and k["cikis_kodu"] == 3
    assert k["baslangic"] and k["bitis"] and k["sure_sn"] >= 0
    assert len(k["yuk_bas"]) == 3 and len(k["yuk_son"]) == 3
    assert k["ortam"]["PYTHONHASHSEED"] == "0"
    assert k["ortam"]["KARADUL_CACHE_DIR"] == str(kok / "cache")
    assert f"file={kok / 'gc.log'}:time,uptime" in k["ortam"]["JAVA_TOOL_OPTIONS"]
    assert k["time_l"]["maximum_resident_set_size"] > 0
    assert k["hedef"]["sha256"] and k["hedef"]["tur"] == "dosya"
    g = k["ghidra"]
    assert g["adim_kaynagi"] == "dosya_zamani"
    # başlangıç = combined (t+50) − 45 = t+5 → functions 5, strings 2, decompile 28, ozet 10
    assert g["adim_sureleri"] == pytest.approx(
        {"otomatik_analiz+fonksiyonlar": 5.0, "dizgiler": 2.0, "decompile": 28.0, "ozet": 10.0}, abs=0.01)
    assert g["son_biten_adim"] == "ozet" and g["decompiled_c"]["sayi"] == 3
    assert g["fonksiyon"] == 7
    b = k["boru"]
    assert b["toplam_sn"] == 60.5 and b["asama_sn"] == {"static": 50.0, "reconstruct": 9.0}
    assert b["reconstruct_timing"] == {"c_naming": 2.5}
    assert b["ilk_rapor_sn"] is not None and b["ilk_rapor_sn"] >= 0
    assert k["gc"]["gc_log_var"] and k["gc"]["duraklama_sayisi"] == 2
    assert k["gc"]["duraklama_toplam_ms"] == pytest.approx(5.0)
    assert k["disk_son"]["ws"]["dosya"] >= 10
    assert k["paket"] is None
    pj = json.loads((kok / "pid.json").read_text())
    assert pj["time_pid"] and pj["karadul_pid"] and pj["time_pid"] != pj["karadul_pid"]
    assert "sahte analiz bitti" in (kok / "kosu.log").read_text()


def test_ghidra_status_adim_sureleri_dosya_zamanindan_once_gelir(tmp_path):
    ws = tmp_path / "ws"
    go = ws / "static" / "ghidra_output"
    go.mkdir(parents=True)
    (go / "functions.json").write_text("{}")
    (go / "combined_results.json").write_text("{}")
    adim = {"functions": 1.5, "decompile": 3.25}
    (ws / "static" / "ghidra_status.json").write_text(json.dumps(
        {"duration_seconds": 9.0, "adim_sureleri": adim, "analysis": {"analyzer_times": {"A": 1.0}}}))
    g = ok.ghidra_kunyesi(ws, time.time() - 10)
    assert g["adim_kaynagi"] == "ghidra_status.adim_sureleri"
    assert g["adim_sureleri"] == adim
    assert g["ghidra_analysis"] == {"analyzer_times": {"A": 1.0}}


def test_yarida_kalan_kopru_nerede_kaldi(tmp_path):
    ws = tmp_path / "ws"
    go = ws / "static" / "ghidra_output"
    (go / "decompiled").mkdir(parents=True)
    t0 = time.time() - 300
    for ad, dt in (("functions.json", 100), ("strings.json", 110), ("call_graph.json", 150)):
        (go / ad).write_text("{}")
        os.utime(go / ad, (t0 + dt, t0 + dt))
    for i in range(4):
        p = go / "decompiled" / f"f{i}.c"
        p.write_text("x")
        os.utime(p, (t0 + 200 + i, t0 + 200 + i))
    g = ok.ghidra_kunyesi(ws, t0)
    assert not g["ghidra_status_var"]
    assert g["adim_kaynagi"] == "yok" and g["adim_sureleri"] is None
    assert g["son_biten_adim"] == "cagri_grafigi"
    assert g["cikti_zamani_sn"] == pytest.approx(
        {"functions.json": 100.0, "strings.json": 110.0, "call_graph.json": 150.0}, abs=0.2)
    assert g["decompiled_c"]["sayi"] == 4 and g["decompiled_c"]["son_sn"] == pytest.approx(203, abs=0.2)


def test_ghidra_adim_sureleri_dosya_zamani(tmp_path):
    go = tmp_path
    t = 1_000_000.0
    for ad, dt in (("functions.json", 10), ("call_graph.json", 25), ("cfg.json", 70),
                   ("combined_results.json", 80)):
        (go / ad).write_text("{}")
        os.utime(go / ad, (t + dt, t + dt))
    assert ok.ghidra_adim_sureleri(go, 75.0) == pytest.approx(
        {"otomatik_analiz+fonksiyonlar": 5.0, "cagri_grafigi": 15.0, "cfg": 45.0, "ozet": 10.0})
    assert ok.ghidra_adim_sureleri(go, None) == {}


def test_time_l_ayristir_son_blok():
    metin = ("çıktı\n        1.00 real         0.50 user         0.10 sys\n"
             "   1000  maximum resident set size\n"
             "        7761.62 real      8050.11 user       447.04 sys\n"
             "          4680646656  maximum resident set size\n"
             "                   0  average shared memory size\n"
             "          5827663560  peak memory footprint\n")
    t = ok.time_l_ayristir(metin)
    assert t["real_sn"] == 7761.62 and t["user_sn"] == 8050.11 and t["sys_sn"] == 447.04
    assert t["maximum_resident_set_size"] == 4680646656
    assert t["peak_memory_footprint"] == 5827663560
    assert ok.time_l_ayristir("") == {} and ok.time_l_ayristir("yok") == {}


def test_gc_ozeti_yalniz_duraklama_satirlari(tmp_path):
    p = tmp_path / "gc.log"
    p.write_text("[a][0.1s] GC(0) Pause Young (Normal) (G1 Evacuation Pause) 24M->4M(260M) 3.250ms\n"
                 "[a][0.1s] GC(0)   Evacuate Collection Set: 2.1ms\n"
                 "[a][0.2s] GC(1) Pause Young (Concurrent Start) 1G->512M(2G) 10.5ms\n"
                 "[a][0.3s] GC(1) Concurrent Mark Cycle 50.000ms\n")
    o = ok.gc_ozeti(p)
    assert o["duraklama_sayisi"] == 2
    assert o["duraklama_toplam_ms"] == pytest.approx(13.75)
    assert o["duraklama_en_uzun_ms"] == 10.5
    assert ok.gc_ozeti(tmp_path / "yok.log") == {"gc_log_var": False}


def test_paket_kunyesi_biten_bilesenler(tmp_path):
    ws = tmp_path / "ws"
    for ad, biten in (("A", True), ("B", False), ("C", True)):
        d = ws / "components" / ad / "static"
        d.mkdir(parents=True)
        if biten:
            (d / "ghidra_status.json").write_text(json.dumps({"duration_seconds": 3.0, "success": True}))
    p = ok.paket_kunyesi(ws)
    assert p["bilesen_dizini"] == 3 and p["ghidra_biten"] == 2
    assert [b["bilesen"] for b in p["bilesenler"]] == ["A", "C"]
    assert p["bundle_analysis_var"] is False
    assert ok.paket_kunyesi(tmp_path / "bos") is None


def test_java_ek_dosyalari():
    o = ok._java_ek_dosyalari("-XX:StartFlightRecording=filename=/yok/k.jfr,settings=profile "
                              "-XX:SharedArchiveFile=/yok/a.jsa")
    assert o["jfr"] == {"yol": "/yok/k.jfr", "var": False, "bayt": None}
    assert o["cds"]["yol"] == "/yok/a.jsa"


# --------------------------------------------------------------------------------------------
# (d) ön denetimler


def test_yanlis_agac_kosuyu_baslatmaz(tmp_path):
    kod, kok, _ = _kos(tmp_path, "uyku", 1, ortam_ek={"SAHTE_AGAC_HATALI": "1"})
    assert kod != 0
    assert not (kok / "BITTI").exists() and not (kok / "kosu.log").exists()


def test_bitmis_koke_yeniden_kosulmaz(tmp_path):
    kok = tmp_path / "kok"
    kok.mkdir()
    (kok / "BITTI").write_text("tamam\n")
    sarmal, sahte, hedef = _hazirla(tmp_path)
    p = subprocess.run([sys.executable, str(sarmal), "--agac", str(tmp_path / "agac"), "--hedef",
                        str(hedef), "--kok", str(kok), "--duvar-sn", "5", "--komut", "true"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode != 0 and "BITTI var" in p.stderr
    assert not (kok / "kosu.log").exists()


def test_bosluklu_kok_reddedilir(tmp_path):
    with pytest.raises(SystemExit, match="boşluk"):
        ok.main(["--agac", str(tmp_path), "--hedef", __file__, "--kok", str(tmp_path / "a b"),
                 "--duvar-sn", "5"])


def test_analiz_komutu_bicimi(tmp_path):
    k = ok.analiz_komutu(Path("/h/x"), tmp_path, tmp_path / "a.yaml")
    assert k[1:5] == ["-m", "karadul", "analyze", "/h/x"]
    assert k[5:] == ["--skip-dynamic", "--output-dir", str(tmp_path / "ws"), "--output",
                     str(tmp_path / "out"), "--config", str(tmp_path / "a.yaml")]


# ============================================================================================
# scripts/arge/olcek/gece_kosusu.py — gece kuyruğu: boş makine denetimi ve sürdürme
#
# Kilitlenen davranışlar:
#   (f) boş makine: 1 dk yük eşiğin KESİNLİKLE altında olmalı; başlamadan önce sönüm beklenir, inmezse
#       koşu başlatılmaz; bitişte en çok son-bekle süresi içinde inmeli; başlangıç yükü koşucunun kaydı;
#   (g) geçersiz deneme saklanır (``.gecersiz<k>``) ve en çok 2 kez yinelenir;
#   (h) sürdürme: ``BITTI`` olan koşu atlanır (``kesildi`` hariç); yarım dizin ``.yarim<k>`` olarak saklanıp
#       yeniden koşulur; canlı pid'li yarım koşuya dokunulmaz; BITTI yazmayan koşu yinelenmez;
#   (i) kuyruk sırası ve koşu tanımları (HZ-0 K1 O1 B1 …, B'de gösteri ayarı, duvarlar, avast kökü,
#       JFR yolu, duman etiketi); ``--kuru`` hiçbir şey oluşturmaz ve TAHMİNİ toplamı basar; Berke onayı
#       olmadan avast grubu koşmaz.

import argparse  # noqa: E402

_GK_PATH = _KOK / "scripts" / "arge" / "olcek" / "gece_kosusu.py"
_gspec = importlib.util.spec_from_file_location("gece_kosusu_under_test", _GK_PATH)
gk = importlib.util.module_from_spec(_gspec)
sys.modules[_gspec.name] = gk
_gspec.loader.exec_module(gk)


def _ns(tmp_path, **kw):
    v = dict(en_cok_deneme=3, yuk_bekle_sn=30, son_bekle_sn=180, yuk_uyar=False, disk_alt_gb=0,
             kuyruk_paket="TEST", kok=tmp_path)
    v.update(kw)
    return argparse.Namespace(**v)


def _kosu(tmp_path, ad="K"):
    return gk.Kosu(grup="hz0", kod=ad, tekrar=1, kok=tmp_path / "hz0" / ad / "1", hedef=tmp_path / "h",
                   duvar=100, etiket=f"hz0:{ad}#1")


class _Yuk:
    """Yük okuyucusu: koşu öncesi ``once``, koşu sonrası ``sonra`` (sahte çalıştırıcı geçiş yapar)."""

    def __init__(self, once=1.0, sonra=1.0):
        self.once, self.sonra, self.kosuldu = once, sonra, False

    def __call__(self):
        return self.sonra if self.kosuldu else self.once


def _sahte_calistirici(yuk, yuk_bas, bitti=True):
    cagri = []

    def calistir(k, agac, paket, deneme, kok):
        cagri.append(deneme)
        yuk.kosuldu = True
        k.kok.mkdir(parents=True, exist_ok=True)
        (k.kok / "kunye.json").write_text(json.dumps({"yuk_bas": [yuk_bas[len(cagri) - 1], 0, 0]}))
        if bitti:
            (k.kok / "BITTI").write_text("tamam\n")
        return {"cikis": 0, "sure_sn": 1.0, "dis_sinir": None}
    return calistir, cagri


@pytest.fixture
def sahte_zaman(monkeypatch):
    monkeypatch.setattr(gk, "uyu", lambda s: None)


def test_bekle_sessiz_esik_kesin_alt(sahte_zaman):
    ok_, okuma, gecen = gk.bekle_sessiz(3.5, 100, oku=iter([3.0]).__next__)
    assert ok_ and okuma == [3.0] and gecen == 0
    # eşik değerinin kendisi "altında" değildir
    ok_, okuma, gecen = gk.bekle_sessiz(3.5, 20, oku=lambda: 3.5)
    assert not ok_ and okuma == [3.5, 3.5, 3.5] and gecen == 20


def test_bekle_sessiz_sonum_bekler(sahte_zaman):
    ok_, okuma, gecen = gk.bekle_sessiz(3.5, 100, oku=iter([8.0, 6.0, 4.0, 3.4]).__next__)
    assert ok_ and okuma == [8.0, 6.0, 4.0, 3.4] and gecen == 30


def test_gecerlilik_kurallari():
    assert gk.gecerlilik(3.0, True, 3.5) == (True, "boş makine")
    g, n = gk.gecerlilik(3.6, True, 3.5)
    assert not g and "başlangıç" in n
    g, n = gk.gecerlilik(3.0, False, 3.5)
    assert not g and "bitişte" in n
    assert not gk.gecerlilik(None, True, 3.5)[0]
    assert gk.yuk_esigi() == pytest.approx(0.25 * os.cpu_count())


def test_bitti_olan_kosu_atlanir(tmp_path, sahte_zaman, monkeypatch):
    k = _kosu(tmp_path)
    k.kok.mkdir(parents=True)
    (k.kok / "BITTI").write_text("zaman_asimi\n")
    yuk = _Yuk()
    monkeypatch.setattr(gk, "yuk_oku", yuk)
    cal, cagri = _sahte_calistirici(yuk, [1.0])
    s = gk.kos_bir(k, tmp_path, _ns(tmp_path), 3.5, calistirici=cal)
    assert s["durum"] == "atlandi_bitti" and cagri == []


def test_kesildi_ve_yarim_dizin_saklanip_yeniden_kosulur(tmp_path, sahte_zaman, monkeypatch):
    k = _kosu(tmp_path)
    k.kok.mkdir(parents=True)
    (k.kok / "BITTI").write_text("kesildi\n")
    yuk = _Yuk()
    monkeypatch.setattr(gk, "yuk_oku", yuk)
    cal, cagri = _sahte_calistirici(yuk, [1.0])
    s = gk.kos_bir(k, tmp_path, _ns(tmp_path), 3.5, calistirici=cal)
    assert s["durum"] == "gecerli" and cagri == [1]
    assert (k.kok.parent / "1.yarim1" / "BITTI").read_text().strip() == "kesildi"
    assert json.loads((k.kok / "gece_durum.json").read_text())["gecerli"] is True
    # BITTI'siz yarım dizin de saklanır
    k2 = _kosu(tmp_path, "O")
    k2.kok.mkdir(parents=True)
    (k2.kok / "kosu.log").write_text("yarım")
    yuk.kosuldu = False
    cal2, cagri2 = _sahte_calistirici(yuk, [1.0])
    assert gk.kos_bir(k2, tmp_path, _ns(tmp_path), 3.5, calistirici=cal2)["durum"] == "gecerli"
    assert (k2.kok.parent / "1.yarim1" / "kosu.log").exists() and cagri2 == [1]


def test_canli_yarim_kosuya_dokunulmaz(tmp_path, sahte_zaman):
    k = _kosu(tmp_path)
    k.kok.mkdir(parents=True)
    (k.kok / "pid.json").write_text(json.dumps({"time_pid": os.getpid(), "karadul_pid": None}))
    with pytest.raises(SystemExit, match="hâlâ çalışıyor"):
        gk.kos_bir(k, tmp_path, _ns(tmp_path), 3.5, calistirici=lambda *a: pytest.fail("koşuldu"))
    assert k.kok.exists()


def test_baslangic_yuku_yuksek_iki_kez_yinelenir(tmp_path, sahte_zaman, monkeypatch):
    k = _kosu(tmp_path)
    yuk = _Yuk()
    monkeypatch.setattr(gk, "yuk_oku", yuk)
    cal, cagri = _sahte_calistirici(yuk, [5.0, 5.0, 5.0])
    s = gk.kos_bir(k, tmp_path, _ns(tmp_path), 3.5, calistirici=cal)
    assert cagri == [1, 2, 3] and s["durum"] == "gecersiz"
    assert (k.kok.parent / "1.gecersiz1").is_dir() and (k.kok.parent / "1.gecersiz2").is_dir()
    assert not (k.kok.parent / "1.gecersiz3").exists()
    d = json.loads((k.kok / "gece_durum.json").read_text())
    assert d["gecerli"] is False and d["deneme"] == 3 and "başlangıç" in d["neden"]


def test_ikinci_denemede_gecerli(tmp_path, sahte_zaman, monkeypatch):
    k = _kosu(tmp_path)
    yuk = _Yuk()
    monkeypatch.setattr(gk, "yuk_oku", yuk)
    cal, cagri = _sahte_calistirici(yuk, [5.0, 1.0])
    s = gk.kos_bir(k, tmp_path, _ns(tmp_path), 3.5, calistirici=cal)
    assert cagri == [1, 2] and s["durum"] == "gecerli" and len(s["gecersiz_saklanan"]) == 1


def test_bitiste_yuk_inmezse_gecersiz(tmp_path, sahte_zaman, monkeypatch):
    k = _kosu(tmp_path)
    yuk = _Yuk(once=1.0, sonra=9.0)  # koşudan sonra yük hiç inmiyor (dış yük)
    monkeypatch.setattr(gk, "yuk_oku", yuk)
    cal, cagri = _sahte_calistirici(yuk, [1.0, 1.0, 1.0])
    s = gk.kos_bir(k, tmp_path, _ns(tmp_path, yuk_bekle_sn=0), 3.5, calistirici=cal)
    # ilk deneme bitişte geçersiz; yük inmediği için sonraki denemeler başlatılamaz
    assert cagri == [1] and s["durum"] == "baslatilamadi"
    assert s["denemeler"][0]["gecerli"] is False and "bitişte" in s["denemeler"][0]["neden"]
    assert all(d["gecerli"] is False for d in s["denemeler"])


def test_on_bekleme_inmezse_baslatilmaz(tmp_path, sahte_zaman, monkeypatch):
    k = _kosu(tmp_path)
    monkeypatch.setattr(gk, "yuk_oku", lambda: 9.0)
    s = gk.kos_bir(k, tmp_path, _ns(tmp_path), 3.5, calistirici=lambda *a: pytest.fail("koşuldu"))
    assert s["durum"] == "baslatilamadi" and len(s["denemeler"]) == 3
    assert all("başlatılmadı" in d["neden"] for d in s["denemeler"])


def test_yuk_uyar_tek_deneme_gecersiz_isaretler(tmp_path, sahte_zaman, monkeypatch):
    k = _kosu(tmp_path)
    yuk = _Yuk(once=9.0, sonra=9.0)
    monkeypatch.setattr(gk, "yuk_oku", yuk)
    cal, cagri = _sahte_calistirici(yuk, [9.0])
    s = gk.kos_bir(k, tmp_path, _ns(tmp_path, yuk_uyar=True, yuk_bekle_sn=0, son_bekle_sn=0), 3.5,
                   calistirici=cal)
    assert cagri == [1] and s["durum"] == "gecersiz"


def test_bitti_yazmayan_kosu_yinelenmez(tmp_path, sahte_zaman, monkeypatch):
    k = _kosu(tmp_path)
    yuk = _Yuk()
    monkeypatch.setattr(gk, "yuk_oku", yuk)
    cal, cagri = _sahte_calistirici(yuk, [1.0], bitti=False)
    s = gk.kos_bir(k, tmp_path, _ns(tmp_path), 3.5, calistirici=cal)
    assert s["durum"] == "hata" and cagri == [1]


def _tekrar_yaz(kok, toplam, gecerli=True):
    kok.mkdir(parents=True, exist_ok=True)
    (kok / "gece_durum.json").write_text(json.dumps({"gecerli": gecerli}))
    (kok / "kunye.json").write_text(json.dumps({"boru": {"toplam_sn": toplam}}))
    (kok / "BITTI").write_text("tamam\n")


def test_hz0_yayilim_ek_tekrar_en_cok_iki(tmp_path, monkeypatch):
    kuy = [gk.Kosu(grup="hz0", kod=kod, tekrar=n, kok=tmp_path / "hz0" / kod / str(n), hedef=None,
                   duvar=10, etiket=f"hz0:{kod}#{n}") for n in (1, 2, 3) for kod in ("K", "O")]
    for k, t in zip(kuy, (100, 200, 100, 201, 130, 202)):  # K: yayılım 0,30; O: 0,01
        _tekrar_yaz(k.kok, t)
    assert gk.yayilim([k.kok for k in kuy if k.kod == "K"]) == pytest.approx(0.30)
    cagri = []

    def kosucu(k, agac, a, esik):
        cagri.append(k.etiket)
        _tekrar_yaz(k.kok, 100)
        return {"etiket": k.etiket, "durum": "gecerli", "denemeler": []}
    monkeypatch.setattr(gk, "_gunluk", lambda kok, metin: None)
    s = gk.hz0_ek_tekrarlar(kuy, tmp_path, _ns(tmp_path), 3.5, kosucu=kosucu)
    # K'de yayılım ek tekrarlarla da 0,30 kalır → tam 2 ek tekrar; O'ya hiç
    assert cagri == ["hz0:K#4", "hz0:K#5"] and len(s) == 2
    assert (tmp_path / "hz0" / "K" / "5" / "BITTI").exists()
    # geçersiz tekrar yayılıma girmez; 3'ten az geçerli → hüküm yok
    _tekrar_yaz(tmp_path / "x" / "1", 100)
    _tekrar_yaz(tmp_path / "x" / "2", 500, gecerli=False)
    _tekrar_yaz(tmp_path / "x" / "3", 101)
    assert gk.yayilim([tmp_path / "x" / str(n) for n in (1, 2, 3)]) is None


def test_kuyruk_sirasi_ve_tanimlari(tmp_path):
    kuy = gk.kuyruk_olustur(("hz0", "p16c", "k_appcds", "avast", "b_jfr", "olc1", "duman"),
                            tmp_path / "g", tmp_path / "av", kuru=True)
    hz0 = [k.etiket for k in kuy if k.grup == "hz0"]
    assert hz0 == ["hz0:K#1", "hz0:O#1", "hz0:B#1", "hz0:K#2", "hz0:O#2", "hz0:B#2",
                   "hz0:K#3", "hz0:O#3", "hz0:B#3"]
    b = next(k for k in kuy if k.etiket == "hz0:B#1")
    assert b.ayar == gk.GOSTERI / "gosteri.yaml" and b.duvar == 10800 and b.hz0_ek
    assert all(k.duvar == 7200 for k in kuy if k.grup == "olc1")
    assert [k.kod for k in kuy if k.grup == "olc1"] == ["T100", "T300", "PAKET"]
    av = [k for k in kuy if k.grup == "avast"]
    assert [k.etiket for k in av] == ["avast:K#1", "avast:O#1", "avast:K#2", "avast:O#2",
                                      "avast:K#3", "avast:O#3"]
    assert all(str(k.kok).startswith(str(tmp_path / "av")) for k in av)
    cds = [k for k in kuy if k.grup == "k_appcds"]
    assert len(cds) == 4 and all("AutoCreateSharedArchive" in k.java_ek and "FlightRecording" not in k.java_ek
                                 for k in cds)
    jfr = next(k for k in kuy if k.grup == "b_jfr")
    assert f"filename={jfr.kok / 'kayit.jfr'}," in jfr.java_ek and "SharedArchive" not in jfr.java_ek
    assert next(k for k in kuy if k.grup == "duman").etiket == "duman:cat"


def test_kuyruk_komutu_kosucunun_ayristiricisiyla_okunur(tmp_path):
    """Duman koşusunun ilk denemesi bu yüzden düştü: '-XX:' ile başlayan değer ayrı belirteçte."""
    kuy = gk.kuyruk_olustur(("hz0", "k_appcds", "b_jfr"), tmp_path / "g", tmp_path / "av", kuru=True)
    for k in (next(x for x in kuy if x.grup == g) for g in ("hz0", "k_appcds", "b_jfr")):
        k.hedef = k.hedef or tmp_path / "h"
        komut = gk._komut(k, tmp_path / "agac", "PAKET", 1)
        assert komut[:3] == [str(gk.KUYRUK), "PAKET", k.etiket]
        assert komut[4] == str(gk.OLCEK_KOS)
        arg = ok.ayristirici().parse_args(komut[5:])
        assert arg.java_ek == k.java_ek and arg.duvar_sn == k.duvar and arg.kok == k.kok
        assert arg.ayar == k.ayar and arg.kill_bekle_sn == ok.KILL_BEKLE_SN
    assert gk._komut(k, tmp_path, "P", 2)[2] == f"{k.etiket}/d2"


def test_kuru_kip_hicbir_sey_olusturmaz(tmp_path, capsys):
    kok = tmp_path / "gece"
    assert gk.main(["--commit", "abcdef1234", "--agac", str(tmp_path / "agac"), "--kok", str(kok),
                    "--gece", "1", "--kuru"]) == 0
    out = capsys.readouterr().out
    assert "TAHMİNİ toplam" in out and "hz0:B#3" in out and "olc1" not in out
    assert "avast grubu koşuda atlanır" in out
    assert not kok.exists()


def test_avast_onaysiz_kosulmaz(tmp_path, monkeypatch):
    monkeypatch.setattr(gk, "agac_kunyesi", lambda agac: {"commit": "x"})
    monkeypatch.setattr(gk, "donanim_kunyesi", lambda: {})
    monkeypatch.setattr(gk, "kos_bir", lambda *a, **kw: pytest.fail("koşuldu"))
    kok = tmp_path / "gece"
    kod = gk.main(["--commit", "abcdef1234", "--agac", str(tmp_path), "--kok", str(kok),
                   "--avast-kok", str(tmp_path / "av"), "--yalniz", "avast"])
    ozet = json.loads((kok / "ozet.json").read_text())
    assert kod == 0 and ozet["sayim"]["atlandi_onay_yok"] == 6
    assert not (kok / "gece.pid").exists()


# ============================================================================================
# scripts/arge/hiz/hz0_ek.py ve zaman_cizelgesi.py'nin kunye.json eki

_HZ_PATH = _KOK / "scripts" / "arge" / "hiz" / "hz0_ek.py"
_hspec = importlib.util.spec_from_file_location("hz0_ek_under_test", _HZ_PATH)
hz = importlib.util.module_from_spec(_hspec)
sys.modules[_hspec.name] = hz
_hspec.loader.exec_module(hz)


def test_hz0_ek_izler_ve_acma_olcer(tmp_path):
    oku = tmp_path / "oku"
    oku.mkdir()
    for i in range(5):
        (oku / f"f{i}.c").write_text("x")
    kok = tmp_path / "kok"
    dec = kok / "ws" / "workspaces" / "a" / "b" / "static" / "ghidra_output" / "decompiled"
    dec.mkdir(parents=True)
    (dec / "g.c").write_text("y")
    # Ömür, başlangıçtaki açma ölçümünün (alt süreç) yük altındaki süresinden belirgin uzun olmalı:
    # tam takımda 2,5 sn'lik süreç tek örnekle bitti (yük altında açma ölçümü ~2 sn sürdü).
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(8)"])
    try:
        s = hz.izle(p.pid, kok, 0.5, oku, en_uzun_sn=30, n=5)
    finally:
        p.kill()
        p.wait()
    assert len(s["ornekler"]) >= 2
    assert all(o["is_parcacigi"] >= 1 and o["toplam_islemci_sn"] >= 0 for o in s["ornekler"])
    assert s["acma_bas"]["oku_ac"]["n"] == 5 and s["acma_son_basvuru"]["oku_ac"]["n"] == 5
    assert s["acma_son_kendi"]["oku_ac"]["n"] == 1 and s["acma_son_kendi"]["dizin"] == str(dec)
    assert s["sure_siniri_doldu"] is False
    d = s["donanim_bas"]
    assert d["cpu_sayisi"] == os.cpu_count() and d["cip"] and d["perflevel"]
    assert hz.acma_olc(tmp_path / "yok", tmp_path / "x.json")["olculmedi"] == "dizin yok"


def test_zaman_cizelgesi_basladi_yoksa_kunye_baslangici(tmp_path):
    import datetime
    zspec = importlib.util.spec_from_file_location(
        "zaman_cizelgesi_under_test", _KOK / "scripts" / "arge" / "hiz" / "zaman_cizelgesi.py")
    zc = importlib.util.module_from_spec(zspec)
    zspec.loader.exec_module(zc)
    kok = tmp_path / "kosu"
    (kok / "ws" / "workspaces" / "a" / "20261120_000000" / "static").mkdir(parents=True)
    (kok / "kunye.json").write_text(json.dumps({"baslangic": "2026-11-20T01:02:03+03:00"}))
    s = zc.gosteri(kok, tmp_path / "zaman")
    assert s["basladi_kaynagi"] == "kunye.json"
    beklenen = datetime.datetime.fromisoformat("2026-11-20T01:02:03+03:00")
    assert s["basladi"] == beklenen.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    assert s["olaylar"][0]["olay"] == "BASLADI" and s["olaylar"][0]["t"] == beklenen.timestamp()
