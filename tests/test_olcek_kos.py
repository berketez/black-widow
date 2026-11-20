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
