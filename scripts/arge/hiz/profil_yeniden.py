#!/usr/bin/env python3
"""HIZ kalem 3: Ghidra sonrası aşamaların cProfile'ı (Ghidra'sız yeniden oynatma, P12a yöntemi).

Var olan bir koşunun çalışma alanı KOPYALANIR (``reconstructed/``, ``reports/``,
``deobfuscated/`` hariç; taban kökü değişmez) ve kopyada sırayla koşulur:
  A  ikili istihbarat (``BinaryIntelligence.analyze`` + ``analyze_decompiled``; ``macho.py:472-509``)
  B  deobfuscate (``BinaryDeobfuscator.deobfuscate``; ``stages.py:1180-1204``)
  C  yeniden kurma (``ReconstructionStage().execute``)
Her biri ayrı ``cProfile.Profile`` ile.

``--seri``: ``concurrent.futures`` süreç ve iş parçacığı havuzları satır içi (seri) yürütücüyle
değiştirilir (karadul içe aktarılmadan ÖNCE). cProfile yalnız çağıran iş parçacığını görür;
seri yürütücü sayesinde işçi süreçlerinin / iş parçacıklarının işi de profile girer. Paralellik
yükü (spawn, pickle) bu kipte ölçülmez; sıcak nokta SIRASI ölçülür. Kipin çıktıyı
değiştirmediği, ad haritasının taban koşusundakiyle karşılaştırılmasıyla denetlenir.

Kullanım (depo kökünden; aynı anda tek koşu):
    PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python scripts/arge/hiz/profil_yeniden.py \
        --kaynak ~/karadul_olcum/runs/urun-onarim-a62f15e/mac/tmux/ws/workspaces/tmux/20261119_052129 \
        --hedef ~/karadul_olcum/runs/arge-2026-11-19/hiz/profil/mac_tmux --seri
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import cProfile
import hashlib
import io
import json
import os
import platform
import pstats
import shutil
import subprocess
import sys
import time
from pathlib import Path


class _SeriYurutucu(cf.Executor):
    """Satır içi yürütücü: ``submit`` işi hemen bu iş parçacığında koşar."""

    def __init__(self, max_workers=None, *args, initializer=None, initargs=(), **kwargs):  # noqa: D401
        if initializer is not None:
            initializer(*initargs)

    def submit(self, fn, /, *args, **kwargs):
        f: cf.Future = cf.Future()
        try:
            f.set_result(fn(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001
            f.set_exception(exc)
        return f

    def shutdown(self, wait=True, *, cancel_futures=False):
        return None


_HAVUZ_KAYIT: list[dict] = []


def _sayacli(taban):
    """Gerçek havuzu saran sınıf: kuruluş yeri, işçi sayısı, iş sayısı, ilk sonuç gecikmesi."""
    import traceback

    class _Sayacli(taban):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            yer = "?"
            for fr in reversed(traceback.extract_stack()[:-1]):
                if "/karadul/" in fr.filename:
                    yer = "%s:%d" % (fr.filename.split("/karadul/", 1)[1], fr.lineno)
                    break
            self._kayit = {"tur": taban.__name__, "yer": "karadul/" + yer if yer != "?" else yer,
                           "isci": getattr(self, "_max_workers", None), "is": 0,
                           "kurulus": time.perf_counter(), "ilk_sonuc_sn": None, "omur_sn": None}
            _HAVUZ_KAYIT.append(self._kayit)

        def submit(self, fn, /, *args, **kwargs):
            k = self._kayit
            k["is"] += 1
            f = super().submit(fn, *args, **kwargs)
            if k["ilk_sonuc_sn"] is None:
                def _ilk(_f, k=k):
                    if k["ilk_sonuc_sn"] is None:
                        k["ilk_sonuc_sn"] = time.perf_counter() - k["kurulus"]
                f.add_done_callback(_ilk)
            return f

        def shutdown(self, wait=True, *, cancel_futures=False):
            r = super().shutdown(wait=wait, cancel_futures=cancel_futures)
            if self._kayit["omur_sn"] is None:
                self._kayit["omur_sn"] = time.perf_counter() - self._kayit["kurulus"]
            return r

    _Sayacli.__name__ = taban.__name__
    return _Sayacli


def _donanim() -> dict:
    def sc(k: str) -> str:
        try:
            return subprocess.run(["sysctl", "-n", k], capture_output=True, text=True).stdout.strip()
        except OSError:
            return ""
    return {
        "cip": sc("machdep.cpu.brand_string"), "perflevel0": sc("hw.perflevel0.logicalcpu"),
        "perflevel1": sc("hw.perflevel1.logicalcpu"), "ncpu": os.cpu_count(),
        "bellek_bayt": sc("hw.memsize"), "os": platform.platform(), "python": platform.python_version(),
        "yuk": os.getloadavg(),
    }


def _sha(p: Path) -> str | None:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


def _tablo(prof: cProfile.Profile, sirala: str, n: int, kok: str) -> str:
    s = io.StringIO()
    st = pstats.Stats(prof, stream=s)
    st.sort_stats(sirala).print_stats(n)
    out = s.getvalue().replace(kok, "")
    return out


def _ilk_n(prof: cProfile.Profile, n: int, kok: str) -> list[dict]:
    st = pstats.Stats(prof)
    rows = []
    for (fn, line, name), (cc, nc, tt, ct, _callers) in st.stats.items():
        rows.append({"yer": "%s:%d(%s)" % (fn.replace(kok, ""), line, name), "cagri": nc,
                     "oz_sn": tt, "toplam_sn": ct})
    rows.sort(key=lambda r: -r["oz_sn"])
    return rows[:n]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kaynak", required=True, type=Path, help=".../ws/workspaces/<ad>/<zaman>")
    ap.add_argument("--hedef", required=True, type=Path)
    ap.add_argument("--seri", action="store_true")
    ap.add_argument("--asamalar", default="ABC")
    ap.add_argument("--referans", type=Path, help="karşılaştırma için naming_map.json (aynı kodla, paralel kipte üretilmiş)")
    ap.add_argument("--havuz-say", action="store_true", help="havuzları say (seri kiple birlikte kullanılmaz)")
    ap.add_argument("--isci", type=int, help="CPU_PERF_CORES ve os.cpu_count bu sürece bu değerle görünür")
    a = ap.parse_args()

    if a.havuz_say and not a.seri:
        cf.ProcessPoolExecutor = _sayacli(cf.ProcessPoolExecutor)  # type: ignore[misc]
        cf.ThreadPoolExecutor = _sayacli(cf.ThreadPoolExecutor)  # type: ignore[misc]
    if a.isci:
        os.cpu_count = lambda: a.isci  # type: ignore[assignment]
        import karadul.config as _kc
        _kc.CPU_PERF_CORES = a.isci
    if a.seri:
        cf.ProcessPoolExecutor = _SeriYurutucu  # type: ignore[misc]
        cf.ThreadPoolExecutor = _SeriYurutucu  # type: ignore[misc]

    kaynak = a.kaynak.expanduser().resolve()
    hedef = a.hedef.expanduser().resolve()
    if hedef.exists():
        raise SystemExit("hedef zaten var (silme yok): %s" % hedef)
    ws_dir = hedef / "ws" / "workspaces" / kaynak.parent.name / kaynak.name
    t_kopya = time.perf_counter()
    shutil.copytree(kaynak, ws_dir, symlinks=True,
                    ignore=shutil.ignore_patterns("reconstructed", "reports", "deobfuscated"))
    t_kopya = time.perf_counter() - t_kopya
    os.environ.setdefault("KARADUL_CACHE_DIR", str(hedef / "cache"))

    import logging
    logging.basicConfig(level=logging.ERROR)
    import karadul
    from karadul.config import Config
    from karadul.core.pipeline import PipelineContext
    from karadul.core.target import Language, TargetInfo, TargetType
    from karadul.core.workspace import Workspace

    ti = json.loads((ws_dir / "raw" / "target_info.json").read_text())
    ham = sorted(p for p in (ws_dir / "raw").iterdir() if p.is_file() and p.name != "target_info.json")
    yol = Path(ti["path"])
    if not yol.exists():
        yol = ham[0]
    target = TargetInfo(path=yol, name=ti["name"], target_type=TargetType(ti["target_type"]),
                        language=Language(ti["language"]), file_size=ti["file_size"],
                        file_hash=ti["file_hash"], metadata=ti.get("metadata") or {})
    ws = Workspace(base_dir=ws_dir.parent.parent, target_name=target.name, workspace_dir=ws_dir)
    ws.create()
    cfg = Config.load(None)
    cfg.project_root = (hedef / "ws").resolve()
    ctx = PipelineContext(target=target, workspace=ws, config=cfg)
    kok = str(Path(karadul.__file__).resolve().parent.parent) + "/"

    sonuc: dict = {"kaynak": str(kaynak), "hedef": str(hedef), "seri": a.seri,
                   "karadul": karadul.__file__, "donanim": _donanim(),
                   "PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED"), "kopya_sn": t_kopya,
                   "asamalar": {}}
    profdir = hedef / "profil"
    profdir.mkdir(parents=True, exist_ok=True)

    def kos(ad: str, fn) -> object:
        prof = cProfile.Profile()
        t0, c0 = time.perf_counter(), time.process_time()
        prof.enable()
        try:
            out = fn()
        finally:
            prof.disable()
        dt, dc = time.perf_counter() - t0, time.process_time() - c0
        prof.dump_stats(str(profdir / ("%s.prof" % ad)))
        (profdir / ("%s_kumulatif.txt" % ad)).write_text(_tablo(prof, "cumulative", 60, kok))
        (profdir / ("%s_oz.txt" % ad)).write_text(_tablo(prof, "tottime", 60, kok))
        sonuc["asamalar"][ad] = {"duvar_sn": dt, "islemci_sn": dc, "ilk20_oz": _ilk_n(prof, 20, kok)}
        print("%s: duvar %.1f sn, işlemci %.1f sn" % (ad, dt, dc), flush=True)
        return out

    static = ws_dir / "static"
    if "A" in a.asamalar:
        from karadul.analyzers.binary_intelligence import BinaryIntelligence

        def istihbarat():
            sr = json.loads((static / "strings_raw.json").read_text()) if (static / "strings_raw.json").exists() else {}
            sy = json.loads((static / "symbols.json").read_text()) if (static / "symbols.json").exists() else {}
            dl = json.loads((static / "dynamic_libraries.json").read_text()) if (static / "dynamic_libraries.json").exists() else {}
            bi = BinaryIntelligence(cfg)
            rep = bi.analyze(strings=sr.get("strings") or [],
                             symbols=[s.get("name", "") for s in sy.get("symbols", []) if s.get("name")],
                             dylibs=[d.get("path", "") for d in dl.get("libraries", []) if d.get("path")],
                             target_name=target.name)
            fa = bi.analyze_decompiled(static / "ghidra_output" / "decompiled")
            return len(fa)
        sonuc["asamalar_A_fonksiyon"] = kos("A_istihbarat", istihbarat)

    if "B" in a.asamalar:
        from karadul.deobfuscators.binary_deobfuscator import BinaryDeobfuscator

        def deob():
            r = BinaryDeobfuscator(cfg).deobfuscate(ws)
            return {"basari": r.success, "stats": r.stats}
        sonuc["B_sonuc"] = kos("B_deobfuscate", deob)

    if "C" in a.asamalar:
        from karadul.stages import ReconstructionStage

        def rec():
            r = ReconstructionStage().execute(ctx)
            return r
        r = kos("C_yeniden_kurma", rec)
        st = getattr(r, "stats", {}) or {}
        sonuc["C_basari"] = getattr(r, "success", None)
        sonuc["C_hata"] = (getattr(r, "errors", None) or [])[:5]
        sonuc["C_adim_sureleri"] = {k[:-len("_duration_s")]: v for k, v in st.items()
                                    if k.endswith("_duration_s") and isinstance(v, (int, float))}
        sonuc["C_ic_sureler"] = {k: v for k, v in st.items()
                                 if k.startswith("timing_") and isinstance(v, (int, float))}
        # Denetim: ad haritası taban koşusundakiyle aynı mı (seri kip çıktıyı değiştirdi mi)
        yeni = ws_dir / "reconstructed" / "src" / "naming_map.json"
        eski = (a.referans.expanduser() if a.referans else kaynak / "reconstructed" / "src" / "naming_map.json")
        sonuc["naming_map_referans"] = str(eski)
        sonuc["naming_map_sha"] = {"taban": _sha(eski), "yeniden": _sha(yeni)}
        sonuc["naming_map_ayni"] = (_sha(eski) is not None and _sha(eski) == _sha(yeni))
        print("naming_map aynı mı:", sonuc["naming_map_ayni"], sonuc["naming_map_sha"], flush=True)

    if a.havuz_say:
        sonuc["havuzlar"] = [{k: v for k, v in h.items() if k != "kurulus"} for h in _HAVUZ_KAYIT]
        print("havuz sayısı:", len(_HAVUZ_KAYIT))
        for h in _HAVUZ_KAYIT:
            print("  %-17s %-60s işçi %s iş %d ilk sonuç %s sn ömür %s sn" % (
                h["tur"], h["yer"], h["isci"], h["is"],
                None if h["ilk_sonuc_sn"] is None else round(h["ilk_sonuc_sn"], 2),
                None if h["omur_sn"] is None else round(h["omur_sn"], 2)))
    sonuc["isci"] = a.isci
    (hedef / "profil_ozet.json").write_text(json.dumps(sonuc, indent=1, ensure_ascii=False, default=str))
    print("özet:", hedef / "profil_ozet.json")


if __name__ == "__main__":
    main()
