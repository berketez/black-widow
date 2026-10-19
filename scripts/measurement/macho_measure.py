#!/usr/bin/env python3
"""Mac (Mach-O) fonksiyon-ismi ölçüm orkestratörü: hazırla -> karadul koş -> puanla.

``measure.py``'nin (ELF) Mac karşılığı; alt komut düzeni aynıdır. Puanlama
``macho_f1.py``'dedir; bu dosya veriyi hazırlar, karadul'u verilen ağaçtan koşar
ve sonuçları tek JSON'da toplar. Ghidra sabitlemesi, ağaç künyesi ve önbellek
kaydı ``measure.py``'den (o da ``karadul.config``'ten) gelir; burada kopyası yok.

Alt komutlar
------------
prepare   Korpustaki (``macho_corpus.json``) özgün ikiliyi al, sha256 doğrula,
          ``/usr/bin/strip`` ile soy, export trie'nin boşaldığını
          (``xcrun dyld_info -exports`` yalnız ``__mh_execute_header``) ve strip'li
          kopyada fonksiyon sembolü kalmadığını doğrula, GT'yi çıkar.
          Doğrulama tutmazsa hat durur. İdempotent.
analyze   ``python -m karadul analyze <strip'li> --skip-dynamic --output-dir <koşu>/ws
          --output <koşu>/out`` komutunu ``--tree`` ağacından koş (cwd ve PYTHONPATH =
          ağaç, GHIDRA_INSTALL_DIR = sabitlenen kurulum). Sabitlenen sürüm değilse
          durur (``--farkli-ghidra-izinli`` hariç). Varsayılan ``--jobs 1``.
score     Koşuları puanla (her koşu dizinine ``macho_score.json``), künyeli tek sonuç
          JSON'u + terminal tablosu. ``--sonuc-etiketi`` ile yeniden puanlama koşu dizinine
          dokunmadan ``results/<etiket>/`` altına yazılır. Erişim sınıfları (ÖL-3) ve talimat
          ağırlığı GT'nin strip'li kopyasından (sha256 denetimiyle) okunur. Hedef türü Mach-O değilse ya da analiz edilen
          dosya GT'nin strip'li kopyası değilse koşu GEÇERSİZ sayılır, toplamlara girmez.
compare   İki sonuç JSON'unu (taban / aday) ikili ve fonksiyon bazında kıyasla.
all       prepare + analyze + score.

Veri dizini: ``<depo>/workspaces/olcum_mac/`` (git dışı, Spotlight dışı);
``KARADUL_OLCUM_MAC_DIR`` ile değişir.

Örnek (taban v2):
    python scripts/measurement/macho_measure.py all --tree . --label taban-v2-$(git rev-parse --short HEAD)
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
for _p in (str(HERE), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import function_f1 as f1  # noqa: E402
import macho_f1 as mf  # noqa: E402
import macho_reach as mr  # noqa: E402
import measure as meas  # noqa: E402
from karadul.config import GHIDRA_PINNED_VERSION  # noqa: E402
from karadul.core.target import TargetType  # noqa: E402
from test_seti_kura import POOL as TEST_SET_POOL, STRESS as TEST_SET_STRESS  # noqa: E402

CORPUS_PATH = HERE / "macho_corpus.json"
CORPUS_SCHEMA = "karadul-macho-corpus/1"
REPORT_SCHEMA = "karadul-macho-f1-report/1"
MANIFEST_SCHEMA = "karadul-macho-prepared/1"
DATA_DIR_ENV = "KARADUL_OLCUM_MAC_DIR"
DEFAULT_DATA_DIR = Path(os.environ.get(DATA_DIR_ENV, str(REPO_ROOT / "workspaces" / "olcum_mac"))).expanduser()

# PATH'te /opt/anaconda3/bin/strip önde ve export trie'yi BIRAKIYOR (2026-10-15
# ölçümü); Apple strip'i yalnız mutlak yoldan çağrılır.
STRIP_PATH = "/usr/bin/strip"
PKGUTIL_PATH = "/usr/sbin/pkgutil"
CLT_PACKAGE_ID = "com.apple.pkg.CLTools_Executables"
# Apple strip'ten sonra export trie'de kalmasına izin verilen tek ad.
ALLOWED_EXPORTS = frozenset({mf.MACH_HEADER_SYMBOL})
# Karadul'un Mac'e özgü statik adımlarını koştuğu hedef türleri (core/target.py).
MACHO_TARGET_TYPES = frozenset({TargetType.MACHO_BINARY.value, TargetType.UNIVERSAL_BINARY.value})
# Korpusta izinli kümeler; test seti (G31'e kadar kilitli) burada yer almaz.
CORPUS_SETS = ("gelistirme", "dogrulama")
# docs/arge/test_seti_kilidi.md: ana küme + yedekler + stres alt kümesi (kura betiğinden).
LOCKED_TEST_PROGRAMS = frozenset(TEST_SET_POOL) | frozenset(TEST_SET_STRESS)
MAC_TIMEOUT_S = 2400  # ikili başına; tmux 15 Ekim'de ~16 dk sürdü (ELF: measure.DEFAULT_TIMEOUT_S)
MAC_JOBS = 1          # makine paylaşılıyor; ikililer sırayla (ELF: measure.DEFAULT_JOBS)
KILL_GRACE_S = 30
# Talimat ağırlığı (ÖL-3) yalnız sabit genişlikli mimaride: korpustaki "arch" -> bayt/komut.
ARCH_INSN_BYTES = {"arm64": mf.ARM64_INSN_BYTES}


class MeasurementError(RuntimeError):
    """Ölçümün geçerliliğini bozan durum: hat burada durur."""


_now = meas._now
_tilde = meas._tilde


# ---------------------------------------------------------------------------
# Korpus ve veri dizini düzeni
# ---------------------------------------------------------------------------

def load_corpus(path: Path = CORPUS_PATH) -> dict[str, Any]:
    """Korpusu oku ve doğrula: şema, küme adı, sha256 biçimi, test seti kilidi."""
    corpus = json.loads(Path(path).read_text(encoding="utf-8"))
    if corpus.get("schema") != CORPUS_SCHEMA:
        raise MeasurementError(f"{path}: şema {corpus.get('schema')!r}, beklenen {CORPUS_SCHEMA!r}")
    for name, spec in corpus.get("binaries", {}).items():
        if spec.get("set") not in CORPUS_SETS:
            raise MeasurementError(f"{name}: küme {spec.get('set')!r} izinli değil ({CORPUS_SETS})")
        sha = spec.get("orig", {}).get("sha256", "")
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise MeasurementError(f"{name}: özgün ikilinin sha256'sı eksik ya da biçimsiz")
        stem = Path(spec["orig"]["path"]).name
        hits = {name, stem} & LOCKED_TEST_PROGRAMS
        if hits:
            raise MeasurementError(
                f"{name}: {sorted(hits)} test seti kilidinde (docs/arge/test_seti_kilidi.md); "
                "G31'den önce analiz edilemez, korpusa eklenemez")
    return corpus


def select_names(corpus: dict[str, Any], only: Optional[list[str]] = None,
                 set_name: Optional[str] = None) -> list[str]:
    names = [n for n, s in corpus["binaries"].items() if set_name is None or s["set"] == set_name]
    if only:
        unknown = sorted(set(only) - set(corpus["binaries"]))
        if unknown:
            raise MeasurementError(f"korpusta olmayan ikili: {unknown}")
        names = [n for n in names if n in only]
    return names


def orig_path(data_dir: Path, name: str) -> Path:
    return data_dir / "corpus" / name / "orig" / name


def bin_path(data_dir: Path, name: str) -> Path:
    return data_dir / "corpus" / name / "bin" / name


def gt_path(data_dir: Path, name: str) -> Path:
    return data_dir / "corpus" / name / "gt" / f"{name}.gt.json"


def run_dir(data_dir: Path, label: str, name: str) -> Path:
    return data_dir / "runs" / label / name


def _source_path(p: str) -> Path:
    path = Path(p).expanduser()
    return path if path.is_absolute() else REPO_ROOT / path


# ---------------------------------------------------------------------------
# prepare: Apple strip + export trie denetimi + GT
# ---------------------------------------------------------------------------

def strip_binary(src: Path, dst: Path, strip_path: str = STRIP_PATH) -> None:
    """``src``'yi Apple strip ile ``dst``'ye soy (özgüne dokunmaz)."""
    if not Path(strip_path).is_absolute():
        raise MeasurementError(
            f"strip yolu mutlak olmalı: {strip_path!r} (PATH'teki conda strip export trie'yi bırakır)")
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".tmp")
    tmp.unlink(missing_ok=True)
    proc = subprocess.run([strip_path, "-o", str(tmp), str(src)], capture_output=True,
                          text=True, timeout=mf.TOOL_TIMEOUT_S)
    if proc.returncode != 0 or not tmp.is_file():
        tmp.unlink(missing_ok=True)
        raise MeasurementError(f"strip başarısız ({proc.returncode}): {proc.stderr.strip()[-300:]}")
    tmp.chmod(0o755)
    os.replace(tmp, dst)


def parse_dyld_exports(text: str) -> list[str]:
    """``dyld_info -exports`` çıktısındaki adlar. Çıktı tanınmazsa hata (sessiz geçiş yok)."""
    if "-exports:" not in text:
        raise MeasurementError("dyld_info çıktısında '-exports:' bölümü yok; export trie doğrulanamadı")
    names = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower().startswith("0x"):
            names.append(parts[1])
    return names


def read_exports(path: Path) -> list[str]:
    proc = subprocess.run([mf.XCRUN_PATH, "dyld_info", "-exports", str(path)], capture_output=True,
                          text=True, timeout=mf.TOOL_TIMEOUT_S)
    if proc.returncode != 0:
        raise MeasurementError(f"dyld_info başarısız ({proc.returncode}): {proc.stderr.strip()[-300:]}")
    return parse_dyld_exports(proc.stdout)


def verify_exports(names: list[str]) -> None:
    """Export trie'de ``ALLOWED_EXPORTS`` dışında ad kaldıysa ölçüm sızıntılıdır: dur."""
    extra = sorted(set(names) - ALLOWED_EXPORTS)
    if extra:
        raise MeasurementError(
            f"export trie boşalmadı: {len(extra)} ad kaldı (ör. {extra[:5]}). Ghidra bu adları "
            "okur, popülasyon bozulur. Apple /usr/bin/strip ile soyulduğundan emin olun.")


def _xcrun_find(tool: str) -> Optional[str]:
    proc = subprocess.run([mf.XCRUN_PATH, "--find", tool], capture_output=True, text=True,
                          timeout=mf.TOOL_TIMEOUT_S)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def tool_info() -> dict[str, Any]:
    """Hazırlık araçlarının künyesi: yol, çözülen ikili, sha256, CLT sürümü."""
    def _tool(path: str, resolved: Optional[str]) -> dict[str, Any]:
        sha = f1.sha256_file(Path(resolved)) if resolved and Path(resolved).is_file() else None
        return {"path": path, "resolved": resolved, "sha256": sha}
    clt = subprocess.run([PKGUTIL_PATH, f"--pkg-info={CLT_PACKAGE_ID}"], capture_output=True,
                         text=True, timeout=mf.TOOL_TIMEOUT_S)
    clt_version = next((ln.split(":", 1)[1].strip() for ln in clt.stdout.splitlines()
                        if ln.startswith("version:")), None)
    return {
        "strip": _tool(STRIP_PATH, _xcrun_find("strip")),
        "dyld_info": _tool(f"{mf.XCRUN_PATH} dyld_info", _xcrun_find("dyld_info")),
        "nm": {**_tool(mf.NM_PATH, _xcrun_find("nm")), "version": mf.nm_version()},
        "clt_version": clt_version,
    }


def prepare(data_dir: Path, corpus: dict[str, Any], names: list[str]) -> dict[str, Any]:
    """Seçilen ikilileri hazırla; manifest'i ``corpus/manifest.json``'a yaz."""
    mpath = data_dir / "corpus" / "manifest.json"
    manifest = (json.loads(mpath.read_text(encoding="utf-8")) if mpath.is_file()
                else {"schema": MANIFEST_SCHEMA, "binaries": {}})
    warnings: list[str] = []
    for name in names:
        spec = corpus["binaries"][name]
        src = _source_path(spec["orig"]["path"])
        dst_orig, dst_bin = orig_path(data_dir, name), bin_path(data_dir, name)
        if not src.is_file() and dst_orig.is_file():
            # Kimlik yol değil sha256'dır: kaynak klasör silindiyse önceki hazırlığın
            # kopyası kullanılır (aşağıda aynı sha256 denetiminden geçer).
            print(f"  not: {_tilde(src)} yok; önceki hazırlığın kopyası kullanılıyor")
            src = dst_orig
        print(f"[prepare] {name}: {_tilde(src)}")
        if not src.is_file():
            raise MeasurementError(f"{name}: özgün ikili yok: {src}")
        got = f1.sha256_file(src)
        if got != spec["orig"]["sha256"]:
            raise MeasurementError(f"{name}: özgün ikilinin sha256'sı uyuşmuyor\n beklenen "
                                   f"{spec['orig']['sha256']}\n gelen    {got}")
        dst_orig.parent.mkdir(parents=True, exist_ok=True)
        if not dst_orig.is_file() or f1.sha256_file(dst_orig) != got:
            dst_orig.unlink(missing_ok=True)
            shutil.copyfile(src, dst_orig)
            dst_orig.chmod(0o444)
        strip_binary(dst_orig, dst_bin)
        try:
            exports = read_exports(dst_bin)
            verify_exports(exports)
            leftover = mf.parse_nm(mf.run_nm(dst_bin))
            if leftover:
                raise MeasurementError(
                    f"{name}: strip'li kopyada {len(leftover)} fonksiyon sembolü kaldı "
                    f"(ör. {list(leftover.values())[:3]}); GT sızar")
        except BaseException:
            dst_bin.unlink(missing_ok=True)  # doğrulanmamış kopya analiz edilmesin
            raise
        stripped_sha = f1.sha256_file(dst_bin)
        expected = spec.get("expected_strip_sha256")
        if expected and expected != stripped_sha:
            warnings.append(f"{name}: strip'li kopyanın sha256'sı korpustakinden farklı "
                            f"({stripped_sha[:16]} ≠ {expected[:16]}); strip sürümü değişmiş olabilir. "
                            "Export trie doğrulandı; sayılar önceki koşularla bayt düzeyinde aynı girdiden değil.")
        gt = mf.build_gt(dst_orig, binary=name, stripped=dst_bin)
        gpath = gt_path(data_dir, name)
        gpath.parent.mkdir(parents=True, exist_ok=True)
        gpath.write_text(json.dumps(gt, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        manifest["binaries"][name] = {
            "set": spec["set"], "orig_source": _tilde(src), "orig_sha256": got,
            "stripped_sha256": stripped_sha,
            "expected_strip_sha256_matches": (expected == stripped_sha) if expected else None,
            "exports_after_strip": exports, "gt_counts": gt["counts"],
            "homebrew": spec.get("homebrew"), "prepared_at": _now(),
        }
        print(f"  {name}: özgün {got[:16]}.. strip'li {stripped_sha[:16]}.. export={exports} "
              f"GT={gt['counts']}")
    manifest.update({"schema": MANIFEST_SCHEMA, "updated_at": _now(),
                     "corpus_file": _tilde(CORPUS_PATH), "tools": tool_info(),
                     "warnings": warnings})
    mpath.parent.mkdir(parents=True, exist_ok=True)
    mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    for w in warnings:
        print(f"UYARI: {w}")
    return manifest


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

def build_command(target: Path, rdir: Path) -> list[str]:
    """Analiz komutu. Dinamik analiz yok (hedef ÇALIŞTIRILMAZ)."""
    return [sys.executable, "-m", "karadul", "analyze", str(target), "--skip-dynamic",
            "--output-dir", str(rdir / "ws"), "--output", str(rdir / "out")]


def _wait_or_kill(proc: subprocess.Popen, timeout: int) -> tuple[Optional[int], str]:
    """Süreci bekle; süre aşılırsa ya da kesilirse bütün süreç grubunu (JVM dahil) öldür."""
    def _kill() -> None:
        for sig, grace in ((signal.SIGTERM, KILL_GRACE_S), (signal.SIGKILL, None)):
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                return
            try:
                proc.wait(timeout=grace)
                return
            except subprocess.TimeoutExpired:
                continue
    try:
        rc = proc.wait(timeout=timeout)
        return rc, "ok" if rc == 0 else "failed"
    except subprocess.TimeoutExpired:
        _kill()
        return None, "timeout"
    except BaseException:
        _kill()
        raise


def run_one(tree: Path, ghidra: Path, data_dir: Path, label: str, name: str,
            timeout: int, force: bool) -> dict[str, Any]:
    rdir = run_dir(data_dir, label, name)
    meta_path = rdir / "run.json"
    if meta_path.is_file() and not force:
        prev = json.loads(meta_path.read_text(encoding="utf-8"))
        if prev.get("status") == "ok":
            print(f"  [atla] {name} (önceden ok)")
            return prev
    target = bin_path(data_dir, name)
    gt = json.loads(gt_path(data_dir, name).read_text(encoding="utf-8"))
    target_sha = f1.sha256_file(target)
    if target_sha != gt["stripped_sha256"]:
        raise MeasurementError(f"{name}: {target} GT'nin strip'li kopyası değil "
                               f"({target_sha[:16]} ≠ {gt['stripped_sha256'][:16]}); prepare'i yeniden koşun")
    for sub in ("ws", "out"):
        if (rdir / sub).exists():
            shutil.rmtree(rdir / sub)
    (rdir / mf.SCORE_FILE_NAME).unlink(missing_ok=True)
    rdir.mkdir(parents=True, exist_ok=True)
    cmd = build_command(target, rdir)
    env = dict(os.environ, PYTHONPATH=str(tree), GHIDRA_INSTALL_DIR=str(ghidra))
    meta: dict[str, Any] = {
        "binary": name, "label": label,
        "command": " ".join(_tilde(c) for c in cmd), "cwd": _tilde(tree),
        "env": {"PYTHONPATH": _tilde(tree), "GHIDRA_INSTALL_DIR": _tilde(ghidra),
                "JAVA_HOME": _tilde(os.environ.get("JAVA_HOME", ""))},
        "target_sha256": target_sha, "orig_sha256": gt["orig_sha256"],
        "cfg_cache_before": meas.cfg_cache_snapshot(), "started_at": _now(),
    }
    print(f"  [koş] {name}")
    t0 = time.monotonic()
    with open(rdir / "karadul.log", "wb") as log:
        proc = subprocess.Popen(cmd, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        rc, status = _wait_or_kill(proc, timeout)
    meta.update({"exit_code": rc, "status": status, "finished_at": _now(),
                 "duration_s": round(time.monotonic() - t0, 1),
                 "cfg_cache_after": meas.cfg_cache_snapshot()})
    if status == "ok" and f1.find_run_artifacts(rdir)["ghidra_functions"] is None:
        meta["status"] = "failed"
        meta["error"] = "ghidra_functions.json üretilmedi"
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"  [bitti] {name}: {meta['status']} {meta['duration_s']} sn")
    return meta


def _porcelain_paths(lines: list[str]) -> set[str]:
    """``git status --porcelain`` satırlarından yol (yeniden adlandırmada yeni ad).

    Sabit ``ln[3:]`` kullanılmaz: 6373908'den önce ``measure._git`` çıktıyı ``strip()``'liyordu
    ve ilk satırın baştaki boşluğu düşüyordu (`` M a`` -> ``M a``); eski oturum dosyalarında
    bu biçim duruyor.
    """
    out = set()
    for ln in lines:
        parts = ln.strip().split(None, 1)
        if len(parts) == 2:
            out.add(parts[1].split(" -> ")[-1])
    return out


def is_engine_path(path: str) -> bool:
    """Analiz sonucunu etkileyen yol mu: motor kodu ya da çalışma zamanı verisi."""
    return path.startswith("karadul/") or path.split("/")[0] in meas.RUNTIME_DATA


def engine_dirty_hashes(tree: Path, info: dict[str, Any]) -> dict[str, Optional[str]]:
    """Kirli motor dosyalarının sha256'sı (koşu başı/sonu kıyası için; silinmişse None)."""
    out: dict[str, Optional[str]] = {}
    for rel in sorted(_porcelain_paths(info["dirty_files"])):
        if is_engine_path(rel):
            f = tree / rel
            out[rel] = f1.sha256_file(f) if f.is_file() else None
    return out


def describe_tree_change(tree: Path, start: dict[str, Any], end: dict[str, Any],
                         start_hashes: Optional[dict[str, Optional[str]]] = None) -> dict[str, Any]:
    """Koşu sırasında ağaçta değişenler; ``engine_paths`` boş değilse sayılar karışık koddandır."""
    paths: set[str] = set()
    if start["commit"] != end["commit"]:
        paths |= set(meas._git(tree, "diff", "--name-only", start["commit"], end["commit"]).splitlines())
    s_dirty, e_dirty = _porcelain_paths(start["dirty_files"]), _porcelain_paths(end["dirty_files"])
    paths |= s_dirty ^ e_dirty
    engine = {p for p in paths if is_engine_path(p)}
    end_hashes = engine_dirty_hashes(tree, end)
    for rel in s_dirty & e_dirty:
        if is_engine_path(rel) and (start_hashes is None
                                    or start_hashes.get(rel) != end_hashes.get(rel)):
            engine.add(rel)   # başta da sonda da kirli: içerik değişmiş (ya da bilinmiyor)
    return {"changed": bool(paths) or bool(engine), "from": start["commit"], "to": end["commit"],
            "paths": sorted(paths), "engine_paths": sorted(engine)}


def analyze(tree: Path, label: str, data_dir: Path, ghidra: Path, names: list[str],
            jobs: int = MAC_JOBS, timeout: int = MAC_TIMEOUT_S, force: bool = False,
            allow_other_ghidra: bool = False) -> dict[str, Any]:
    tree = tree.expanduser().resolve()
    gi = meas.ghidra_info(ghidra)
    meas.require_pinned_ghidra(gi, allow_other_ghidra)
    for name in names:
        if not bin_path(data_dir, name).is_file() or not gt_path(data_dir, name).is_file():
            raise MeasurementError(f"{name}: hazırlanmamış (önce prepare)")
    info = meas.tree_info(tree)
    start_hashes = engine_dirty_hashes(tree, info)
    if info["runtime_data_missing"]:
        print(f"UYARI: ağaçta çalışma zamanı verisi yok: {info['runtime_data_missing']}")
    label_dir = data_dir / "runs" / label
    label_dir.mkdir(parents=True, exist_ok=True)
    session: dict[str, Any] = {
        "label": label, "tree": info, "ghidra": gi, "allow_other_ghidra": allow_other_ghidra,
        "python": sys.version.split()[0], "python_executable": _tilde(sys.executable),
        "platform": platform.platform(), "started_at": _now(), "jobs": jobs,
        "timeout_s": timeout, "binaries": names, "engine_dirty_sha256": start_hashes,
    }
    spath = label_dir / "session.json"
    spath.write_text(json.dumps(session, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"[analyze] {label}: {info['commit'][:10]} ({info['karadul_file']}), Ghidra {gi['version']}, "
          f"kirli dosya {len(info['dirty_files'])}")
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        metas = list(pool.map(
            lambda n: run_one(tree, ghidra, data_dir, label, n, timeout, force), names))
    # Ağaç koşu sırasında değişti mi (paralel ajanlar)? Motor dosyası değiştiyse sayılar
    # künyedeki commit'in kodundan değil, karışık koddan gelir.
    end = meas.tree_info(tree)
    change = describe_tree_change(tree, info, end, start_hashes)
    session.update({"finished_at": _now(), "tree_at_end": end, "tree_change": change,
                    "tree_changed_during_run": change["changed"]})
    spath.write_text(json.dumps(session, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return {"session": session, "runs": metas}


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------

def _read_json(path: Optional[Path]) -> Optional[dict[str, Any]]:
    if path is None or not Path(path).is_file():
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def target_types(rdir: Path, art: dict[str, Any]) -> dict[str, Any]:
    """Karadul'un hedef türü, bulunduğu her kaynaktan (üçü de aynı olmalı)."""
    out: dict[str, Any] = {}
    rep = _read_json(rdir / "out" / "report.json")
    if rep is not None:
        tt = (rep.get("pipeline", {}).get("stages", {}).get("identify", {})
              .get("stats", {}).get("target_type"))
        if tt is not None:
            out["out_report"] = tt
    if art.get("ts_dir") is not None:
        wrep = _read_json(art["ts_dir"] / "reports" / "report.json")
        if wrep is not None and wrep.get("target", {}).get("type") is not None:
            out["ws_report"] = wrep["target"]["type"]
    ti = _read_json(art.get("target_info"))
    if ti is not None and ti.get("target_type") is not None:
        out["target_info"] = ti["target_type"]
    return out


def report_ghidra(rdir: Path, art: dict[str, Any]) -> Optional[dict[str, Any]]:
    """report.json ``environment.ghidra`` (9bbadc8 sonrası çalışma alanı raporunda)."""
    paths = [rdir / "out" / "report.json"]
    if art.get("ts_dir") is not None:
        paths.insert(0, art["ts_dir"] / "reports" / "report.json")
    for p in paths:
        rep = _read_json(p)
        if rep is not None and isinstance(rep.get("environment", {}).get("ghidra"), dict):
            return rep["environment"]["ghidra"]
    return None


def run_checks(rdir: Path, gt_doc: dict[str, Any], meta: dict[str, Any],
               session: dict[str, Any]) -> dict[str, Any]:
    """Koşunun geçerlilik denetimleri; ``valid`` False ise sayılar toplamlara girmez."""
    art = f1.find_run_artifacts(rdir)
    ti = _read_json(art.get("target_info"))
    analyzed = ti.get("file_hash") if ti else None
    tt = target_types(rdir, art)
    rg = report_ghidra(rdir, art)
    checks: dict[str, Any] = {
        "analyzed_sha256": analyzed,
        "analyzed_sha256_matches_gt": (analyzed == gt_doc["stripped_sha256"]) if analyzed else None,
        "run_target_sha256_matches_gt": meta.get("target_sha256") == gt_doc["stripped_sha256"],
        "target_type": tt,
        "target_type_ok": bool(tt) and all(v in MACHO_TARGET_TYPES for v in tt.values()),
        "ghidra_report": rg,
        "ghidra_report_matches_session": (
            rg.get("version") == session["ghidra"]["version"]) if rg else None,
        "ambiguous_workspace": art["ambiguous"],
    }
    reasons = []
    if checks["analyzed_sha256_matches_gt"] is not True:
        reasons.append(f"analiz edilen dosya GT'nin strip'li kopyası olarak doğrulanamadı "
                       f"(target_info sha256={analyzed})")
    if not checks["run_target_sha256_matches_gt"]:
        reasons.append("run.json'daki hedef sha256'sı GT ile uyuşmuyor")
    if not checks["target_type_ok"]:
        reasons.append(f"hedef türü Mach-O değil: {tt or 'bulunamadı'} "
                       "(Mac'e özgü statik adımlar koşmamış olabilir)")
    if checks["ghidra_report_matches_session"] is False:
        reasons.append(f"koşudaki Ghidra {(rg or {}).get('version')} oturumdakinden "
                       f"({session['ghidra']['version']}) farklı")
    if checks["ambiguous_workspace"]:
        reasons.append("koşu dizininde birden çok çalışma alanı var")
    checks["invalid_reasons"] = reasons
    checks["valid"] = not reasons
    return checks


def _harness_fingerprint() -> dict[str, str]:
    files = [HERE / "macho_f1.py", HERE / "macho_measure.py", HERE / "macho_reach.py",
             HERE / "function_f1.py", REPO_ROOT / "tests" / "benchmark" / "metrics.py"]
    return {str(p.relative_to(REPO_ROOT)): f1.sha256_file(p)[:16] for p in files}


def aggregate(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Geçerli ikililerin toplamı: sınıf başına mikro; program sınıfı için makro."""
    valid = [e for e in entries if e.get("valid")]
    out: dict[str, Any] = {"binaries": len(valid),
                           "excluded": [e["binary"] for e in entries if not e.get("valid")]}
    for cls in mf.CLASS_ORDER:
        out[cls] = {"micro": mf.combine_blocks([e["summary"]["siniflar"][cls] for e in valid])}
    if valid:
        out[mf.CLASS_PROGRAM]["macro"] = {
            m: round(sum(e["summary"]["siniflar"][mf.CLASS_PROGRAM][m] for e in valid) / len(valid), 4)
            for m in ("precision", "recall", "f1")}
    # ÖL-3: erişim sınıfları (program sınıfı içinde); bir ikilide yoksa toplam verilmez.
    acc = [e["summary"].get("erisim_siniflari") for e in valid]
    out["erisim_siniflari"] = None
    if valid and all(acc):
        blocks = {a: {"micro": mf.combine_blocks([x[a] for x in acc])} for a in mf.ACCESS_ORDER}
        diags = [x[mf.ACCESS_NONE].get("kod_referansi") for x in acc]
        if all(diags):
            blocks[mf.ACCESS_NONE]["micro"]["kod_referansi"] = {
                k: sum(d[k] for d in diags) for k in diags[0]}
        out["erisim_siniflari"] = blocks
    return out


DEFINITIONS = {
    "gt": "/usr/bin/nm -n -U <özgün> T/t sembolleri, __mh_execute_header hariç; adres başına bir kayıt (takma adlar birlikte)",
    "strip": "karadul'un gördüğü kopya /usr/bin/strip ile soyulur; export trie'de yalnız __mh_execute_header kalmalı, nm -U boş olmalı",
    "population": "GT'de olup Ghidra'nın strip'li kopyada thunk OLMAYAN ve jenerik adlı (kendisinin adlandıramadığı) fonksiyonları",
    "undetected": "o adreste thunk olmayan Ghidra fonksiyonu yok (undetected_thunk + undetected_missing); popülasyon dışı",
    "ghidra_known_from_exports": "adını Ghidra kendisi biliyor (export trie/FID); popülasyon dışı, Apple strip'te ~0 beklenir",
    "sinif": "program | cold (.cold.N) | outlined (OUTLINED_FUNCTION_N); başlık sayısı program sınıfı",
    "strict": "tp = normalize(temel(tahmin)) == normalize(temel(GT)); temel() .cold.N/.llvm.N/.__uniq.N/$VARYANT eklerini soyar; normalize = metrics.AccuracyCalculator._normalize",
    "metrics": "P = TP/(TP+yanlış), R = TP/popülasyon, F1 harmonik ortalama; %95 Wilson aralığı",
    "lenient": "tp ya da compare_name exact/semantic/partial tutan yanlış",
    "legacy_summary": "macho_score.json özetindeki eski anahtarlar (tp, wrong, precision ...) 15 Ekim tanımıyla bütün sınıfları birlikte sayar",
    "valid": "hedef türü Mach-O, analiz edilen dosya GT'nin strip'li kopyası, Ghidra raporu oturumla aynı, tek çalışma alanı",
    "erisim": "ÖL-3, program sınıfı içinde: dogrudan = ghidra_call_graph'ta çağıranı var (öz-kenar hariç); tablo = çağıranı yok, strip'li ikilide bir rebase fixup'ı (xcrun dyld_info -fixups, chained dahil) tam fonksiyon başını gösteriyor; referanssiz = ikisi de yok",
    "kod_referansi": "referanssiz tanısı (objdump): adresi_alinan = adrp+add (16 komut içinde) ya da adr ile adresi hesaplanan; kuyruk_cagrisi = başka fonksiyondan b/b.cond ile gidilen; hicbiri = ikisi de değil",
    "talimat": "Ghidra fonksiyon gövdesi baytı / 4 (arm64); talimat kapsamı = isim verilenlerin talimatı / popülasyonun talimatı, talimat doğruluğu = TP talimatı / isim verilenlerin talimatı",
    "coverage": "isim verilen / popülasyon (%95 Wilson); ağırlıklı oranlara Wilson verilmez (binom değil)",
    "micro": "küme içi sayılar toplanıp hesaplanır",
    "macro": "ikili F1/P/R'lerinin aritmetik ortalaması (program sınıfı)",
}


def score_label(label: str, data_dir: Path, corpus: dict[str, Any], names: list[str],
                with_reach: bool = False, result_label: Optional[str] = None) -> dict[str, Any]:
    """Koşuları puanla. ``result_label`` verilirse puan dosyaları koşu dizinine değil
    ``results/<result_label>/<ad>/macho_score.json``'a yazılır (eski puan dosyası kalır)."""
    label_dir = data_dir / "runs" / label
    session = json.loads((label_dir / "session.json").read_text(encoding="utf-8"))
    manifest = _read_json(data_dir / "corpus" / "manifest.json") or {}
    change = session.get("tree_change")
    if change is None and session.get("tree_at_end"):
        # tree_change alanından önceki oturum dosyası: commit'ler ve kirli listeler yeterli;
        # başlangıç sha256'ları yok, iki uçta da kirli motor dosyası "bilinmiyor" sayılır.
        change = describe_tree_change(Path(session["tree"]["tree"]).expanduser(), session["tree"],
                                      session["tree_at_end"], session.get("engine_dirty_sha256"))
    engine_changed = bool(change and change["engine_paths"])
    per_binary: list[dict[str, Any]] = []
    warnings: list[str] = []
    for name in names:
        rdir = run_dir(data_dir, label, name)
        meta = _read_json(rdir / "run.json") or {}
        entry: dict[str, Any] = {
            "binary": name, "set": corpus["binaries"][name]["set"],
            "run": {k: meta.get(k) for k in ("status", "exit_code", "duration_s", "command", "cwd",
                                             "started_at", "finished_at", "target_sha256",
                                             "orig_sha256")},
            "valid": False,
        }
        if meta.get("status") != "ok":
            entry["error"] = meta.get("error") or f"koşu durumu: {meta.get('status', 'yok')}"
            warnings.append(f"{name}: ÖLÇÜLEMEDİ — {entry['error']}")
            per_binary.append(entry)
            continue
        gpath = gt_path(data_dir, name)
        gt_doc = json.loads(gpath.read_text(encoding="utf-8"))
        score_out = (data_dir / "results" / result_label / name / mf.SCORE_FILE_NAME
                     if result_label else rdir / mf.SCORE_FILE_NAME)
        # Erişim sınıfları yalnız karadul'un analiz ettiği dosyanın kendisinden okunur.
        bpath = bin_path(data_dir, name)
        stripped = bpath if bpath.is_file() and f1.sha256_file(bpath) == gt_doc["stripped_sha256"] else None
        arch = corpus["binaries"][name].get("arch")
        insn = ARCH_INSN_BYTES.get(arch) if arch else None
        res = mf.score_run(rdir, gt_path=gpath, out=score_out, stripped=stripped, insn_bytes=insn)
        summary = res["summary"]
        summary["inputs"] = {k: (_tilde(v) if isinstance(v, str) else v)
                             for k, v in summary["inputs"].items()}
        if summary.get("erisim_kaynaklari"):
            summary["erisim_kaynaklari"] = {k: (_tilde(v) if isinstance(v, str) else v)
                                            for k, v in summary["erisim_kaynaklari"].items()}
        if stripped is None:
            warnings.append(f"{name}: strip'li kopya yok ya da GT'nin strip'li kopyası değil; "
                            "erişim sınıfları hesaplanmadı")
        if insn is None:
            warnings.append(f"{name}: mimari {arch!r} için talimat genişliği tanımlı değil; "
                            "talimat ağırlığı yok")
        checks = run_checks(rdir, gt_doc, meta, session)
        if engine_changed:
            checks["invalid_reasons"].append(
                f"motor dosyaları koşu sırasında değişti: {change['engine_paths'][:5]}")
            checks["valid"] = False
        entry.update({
            "orig_sha256": gt_doc["orig_sha256"], "stripped_sha256": gt_doc["stripped_sha256"],
            "valid": checks["valid"], "checks": checks, "summary": summary,
            "score_file": _tilde(score_out),
            "karadul_report": meas._report_stats(rdir),
            "cfg_cache_before": meta.get("cfg_cache_before", {}),
            "cfg_cache_after": meta.get("cfg_cache_after", {}),
        })
        if with_reach:
            entry["reach"] = mr.run_reach(rdir, res["rows"])
        entry["rows"] = res["rows"]
        for r in checks["invalid_reasons"]:
            warnings.append(f"{name}: GEÇERSİZ — {r}")
        if checks["ghidra_report"] is None:
            warnings.append(f"{name}: report.json'da environment.ghidra yok; Ghidra sürümü yalnız oturumdan")
        for w in summary["warnings"]:
            warnings.append(f"{name}: {w}")
        if (entry["karadul_report"].get("cross_binary_candidates") or 0) > 0:
            warnings.append(f"{name}: çapraz-ikili önbellek adayı kullanıldı "
                            f"({entry['karadul_report']['cross_binary_candidates']})")
        per_binary.append(entry)
    if session["ghidra"].get("version") != GHIDRA_PINNED_VERSION:
        warnings.append(f"koşular Ghidra {session['ghidra'].get('version')} ile alındı; "
                        f"sabitlenen sürüm {GHIDRA_PINNED_VERSION}")
    if session["tree"]["dirty_files"]:
        warnings.append(f"ağaç kirliyken koşuldu: {session['tree']['dirty_files']}")
    if change and change["changed"] and not engine_changed:
        warnings.append(f"ağaç koşu sırasında değişti ({change['from'][:10]} → {change['to'][:10]}) ama "
                        f"motor dosyaları (karadul/, çalışma zamanı verisi) değişmedi: {change['paths']}")
    sets = sorted({e["set"] for e in per_binary})
    return {
        "schema": REPORT_SCHEMA,
        "label": label,
        "result_label": result_label or label,
        "scored_at": _now(),
        "karadul": {"commit": session["tree"]["commit"], "tree": session["tree"]["tree"],
                    "dirty_files": session["tree"]["dirty_files"],
                    "version": session["tree"]["karadul_version"],
                    "tree_change": change},
        "environment": {"ghidra": session["ghidra"], "ghidra_pinned": GHIDRA_PINNED_VERSION,
                        "allow_other_ghidra": session.get("allow_other_ghidra", False),
                        "python": session["python"], "platform": session["platform"],
                        "jobs": session["jobs"], "timeout_s": session["timeout_s"],
                        "analysis_started_at": session.get("started_at"),
                        "analysis_finished_at": session.get("finished_at")},
        "tools": manifest.get("tools"),
        "harness": _harness_fingerprint(),
        "corpus": {"file": str(CORPUS_PATH.relative_to(REPO_ROOT)),
                   "sha256": f1.sha256_file(CORPUS_PATH)[:16]},
        "definitions": DEFINITIONS,
        "reproduce": [
            "python scripts/measurement/macho_measure.py prepare",
            f"python scripts/measurement/macho_measure.py analyze --tree {session['tree']['tree']} "
            f"--label {label} --jobs {session['jobs']}",
            f"python scripts/measurement/macho_measure.py score --label {label}"
            + (f" --sonuc-etiketi {result_label}" if result_label else ""),
        ],
        "aggregate": {s: aggregate([e for e in per_binary if e["set"] == s]) for s in sets},
        "warnings": warnings,
        "per_binary": per_binary,
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    """Raporu yaz; satır kayıtları tek satır (diff'lenebilir, kısa)."""
    shadow = json.loads(json.dumps(report))
    slots: dict[str, str] = {}
    for i, entry in enumerate(shadow.get("per_binary", [])):
        rows = entry.get("rows")
        if not rows:
            continue
        keys = []
        for j, rec in enumerate(rows):
            key = f"__ROW_{i}_{j}__"
            slots[f'"{key}"'] = json.dumps(rec, ensure_ascii=False)
            keys.append(key)
        entry["rows"] = keys
    text = json.dumps(shadow, ensure_ascii=False, indent=1)
    for key, line in slots.items():
        text = text.replace(key, line, 1)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def _ci(ci: Optional[list[float]]) -> str:
    return f"[{ci[0]:.3f}–{ci[1]:.3f}]" if ci else "[—]"


def _tw(block: dict[str, Any], key: str) -> str:
    t = block.get("talimat")
    return f"{t[key]:.3f}" if t else "—"


def print_table(report: dict[str, Any]) -> None:
    env = report["environment"]["ghidra"]
    print(f"\n### {report['result_label']} (koşu {report['label']}) — karadul {report['karadul']['commit'][:10]} — "
          f"Ghidra {env.get('version')} — puanlandı {report['scored_at']}")
    print("| ikili | küme | GT | thunk | yok | Ghidra biliyor | popülasyon | isim verilen | TP | yanlış "
          "| isimsiz | kapsam [%95] | P [%95] | R [%95] | F1 | talimat kapsamı | talimat doğruluğu "
          "| lenient P | cold pop/isim/TP | outlined pop/isim/TP | geçerli |")
    print("|" + "---|" * 21)
    for e in report["per_binary"]:
        if "summary" not in e:
            print(f"| {e['binary']} | {e['set']} | ÖLÇÜLEMEDİ: {e.get('error')} |")
            continue
        s = e["summary"]
        p, c, o = (s["siniflar"][k] for k in mf.CLASS_ORDER)
        valid = "evet" if e["valid"] else "HAYIR: " + "; ".join(e["checks"]["invalid_reasons"])
        print(f"| {e['binary']} | {e['set']} | {s['gt_functions']} | {s['undetected_thunk']} | "
              f"{s['undetected_missing']} | {s['ghidra_known_from_exports']} | {p['population']} | "
              f"{p['named']} | {p['tp']} | {p['wrong']} | {p['unnamed']} | "
              f"{p['coverage']:.3f} {_ci(p['coverage_ci95'])} | "
              f"{p['precision']:.3f} {_ci(p['precision_ci95'])} | {p['recall']:.3f} {_ci(p['recall_ci95'])} | "
              f"{p['f1']:.3f} | {_tw(p, 'coverage')} | {_tw(p, 'precision')} | {p['lenient_precision']:.3f} | "
              f"{c['population']}/{c['named']}/{c['tp']} | {o['population']}/{o['named']}/{o['tp']} | {valid} |")
    for set_name, a in report["aggregate"].items():
        if not a.get("binaries"):
            print(f"| **{set_name}** | geçerli ikili yok |")
            continue
        m = a[mf.CLASS_PROGRAM]["micro"]
        mac = a[mf.CLASS_PROGRAM].get("macro", {})
        print(f"| **{set_name}** | {a['binaries']} ikili | | | | | {m['population']} | {m['named']} | "
              f"{m['tp']} | {m['wrong']} | {m['unnamed']} | {m['coverage']:.3f} {_ci(m['coverage_ci95'])} | "
              f"{m['precision']:.3f} {_ci(m['precision_ci95'])} | "
              f"{m['recall']:.3f} {_ci(m['recall_ci95'])} | mikro {m['f1']:.3f} / makro {mac.get('f1', 0):.3f} | "
              f"{_tw(m, 'coverage')} | {_tw(m, 'precision')} | {m['lenient_precision']:.3f} | | | |")
    # ÖL-3: erişim sınıfları (program sınıfı içinde)
    lines = []
    for e in report["per_binary"]:
        acc = e.get("summary", {}).get("erisim_siniflari")
        if acc:
            lines.append((e["binary"], acc))
    for set_name, a in report["aggregate"].items():
        if a.get("erisim_siniflari"):
            lines.append((f"**{set_name}**", {k: v["micro"] for k, v in a["erisim_siniflari"].items()}))
    if lines:
        print("\n| ikili | erişim | popülasyon | isim verilen | TP | yanlış | kapsam [%95] | P [%95] "
              "| talimat | talimat kapsamı | talimat doğruluğu |")
        print("|" + "---|" * 11)
        for name, acc in lines:
            for k in mf.ACCESS_ORDER:
                b = acc[k]
                t = b.get("talimat") or {}
                print(f"| {name} | {k} | {b['population']} | {b['named']} | {b['tp']} | {b['wrong']} | "
                      f"{b['coverage']:.3f} {_ci(b['coverage_ci95'])} | "
                      f"{b['precision']:.3f} {_ci(b['precision_ci95'])} | {t.get('population', '—')} | "
                      f"{_tw(b, 'coverage')} | {_tw(b, 'precision')} |")
            kr = acc[mf.ACCESS_NONE].get("kod_referansi")
            if kr:
                print(f"| {name} | referanssız tanısı | kodda adresi alınan {kr['adresi_alinan']}, "
                      f"kuyruk çağrısı {kr['kuyruk_cagrisi']}, hiçbiri {kr['hicbiri']} | | | | | | | | |")
    for e in report["per_binary"]:
        if "reach" in e:
            print(f"{e['binary']} erişim (reach): {mr.format_line(e['reach'])}")
    for w in report["warnings"]:
        print(f"UYARI: {w}")


# ---------------------------------------------------------------------------
# compare (A/B)
# ---------------------------------------------------------------------------

def _program_rows(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["addr"]: r for r in entry.get("rows", [])
            if r.get("sinif", mf.CLASS_PROGRAM) == mf.CLASS_PROGRAM}


def compare_reports(a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    """İki raporun ikili başına program sınıfı farkı (yalnız ikisi de geçerliyse)."""
    bi = {e["binary"]: e for e in b["per_binary"]}
    out = []
    for ea in a["per_binary"]:
        eb = bi.get(ea["binary"])
        if not eb or not ea.get("valid") or not eb.get("valid"):
            out.append({"binary": ea["binary"], "comparable": False})
            continue
        ra, rb = _program_rows(ea), _program_rows(eb)
        status_a = {k: v["status"] for k, v in ra.items()}
        status_b = {k: v["status"] for k, v in rb.items()}
        gained = sorted(k for k, s in status_b.items() if s == "tp" and status_a.get(k) != "tp")
        lost = sorted(k for k, s in status_a.items() if s == "tp" and status_b.get(k) != "tp")
        new_wrong = sorted(k for k, s in status_b.items() if s == "wrong" and status_a.get(k) != "wrong")
        fixed_wrong = sorted(k for k, s in status_a.items() if s == "wrong" and status_b.get(k) != "wrong")
        pa, pb = ea["summary"]["siniflar"][mf.CLASS_PROGRAM], eb["summary"]["siniflar"][mf.CLASS_PROGRAM]
        out.append({
            "binary": ea["binary"], "comparable": True,
            "population_same": set(ra) == set(rb),
            "a": {k: pa[k] for k in ("named", "tp", "wrong", "precision", "recall", "f1")},
            "b": {k: pb[k] for k in ("named", "tp", "wrong", "precision", "recall", "f1")},
            "gained_tp": [rb[k]["gt"][0] for k in gained], "lost_tp": [ra[k]["gt"][0] for k in lost],
            "new_wrong": len(new_wrong), "fixed_wrong": len(fixed_wrong),
            "sign_test_p": meas.sign_test_p(len(gained), len(lost)),
        })
    return out


def compare(a_path: Path, b_path: Path) -> int:
    a = json.loads(Path(a_path).read_text(encoding="utf-8"))
    b = json.loads(Path(b_path).read_text(encoding="utf-8"))
    if a.get("harness") != b.get("harness"):
        print("UYARI: iki rapor farklı puanlayıcı sürümüyle puanlanmış — ikisini de `score` ile yeniden puanlayın.")
    if a["environment"]["ghidra"] != b["environment"]["ghidra"]:
        print("UYARI: Ghidra farklı — fark motordan değil Ghidra'dan gelebilir.")
    if a.get("corpus") != b.get("corpus"):
        print("UYARI: korpus dosyası farklı.")
    print(f"A={a['label']} ({a['karadul']['commit'][:10]})  B={b['label']} ({b['karadul']['commit'][:10]})")
    print("| ikili | isim A→B | TP A→B | yanlış A→B | P A→B | R A→B | F1 A→B | kazanılan TP | kaybedilen TP "
          "| yeni yanlış | düzelen yanlış | işaret testi p |")
    print("|" + "---|" * 12)
    for d in compare_reports(a, b):
        if not d["comparable"]:
            print(f"| {d['binary']} | kıyaslanamadı (eksik ya da geçersiz koşu) |")
            continue
        x, y = d["a"], d["b"]
        note = "" if d["population_same"] else " (popülasyon farklı!)"
        print(f"| {d['binary']}{note} | {x['named']}→{y['named']} | {x['tp']}→{y['tp']} | "
              f"{x['wrong']}→{y['wrong']} | {x['precision']:.3f}→{y['precision']:.3f} | "
              f"{x['recall']:.3f}→{y['recall']:.3f} | {x['f1']:.3f}→{y['f1']:.3f} | "
              f"{len(d['gained_tp'])} | {len(d['lost_tp'])} | {d['new_wrong']} | {d['fixed_wrong']} | "
              f"{d['sign_test_p']:.3g} |")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR,
                    help=f"ölçüm verisi (varsayılan {_tilde(DEFAULT_DATA_DIR)}; {DATA_DIR_ENV})")
    ap.add_argument("--corpus", type=Path, default=CORPUS_PATH, help="korpus tanımı")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def _sel(p: argparse.ArgumentParser) -> None:
        p.add_argument("--only", nargs="*", default=None, help="yalnız bu ikililer (ör. htop)")
        p.add_argument("--set", dest="set_name", choices=CORPUS_SETS, default=None,
                       help="yalnız bu küme")

    def _run_args(p: argparse.ArgumentParser) -> None:
        _sel(p)
        p.add_argument("--tree", type=Path, required=True, help="karadul'un koşulacağı ağaç")
        p.add_argument("--label", required=True, help="koşu etiketi (runs/<etiket>/)")
        p.add_argument("--ghidra", type=Path, default=meas.DEFAULT_GHIDRA)
        p.add_argument("--jobs", type=int, default=MAC_JOBS)
        p.add_argument("--timeout", type=int, default=MAC_TIMEOUT_S, help="ikili başına saniye")
        p.add_argument("--force", action="store_true", help="ok koşuları da yeniden koş")
        p.add_argument("--farkli-ghidra-izinli", action="store_true",
                       help=f"sabitlenen Ghidra {GHIDRA_PINNED_VERSION} dışındaki bir sürümle koşmaya izin ver")

    def _score_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--out", type=Path, default=None,
                       help="sonuç JSON'u (varsayılan results/<sonuç etiketi>.json)")
        p.add_argument("--sonuc-etiketi", default=None,
                       help="yeniden puanlamayı yeni etiketle yaz: results/<etiket>.json ve "
                            "results/<etiket>/<ad>/macho_score.json; koşu dizinindeki puan dosyası kalır")
        p.add_argument("--reach", action="store_true", help="erişim (macho_reach) bölümünü ekle")

    _sel(sub.add_parser("prepare", help="özgünü doğrula, Apple strip ile soy, export trie denetle, GT çıkar"))
    _run_args(sub.add_parser("analyze", help="karadul'u ağaçtan koş"))
    sp = sub.add_parser("score", help="koşuları puanla")
    _sel(sp)
    sp.add_argument("--label", required=True)
    _score_args(sp)
    ap_all = sub.add_parser("all", help="prepare + analyze + score")
    _run_args(ap_all)
    _score_args(ap_all)
    cp = sub.add_parser("compare", help="iki sonuç JSON'unu kıyasla")
    cp.add_argument("a", type=Path)
    cp.add_argument("b", type=Path)

    args = ap.parse_args(argv)
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]  # log'da ilerleme görünsün
    if args.cmd == "compare":
        return compare(args.a, args.b)
    data_dir = args.data_dir.expanduser()
    corpus = load_corpus(args.corpus)
    names = select_names(corpus, args.only, args.set_name)
    if not names:
        raise MeasurementError("seçimde ikili yok")
    if args.cmd in ("prepare", "all"):
        prepare(data_dir, corpus, names)
    if args.cmd in ("analyze", "all"):
        analyze(args.tree, args.label, data_dir, args.ghidra.expanduser(), names, args.jobs,
                args.timeout, args.force, args.farkli_ghidra_izinli)
    if args.cmd in ("score", "all"):
        report = score_label(args.label, data_dir, corpus, names, with_reach=args.reach,
                             result_label=args.sonuc_etiketi)
        out = args.out or (data_dir / "results" / f"{report['result_label']}.json")
        write_report(report, out)
        print_table(report)
        print(f"\nsonuç: {_tilde(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
