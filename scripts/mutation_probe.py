#!/usr/bin/env python3
"""mutation_probe.py -- git-safe HEDEFLI mutasyon testi harness'i.

Bir kaynak dosyaya hedefli bir mutant enjekte eder (literal veya regex ile bir
operatoru/sabiti degistirir), SADECE ilgili testi kosar, sonucu raporlar ve
MUTLAKA kaynagi geri alir (try/finally + atexit + ``git checkout``). Amac:
"yesil test kanit degil" -- bir testin gercekten bir mutanti OLDURDUGUNU
(mutant koda karsi KIRMIZI olduGunu) tekrarlanabilir sekilde kanitlamak.

Terminoloji:
  killed   -- test mutant koda karsi FAIL etti  => testimiz mutanti yakaliyor (IYI)
  survived -- test mutant koda karsi PASS etti   => test deligi (KOTU)
  error    -- mutant uygulanamadi (find eslesmedi / beklenmedik sayida eslesme)

GUVENLIK:
  * Kaynak dosyanin orijinal baytlari BELLEGE alinir; her kosumun sonunda
    (crash/KeyboardInterrupt dahil) geri yazilir.
  * Dosya baslangicta git-temizse ek olarak ``git checkout -- <file>`` ile de
    geri alinir (kemer + askı). Dosyada onceden commit'lenmemis degisiklik
    varsa git checkout ATLANIR (o degisiklikleri yok etmemek icin) -- bayt
    geri-yazimi yeter.
  * atexit + SIGINT/SIGTERM handler'lari yarim kalan mutasyonu geri alir.

Kullanim:
  # Tek mutant:
  python scripts/mutation_probe.py \
      --module karadul/reconstruction/c_comment_generator.py \
      --test  tests/test_comment_offset_and_data_codeunit.py::test_x \
      --find  "line_offset + 500" --replace "line_offset + 0" --expect killed

  # Toplu (mutant-tanim dosyasi):
  python scripts/mutation_probe.py --spec docs/mutation_specs.json
  python scripts/mutation_probe.py --spec docs/mutation_specs.json --id comment_offset_window

Mutant-tanim dosyasi (JSON) semasi -- list[dict] veya {"mutants": [...]}:
  {
    "id": "comment_offset_window",
    "module": "karadul/reconstruction/c_comment_generator.py",
    "test": "tests/test_comment_offset_and_data_codeunit.py::test_x",
    "find": "line_offset + 500",
    "replace": "line_offset + 0",
    "regex": false,          # opsiyonel (varsayilan literal)
    "occurrence": 1,          # opsiyonel: kacinci eslesme (1-tabanli); 0=hepsi
    "expect": "killed",       # opsiyonel: killed|survived (varsayilan killed)
    "desc": "..."             # opsiyonel
  }
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

# Repo koku = bu dosyanin (scripts/) bir ustu.
REPO_ROOT = Path(__file__).resolve().parent.parent

# Yarim kalan mutasyonlari geri almak icin aktif restore kaydi: {abs_path: orig_bytes}
_ACTIVE_RESTORE: dict[str, bytes] = {}


def _emergency_restore() -> None:
    """Yarim kalan tum mutasyonlari orijinal baytlariyla geri yaz."""
    for path_str, orig in list(_ACTIVE_RESTORE.items()):
        try:
            Path(path_str).write_bytes(orig)
        except Exception:
            sys.stderr.write(f"[mutation_probe] KRITIK: {path_str} geri alinamadi!\n")
        finally:
            _ACTIVE_RESTORE.pop(path_str, None)


def _signal_handler(signum, _frame) -> None:  # noqa: ANN001
    _emergency_restore()
    # Varsayilan davranisi taklit et: cikis.
    sys.exit(128 + signum)


atexit.register(_emergency_restore)
for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, _signal_handler)
    except (ValueError, OSError):  # pragma: no cover -- ana thread degilse
        pass


def _git_is_clean(abs_path: Path) -> bool:
    """Dosyanin commit'lenmemis degisikligi YOK mu (git checkout guvenli mi)?"""
    try:
        rc = subprocess.run(
            ["git", "diff", "--quiet", "--", str(abs_path)],
            cwd=REPO_ROOT,
            capture_output=True,
        ).returncode
        # rc==0 -> fark yok (temiz). rc==1 -> fark var. Diger -> bilinmiyor (guvensiz say).
        return rc == 0
    except Exception:
        return False


def _git_checkout(abs_path: Path) -> None:
    """git checkout -- <file> (kemer+aski geri alma; hatalari yut)."""
    try:
        subprocess.run(
            ["git", "checkout", "--", str(abs_path)],
            cwd=REPO_ROOT,
            capture_output=True,
        )
    except Exception:  # pragma: no cover
        pass


def _invalidate_pyc(abs_path: Path) -> None:
    """Modulun __pycache__ .pyc'sini SIL.

    KRITIK: mutant kod bir subprocess tarafindan import edilirse CPython mutant'i
    .pyc'ye yazar (source-mtime = mutant zamani). Kaynak AYNI saniye icinde ve AYNI
    boyutta (ornegin `0.4`->`0.7`) geri yazilirsa CPython'un mtime+size gecerlilik
    kontrolu STALE .pyc'yi taze sanar -> restore edilmis kaynaga ragmen MUTANT
    davranis yuklenir. Bu, testin yanlislikla mutantla kosmasina yol acar (bu
    harness'te olctugumuz gercek bir fiyaskoydu). Cozum: restore sonrasi .pyc'yi
    fiziksel sil + subprocess'te PYTHONDONTWRITEBYTECODE=1 (bkz _run_test)."""
    try:
        cache = abs_path.parent / "__pycache__"
        if cache.is_dir():
            for pyc in cache.glob(f"{abs_path.stem}.*.pyc"):
                pyc.unlink(missing_ok=True)
    except Exception:  # pragma: no cover
        pass


def _apply_mutation(
    text: str, find: str, replace: str, regex: bool, occurrence: int
) -> tuple[str, int]:
    """Mutasyonu uygula. (yeni_metin, degisen_eslesme_sayisi) dondur.

    occurrence==0 -> tum eslesmeler; >=1 -> yalniz o kacinci eslesme (1-tabanli).
    """
    if regex:
        pattern = re.compile(find)
        matches = list(pattern.finditer(text))
        if not matches:
            return text, 0
        if occurrence <= 0:
            new_text, n = pattern.subn(replace, text)
            return new_text, n
        if occurrence > len(matches):
            return text, 0
        m = matches[occurrence - 1]
        new_text = text[: m.start()] + m.expand(replace) + text[m.end():]
        return new_text, 1

    # Literal
    count = text.count(find)
    if count == 0:
        return text, 0
    if occurrence <= 0:
        return text.replace(find, replace), count
    if occurrence > count:
        return text, 0
    # occurrence'inci literal eslesmeyi degistir
    idx = -1
    for _ in range(occurrence):
        idx = text.find(find, idx + 1)
    new_text = text[:idx] + replace + text[idx + len(find):]
    return new_text, 1


def _run_test(test_target: str) -> tuple[bool, str]:
    """Testi kos. (passed, kisa_ozet) dondur. passed=True -> test gecti."""
    cmd = [
        sys.executable, "-m", "pytest", test_target,
        "-q", "-p", "no:cacheprovider", "-x",
        "--no-header", "-o", "addopts=",
    ]
    # PYTHONDONTWRITEBYTECODE=1: mutant kodun .pyc'ye yazilmasini engeller ->
    # restore sonrasi stale-.pyc tuzagini (bkz _invalidate_pyc) kokten onler.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, env=env
    )
    passed = proc.returncode == 0
    tail = (proc.stdout or "").strip().splitlines()
    summary = tail[-1] if tail else (proc.stderr or "").strip()[-200:]
    return passed, summary


def probe_one(mutant: dict[str, Any], verbose: bool = False) -> dict[str, Any]:
    """Tek bir mutanti test et. Sonuc dict'i dondur."""
    mid = mutant.get("id", "?")
    module = mutant["module"]
    test_target = mutant["test"]
    find = mutant["find"]
    replace = mutant["replace"]
    regex = bool(mutant.get("regex", False))
    occurrence = int(mutant.get("occurrence", 1))
    expect = mutant.get("expect", "killed")

    abs_path = (REPO_ROOT / module).resolve()
    result: dict[str, Any] = {
        "id": mid, "module": module, "test": test_target,
        "expect": expect, "status": "error", "detail": "",
    }

    if not abs_path.exists():
        result["detail"] = f"modul yok: {abs_path}"
        return result

    orig_bytes = abs_path.read_bytes()
    orig_text = orig_bytes.decode("utf-8")
    was_clean = _git_is_clean(abs_path)

    new_text, n = _apply_mutation(orig_text, find, replace, regex, occurrence)
    if n == 0:
        result["detail"] = f"find eslesmedi (regex={regex}): {find!r}"
        return result
    if new_text == orig_text:
        result["detail"] = "mutasyon metni degistirmedi (find==replace?)"
        return result

    # --- Mutasyonu uygula, testi kos, GERI AL (try/finally) ---
    _ACTIVE_RESTORE[str(abs_path)] = orig_bytes
    try:
        abs_path.write_bytes(new_text.encode("utf-8"))
        passed, summary = _run_test(test_target)
    finally:
        # 1) her kosulda orijinal baytlari geri yaz
        abs_path.write_bytes(orig_bytes)
        _ACTIVE_RESTORE.pop(str(abs_path), None)
        # 2) baslangicta git-temizdiyse checkout ile de dogrula (aski+kemer)
        if was_clean:
            _git_checkout(abs_path)
        # 3) stale-.pyc tuzagini kes (mutant subprocess .pyc yazmis olabilir)
        _invalidate_pyc(abs_path)

    # Geri alma dogrulama
    if abs_path.read_bytes() != orig_bytes:
        result["status"] = "error"
        result["detail"] = "KRITIK: geri alma basarisiz -- dosya kirli!"
        return result

    status = "killed" if not passed else "survived"
    result["status"] = status
    result["detail"] = summary
    result["ok"] = (status == expect)
    if verbose:
        print(f"    [{mid}] uygulanan eslesme={n} test={'FAIL' if not passed else 'PASS'} "
              f"-> {status} (beklenen {expect}) :: {summary}")
    return result


def load_spec(spec_path: Path) -> list[dict[str, Any]]:
    data = json.loads(spec_path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("mutants", [])
    if not isinstance(data, list):
        raise ValueError("spec dosyasi list veya {'mutants': [...]} olmali")
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="git-safe hedefli mutasyon testi")
    ap.add_argument("--spec", type=Path, help="mutant-tanim JSON dosyasi")
    ap.add_argument("--id", help="spec icinden yalniz bu id'yi kosar (virgulle coklu)")
    ap.add_argument("--module", help="tek mutant: kaynak dosya yolu")
    ap.add_argument("--test", help="tek mutant: pytest hedefi")
    ap.add_argument("--find", help="tek mutant: aranacak metin")
    ap.add_argument("--replace", help="tek mutant: yerine yazilacak metin")
    ap.add_argument("--regex", action="store_true", help="find regex olarak yorumlansin")
    ap.add_argument("--occurrence", type=int, default=1, help="kacinci eslesme (0=hepsi)")
    ap.add_argument("--expect", default="killed", choices=["killed", "survived"])
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.spec:
        mutants = load_spec(args.spec)
        if args.id:
            wanted = {x.strip() for x in args.id.split(",")}
            mutants = [m for m in mutants if m.get("id") in wanted]
    elif args.module and args.test and args.find is not None and args.replace is not None:
        mutants = [{
            "id": "cli", "module": args.module, "test": args.test,
            "find": args.find, "replace": args.replace, "regex": args.regex,
            "occurrence": args.occurrence, "expect": args.expect,
        }]
    else:
        ap.error("ya --spec ver ya da --module/--test/--find/--replace birlikte ver")
        return 2

    if not mutants:
        print("mutant bulunamadi (spec bos veya --id eslesmedi)")
        return 1

    print(f"== mutation_probe: {len(mutants)} mutant ==")
    results = []
    for m in mutants:
        r = probe_one(m, verbose=args.verbose)
        results.append(r)
        icon = {"killed": "OLDU", "survived": "HAYATTA", "error": "HATA"}[r["status"]]
        ok = r.get("ok")
        mark = "" if ok is None else (" [BEKLENEN]" if ok else " [!! BEKLENMEYEN]")
        print(f"  {r['id']:<32} {icon:<8} (beklenen {r['expect']}){mark}")
        if r["status"] == "error":
            print(f"      -> {r['detail']}")

    # Ozet
    killed = sum(1 for r in results if r["status"] == "killed")
    survived = sum(1 for r in results if r["status"] == "survived")
    errors = sum(1 for r in results if r["status"] == "error")
    mismatched = [r for r in results if r.get("ok") is False]
    print(f"\n== ozet: {killed} killed, {survived} survived, {errors} error ==")
    if mismatched:
        print(f"!! {len(mismatched)} mutant beklentiyle uyusmadi:")
        for r in mismatched:
            print(f"   - {r['id']}: {r['status']} (beklenen {r['expect']}) :: {r['detail']}")
        return 1
    if errors:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
