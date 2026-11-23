"""BA-1: blok açıklama adımının (``engineering_annotation``) Ghidra'sız yeniden oynatılması.

Adımın girdileri (``karadul/pipeline/steps/engineering_annotation.py``):

- ``capa_annotation_decompiled_dir``: ``comment_generation``'ın çıktısı
  ``reconstructed/commented/`` (CAPA kod beslemesi K-1 gereği kapalı;
  dizin değişmeden geçer),
- ``functions_json_path`` / ``call_graph_json_path``: ``ghidra_metadata``'nın
  seçtiği ``ghidra_functions.json`` / ``ghidra_call_graph.json`` (önce
  ``deobfuscated/``, yoksa ``static/``),
- ``algo_result`` + ``eng_result``: ``reconstructed/algorithms.json`` ve
  ``reconstructed/engineering_algorithms.json``'dan geri kurulur
  (``algorithms.json`` ``detection_method`` / ``address`` taşımaz; bu iki alan
  yalnız başlık kutusu kategorilerinde çıktıya girer, sayısı rapora yazılır).

Çıktı: ``--cikti`` altına ``annotated/`` (adımın yazdığı ``*.c`` +
``block_annotations.json``) ve ``zamanlama.json``. Çalışma alanına YAZMAZ.

Koşu ayrı çocuk süreçte, zaman aşımıyla (C düzeyindeki eşleşme SIGTERM'e
yanıt vermez; ``subprocess.run(timeout=...)`` SIGKILL gönderir). Çocuk her
dosyaya başlarken ``ilerleme.txt``'ye dosya adını yazar: takılırsa nerede
takıldığı bilinir.

Kullanım (worktree kökünden):

    python scripts/arge/ba1/yeniden_oynat.py --ws <oturum_dizini> --cikti <dizin> \
        [--eski-modul <block_annotator.py kopyası>] [--zaman-asimi 900]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

KOK = Path(__file__).resolve().parents[3]


def _modul_yukle(eski_modul: str | None):
    if str(KOK) not in sys.path:
        sys.path.insert(0, str(KOK))
    if not eski_modul:
        import karadul.reconstruction.engineering.block_annotator as mod

        return mod
    spec = importlib.util.spec_from_file_location("block_annotator_eski", eski_modul)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["block_annotator_eski"] = mod
    spec.loader.exec_module(mod)
    return mod


def _sec(ws: Path, ad: str) -> Path:
    p = ws / "deobfuscated" / ad
    return p if p.exists() else ws / "static" / ad


def _algoritmalar(ws: Path) -> tuple[list, dict]:
    from karadul.reconstruction.c_algorithm_id import AlgorithmMatch

    algos: list = []
    kunye = {"algorithms_json": 0, "engineering": 0, "baslik_kategorisi": 0}
    a = ws / "reconstructed" / "algorithms.json"
    if a.exists():
        for d in json.loads(a.read_text(encoding="utf-8")).get("algorithms", []):
            algos.append(AlgorithmMatch(
                name=d["name"], category=d["category"], confidence=d["confidence"],
                detection_method=d.get("detection_method", ""),
                evidence=d.get("evidence", []),
                function_name=d.get("function_name") or d.get("function", ""),
                address=d.get("address", ""),
            ))
            kunye["algorithms_json"] += 1
    e = ws / "reconstructed" / "engineering_algorithms.json"
    if e.exists():
        ed = json.loads(e.read_text(encoding="utf-8"))
        if ed.get("success"):
            for d in ed.get("algorithms", []):
                algos.append(AlgorithmMatch(
                    name=d["name"], category=d["category"], confidence=d["confidence"],
                    detection_method=d.get("detection_method", ""),
                    evidence=d.get("evidence", []),
                    function_name=d.get("function_name") or d.get("function", ""),
                    address=d.get("address", ""),
                ))
                kunye["engineering"] += 1
    return algos, kunye


def _cocuk(args: argparse.Namespace) -> int:
    mod = _modul_yukle(args.eski_modul)
    ws = Path(args.ws)
    cikti = Path(args.cikti)
    annotated = cikti / "annotated"
    annotated.mkdir(parents=True, exist_ok=True)
    ilerleme = cikti / "ilerleme.txt"
    algos, kunye = _algoritmalar(ws)
    kunye["baslik_kategorisi"] = sum(
        1 for a in algos if a.category in mod._ALGORITHM_HEADER_CATEGORIES
    )

    # Dosya başına süre: _extract_functions her dosyada bir kez çağrılır.
    damgalar: list[tuple[str, float]] = []
    asil = mod.CodeBlockAnnotator._extract_functions

    def sarili(content, func_meta, file_stem):
        damgalar.append((file_stem, time.perf_counter()))
        with open(ilerleme, "w", encoding="utf-8") as f:
            f.write(f"{len(damgalar)}\t{file_stem}\n")
        return asil(content, func_meta, file_stem)

    mod.CodeBlockAnnotator._extract_functions = staticmethod(sarili)
    an = mod.CodeBlockAnnotator(None)
    t0 = time.perf_counter()
    sonuc = an.annotate(
        decompiled_dir=ws / "reconstructed" / "commented",
        functions_json=_sec(ws, "ghidra_functions.json"),
        call_graph_json=_sec(ws, "ghidra_call_graph.json"),
        output_dir=annotated,
        algorithm_matches=algos,
    )
    bitis = time.perf_counter()
    sureler = []
    for i, (stem, t) in enumerate(damgalar):
        sonraki = damgalar[i + 1][1] if i + 1 < len(damgalar) else bitis
        sureler.append((sonraki - t, stem))
    sureler.sort(reverse=True)
    rapor = {
        "modul": mod.__file__,
        "ws": str(ws),
        "algoritma_kunyesi": kunye,
        "basari": sonuc.success,
        "hatalar": sonuc.errors[:20],
        "toplam_aciklama": sonuc.total_annotations,
        "tur_basina": sonuc.by_type,
        "islenen_dosya": len(damgalar),
        "yazilan_dosya": len(sonuc.annotated_files),
        "toplam_sure_sn": round(bitis - t0, 3),
        "en_uzun_10": [[round(s, 4), st] for s, st in sureler[:10]],
    }
    (cikti / "zamanlama.json").write_text(
        json.dumps(rapor, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: rapor[k] for k in (
        "basari", "islenen_dosya", "yazilan_dosya", "toplam_sure_sn", "toplam_aciklama")}))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ws", required=True, help="çalışma alanı oturum dizini (…/workspaces/<ad>/<zaman>)")
    ap.add_argument("--cikti", required=True)
    ap.add_argument("--eski-modul")
    ap.add_argument("--zaman-asimi", type=float, default=900.0)
    ap.add_argument("--cocuk", action="store_true")
    args = ap.parse_args(argv)
    if args.cocuk:
        return _cocuk(args)
    Path(args.cikti).mkdir(parents=True, exist_ok=True)
    komut = [sys.executable, str(Path(__file__).resolve()), "--cocuk",
             "--ws", args.ws, "--cikti", args.cikti]
    if args.eski_modul:
        komut += ["--eski-modul", args.eski_modul]
    t0 = time.perf_counter()
    try:
        cp = subprocess.run(komut, timeout=args.zaman_asimi, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        ilerleme = Path(args.cikti) / "ilerleme.txt"
        son = ilerleme.read_text(encoding="utf-8").strip() if ilerleme.exists() else "?"
        print(f"ZAMAN AŞIMI ({args.zaman_asimi} sn, çocuk öldürüldü); son dosya: {son}")
        return 124
    sys.stdout.write(cp.stdout)
    if cp.returncode != 0:
        sys.stderr.write(cp.stderr[-3000:])
    print(f"duvar {round(time.perf_counter() - t0, 1)} sn, çıkış {cp.returncode}")
    return cp.returncode


if __name__ == "__main__":
    sys.exit(main())
