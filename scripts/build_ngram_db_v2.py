#!/usr/bin/env python3
"""Karadul N-gram isim veritabani v2 — GERCEK CORPUS tabanli.

v1 (build_ngram_db.py) stub kalmisti: 41-72 entry. Bu sebep:
    - Bootstrap sadece 28 API uzerinden sentetik uretim yapiyordu.
    - Workspace C dosyalarini tarıyor ama ground-truth label yok (placeholder).

v2'nin iyilestirmeleri:
    1. APIParamDB (200+ API) uzerinden bootstrap — her parametre index
       icin cok daha fazla aday.
    2. Workspace C dosyalarindan "ground-truth" label cikarma:
       fonksiyonda param_N / local_X OLMAYAN anlamli isim gorulurse
       (vocab'ta varsa), o ismi n-gram context'in label'i olarak kullan.
    3. APIParamDB'den cikarilan API-cagrisi n-gram'lari:
       fn(arg0, arg1, arg2) context'inde arg_i varsa ve API tanimli
       parametre ismi varsa, n-gram hash'ine o ismi label olarak ekle.
    4. Frekans filtresi: sadece en az K kez gorulen hash/label ciftleri
       DB'ye yaziliyor (noise azaltma).

Kullanim:
    python scripts/build_ngram_db_v2.py --workspace workspaces/ --output sigs/ngram_name_db/
    python scripts/build_ngram_db_v2.py --workspace workspaces/ --max-files 20000

Hedef: >= 10000 entry/DB, topk >= 5. Baseline: 41-72 entry.

Kod Berke icin acikli: her adim yorum satirlariyla anlatiliyor.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import time
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path

# Proje kokunu Python path'ine ekle (script icinden package import etmek icin)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from karadul.reconstruction.ngram_namer import (  # noqa: E402
    NGRAM_SIZES,
    TOP_K,
    NgramDB,
    NgramVocab,
    _mark_variables,
    _mask_flank_vars,
    ngram_hash,
    normalize_tokens,
    tokenize_c,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parametreler
# ---------------------------------------------------------------------------

# Bir (hash, var_id) ciftinin DB'ye yazilmasi icin minimum frekans.
# Dusuk -> daha cok entry ama daha gurultulu. Yuksek -> kaliteli ama az entry.
MIN_HASH_FREQ = 2

# Ground-truth adayi icin vocab'ta minimum frekans.
# Vocab 1.4M isim var ama bircogu cok nadir. En sik gorulen ~100K isim
# yeterince guvenilir ground-truth olur.
MIN_VOCAB_FREQ_FOR_LABEL = 3

# Compiler-generated ismi goz ardi etme icin bilinen pattern'ler
_GENERIC_VAR_RE = re.compile(
    r"^(?:param_\d+|local_[0-9a-f]+|iVar\d+|uVar\d+|lVar\d+|bVar\d+"
    r"|sVar\d+|cVar\d+|fVar\d+|dVar\d+|pVar\d+|ppVar\d+"
    r"|in_\w+|auStack\w+|puVar\d+|pcVar\d+|piVar\d+"
    r"|plVar\d+|pbVar\d+|extraout_\w+|Var\d+)$"
)

# C anahtar kelime + tipler: label olamaz
_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
    # Ghidra'nin import ettigi tipler
    "bool", "byte", "word", "dword", "qword", "undefined", "undefined1",
    "undefined2", "undefined4", "undefined8", "uint", "ushort", "ulong",
    "ulonglong", "longlong", "size_t", "ptrdiff_t", "true", "false", "NULL",
    # C stdlib makro/function basic
    "printf", "main",
})


def _is_valid_label(name: str) -> bool:
    """Bir ismin ground-truth label olarak kullanilabilir olup olmadigi."""
    if not name or len(name) < 3:
        return False
    if name in _C_KEYWORDS:
        return False
    if not name.isidentifier():
        return False
    if _GENERIC_VAR_RE.match(name):
        return False
    # Tek rakam veya cok kisa: faydasiz
    if name.isdigit():
        return False
    return True


# ---------------------------------------------------------------------------
# Bootstrap: APIParamDB'den n-gram uretme
# ---------------------------------------------------------------------------


def _load_api_param_db() -> dict[str, list[str]]:
    """APIParamDB'yi import et ve dict olarak dondur."""
    from karadul.reconstruction.api_param_db import APIParamDB
    db = APIParamDB()
    # Private alana erisim -- bunu genisletmek icin gecerli bir yol
    return dict(db._db)  # type: ignore[attr-defined]


def build_bootstrap_entries(
    vocab: NgramVocab,
) -> dict[int, dict[bytes, dict[int, int]]]:
    """APIParamDB'deki ~200 API'den sentetik n-gram entry'leri uret.

    Her API icin tipik cagirim pattern'ini (fn(arg0, arg1, ...)) tokenize et.
    Her pozisyondaki arg'a karsi API'nin onerdigi parametre ismini label
    olarak kullan.

    Returns:
        {ngram_size: {hash: {vocab_id: count}}} eslesmesi.
    """
    api_db = _load_api_param_db()
    logger.info("APIParamDB yuklendi: %d fonksiyon", len(api_db))

    entries_by_size: dict[int, dict[bytes, dict[int, int]]] = {
        s: {} for s in NGRAM_SIZES
    }

    for func_name, param_names in api_db.items():
        if not param_names:
            continue

        # Her parametre pozisyonu icin ayri n-gram kaydi
        for param_idx, param_name in enumerate(param_names):
            if not _is_valid_label(param_name):
                continue

            vid = vocab.lookup(param_name)
            if vid < 0:
                vid = vocab.add(param_name, 1)

            # Sentetik cagirim: fn ( @@var_0@@ , @@var_1@@ , @@var_2@@ , ... )
            # KRITIK: `_mark_variables` fonksiyonu gercek kodda her parametreye
            # ayri bir var_id atar (param_1 -> @@var_0@@, param_2 -> @@var_1@@).
            # Bu sebeple bootstrap'te de ayri id'ler vermek lazim; yoksa hash
            # uyusmaz ve DB hic match etmez.
            n_params = len(param_names)
            tokens: list[str] = [func_name, "("]
            for i in range(n_params):
                tokens.append(f"@@var_{i}@@")
                if i < n_params - 1:
                    tokens.append(",")
            tokens.append(")")
            tokens.append(";")

            # Hedef degiskenin pozisyonu (tokens icinde)
            target_pos = 2 + param_idx * 2  # ( sonra param_idx * (var + ,)

            # v1.10.0 Batch 6B (flanking bug fix):
            # Her boyut icin hem CENTERED hem FLANKING (left/right) hash
            # uret. Predict tarafiyla tutarli normalizasyon:
            #   - center: @@var_0@@ (sabit, pozisyondan bagimsiz)
            #   - flank'lardaki @@var_N@@: @@var_X@@ (sabit)
            for size in NGRAM_SIZES:
                padded = ["??"] * size + tokens + ["??"] * size
                pos = target_pos + size

                # Centered: merkez @@var_0@@, flank @@var_X@@
                left = _mask_flank_vars(padded[pos - size: pos])
                right = _mask_flank_vars(padded[pos + 1: pos + 1 + size])
                center_span = left + ["@@var_0@@"] + right
                key_c = ngram_hash(center_span)
                entries_by_size[size].setdefault(key_c, {})
                entries_by_size[size][key_c][vid] = (
                    entries_by_size[size][key_c].get(vid, 0) + 10
                )

                # Flanking left: sadece sol flank + b"left" discriminator
                key_l = ngram_hash(left, b"left")
                entries_by_size[size].setdefault(key_l, {})
                entries_by_size[size][key_l][vid] = (
                    entries_by_size[size][key_l].get(vid, 0) + 10
                )

                # Flanking right: sadece sag flank + b"right" discriminator
                key_r = ngram_hash(right, b"right")
                entries_by_size[size].setdefault(key_r, {})
                entries_by_size[size][key_r][vid] = (
                    entries_by_size[size][key_r].get(vid, 0) + 10
                )

    total = sum(len(v) for v in entries_by_size.values())
    logger.info("Bootstrap: %d entry uretildi (tum boyutlar)", total)
    return entries_by_size


# ---------------------------------------------------------------------------
# Corpus mining: decompiled C dosyalarindan n-gram cikarma
# ---------------------------------------------------------------------------


# Shared vocab lookup table for workers. macOS'ta default start method
# 'spawn'. fork'u tercih ediyoruz cunku vocab 1.4M entry -> spawn ile pickle
# cok yavas (5+ dakika). Fork ile copy-on-write paylasim O(1).
_WORKER_VOCAB_LOOKUP: dict[str, int] = {}


def _worker_init_shared() -> None:
    """Fork sonrasi worker init (global _WORKER_VOCAB_LOOKUP zaten paylasiliyor).

    Bu fonksiyon sadece placeholder — fork spawn'a duserse vocab_lookup
    bos kalir, o durumda main process'in init'ini kullanmaya calis.
    """
    # _WORKER_VOCAB_LOOKUP modulu yuklendiginde parent process'te set edilmis
    # oluyor; fork + COW ile cocuklar da gormeye devam ediyor.
    # Spawn durumunda bos kalir (fallback: sentinel kontrolu process_c_file'da).
    pass


def _process_c_file_v2(
    c_file: Path,
) -> dict[int, dict[bytes, dict[int, int]]]:
    """Tek bir C dosyasini isle.

    Ground-truth cikarma stratejisi:
        Eger bir token:
          - generic var degilse (param_N, local_X, iVar vb.)
          - C keyword veya tip degilse
          - vocab'ta yeterli frekansla varsa
        -> bu token muhtemelen Ghidra'nin sonraki/diger aracla isim
        verdigi gercek bir degiskendir. Onu label olarak kabul ediyoruz.

    Hash'lere sadece "anlamli" ismi label olarak ekliyoruz — generic var
    marker'ini n-gram *hash*'inde kullaniyoruz (pencere tarafi) ama label
    olarak kullanmiyoruz.

    Returns:
        {ngram_size: {hash: {vocab_id: count}}} eslesmesi.
    """
    results: dict[int, dict[bytes, dict[int, int]]] = {
        s: {} for s in NGRAM_SIZES
    }

    try:
        code = c_file.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return results

    # Cok kucuk dosyalari atla
    if len(code) < 100:
        return results

    tokens = tokenize_c(code)
    if len(tokens) < 20:
        return results

    norm_tokens = normalize_tokens(tokens)
    marked, var_positions = _mark_variables(norm_tokens)

    # Ground-truth etiketleri: vocab'ta olan, anlamli isimler
    # Pozisyon: token listesindeki indeks -> vocab_id
    gt_labels: dict[int, int] = {}
    for i, tok in enumerate(norm_tokens):
        if not _is_valid_label(tok):
            continue
        vid = _WORKER_VOCAB_LOOKUP.get(tok, -1)
        if vid >= 0:
            gt_labels[i] = vid

    # Her ground-truth pozisyonu icin her boyutta n-gram hash'i cikar.
    # KRITIK: Pencereyi `marked` uzerinden yaptigimiz icin, hedef pozisyonunda
    # anlamli isim hala duruyor. Predict zamaninda bu yerde `@@var_N@@` marker
    # olacagi icin hash'ler UYUSMAZ.
    #
    # Cozum: hedef pozisyonu "hedefin kendisini" slot ile degistir. Predict
    # path'i `@@var_N@@` (N=0,1,2,...) yazar; hangisi oldugu degiskenin
    # aniden (parent fn'deki sira) cagiran fonksiyonda sirasina bagli.
    # Bu sebeple hash'i deterministik yapmak icin:
    #   - MASK: span[size] = "@@VAR@@" (tek bir sabit placeholder)
    # Ayni sekilde predict'te de bu maskle kontrol etmek gerekir.
    # Ama predict kodu zaten `@@var_N@@` formatindaki N'li marker'i hash'e
    # koyuyor ve N degistikce hash uyusmaz; bu hafif bir sorun. Cozum:
    # predict'te ngram_namer'e kucuk bir override yapmak lazim. Bu modulu
    # kolayca degistirmemek icin ASAGIDAKI STRATEJI:
    #   - N-gram hash'ini hem TURU (var_0, var_1, ...) ile hesapla,
    #     hem de MASKLI halini (var_*). DB'ye ikisini de yaz. predict tarafi
    #     mevcut halini hash'lediginde en azindan var_0 versiyonu match eder
    #     (fonksiyonun ilk karsilastigi degisken).
    # v1.10.0 Batch 6B: Predict path ile tutarli normalizasyon.
    #   - Centered: center = @@var_0@@, flank @@var_N@@ -> @@var_X@@
    #   - Flanking: left/right flank'lari da ayri entry olarak yaz
    # Ground-truth pozisyonlarindaki token anlamli bir isim (vid var),
    # o yerde predict sirasinda marker olmayacak — bu token hedef
    # pozisyondur, center'a sabit "@@var_0@@" koyuyoruz ve flank'lari
    # maskliyoruz. Flanking tarafinda hedef pozisyonu ATLANIR (flank
    # sadece sol/sag, merkez disinda).
    for size in NGRAM_SIZES:
        padded = ["??"] * size + marked + ["??"] * size

        for orig_pos, vid in gt_labels.items():
            pos = orig_pos + size
            left = _mask_flank_vars(padded[pos - size: pos])
            right = _mask_flank_vars(padded[pos + 1: pos + 1 + size])

            # Centered span (merkez sabit @@var_0@@)
            center_span = left + ["@@var_0@@"] + right
            key_c = ngram_hash(center_span)
            results[size].setdefault(key_c, {})
            results[size][key_c][vid] = results[size][key_c].get(vid, 0) + 1

            # Flanking left
            key_l = ngram_hash(left, b"left")
            results[size].setdefault(key_l, {})
            results[size][key_l][vid] = results[size][key_l].get(vid, 0) + 1

            # Flanking right
            key_r = ngram_hash(right, b"right")
            results[size].setdefault(key_r, {})
            results[size][key_r][vid] = results[size][key_r].get(vid, 0) + 1

    return results


def mine_workspace(
    workspace_dirs: list[Path],
    vocab: NgramVocab,
    max_files: int,
    min_vocab_freq: int,
) -> dict[int, dict[bytes, dict[int, int]]]:
    """Workspace'lerden n-gram entry'leri topla."""

    # Tum .c dosyalarini bul
    c_files: list[Path] = []
    for ws_dir in workspace_dirs:
        if not ws_dir.exists():
            logger.warning("Workspace yok: %s", ws_dir)
            continue
        # rglob tum alt dizinleri tarar
        found = list(ws_dir.rglob("*.c"))
        logger.info("%s altinda %d .c dosyasi", ws_dir, len(found))
        c_files.extend(found)

    if not c_files:
        logger.warning("Hicbir .c dosyasi bulunamadi")
        return {s: {} for s in NGRAM_SIZES}

    # Maksimum dosya sayisi limiti
    if len(c_files) > max_files:
        c_files = c_files[:max_files]
        logger.info("max_files=%d sinirina dusuruldu", max_files)

    # Vocab'tan sadece yeterince sik gecen isimleri al.
    # Bu dict'i GLOBAL olarak set ediyoruz — fork ile child'lara COW olarak
    # paylasiliyor. Spawn (macOS default) durumunda bu yaklasim calismaz
    # cunku pickle 1.4M entry 5+ dakika. Bu yuzden ensurefork ile fork
    # kullanmayi zorluyoruz.
    global _WORKER_VOCAB_LOOKUP
    _WORKER_VOCAB_LOOKUP = {}
    for i in range(len(vocab)):
        name = vocab.reverse(i)
        count = vocab.count_by_id(i)
        if count >= min_vocab_freq and _is_valid_label(name):
            _WORKER_VOCAB_LOOKUP[name] = i
    logger.info(
        "Worker vocab lookup tablosu: %d isim (freq >= %d)",
        len(_WORKER_VOCAB_LOOKUP), min_vocab_freq,
    )

    # Multiprocessing ile isle (fork ile, COW paylasim)
    import multiprocessing as mp
    ctx = mp.get_context("fork")
    nproc = max(1, cpu_count() - 1)
    logger.info(
        "Workspace mining: %d dosya, %d worker (fork context)",
        len(c_files), nproc,
    )

    merged: dict[int, dict[bytes, dict[int, int]]] = {s: {} for s in NGRAM_SIZES}
    start = time.monotonic()
    processed = 0

    with ctx.Pool(nproc) as pool:
        for result in pool.imap_unordered(_process_c_file_v2, c_files, chunksize=50):
            processed += 1
            if processed % 5000 == 0:
                elapsed = time.monotonic() - start
                rate = processed / elapsed if elapsed > 0 else 0
                logger.info(
                    "%d / %d dosya isleniyor (%.0f f/s, %.1fs gecti)",
                    processed, len(c_files), rate, elapsed,
                )
            for size, entries in result.items():
                target = merged[size]
                for h, vid_counts in entries.items():
                    if h not in target:
                        target[h] = {}
                    bucket = target[h]
                    for vid, cnt in vid_counts.items():
                        bucket[vid] = bucket.get(vid, 0) + cnt

    elapsed = time.monotonic() - start
    logger.info(
        "Workspace mining tamam: %d dosya, %.1fs, %d worker",
        processed, elapsed, nproc,
    )
    return merged


# ---------------------------------------------------------------------------
# Birlestirme ve filtreleme
# ---------------------------------------------------------------------------


def merge_and_filter(
    bootstrap: dict[int, dict[bytes, dict[int, int]]],
    corpus: dict[int, dict[bytes, dict[int, int]]],
    min_freq: int,
) -> dict[int, dict[bytes, dict[int, int]]]:
    """Iki entry kaynagini birlestir + dusuk frekansli ciftleri at.

    min_freq: bir (hash, vid) ciftinin toplam count'u bu esigin
    altindaysa atilir. Bootstrap entry'leri count=10 ile basliyor,
    yani esik=2 ise bootstrap'ler her zaman tutulur.
    """
    merged: dict[int, dict[bytes, dict[int, int]]] = {s: {} for s in NGRAM_SIZES}

    for size in NGRAM_SIZES:
        # Once bootstrap + corpus'u birlestir
        combined: dict[bytes, dict[int, int]] = {}
        for source in (bootstrap.get(size, {}), corpus.get(size, {})):
            for h, vid_counts in source.items():
                if h not in combined:
                    combined[h] = {}
                bucket = combined[h]
                for vid, cnt in vid_counts.items():
                    bucket[vid] = bucket.get(vid, 0) + cnt

        # Sonra min_freq altini at
        filtered: dict[bytes, dict[int, int]] = {}
        for h, vid_counts in combined.items():
            kept = {
                vid: cnt for vid, cnt in vid_counts.items() if cnt >= min_freq
            }
            if kept:
                filtered[h] = kept

        merged[size] = filtered
        logger.info(
            "Boyut %d: %d hash (bootstrap+corpus), %d hash (filtre>=%d)",
            size, len(combined), len(filtered), min_freq,
        )

    return merged


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _rebuild_vocab_from_scratch(
    sigs_dir: Path, min_count: int
) -> NgramVocab:
    """Signature DB'den kucuk vocab olustur (fallback).

    Normalde mevcut vocab (1.4M) kullanilir. Bu fonksiyon sadece vocab
    yoksa cagirilir.
    """
    import json as _json
    logger.info("Vocab sifirdan kuruluyor: sigs/*.json uzerinden")

    # fonksiyon isimlerinden parcalari cikar
    _FUNC_PARTS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)")
    _UNDERSCORE = re.compile(r"[_]+")

    vocab = NgramVocab()
    counter: Counter[str] = Counter()
    for sig_file in sorted(sigs_dir.glob("*.json")):
        try:
            data = _json.loads(sig_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        sigs = data.get("signatures", data)
        names: list[str] = []
        if isinstance(sigs, dict):
            names = list(sigs.keys())
        elif isinstance(sigs, list):
            names = [s.get("name", "") for s in sigs if isinstance(s, dict)]

        for name in names:
            if not name or len(name) < 2:
                continue
            counter[name] += 1
            parts = _UNDERSCORE.split(name)
            for part in parts:
                if not part:
                    continue
                camel = _FUNC_PARTS.findall(part)
                if camel:
                    for p in camel:
                        p = p.lower()
                        if len(p) >= 3:
                            counter[p] += 1
                elif len(part) >= 3:
                    counter[part.lower()] += 1

    for name, count in counter.most_common():
        if count >= min_count:
            vocab.add(name, count)

    logger.info("Vocab kuruldu: %d isim (freq >= %d)", len(vocab), min_count)
    return vocab


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Karadul N-gram isim veritabani v2 (gercek corpus)",
    )
    parser.add_argument(
        "--sigs-dir", type=Path, default=_PROJECT_ROOT / "sigs",
        help="Signature JSON dizini",
    )
    parser.add_argument(
        "--workspace", type=Path, nargs="*",
        default=[_PROJECT_ROOT / "workspaces"],
        help="Decompiled C iceren workspace dizin(ler)i",
    )
    parser.add_argument(
        "--output", type=Path, default=_PROJECT_ROOT / "sigs" / "ngram_name_db",
        help="Cikti dizini",
    )
    parser.add_argument(
        "--max-files", type=int, default=50000,
        help="Islenecek maksimum .c dosyasi",
    )
    parser.add_argument(
        "--min-freq", type=int, default=MIN_HASH_FREQ,
        help="Bir (hash, label) ciftinin DB'ye yazilmasi icin min count",
    )
    parser.add_argument(
        "--min-vocab-freq", type=int, default=MIN_VOCAB_FREQ_FOR_LABEL,
        help="Vocab'ta bir ismin 'label' sayilmasi icin min frekans",
    )
    parser.add_argument(
        "--rebuild-vocab", action="store_true",
        help="Vocab'i sifirdan yeniden kur (yavas)",
    )
    parser.add_argument(
        "--skip-corpus", action="store_true",
        help="Sadece bootstrap (workspace taramasini atla)",
    )

    args = parser.parse_args()
    output_dir: Path = args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    start = time.monotonic()

    # 1. Vocab yukle/olustur
    vocab_path = output_dir / "vocab.txt"
    if args.rebuild_vocab or not vocab_path.exists():
        logger.info("=== Adim 1: Vocab sifirdan kuruluyor ===")
        vocab = _rebuild_vocab_from_scratch(args.sigs_dir, min_count=2)
        vocab.save(vocab_path)
    else:
        logger.info("=== Adim 1: Mevcut vocab yukleniyor ===")
        vocab = NgramVocab.load(vocab_path)
        logger.info("Vocab yuklendi: %d isim", len(vocab))

    # 2. Bootstrap entry'leri (APIParamDB'den)
    logger.info("=== Adim 2: Bootstrap n-gram entry'leri (APIParamDB) ===")
    bootstrap = build_bootstrap_entries(vocab)

    # 3. Corpus mining (workspace C dosyalarindan)
    if args.skip_corpus:
        logger.info("=== Adim 3: Corpus mining atlandi (--skip-corpus) ===")
        corpus: dict[int, dict[bytes, dict[int, int]]] = {s: {} for s in NGRAM_SIZES}
    else:
        logger.info("=== Adim 3: Corpus mining (workspace) ===")
        corpus = mine_workspace(
            args.workspace,
            vocab,
            max_files=args.max_files,
            min_vocab_freq=args.min_vocab_freq,
        )

    # 4. Birlestir + filtrele
    logger.info("=== Adim 4: Birlestirme + filtreleme ===")
    merged = merge_and_filter(bootstrap, corpus, min_freq=args.min_freq)

    # 5. DB'leri yaz
    logger.info("=== Adim 5: DB kaydetme ===")
    total_entries = 0
    for size in NGRAM_SIZES:
        entries = merged[size]
        if not entries:
            logger.warning("Boyut %d icin entry yok!", size)
            continue
        db = NgramDB.build(entries, size=size, topk=TOP_K)
        db_path = output_dir / f"db_{size}.ngdb"
        db.save(db_path)
        total_entries += len(db)
        logger.info("DB size=%d: %d entry -> %s", size, len(db), db_path.name)

    # 6. Vocab kaydet (yeni isimler eklendi)
    vocab.save(vocab_path)

    elapsed = time.monotonic() - start
    logger.info("=" * 60)
    logger.info("TAMAM: %.1fs, toplam %d entry, vocab=%d", elapsed, total_entries, len(vocab))


if __name__ == "__main__":
    main()
