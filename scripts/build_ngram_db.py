#!/usr/bin/env python3
"""Karadul N-gram isim veritabani olusturucu.

Mevcut signature corpus'tan (sigs/*.json) ve opsiyonel olarak
decompiled C dosyalarindan n-gram isim veritabani olusturur.

Kullanim:
    python scripts/build_ngram_db.py [--sigs-dir sigs/] [--workspace workspaces/] [--output sigs/ngram_name_db/]

Kaynak 1 — Signature DB (Varsayilan):
    sigs/*.json dosyalarindan fonksiyon isimlerini cikarip vocab'a ekler.
    Her fonksiyon ismi bir potansiyel degisken ismi olarak kaydedilir.

Kaynak 2 — Decompiled C dosyalari (Opsiyonel):
    workspaces/*/decompiled/*.c dosyalarindan gercek degisken kullanim
    baglamlarini cikarip n-gram eslesmesi olusturur.

Cikti:
    sigs/ngram_name_db/
        vocab.txt           -- Isim vocabularisi (frekans sirali)
        db_2.ngdb           -- N-gram DB (boyut 2)
        db_4.ngdb           -- N-gram DB (boyut 4)
        db_8.ngdb           -- N-gram DB (boyut 8)
        db_12.ngdb          -- N-gram DB (boyut 12)
        db_48.ngdb          -- N-gram DB (boyut 48)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from collections import Counter
from multiprocessing import Pool, cpu_count
from pathlib import Path

# Proje kokunu Python path'ine ekle
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from karadul.reconstruction.ngram_namer import (
    NGRAM_SIZES,
    TOP_K,
    NgramDB,
    NgramVocab,
    _mark_variables,
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
# Kaynak 1: Signature DB'den vocab olusturma
# ---------------------------------------------------------------------------

# C fonksiyon isimlerini anlamli degisken isimlerine donusturme
_FUNC_NAME_PARTS_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)")
_UNDERSCORE_SPLIT_RE = re.compile(r"[_]+")


def _extract_name_parts(func_name: str) -> list[str]:
    """Fonksiyon ismindan anlamli alt isimler cikar.

    Ornek:
        "SSL_CTX_new" -> ["ssl", "ctx", "new"]
        "getHostByName" -> ["get", "host", "by", "name"]
        "strcmp" -> ["strcmp"]
    """
    # Alt cizgi ile bol
    parts = _UNDERSCORE_SPLIT_RE.split(func_name)
    result = []
    for part in parts:
        if not part:
            continue
        # CamelCase bol
        camel_parts = _FUNC_NAME_PARTS_RE.findall(part)
        if camel_parts:
            result.extend(p.lower() for p in camel_parts)
        else:
            result.append(part.lower())
    return result


def build_vocab_from_signatures(sigs_dir: Path) -> NgramVocab:
    """sigs/*.json dosyalarindan isim vocabularisi olustur."""
    vocab = NgramVocab()
    name_counter: Counter[str] = Counter()

    sig_files = sorted(sigs_dir.glob("*.json"))
    logger.info("Signature dosyalari taraniyor: %d dosya", len(sig_files))

    for sig_file in sig_files:
        try:
            data = json.loads(sig_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        # Format 1: {"signatures": {"name": {...}, ...}}
        # Format 2: {"signatures": [{"name": "...", ...}, ...]}
        sigs = data.get("signatures", data)

        if isinstance(sigs, dict):
            names = list(sigs.keys())
        elif isinstance(sigs, list):
            names = [s.get("name", "") for s in sigs if isinstance(s, dict)]
        else:
            continue

        for name in names:
            if not name or len(name) < 2:
                continue
            # Fonksiyon ismi direkt
            name_counter[name] += 1
            # Alt parcalar (get, set, buf, ctx, vb.)
            for part in _extract_name_parts(name):
                if len(part) >= 3:  # 2 karakterden kisa parcalari atla
                    name_counter[part] += 1

    # Vocab'a ekle (en az 2 kez gorulenler)
    for name, count in name_counter.most_common():
        if count >= 2:
            vocab.add(name, count)

    logger.info("Vocab olusturuldu: %d isim", len(vocab))
    return vocab


# ---------------------------------------------------------------------------
# Kaynak 2: Decompiled C dosyalarindan n-gram olusturma
# ---------------------------------------------------------------------------

# Bilinen degisken isimleri (ground truth seed'leri)
# Bu isimler signature eslesmesi ile isimlendirilen fonksiyonlardan geliyor
_KNOWN_VAR_PATTERNS = re.compile(
    r"^(?!param_\d|local_[0-9a-f]|iVar\d|uVar\d|lVar\d)[a-zA-Z_]\w{2,}$"
)


def _process_c_file(args: tuple[Path, int]) -> dict[int, dict[bytes, dict[int, int]]]:
    """Tek bir C dosyasini isle (multiprocessing worker).

    Returns:
        {ngram_size: {hash: {vocab_id: count}}} eslesmesi.
    """
    c_file, _worker_id = args
    results: dict[int, dict[bytes, dict[int, int]]] = {
        s: {} for s in NGRAM_SIZES
    }

    try:
        code = c_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return results

    tokens = tokenize_c(code)
    if len(tokens) < 4:
        return results

    norm_tokens = normalize_tokens(tokens)
    marked, var_positions = _mark_variables(norm_tokens)

    if not var_positions:
        return results

    # Ground truth: dosyada zaten anlamli isim verilmis degiskenler var mi?
    # Bunlari kullanarak n-gram DB'yi zenginlestirebiliriz
    # (Simdilik sadece tokenize + hash islemi)

    for size in NGRAM_SIZES:
        if len(marked) < size:
            continue

        half = size
        padded = ["??"] * half + marked + ["??"] * half

        for orig_pos, _var_name in var_positions.items():
            pos = orig_pos + half
            span = padded[pos - half: pos + half + 1]
            key = ngram_hash(span)

            if key not in results[size]:
                results[size][key] = {}
            # Burada vocab_id yerine placeholder kullaniyoruz
            # Gercek DB build'de ground truth label ile eslestirilecek

    return results


def build_ngram_dbs_from_workspace(
    workspace_dirs: list[Path],
    vocab: NgramVocab,
    output_dir: Path,
    max_files: int = 50000,
) -> dict[int, NgramDB]:
    """Decompiled C dosyalarindan n-gram DB'leri olustur."""
    c_files: list[Path] = []
    for ws_dir in workspace_dirs:
        c_files.extend(sorted(ws_dir.rglob("*.c"))[:max_files])

    if not c_files:
        logger.info("Decompiled C dosyasi bulunamadi")
        return {}

    logger.info("Islenecek C dosyasi: %d", len(c_files))

    # Multiprocessing
    nproc = max(1, cpu_count() - 1)
    args = [(f, i % nproc) for i, f in enumerate(c_files)]

    merged: dict[int, dict[bytes, dict[int, int]]] = {s: {} for s in NGRAM_SIZES}

    with Pool(nproc) as pool:
        for result in pool.imap_unordered(_process_c_file, args, chunksize=50):
            for size, entries in result.items():
                for h, vid_counts in entries.items():
                    if h not in merged[size]:
                        merged[size][h] = {}
                    for vid, cnt in vid_counts.items():
                        merged[size][h][vid] = merged[size][h].get(vid, 0) + cnt

    dbs = {}
    for size in NGRAM_SIZES:
        if merged[size]:
            db = NgramDB.build(merged[size], size=size, topk=TOP_K)
            dbs[size] = db
            logger.info("DB size=%d: %d entry", size, len(db))

    return dbs


# ---------------------------------------------------------------------------
# Bootstrap: Signature isimlerinden sentetik n-gram olusturma
# ---------------------------------------------------------------------------


def build_bootstrap_dbs(vocab: NgramVocab, output_dir: Path) -> None:
    """Vocab'taki isimlerden temel n-gram pattern'leri olustur.

    Gercek decompiled verisi olmadan bile, bilinen API fonksiyonlarinin
    tipik kullanim pattern'lerini n-gram DB'ye ekler.

    Ornek pattern'ler:
        strlen(param_1) -> param_1 buyuk olasilikla "str" veya "buffer"
        malloc(param_1) -> param_1 buyuk olasilikla "size"
        free(param_1) -> param_1 buyuk olasilikla "ptr"
    """
    # Tipik API-degisken eslestirmeleri
    _API_VAR_HINTS: dict[str, list[tuple[int, str]]] = {
        # func_name: [(param_idx, likely_var_name), ...]
        "strlen": [(0, "str"), (0, "buffer"), (0, "string")],
        "strcmp": [(0, "str1"), (0, "s1"), (1, "str2"), (1, "s2")],
        "strncmp": [(0, "str1"), (1, "str2"), (2, "length"), (2, "n")],
        "strcpy": [(0, "dest"), (0, "dst"), (1, "src"), (1, "source")],
        "strncpy": [(0, "dest"), (1, "src"), (2, "count"), (2, "n")],
        "strcat": [(0, "dest"), (1, "src")],
        "strstr": [(0, "haystack"), (1, "needle")],
        "strchr": [(0, "str"), (1, "character"), (1, "ch")],
        "memcpy": [(0, "dest"), (0, "dst"), (1, "src"), (2, "size"), (2, "n")],
        "memmove": [(0, "dest"), (1, "src"), (2, "size")],
        "memset": [(0, "ptr"), (0, "dest"), (1, "value"), (2, "size")],
        "memcmp": [(0, "buf1"), (0, "ptr1"), (1, "buf2"), (2, "size")],
        "malloc": [(0, "size")],
        "calloc": [(0, "count"), (0, "nmemb"), (1, "size")],
        "realloc": [(0, "ptr"), (1, "size")],
        "free": [(0, "ptr"), (0, "pointer")],
        "fopen": [(0, "filename"), (0, "path"), (1, "mode")],
        "fclose": [(0, "file"), (0, "fp"), (0, "stream")],
        "fread": [(0, "buffer"), (0, "ptr"), (1, "size"), (2, "count"), (3, "file")],
        "fwrite": [(0, "buffer"), (0, "data"), (1, "size"), (2, "count"), (3, "file")],
        "fprintf": [(0, "file"), (0, "stream"), (1, "format")],
        "printf": [(0, "format")],
        "sprintf": [(0, "buffer"), (0, "str"), (1, "format")],
        "snprintf": [(0, "buffer"), (1, "size"), (2, "format")],
        "open": [(0, "path"), (0, "filename"), (1, "flags"), (2, "mode")],
        "close": [(0, "fd")],
        "read": [(0, "fd"), (1, "buffer"), (1, "buf"), (2, "count"), (2, "size")],
        "write": [(0, "fd"), (1, "buffer"), (1, "data"), (2, "count"), (2, "size")],
        "socket": [(0, "domain"), (1, "type"), (2, "protocol")],
        "connect": [(0, "sockfd"), (0, "fd"), (1, "addr"), (2, "addrlen")],
        "bind": [(0, "sockfd"), (1, "addr"), (2, "addrlen")],
        "listen": [(0, "sockfd"), (1, "backlog")],
        "accept": [(0, "sockfd"), (1, "addr"), (2, "addrlen")],
        "send": [(0, "sockfd"), (1, "buffer"), (1, "data"), (2, "length"), (3, "flags")],
        "recv": [(0, "sockfd"), (1, "buffer"), (2, "length"), (3, "flags")],
        "pthread_create": [(0, "thread"), (1, "attr"), (2, "start_routine"), (3, "arg")],
        "pthread_join": [(0, "thread"), (1, "retval")],
        "pthread_mutex_lock": [(0, "mutex")],
        "pthread_mutex_unlock": [(0, "mutex")],
    }

    entries_by_size: dict[int, dict[bytes, dict[int, int]]] = {
        s: {} for s in NGRAM_SIZES
    }

    for func_name, hints in _API_VAR_HINTS.items():
        for param_idx, var_name in hints:
            vid = vocab.lookup(var_name)
            if vid < 0:
                vid = vocab.add(var_name, 1)

            # Sentetik token dizisi: func_name ( @@var_0@@ , ... )
            # param_idx'e gore pozisyon
            tokens_before = [func_name, "("]
            for i in range(param_idx):
                tokens_before.extend(["@@var_0@@", ","])
            tokens_after = ["@@var_0@@"]
            if param_idx < 3:
                tokens_after.extend([",", "@@var_0@@"])
            tokens_after.append(")")

            context = tokens_before + tokens_after

            # Her DB boyutu icin
            for size in NGRAM_SIZES:
                if len(context) < 3:
                    continue
                # Centered n-gram (basit versiyon)
                half = min(size, len(context) // 2)
                # Degisken pozisyonu: tokens_before'un sonu
                var_pos = len(tokens_before)
                padded = ["??"] * half + context + ["??"] * half
                padded_pos = var_pos + half
                span = padded[padded_pos - half: padded_pos + half + 1]
                if len(span) < 3:
                    continue

                key = ngram_hash(span)
                if key not in entries_by_size[size]:
                    entries_by_size[size][key] = {}
                entries_by_size[size][key][vid] = (
                    entries_by_size[size][key].get(vid, 0) + 10
                )

    # DB'leri olustur ve kaydet
    for size in NGRAM_SIZES:
        if entries_by_size[size]:
            db = NgramDB.build(entries_by_size[size], size=size, topk=TOP_K)
            db_path = output_dir / f"db_{size}.ngdb"
            db.save(db_path)
            logger.info("Bootstrap DB size=%d: %d entry -> %s", size, len(db), db_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Karadul N-gram isim veritabani olusturucu",
    )
    parser.add_argument(
        "--sigs-dir", type=Path, default=_PROJECT_ROOT / "sigs",
        help="Signature JSON dizini (varsayilan: sigs/)",
    )
    parser.add_argument(
        "--workspace", type=Path, nargs="*", default=[],
        help="Decompiled C dosyalari iceren workspace dizin(ler)i",
    )
    parser.add_argument(
        "--output", type=Path, default=_PROJECT_ROOT / "sigs" / "ngram_name_db",
        help="Cikti dizini (varsayilan: sigs/ngram_name_db/)",
    )
    parser.add_argument(
        "--max-files", type=int, default=50000,
        help="Islenecek maksimum C dosyasi sayisi",
    )

    args = parser.parse_args()

    start = time.monotonic()
    output_dir = args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Vocab olustur
    logger.info("=== Adim 1: Vocabulary olusturuluyor ===")
    vocab = build_vocab_from_signatures(args.sigs_dir)

    # 2. Bootstrap DB'ler (API pattern'lerinden)
    logger.info("=== Adim 2: Bootstrap DB olusturuluyor ===")
    build_bootstrap_dbs(vocab, output_dir)

    # 3. Workspace'lerden n-gram DB (opsiyonel)
    if args.workspace:
        logger.info("=== Adim 3: Workspace DB olusturuluyor ===")
        dbs = build_ngram_dbs_from_workspace(
            args.workspace, vocab, output_dir, args.max_files,
        )
        for size, db in dbs.items():
            db_path = output_dir / f"db_{size}.ngdb"
            db.save(db_path)

    # 4. Vocab kaydet
    vocab.save(output_dir / "vocab.txt")
    logger.info("Vocab kaydedildi: %d isim -> %s", len(vocab), output_dir / "vocab.txt")

    elapsed = time.monotonic() - start
    logger.info("Tamamlandi: %.1fs", elapsed)

    # Ozet
    db_files = sorted(output_dir.glob("*.ngdb"))
    total_entries = 0
    for f in db_files:
        db = NgramDB.load(f)
        total_entries += len(db)
        logger.info("  %s: %d entry", f.name, len(db))
    logger.info("Toplam: %d DB, %d entry, vocab=%d", len(db_files), total_entries, len(vocab))


if __name__ == "__main__":
    main()
