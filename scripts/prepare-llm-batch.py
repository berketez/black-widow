#!/usr/bin/env python3
"""Context JSON'dan LLM batch dosyalari hazirla.

Context analyzer'in scope-aware ciktisini okur, dusuk-confidence
degiskenleri filtreler ve batch dosyalari olusturur.

Her batch dosyasi:
- 15 degisken
- Her degisken icin: scope bilgisi, data flow, API kullanimi, mevcut tahmin
- Toplam ~2000 token

Kullanim:
    python scripts/prepare-llm-batch.py <context.json> [--output-dir batches/]
    python scripts/prepare-llm-batch.py workspaces/Claude/*/raw/context_analysis.json

Cikti:
    batches/batch_001.txt
    batches/batch_002.txt
    ...
"""

import argparse
import json
import sys
from pathlib import Path

# Proje root'u
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from karadul.reconstruction.naming.llm_naming import (
    ClaudeLLMNamer,
    NAMING_PROMPT,
    VARIABLE_CONTEXT_TEMPLATE,
)


def main():
    parser = argparse.ArgumentParser(
        description="Context JSON'dan LLM batch dosyalari hazirla"
    )
    parser.add_argument(
        "context_json",
        type=Path,
        help="Context analyzer JSON ciktisi",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("batches"),
        help="Batch dosyalarinin yazilacagi dizin (varsayilan: batches/)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=15,
        help="Batch basina degisken sayisi (varsayilan: 15)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="Bu degerden dusuk confidence'li degiskenler secilir (varsayilan: 0.5)",
    )
    parser.add_argument(
        "--min-references",
        type=int,
        default=2,
        help="Minimum referans sayisi (varsayilan: 2)",
    )
    parser.add_argument(
        "--source-file",
        type=Path,
        default=None,
        help="Orijinal JS kaynak dosyasi (kod snippet'leri icin)",
    )
    args = parser.parse_args()

    # Context JSON oku
    if not args.context_json.exists():
        print(f"HATA: Context JSON bulunamadi: {args.context_json}")
        sys.exit(1)

    print(f"Context JSON okunuyor: {args.context_json}")
    context_data = json.loads(args.context_json.read_text())

    # Kaynak dosyayi oku (varsa)
    source_lines: list[str] = []
    if args.source_file and args.source_file.exists():
        source_lines = args.source_file.read_text(errors="replace").splitlines()
        print(f"Kaynak dosya: {args.source_file} ({len(source_lines)} satir)")

    # Degiskenleri cikar
    from karadul.config import Config
    config = Config()
    namer = ClaudeLLMNamer(
        config,
        min_confidence=args.min_confidence,
        min_references=args.min_references,
        batch_size=args.batch_size,
    )
    candidates = namer._extract_low_confidence_vars(context_data)

    print(f"Toplam degisken: {len(context_data.get('variables', []))}")
    print(f"Dusuk-confidence aday: {len(candidates)}")
    print(f"Filtre: confidence < {args.min_confidence}, references >= {args.min_references}")

    if not candidates:
        print("Hicbir degisken filtreyi gecmedi, batch olusturulmuyor.")
        sys.exit(0)

    # Batch'lere bol
    batches = [
        candidates[i : i + args.batch_size]
        for i in range(0, len(candidates), args.batch_size)
    ]

    print(f"Batch sayisi: {len(batches)} (batch_size={args.batch_size})")

    # Cikti dizini olustur
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Her batch icin prompt dosyasi yaz
    for batch_idx, batch in enumerate(batches):
        prompt = namer._prepare_batch(batch, source_lines)

        batch_file = args.output_dir / f"batch_{batch_idx + 1:03d}.txt"
        batch_file.write_text(prompt, encoding="utf-8")

        # Token tahmini (kaba: 4 char ~= 1 token)
        est_tokens = len(prompt) // 4

        print(
            f"  batch_{batch_idx + 1:03d}.txt: "
            f"{len(batch)} degisken, "
            f"~{est_tokens} token, "
            f"{len(prompt)} char"
        )

    # Ozet JSON
    summary = {
        "context_json": str(args.context_json),
        "source_file": str(args.source_file) if args.source_file else None,
        "total_variables": len(context_data.get("variables", [])),
        "candidates": len(candidates),
        "batches": len(batches),
        "batch_size": args.batch_size,
        "min_confidence": args.min_confidence,
        "min_references": args.min_references,
    }
    summary_path = args.output_dir / "batch_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    print(f"\nOzet: {summary_path}")
    print("Tamamlandi.")


if __name__ == "__main__":
    main()
