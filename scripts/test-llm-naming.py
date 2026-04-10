#!/usr/bin/env python3
"""Claude CLI ile LLM variable naming testi.

5 degisken secer, Claude CLI ile isimlendirir, sonucu gosterir.
Electron window state manager ornegi -- gercek deobfuscation senaryosu.

Kullanim:
    python scripts/test-llm-naming.py
    python scripts/test-llm-naming.py --model claude-opus-4-20250514
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

# Proje root'u
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from karadul.config import Config
from karadul.reconstruction.naming.llm_naming import ClaudeLLMNamer, CLAUDE_CLI_PATH


def main():
    parser = argparse.ArgumentParser(description="Claude CLI LLM naming testi")
    parser.add_argument(
        "--model",
        default="sonnet",
        help="Claude model alias (varsayilan: sonnet, alternatif: opus)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout (saniye)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  Black Widow v1.0 -- LLM Variable Naming Test")
    print("=" * 60)
    print()

    # Claude CLI kontrolu
    if not CLAUDE_CLI_PATH.exists():
        print(f"HATA: Claude CLI bulunamadi: {CLAUDE_CLI_PATH}")
        sys.exit(1)
    print(f"Claude CLI: {CLAUDE_CLI_PATH}")
    print(f"Model: {args.model}")
    print()

    # Test degiskenleri -- Electron window state manager modulu
    # Bu degiskenler gercek bir deobfuscated Electron uygulamasindan
    test_variables = [
        {
            "old": "e",
            "scope": "func:u9e:930",
            "apis": ["app", "screen", "BrowserWindow"],
            "props": ["getPath", "on", "ready"],
            "data_flow": "e = require('electron')",
            "code_snippet": (
                "var e = require('electron');\n"
                "var t = e.app;\n"
                "var n = e.screen;\n"
                "e.BrowserWindow;"
            ),
            "confidence": 0.3,
            "reference_count": 47,
            "declaration_type": "var",
        },
        {
            "old": "t",
            "scope": "func:u9e:930",
            "apis": ["join", "dirname", "resolve"],
            "props": ["join", "dirname", "basename"],
            "data_flow": "t = require('path')",
            "code_snippet": (
                "var t = require('path');\n"
                "var s = t.join(e.getPath('userData'), 'state.json');\n"
                "t.dirname(s);"
            ),
            "confidence": 0.25,
            "reference_count": 23,
            "declaration_type": "var",
        },
        {
            "old": "s",
            "scope": "func:u9e:930",
            "apis": ["app", "remote.app"],
            "props": ["getPath"],
            "data_flow": "s = path.join(app.getPath('userData'), 'window-state.json')",
            "code_snippet": (
                "var s = t.join(r.getPath('userData'), 'window-state.json');\n"
                "function a() {\n"
                "  try { return JSON.parse(require('fs').readFileSync(s, 'utf-8')); }\n"
                "  catch(e) { return {}; }\n"
                "}"
            ),
            "confidence": 0.15,
            "reference_count": 12,
            "declaration_type": "var",
        },
        {
            "old": "c",
            "scope": "func:u9e:930",
            "apis": [],
            "props": ["on", "removeListener", "x", "y", "width", "height"],
            "data_flow": "c = BrowserWindow instance, event target",
            "code_snippet": (
                "function l(c) {\n"
                "  c.on('resize', u);\n"
                "  c.on('move', u);\n"
                "  c.on('close', function() {\n"
                "    d = c.getBounds();\n"
                "    c.removeListener('resize', u);\n"
                "  });\n"
                "}"
            ),
            "confidence": 0.1,
            "reference_count": 31,
            "declaration_type": "parameter",
        },
        {
            "old": "d",
            "scope": "func:u9e:930",
            "apis": [],
            "props": ["x", "y", "width", "height", "isMaximized"],
            "data_flow": "d = {x, y, width, height}, written to state file",
            "code_snippet": (
                "var d = a();\n"
                "d = c.getBounds();\n"
                "d.isMaximized = c.isMaximized();\n"
                "require('fs').writeFileSync(s, JSON.stringify(d));"
            ),
            "confidence": 0.1,
            "reference_count": 18,
            "declaration_type": "var",
        },
    ]

    print(f"Test degiskenleri: {len(test_variables)} adet")
    print("-" * 60)
    for v in test_variables:
        print(f"  {v['old']:3s}  scope={v['scope']:<20s}  refs={v['reference_count']:3d}  conf={v['confidence']:.2f}")
    print()

    # ClaudeLLMNamer ile isimlendir
    config = Config()
    namer = ClaudeLLMNamer(
        config,
        model=args.model,
        timeout=args.timeout,
    )

    if not namer.is_available:
        print("HATA: Claude CLI kulanilamiyor")
        sys.exit(1)

    print("Claude CLI cagriliyor...")
    t0 = time.monotonic()

    result = namer.name_variables_from_list(test_variables)

    elapsed = time.monotonic() - t0

    print(f"Tamamlandi: {elapsed:.1f}s")
    print()

    # Sonuclari goster
    print("=" * 60)
    print("  SONUCLAR")
    print("=" * 60)
    print()
    print(f"Basari:     {result.success}")
    print(f"Toplam:     {result.total_named} degisken isimlendirildi")
    print(f"Batch:      {result.total_batches} batch, {result.failed_batches} hata")
    print(f"Model:      {result.model_used}")
    print(f"Sure:       {result.duration_seconds:.1f}s")
    print()

    if result.errors:
        print("HATALAR:")
        for err in result.errors:
            print(f"  - {err}")
        print()

    if result.mappings:
        print("ONCE -> SONRA:")
        print("-" * 60)
        for scope_id, scope_mappings in result.mappings.items():
            for old_name, new_name in scope_mappings.items():
                reason = result.reasons.get(f"{scope_id}::{old_name}", "")
                print(f"  {old_name:10s} -> {new_name:25s}  ({reason})")
        print()

        # ONCE/SONRA karsilastirma
        print("KARSILASTIRMA:")
        print("-" * 60)
        for v in test_variables:
            old = v["old"]
            scope = v.get("scope", "global")
            scope_mappings = result.mappings.get(scope, {})
            new_name = scope_mappings.get(old, "[isimlendirilmedi]")
            print(f"  {old:3s} -> {new_name:25s}  (apis: {', '.join(v.get('apis', [])[:3])})")
    else:
        print("Hicbir degisken isimlendirilemedi.")

    print()
    print("=" * 60)

    # JSON olarak da kaydet
    output_path = PROJECT_ROOT / "workspaces" / "llm-naming-test.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_data = {
        "success": result.success,
        "total_named": result.total_named,
        "model": result.model_used,
        "duration_seconds": result.duration_seconds,
        "mappings": result.mappings,
        "reasons": result.reasons,
        "errors": result.errors,
        "test_variables": test_variables,
    }
    output_path.write_text(json.dumps(output_data, indent=2, ensure_ascii=False))
    print(f"Sonuc kaydedildi: {output_path}")


if __name__ == "__main__":
    main()
