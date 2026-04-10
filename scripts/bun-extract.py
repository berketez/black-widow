#!/usr/bin/env python3
"""
bun-extract.py -- Bun Single-File Executable JS Kaynak Kodu Cikarici

Bun 1.x ile derlenmis Mach-O binary'lerden JS kaynak kodunu cikarir.

Bun binary yapisi:
  - Standard Mach-O headers + Bun runtime (C/C++ compiled)
  - __BUN segment, __bun section: Embedded JS bytecode + source
  - Null-separated text segments icinde JS kaynak kodu

Kullanim:
  python3 bun-extract.py <binary> <output-dir>

Cikti:
  output-dir/bundle.js          -- Ana JS bundle (CJS-wrapped esbuild bundle)
  output-dir/bundle_unwrapped.js -- CJS wrapper kaldirilmis hali
  output-dir/helpers/            -- Yardimci JS modulleri (resvg.js vb.)
  output-dir/metadata.json       -- Extraction metadata

Karadul v1.0 -- Bun binary JS extractor
"""

import mmap
import hashlib
import json
import os
import sys
import struct
import subprocess
from datetime import datetime


def find_bun_section(binary_path):
    """Mach-O binary'den __BUN section offset ve size bilgisini al."""
    result = subprocess.run(
        ['otool', '-l', binary_path],
        capture_output=True, text=True
    )

    lines = result.stdout.split('\n')
    in_bun = False
    offset = None
    size = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if 'sectname __bun' in stripped:
            in_bun = True
        if in_bun:
            if stripped.startswith('offset'):
                offset = int(stripped.split()[-1])
            if stripped.startswith('size'):
                size_str = stripped.split()[-1]
                if size_str.startswith('0x'):
                    size = int(size_str, 16)
                else:
                    size = int(size_str)
            if offset is not None and size is not None:
                return offset, size

    return None, None


def find_js_entry(mm, bun_offset, bun_size):
    """BUN section icinde ana JS entry point'ini bul."""
    # Bun CJS wrapper pattern
    cjs_pattern = b'(function(exports, require, module, __filename, __dirname) {'

    entries = []
    pos = bun_offset
    end = bun_offset + bun_size

    while pos < end:
        idx = mm.find(cjs_pattern, pos, end)
        if idx == -1:
            break

        # Bu entry'nin context'ini oku
        ctx_start = max(bun_offset, idx - 100)
        mm.seek(ctx_start)
        context = mm.read(idx - ctx_start).decode('utf-8', errors='replace')

        # Entry'nin adini bul (genelde hemen oncesinde path var)
        name = 'unknown'
        if '/$bunfs/root/' in context:
            parts = context.split('/$bunfs/root/')
            if parts:
                name = parts[-1].split('\x00')[-1].split('\n')[-1].strip()
        elif '@bun-cjs' in context:
            name = 'main_bundle'

        # JS'in sonunu bul (null byte)
        mm.seek(idx)
        js_chunks = []
        total = 0
        while total < 20 * 1024 * 1024:  # Max 20MB
            chunk = mm.read(1024 * 1024)
            if not chunk:
                break
            null_pos = chunk.find(b'\x00')
            if null_pos != -1:
                js_chunks.append(chunk[:null_pos])
                total += null_pos
                break
            js_chunks.append(chunk)
            total += len(chunk)

        js_data = b''.join(js_chunks)
        js_size = len(js_data)

        entries.append({
            'name': name,
            'offset': idx,
            'size': js_size,
            'context': context[-60:].strip(),
        })

        pos = idx + js_size + 1

    return entries


def extract_bundle(mm, offset, size):
    """Binary'den JS bundle'i cikar."""
    mm.seek(offset)
    data = mm.read(size)

    # Trailing non-printable bytes temizle
    text = data.decode('utf-8', errors='replace')
    while text and ord(text[-1]) < 32 and text[-1] not in '\n\r\t':
        text = text[:-1]

    return text


def unwrap_cjs(js_text):
    """CJS wrapper'i kaldir."""
    prefix = "(function(exports, require, module, __filename, __dirname) {"
    if js_text.startswith(prefix):
        js_text = js_text[len(prefix):]

    # Sonundaki CJS kapanisini kaldir
    stripped = js_text.rstrip()
    if stripped.endswith(';})'):
        stripped = stripped[:-2]
    elif stripped.endswith('})'):
        stripped = stripped[:-2]

    return stripped


def main():
    if len(sys.argv) < 3:
        print(f"Kullanim: {sys.argv[0]} <binary> <output-dir>")
        print(f"Ornek:    {sys.argv[0]} /opt/homebrew/Caskroom/claude-code/2.1.81/claude ./extracted")
        sys.exit(1)

    binary_path = os.path.abspath(sys.argv[1])
    output_dir = os.path.abspath(sys.argv[2])
    helpers_dir = os.path.join(output_dir, 'helpers')

    if not os.path.exists(binary_path):
        print(f"Hata: Binary bulunamadi: {binary_path}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(helpers_dir, exist_ok=True)

    binary_size = os.path.getsize(binary_path)
    print(f"Binary: {binary_path}")
    print(f"Size: {binary_size} bytes ({binary_size/1024/1024:.1f} MB)")

    # __BUN section bul
    bun_offset, bun_size = find_bun_section(binary_path)
    if bun_offset is None:
        print("Hata: __BUN section bulunamadi. Bu bir Bun binary degil mi?")
        sys.exit(1)

    print(f"__BUN section: offset={bun_offset} (0x{bun_offset:X}), size={bun_size} ({bun_size/1024/1024:.1f} MB)")

    with open(binary_path, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        # JS entry'lerini bul
        print("\nJS entry'leri araniyor...")
        entries = find_js_entry(mm, bun_offset, bun_size)
        print(f"Bulunan entry sayisi: {len(entries)}")

        if not entries:
            print("Hata: JS entry bulunamadi!")
            mm.close()
            sys.exit(1)

        # En buyuk entry ana bundle
        main_entry = max(entries, key=lambda e: e['size'])
        print(f"\nAna bundle: offset={main_entry['offset']}, size={main_entry['size']} ({main_entry['size']/1024/1024:.2f} MB)")

        # Ana bundle'i cikar
        js_text = extract_bundle(mm, main_entry['offset'], main_entry['size'])
        sha256 = hashlib.sha256(js_text.encode('utf-8')).hexdigest()

        # Kaydet - orijinal (CJS wrapped)
        bundle_path = os.path.join(output_dir, 'bundle.js')
        with open(bundle_path, 'w', encoding='utf-8') as out:
            out.write(js_text)
        print(f"  bundle.js: {len(js_text)} chars, SHA256: {sha256[:16]}...")

        # CJS unwrapped
        unwrapped = unwrap_cjs(js_text)
        unwrapped_path = os.path.join(output_dir, 'bundle_unwrapped.js')
        with open(unwrapped_path, 'w', encoding='utf-8') as out:
            out.write(unwrapped)
        print(f"  bundle_unwrapped.js: {len(unwrapped)} chars")

        # Helper modulleri cikar
        helpers_extracted = []
        for entry in entries:
            if entry['size'] < main_entry['size'] and entry['size'] > 10:
                name = entry['name'] if entry['name'] != 'unknown' else f"module_{entry['offset']}.js"
                if not name.endswith('.js'):
                    name += '.js'

                helper_text = extract_bundle(mm, entry['offset'], entry['size'])
                helper_path = os.path.join(helpers_dir, os.path.basename(name))
                with open(helper_path, 'w', encoding='utf-8') as out:
                    out.write(helper_text)

                helpers_extracted.append({
                    'name': name,
                    'file': os.path.basename(name),
                    'offset': entry['offset'],
                    'size': entry['size'],
                })
                print(f"  helpers/{os.path.basename(name)}: {entry['size']} bytes")

        # Paren/brace balance hesapla
        open_p = js_text.count('(') - js_text.count(')')
        open_b = js_text.count('{') - js_text.count('}')

        # Metadata
        metadata = {
            'source_binary': binary_path,
            'binary_size': binary_size,
            'binary_type': 'Mach-O 64-bit executable arm64 (Bun single-file executable)',
            'extraction_date': datetime.now().isoformat(),
            'extraction_tool': 'Karadul bun-extract v1.0',
            'bun_section': {
                'segment': '__BUN',
                'section': '__bun',
                'offset': bun_offset,
                'offset_hex': f'0x{bun_offset:X}',
                'size': bun_size,
                'size_mb': round(bun_size / 1024 / 1024, 2)
            },
            'main_bundle': {
                'file': 'bundle.js',
                'unwrapped_file': 'bundle_unwrapped.js',
                'binary_offset': main_entry['offset'],
                'size_bytes': main_entry['size'],
                'size_mb': round(main_entry['size'] / 1024 / 1024, 2),
                'sha256': sha256,
                'format': 'esbuild CJS bundle, Bun CJS-wrapped',
                'lines': js_text.count('\n') + 1,
                'unmatched_parens': open_p,
                'unmatched_braces': open_b,
                'bytecode_note': 'Some function bodies compiled to Bun bytecode - source is partially incomplete'
            },
            'helper_modules': helpers_extracted,
            'total_entries_found': len(entries)
        }

        meta_path = os.path.join(output_dir, 'metadata.json')
        with open(meta_path, 'w', encoding='utf-8') as out:
            json.dump(metadata, out, indent=2)

        print(f"\nMetadata: {meta_path}")
        print(f"\nOzet:")
        print(f"  Ana bundle: {main_entry['size']/1024/1024:.2f} MB, {js_text.count(chr(10))+1} satir")
        print(f"  Helper modulleri: {len(helpers_extracted)}")
        print(f"  Bracket dengesizligi: ({open_p}) parantez, {{{open_b}}} brace (bytecode-compiled fonksiyonlar)")

        mm.close()

    print("\nTamamlandi.")


if __name__ == '__main__':
    main()
