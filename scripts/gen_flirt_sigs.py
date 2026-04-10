#!/usr/bin/env python3
"""GitHub FLIRT/Signature DB'lerinden fonksiyon ismi cikarma.

Kaynaklar:
  1. Maktm/FLIRTDB  - .pat (text) formatinda IDA FLIRT pattern'leri
  2. push0ebp/sig-database - .sig (binary) formatinda IDA FLIRT imzalari

Parse stratejisi:
  .pat: Satirlardaki :XXXX ve ^XXXX token'larindan sonra gelen isimler
  .sig: `strings` komutuyla cikan valid C/C++ identifier'lar

Cikti: sigs/flirt_github.json
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

FLIRTDB_DIR = "/tmp/FLIRTDB"
SIGDB_DIR = "/tmp/sig-database"
OUTPUT_PATH = "/Users/apple/Desktop/black-widow/sigs/flirt_github.json"

# Mevcut DB - dedup icin
EXISTING_DB_PATH = "/Users/apple/Desktop/black-widow/sigs/combined_1M.json"

MIN_NAME_LEN = 3
MAX_NAME_LEN = 500

# Valid C identifier veya MSVC mangled (? ile baslayan)
# C++ mangled: _Z... veya ??... veya ?name@...
VALID_NAME_RE = re.compile(
    r'^[_a-zA-Z?@][_a-zA-Z0-9@$?]*$'
)

# Garbage pattern'ler - bunlari atla
GARBAGE_PATTERNS = [
    re.compile(r'^@'),                        # @ ile baslayan (binary artifact)
    re.compile(r'^[0-9a-fA-F]+$'),          # sadece hex
    re.compile(r'^[0-9]+$'),                  # sadece sayi
    re.compile(r'^_{3,}'),                    # ___ ile baslayan
    re.compile(r'^\.L'),                      # .L (GCC local label)
    re.compile(r'^ltmp'),                     # ltmp (local temp)
    re.compile(r'^L_'),                       # L_ (local label)
    re.compile(r'^l_'),                       # l_ (local label)
    re.compile(r'^\$'),                       # $ ile baslayan (assembler label)
    re.compile(r'^GCC_except'),               # GCC exception table
    re.compile(r'^_OBJC_'),                   # Objective-C metadata
    re.compile(r'^__GLOBAL_'),                # Global init
    re.compile(r'^radr://'),                  # radar URL
    re.compile(r'^IDASGN'),                   # IDA signature header
    re.compile(r'^Unnamed'),                  # Unnamed sample
    re.compile(r'^\.\w+$'),                   # .text, .data etc
    re.compile(r'^_+$'),                      # sadece underscore
]


def is_valid_name(name: str) -> bool:
    """Fonksiyon isminin gecerli olup olmadigini kontrol et."""
    if not name:
        return False
    if len(name) < MIN_NAME_LEN or len(name) > MAX_NAME_LEN:
        return False

    # @ iceren MSVC mangled isimleri kabul et
    # ? ile baslayan MSVC demangled isimleri kabul et
    # Normal C identifier'lari kabul et
    if not VALID_NAME_RE.match(name):
        return False

    for pattern in GARBAGE_PATTERNS:
        if pattern.search(name):
            return False

    # MSVC mangled isim kurallari:
    # ?func@namespace@@... formati en az bir @ icermeli
    # ?$ ile baslayan template instantiation'lar: ?$basic_string@... seklinde uzun olmali
    # Kisa ?XX, ?$XX token'lari binary garbage'dir
    if name.startswith('?'):
        # Gecerli MSVC mangled: en az 8 char ve @ icermeli
        # veya ?? ile baslayan (operator overload, RTTI)
        if '@' not in name:
            # @ olmayan ?xxx -> min 8 char olmali (orn: ?handler)
            if len(name) < 8:
                return False
        else:
            # @ iceren MSVC mangled: en az 10 char olmali
            # ?1@, ?@2, ??j@ gibi kisa token'lar garbage
            if len(name) < 10:
                return False
            if name.startswith('?$'):
                # ?$template@... -> en az 12 char olmali
                if len(name) < 12:
                    return False

    return True


def strip_leading_underscores(name: str) -> str:
    """Platform prefix underscore'larini kaldir (_func -> func, __func -> _func).

    Ama dikkat: __ ile baslayan C++ mangled isimler korunmali.
    Sadece tek _ prefix'i kaldirilir, isim zaten valid ise.
    """
    # _Z ile baslayan = C++ mangled, dokunma
    if name.startswith('_Z') or name.startswith('__Z'):
        return name
    # ? ile baslayan = MSVC mangled, dokunma
    if name.startswith('?'):
        return name
    # Tek _ prefix'i kaldir (platform convention)
    if name.startswith('_') and not name.startswith('__'):
        stripped = name[1:]
        if stripped and stripped[0].isalpha():
            return stripped
    return name


# ---------------------------------------------------------------------------
# Library ismi cikarma
# ---------------------------------------------------------------------------

def _clean_lib_name(raw: str) -> str:
    """Ham dosya/dizin isminden temiz library ismi cikar.

    Ornekler:
        libboost_filesystem-vc140-mt-x32-1_70 -> boost_filesystem
        openssl-1.1.1a-x64 -> openssl
        vc12msvcrt -> msvcrt
        libc6 -> libc
        libssl_1.1.0h-4ubuntu1_amd64 -> libssl
        libstdc++-8_8.3.0-29ubuntu1_amd64 -> libstdcpp
    """
    name = raw.lower().strip()

    # lib prefix'i kaldir (ama libc, libm gibi kisa olanlar haric)
    if name.startswith("lib") and len(name) > 5:
        name = name[3:]

    # + karakterlerini pp yap (libstdc++ -> stdcpp)
    name = name.replace('+', 'p')

    # Versiyon, platform ve build suffix'lerini temizle
    # -vc140-mt-x32-1_70, -1.1.1a-x64, _1.0.2d, _8.3.0-29ubuntu1_amd64 vs.
    name = re.sub(r'-vc\d+.*$', '', name)          # -vc140-mt-... kaldir
    name = re.sub(r'-\d+[\.\d]*[a-z]*.*$', '', name)  # -1.1.1a-x64 kaldir
    name = re.sub(r'_\d+[\.\d].*$', '', name)      # _1.0.2d, _8.3.0-... kaldir
    name = re.sub(r'[-_](x86|x64|x32|arm|amd64|i386|armhf)$', '', name)

    # vc12msvcrt -> msvcrt
    name = re.sub(r'^vc\d+', '', name)

    # Son temizlik
    name = name.strip('_-')
    return name if name else "unknown"


# Bilinen sig-database dizin isimleri -> lib ismi mapping'i
_SIGDB_DIR_TO_LIB = {
    'openssl': 'openssl',
    'libstdc++': 'libstdcpp',
    'libsodium': 'libsodium',
}


def extract_lib_from_path(filepath: str) -> tuple[str, str]:
    """Dosya yolundan library ismi ve category cikar.

    Returns:
        (lib_name, category)

    FLIRTDB yapisi:   /tmp/FLIRTDB/<library>/<platform>/file.pat
    sig-database:     /tmp/sig-database/<platform>/<lib_or_compiler>/[version]/file.sig
    """

    # FLIRTDB: Ust dizin = library ismi (openssl, boost, intel, lua, etc.)
    if FLIRTDB_DIR in filepath:
        rel = os.path.relpath(filepath, FLIRTDB_DIR)
        rel_parts = rel.split(os.sep)
        if len(rel_parts) >= 2:
            top_dir = rel_parts[0]  # openssl, boost, intel, etc.
            lib_name = top_dir
            category = f"flirt_{top_dir}"
        else:
            lib_name = _clean_lib_name(Path(filepath).stem)
            category = "flirt_db"
        return lib_name, category

    # sig-database: platform/lib_or_compiler/[version/]file.sig
    if SIGDB_DIR in filepath:
        rel = os.path.relpath(filepath, SIGDB_DIR)
        rel_parts = rel.split(os.sep)

        if len(rel_parts) >= 2:
            platform = rel_parts[0]        # windows, ubuntu
            subdir = rel_parts[1]          # VC12, OpenSSL, libstdc++, etc.

            # VC12 gibi compiler version dizinleri
            vc_match = re.match(r'^VC(\d+)$', subdir, re.IGNORECASE)
            if vc_match:
                # Dosya adindan lib ismi cikar: vc12msvcrt -> msvcrt
                lib_name = _clean_lib_name(Path(filepath).stem)
                category = f"flirt_vc{vc_match.group(1)}"
            elif subdir.lower().rstrip('+') in ('openssl',):
                lib_name = "openssl"
                category = "flirt_openssl"
            elif subdir in _SIGDB_DIR_TO_LIB:
                lib_name = _SIGDB_DIR_TO_LIB[subdir]
                category = f"flirt_{lib_name}"
            else:
                # ubuntu altindaki diger dizinler (libc6, libsodium, etc.)
                lib_name = _clean_lib_name(subdir)
                category = f"flirt_{platform}"

            return lib_name, category

    # Fallback
    lib_name = _clean_lib_name(Path(filepath).stem)
    return lib_name, "flirt_db"


# ---------------------------------------------------------------------------
# .pat dosya parse
# ---------------------------------------------------------------------------

# .pat satir formati:
# HEX_BYTES SIZE CRC LEN :OFFSET FUNCNAME ^OFFSET REFNAME ...
# :XXXX sonrasi = ana fonksiyon adi
# ^XXXX sonrasi = referans edilen fonksiyon adi
# @ suffix = "local" (collision marker), atlamayalim

PAT_NAME_RE = re.compile(
    r'[:^][0-9a-fA-F]{4}@?\s+([^\s:^]+)'
)


def parse_pat_file(filepath: str) -> dict[str, tuple[str, str]]:
    """Bir .pat dosyasini parse et, fonksiyon isimleri cikar.

    Returns:
        {name: (lib, category)} dict
    """
    names: dict[str, tuple[str, str]] = {}
    lib_name, category = extract_lib_from_path(filepath)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line == '---':
                    continue

                # :XXXX ve ^XXXX token'larini bul
                for match in PAT_NAME_RE.finditer(line):
                    name = match.group(1)
                    # @ suffix'i kaldir (collision marker)
                    # Bazen isimde @ vardir (MSVC)
                    if is_valid_name(name):
                        clean = strip_leading_underscores(name)
                        if is_valid_name(clean):
                            names[clean] = (lib_name, category)
                        # Orijinal ismi de ekle (leading _ ile)
                        if name != clean:
                            names[name] = (lib_name, category)

    except (OSError, IOError) as e:
        print(f"  HATA: {filepath}: {e}", file=sys.stderr)

    return names


def parse_all_pat_files(base_dir: str) -> dict[str, tuple[str, str]]:
    """Tum .pat dosyalarini parse et."""
    all_names: dict[str, tuple[str, str]] = {}
    pat_files = list(Path(base_dir).rglob("*.pat"))
    print(f"  {len(pat_files)} .pat dosyasi bulundu")

    for i, pf in enumerate(pat_files):
        filepath = str(pf)
        names = parse_pat_file(filepath)
        all_names.update(names)

        if (i + 1) % 50 == 0 or i == len(pat_files) - 1:
            print(f"  [{i+1}/{len(pat_files)}] {len(all_names)} isim toplandi")

    return all_names


# ---------------------------------------------------------------------------
# .sig dosya parse (binary, strings ile)
# ---------------------------------------------------------------------------

# strings ciktisinda valid C/C++ identifier'lari yakala
SIG_NAME_RE = re.compile(r'^([_a-zA-Z?@][_a-zA-Z0-9@$?]*)$')


def parse_sig_file(filepath: str) -> dict[str, tuple[str, str]]:
    """Bir .sig dosyasindan strings ile fonksiyon isimleri cikar.

    Returns:
        {name: (lib, category)} dict
    """
    names: dict[str, tuple[str, str]] = {}
    lib_name, category = extract_lib_from_path(filepath)

    try:
        result = subprocess.run(
            ['strings', '-n', '3', filepath],
            capture_output=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  HATA: strings calistirilamadi: {filepath}: {e}", file=sys.stderr)
        return names

    # Binary cikti UTF-8 olmayan baytlar icerebilir
    stdout_text = result.stdout.decode('utf-8', errors='replace')

    for line in stdout_text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Bazen bir satirda birden fazla isim olabilir (null-separated)
        # strings zaten ayiriyor ama bazen birlesik de olabiliyor
        # Her satiri tek isim olarak dene
        if is_valid_name(line):
            clean = strip_leading_underscores(line)
            if is_valid_name(clean):
                names[clean] = (lib_name, category)
            if line != clean:
                names[line] = (lib_name, category)

    return names


def parse_all_sig_files(base_dir: str) -> dict[str, tuple[str, str]]:
    """Tum .sig dosyalarini parse et."""
    all_names: dict[str, tuple[str, str]] = {}
    sig_files = list(Path(base_dir).rglob("*.sig"))
    print(f"  {len(sig_files)} .sig dosyasi bulundu")

    for i, sf in enumerate(sig_files):
        filepath = str(sf)
        names = parse_sig_file(filepath)
        all_names.update(names)

        if (i + 1) % 200 == 0 or i == len(sig_files) - 1:
            print(f"  [{i+1}/{len(sig_files)}] {len(all_names)} isim toplandi")

    return all_names


# ---------------------------------------------------------------------------
# Mevcut DB'den isimleri yukle (dedup icin)
# ---------------------------------------------------------------------------

def load_existing_names(db_path: str) -> set[str]:
    """Mevcut signature DB'den tum isimleri yukle."""
    names: set[str] = set()

    if not os.path.exists(db_path):
        return names

    print(f"  Mevcut DB yukleniyor: {db_path}")
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  UYARI: DB okunamadi: {e}", file=sys.stderr)
        return names

    sigs = data.get('signatures', [])

    if isinstance(sigs, list):
        for entry in sigs:
            if isinstance(entry, dict) and 'name' in entry:
                names.add(entry['name'])
                # Leading underscore'suz versiyonu da ekle
                clean = strip_leading_underscores(entry['name'])
                names.add(clean)
    elif isinstance(sigs, dict):
        names.update(sigs.keys())
        for k in list(sigs.keys()):
            names.add(strip_leading_underscores(k))

    print(f"  Mevcut DB: {len(names)} unique isim")
    return names


def load_all_existing_names() -> set[str]:
    """sigs/ dizinindeki tum JSON DB'lerden isimleri topla."""
    sigs_dir = Path("/Users/apple/Desktop/black-widow/sigs")
    all_names: set[str] = set()

    json_files = list(sigs_dir.glob("*.json"))
    print(f"\n=== Mevcut DB'ler (dedup icin) ===")
    print(f"  {len(json_files)} JSON dosyasi bulundu")

    for jf in json_files:
        if jf.name == "flirt_github.json":
            continue  # Kendi ciktimizi atla
        try:
            with open(jf, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        sigs = data.get('signatures', [])
        before = len(all_names)

        if isinstance(sigs, list):
            for entry in sigs:
                if isinstance(entry, dict) and 'name' in entry:
                    n = entry['name']
                    all_names.add(n)
                    all_names.add(strip_leading_underscores(n))
        elif isinstance(sigs, dict):
            for k in sigs.keys():
                all_names.add(k)
                all_names.add(strip_leading_underscores(k))

        added = len(all_names) - before
        if added > 0:
            print(f"  {jf.name}: +{added} isim")

    print(f"  TOPLAM mevcut: {len(all_names)} unique isim")
    return all_names


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    start_time = time.time()

    print("=" * 60)
    print("GitHub FLIRT/Signature DB'lerinden Fonksiyon Ismi Cikarma")
    print("=" * 60)

    # 1. Mevcut DB'leri yukle (dedup icin)
    existing_names = load_all_existing_names()

    all_names: dict[str, tuple[str, str]] = {}

    # 2. FLIRTDB .pat dosyalari
    if os.path.isdir(FLIRTDB_DIR):
        print(f"\n=== Maktm/FLIRTDB (.pat) ===")
        pat_names = parse_all_pat_files(FLIRTDB_DIR)
        print(f"  .pat toplam: {len(pat_names)} unique isim")
        all_names.update(pat_names)
    else:
        print(f"\nUYARI: {FLIRTDB_DIR} bulunamadi, atlaniyor")

    # 3. sig-database .sig dosyalari
    if os.path.isdir(SIGDB_DIR):
        print(f"\n=== push0ebp/sig-database (.sig) ===")
        sig_names = parse_all_sig_files(SIGDB_DIR)
        print(f"  .sig toplam: {len(sig_names)} unique isim")
        all_names.update(sig_names)
    else:
        print(f"\nUYARI: {SIGDB_DIR} bulunamadi, atlaniyor")

    print(f"\n=== Birlestirme ===")
    print(f"  Toplam (ham): {len(all_names)} unique isim")

    # 4. Dedup: mevcut DB'de zaten olan isimleri cikar
    new_names: dict[str, tuple[str, str]] = {}
    dup_count = 0
    for name, (lib, cat) in all_names.items():
        if name in existing_names:
            dup_count += 1
        else:
            new_names[name] = (lib, cat)

    print(f"  Mevcut DB'de var (atildi): {dup_count}")
    print(f"  Net new: {len(new_names)}")

    # 5. JSON olustur
    signatures: dict[str, dict] = {}
    for name, (lib, cat) in sorted(new_names.items()):
        signatures[name] = {
            "lib": lib,
            "purpose": "",
            "category": cat,
        }

    output_data = {
        "meta": {
            "generator": "karadul-sig-gen-flirt",
            "date": time.strftime("%Y-%m-%d"),
            "source": "GitHub FLIRT databases",
            "sources": [
                {"name": "Maktm/FLIRTDB", "url": "https://github.com/Maktm/FLIRTDB", "format": ".pat"},
                {"name": "push0ebp/sig-database", "url": "https://github.com/push0ebp/sig-database", "format": ".sig"},
            ],
            "total": len(signatures),
            "dedup_removed": dup_count,
        },
        "signatures": signatures,
    }

    # 6. Kaydet
    output_path = Path(OUTPUT_PATH)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    elapsed = time.time() - start_time
    file_size = output_path.stat().st_size

    print(f"\n{'=' * 60}")
    print(f"SONUC")
    print(f"{'=' * 60}")
    print(f"  Net new signatures: {len(signatures):,}")
    print(f"  Dedup removed:      {dup_count:,}")
    print(f"  Output:             {output_path}")
    print(f"  File size:          {file_size / 1024 / 1024:.1f} MB")
    print(f"  Elapsed:            {elapsed:.1f}s")

    # 7. Ornek isimler
    print(f"\n  Ornek isimler (ilk 20):")
    for name in list(signatures.keys())[:20]:
        info = signatures[name]
        print(f"    {name}  [{info['lib']}]  ({info['category']})")


if __name__ == "__main__":
    main()
