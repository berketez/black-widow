#!/usr/bin/env python3
"""
gen_mingw_headers_sigs.py - mingw-w64 header'larından Windows API sembollerini çıkar.

mingw-w64 header'ları gerçek Windows API deklarasyonlarını içerir.
Template-based generation yerine gerçek kaynak veri — daha yüksek güvenilirlik.

Çıktı: sigs/mingw_headers.json
"""

import json
import os
import re
import subprocess
import sys
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ==========================================================================
# Konfigürasyon
# ==========================================================================
REPO_URL = "https://github.com/mingw-w64/mingw-w64.git"
CLONE_DIR = Path("/tmp/mingw-w64-headers")
HEADERS_DIR = CLONE_DIR / "mingw-w64-headers" / "include"
# Bazı deklarasyonlar crt/ altında da olabiliyor
CRT_DIR = CLONE_DIR / "mingw-w64-headers" / "crt"

PROJECT_ROOT = Path("/Users/apple/Desktop/black-widow")
OUTPUT_FILE = PROJECT_ROOT / "sigs" / "mingw_headers.json"

# Mevcut DB dosyaları — dedup için
EXISTING_DBS = [
    PROJECT_ROOT / "sigs" / "windows_api_signatures.json",
    PROJECT_ROOT / "sigs" / "windows_expanded.json",
]

# Header dosyasından DLL mapping
# mingw-w64'ün .def dosyaları en güvenilir kaynak
HEADER_TO_LIB = {
    # kernel32
    "winbase.h": "kernel32",
    "wincon.h": "kernel32",
    "winnls.h": "kernel32",
    "fileapi.h": "kernel32",
    "processthreadsapi.h": "kernel32",
    "synchapi.h": "kernel32",
    "memoryapi.h": "kernel32",
    "heapapi.h": "kernel32",
    "libloaderapi.h": "kernel32",
    "debugapi.h": "kernel32",
    "errhandlingapi.h": "kernel32",
    "fibersapi.h": "kernel32",
    "handleapi.h": "kernel32",
    "ioapiset.h": "kernel32",
    "jobapi.h": "kernel32",
    "namedpipeapi.h": "kernel32",
    "namespaceapi.h": "kernel32",
    "profileapi.h": "kernel32",
    "realtimeapiset.h": "kernel32",
    "securitybaseapi.h": "kernel32",
    "sysinfoapi.h": "kernel32",
    "threadpoolapiset.h": "kernel32",
    "threadpoollegacyapiset.h": "kernel32",
    "utilapiset.h": "kernel32",
    "wow64apiset.h": "kernel32",
    "processenv.h": "kernel32",
    "timezoneapi.h": "kernel32",

    # user32
    "winuser.h": "user32",

    # gdi32
    "wingdi.h": "gdi32",

    # advapi32
    "winreg.h": "advapi32",
    "winsvc.h": "advapi32",
    "wincrypt.h": "advapi32",
    "lmaccess.h": "advapi32",
    "sddl.h": "advapi32",
    "securitybaseapi.h": "advapi32",
    "aclapi.h": "advapi32",

    # ntdll
    "winternl.h": "ntdll",

    # ws2_32
    "winsock2.h": "ws2_32",
    "ws2tcpip.h": "ws2_32",
    "mswsock.h": "mswsock",

    # shell32
    "shellapi.h": "shell32",
    "shlobj.h": "shell32",

    # ole32
    "objbase.h": "ole32",
    "combaseapi.h": "ole32",

    # oleaut32
    "oleauto.h": "oleaut32",

    # shlwapi
    "shlwapi.h": "shlwapi",

    # iphlpapi
    "iphlpapi.h": "iphlpapi",
    "iptypes.h": "iphlpapi",

    # psapi
    "psapi.h": "psapi",

    # dbghelp
    "dbghelp.h": "dbghelp",

    # version
    "winver.h": "version",

    # crypt32
    "wincrypt.h": "crypt32",

    # setupapi
    "setupapi.h": "setupapi",

    # wintrust
    "wintrust.h": "wintrust",

    # userenv
    "userenv.h": "userenv",

    # pdh
    "pdh.h": "pdh",

    # netapi32
    "lm.h": "netapi32",
    "lmaccess.h": "netapi32",
    "lmshare.h": "netapi32",
    "lmserver.h": "netapi32",
    "lmjoin.h": "netapi32",
    "lmwksta.h": "netapi32",

    # winmm
    "mmsystem.h": "winmm",

    # winhttp
    "winhttp.h": "winhttp",

    # wininet
    "wininet.h": "wininet",

    # d3d / directx
    "d3d9.h": "d3d9",
    "d3d11.h": "d3d11",
    "d3d12.h": "d3d12",
    "dxgi.h": "dxgi",
    "ddraw.h": "ddraw",
    "dinput.h": "dinput8",

    # opengl
    "gl/gl.h": "opengl32",

    # comctl32
    "commctrl.h": "comctl32",

    # comdlg32
    "commdlg.h": "comdlg32",

    # wtsapi32
    "wtsapi32.h": "wtsapi32",

    # secur32
    "sspi.h": "secur32",
    "security.h": "secur32",

    # rpcrt4
    "rpcdce.h": "rpcrt4",
    "rpcndr.h": "rpcrt4",

    # mpr
    "winnetwk.h": "mpr",

    # powrprof
    "powrprof.h": "powrprof",

    # dnsapi
    "windns.h": "dnsapi",

    # imagehlp
    "imagehlp.h": "imagehlp",
}

# Header dosya adından fonksiyon kategorisi çıkar
HEADER_TO_CATEGORY = {
    "winbase.h": "win_system",
    "wincon.h": "win_console",
    "winnls.h": "win_locale",
    "fileapi.h": "win_file",
    "processthreadsapi.h": "win_process",
    "synchapi.h": "win_sync",
    "memoryapi.h": "win_memory",
    "heapapi.h": "win_memory",
    "winuser.h": "win_gui",
    "wingdi.h": "win_gdi",
    "winreg.h": "win_registry",
    "winsvc.h": "win_service",
    "wincrypt.h": "win_crypto",
    "winternl.h": "win_ntdll",
    "winsock2.h": "win_network",
    "ws2tcpip.h": "win_network",
    "shellapi.h": "win_shell",
    "shlobj.h": "win_shell",
    "objbase.h": "win_com",
    "combaseapi.h": "win_com",
    "oleauto.h": "win_com",
    "shlwapi.h": "win_shell",
    "iphlpapi.h": "win_network",
    "psapi.h": "win_process",
    "dbghelp.h": "win_debug",
    "winver.h": "win_version",
    "setupapi.h": "win_setup",
    "wintrust.h": "win_crypto",
    "userenv.h": "win_user",
    "pdh.h": "win_perf",
    "mmsystem.h": "win_multimedia",
    "winhttp.h": "win_network",
    "wininet.h": "win_network",
    "d3d9.h": "win_directx",
    "d3d11.h": "win_directx",
    "d3d12.h": "win_directx",
    "dxgi.h": "win_directx",
    "ddraw.h": "win_directx",
    "dinput.h": "win_directx",
    "commctrl.h": "win_gui",
    "commdlg.h": "win_gui",
    "wtsapi32.h": "win_terminal",
    "sspi.h": "win_security",
    "security.h": "win_security",
    "rpcdce.h": "win_rpc",
    "windns.h": "win_network",
    "powrprof.h": "win_power",
    "imagehlp.h": "win_debug",
    "winnetwk.h": "win_network",
    "lm.h": "win_network",
    "lmaccess.h": "win_network",
    "lmshare.h": "win_network",
    "lmserver.h": "win_network",
    "libloaderapi.h": "win_module",
    "errhandlingapi.h": "win_error",
    "debugapi.h": "win_debug",
    "handleapi.h": "win_system",
    "ioapiset.h": "win_io",
    "namedpipeapi.h": "win_ipc",
    "profileapi.h": "win_perf",
    "sysinfoapi.h": "win_system",
    "threadpoolapiset.h": "win_thread",
    "threadpoollegacyapiset.h": "win_thread",
    "utilapiset.h": "win_system",
    "processenv.h": "win_process",
    "timezoneapi.h": "win_time",
    "aclapi.h": "win_security",
    "sddl.h": "win_security",
}

# ==========================================================================
# mingw-w64 .def dosyalarından da export çıkarma
# .def dosyaları hangi DLL'den hangi fonksiyonun export edildiğini doğrudan verir
# ==========================================================================
DEF_DIRS = [
    CLONE_DIR / "mingw-w64-crt" / "lib-common",
    CLONE_DIR / "mingw-w64-crt" / "lib32",
    CLONE_DIR / "mingw-w64-crt" / "lib64",
]

# ==========================================================================
# Regex pattern'leri — fonksiyon deklarasyonlarını yakalar
# ==========================================================================

# Calling convention macros
CC_MACROS = r'(?:WINAPI|APIENTRY|NTAPI|CALLBACK|STDMETHODCALLTYPE|WINBASEAPI|PASCAL|WSAAPI|__stdcall|__cdecl|STDAPICALLTYPE)'

# Return type macros (dönüş tipi olarak kullanılan)
DECLSPEC = r'(?:WINBASEAPI|WINUSERAPI|WINGDIAPI|WINADVAPI|NTSYSAPI|NTSTATUS|INTERNETAPI|HTTPAPI|LWSTDAPI(?:_\([\w\s\*]+\))?|SHSTDAPI(?:_\([\w\s\*]+\))?|__declspec\s*\(\s*dllimport\s*\))'

# Ana pattern'ler
PATTERNS = [
    # Pattern 1: DECLSPEC RET_TYPE CC FuncName(
    # Örnek: WINBASEAPI BOOL WINAPI CreateProcessW(
    re.compile(
        rf'^\s*(?:{DECLSPEC})\s+[\w\s\*]+?\s+(?:{CC_MACROS})\s+(\w+)\s*\(',
        re.MULTILINE
    ),
    # Pattern 2: RET_TYPE CC FuncName(  — calling convention ile
    # Örnek: BOOL WINAPI VirtualAlloc(
    re.compile(
        rf'^\s*(?:extern\s+)?(?:[\w]+\s+)*?(?:{CC_MACROS})\s+(\w+)\s*\(',
        re.MULTILINE
    ),
    # Pattern 3: NTSTATUS NTAPI NtFunc(
    re.compile(
        rf'^\s*NTSTATUS\s+(?:NTAPI|WINAPI)\s+(\w+)\s*\(',
        re.MULTILINE
    ),
    # Pattern 4: __declspec(dllimport) ... FuncName(
    re.compile(
        r'^\s*__declspec\s*\(\s*dllimport\s*\)\s+[\w\s\*]+?\s+(\w+)\s*\(',
        re.MULTILINE
    ),
    # Pattern 5: STDAPI FuncName(  veya  STDAPI_(type) FuncName(
    re.compile(
        r'^\s*STDAPI(?:_\([\w\s\*]+\))?\s+(\w+)\s*\(',
        re.MULTILINE
    ),
    # Pattern 6: HRESULT STDMETHODCALLTYPE FuncName(
    re.compile(
        r'^\s*HRESULT\s+STDMETHODCALLTYPE\s+(\w+)\s*\(',
        re.MULTILINE
    ),
]

# Filtreleme — bunlar fonksiyon değil
BLACKLIST_PREFIXES = [
    # Tipler, macro'lar
    "DECLARE_", "DEFINE_", "MIDL_", "BEGIN_", "END_",
    "IS_", "MAKE_", "CONTAINING_RECORD",
    # İç yapılar
    "__", "_CRT_", "_CRTIMP",
    # Tipler
    "typedef", "struct", "union", "enum",
]

BLACKLIST_EXACT = {
    "main", "wmain", "WinMain", "wWinMain", "DllMain",
    "TRUE", "FALSE", "NULL", "VOID", "BOOL", "DWORD",
    "HANDLE", "HRESULT", "NTSTATUS", "LONG", "ULONG",
    "LPVOID", "PVOID", "LPCSTR", "LPCWSTR", "LPSTR", "LPWSTR",
    "WINAPI", "CALLBACK", "APIENTRY", "NTAPI", "PASCAL",
    "STDAPI", "if", "else", "while", "for", "return", "switch",
    "case", "do", "sizeof", "defined",
}

# Minimum isim uzunluğu
MIN_NAME_LEN = 3


def clone_repo():
    """mingw-w64 repo'yu clone et (shallow)."""
    if CLONE_DIR.exists():
        print(f"[*] {CLONE_DIR} zaten var, tekrar clone etmiyorum")
        return True

    print(f"[*] Cloning mingw-w64 (sparse, depth=1)...")
    result = subprocess.run(
        [
            "git", "clone", "--depth", "1",
            "--filter=blob:none", "--sparse",
            REPO_URL, str(CLONE_DIR)
        ],
        capture_output=True, text=True, timeout=300
    )
    if result.returncode != 0:
        print(f"[!] Clone failed: {result.stderr[:500]}")
        return False

    # Sparse checkout — sadece header ve def dosyalarını al
    subprocess.run(
        ["git", "sparse-checkout", "set",
         "mingw-w64-headers/include",
         "mingw-w64-crt/lib-common",
         "mingw-w64-crt/lib32",
         "mingw-w64-crt/lib64"],
        cwd=str(CLONE_DIR),
        capture_output=True, text=True, timeout=120
    )
    print("[+] Clone tamamlandı")
    return True


def is_valid_func_name(name: str) -> bool:
    """Fonksiyon adı geçerli mi?"""
    if not name or len(name) < MIN_NAME_LEN:
        return False
    if name in BLACKLIST_EXACT:
        return False
    for prefix in BLACKLIST_PREFIXES:
        if name.startswith(prefix):
            return False
    # Tamamı büyük harf = muhtemelen macro
    if name.isupper() and len(name) > 4:
        return False
    # En az bir küçük harf içermeli (CamelCase)
    if not any(c.islower() for c in name):
        return False
    # Sadece alfanumerik ve _ olmalı
    if not re.match(r'^[A-Za-z_]\w*$', name):
        return False
    return True


def get_lib_and_category(header_name: str):
    """Header dosya adından lib ve kategori çıkar."""
    h = header_name.lower()

    lib = HEADER_TO_LIB.get(h, None)
    category = HEADER_TO_CATEGORY.get(h, None)

    # Bilinmeyen header'lar için tahmin
    if lib is None:
        if "nt" in h and ("api" in h or "sys" in h):
            lib = "ntdll"
        elif "wlan" in h:
            lib = "wlanapi"
        elif "bluetooth" in h or "bth" in h:
            lib = "bluetoothapis"
        elif "wevt" in h:
            lib = "wevtapi"
        elif "dhcp" in h:
            lib = "dhcpcsvc"
        elif "snmp" in h:
            lib = "snmpapi"
        elif "msi" in h:
            lib = "msi"
        elif "ras" in h:
            lib = "rasapi32"
        elif "tapi" in h or "tspi" in h:
            lib = "tapi32"
        elif "cert" in h:
            lib = "crypt32"
        elif "evt" in h:
            lib = "advapi32"
        elif "sec" in h or "cred" in h:
            lib = "advapi32"
        elif "d3d" in h or "dx" in h or "direct" in h:
            lib = "d3d11"
        elif "wbem" in h:
            lib = "wbemuuid"
        elif "mshtml" in h:
            lib = "mshtml"
        elif "iads" in h or "ads" in h:
            lib = "activeds"
        elif "mq" in h:
            lib = "mqrt"
        elif "tapi3" in h:
            lib = "tapi32"
        elif "rtc" in h:
            lib = "rtccore"
        elif "clus" in h:
            lib = "clusapi"
        elif "oledb" in h:
            lib = "oledb32"
        elif "strm" in h or "dshow" in h:
            lib = "strmiids"
        elif "sho" in h:
            lib = "shell32"
        elif "cdo" in h:
            lib = "cdosys"
        elif "comsvcs" in h or "com" in h:
            lib = "ole32"
        elif "gl" in h:
            lib = "opengl32"
        elif "win" in h:
            lib = "kernel32"
        else:
            lib = "unknown"

    if category is None:
        # Header dosya adından daha iyi kategori çıkar
        if any(x in h for x in ("mshtml", "iads", "oledb", "comsvcs", "cdo")):
            category = "win_com"
        elif any(x in h for x in ("gl", "d3d", "dx", "ddraw")):
            category = "win_directx"
        elif any(x in h for x in ("wlan", "bluetooth", "bth")):
            category = "win_network"
        elif any(x in h for x in ("mq", "tapi", "rtc")):
            category = "win_network"
        elif any(x in h for x in ("clus",)):
            category = "win_cluster"
        elif any(x in h for x in ("strmif", "dshow")):
            category = "win_multimedia"
        else:
            category = "win_api"

    return lib, category


def extract_from_headers(headers_dir: Path) -> dict:
    """Header dosyalarından fonksiyon isimlerini çıkar."""
    results = {}
    header_stats = defaultdict(int)

    if not headers_dir.exists():
        print(f"[!] Headers dizini bulunamadı: {headers_dir}")
        return results

    header_files = list(headers_dir.rglob("*.h"))
    print(f"[*] {len(header_files)} header dosyası bulundu")

    for hfile in header_files:
        try:
            content = hfile.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Relative path for mapping
        try:
            rel = hfile.relative_to(headers_dir)
        except ValueError:
            rel = hfile.name
        header_name = str(rel)

        lib, category = get_lib_and_category(hfile.name)

        found_in_file = set()
        for pattern in PATTERNS:
            for match in pattern.finditer(content):
                name = match.group(1).strip()
                if is_valid_func_name(name) and name not in found_in_file:
                    found_in_file.add(name)

        for name in found_in_file:
            if name not in results:
                results[name] = {
                    "lib": lib,
                    "header": header_name,
                    "category": category,
                }
                header_stats[hfile.name] += 1

    print(f"[+] Header'lardan {len(results)} fonksiyon çıkarıldı")
    # En verimli header'lar
    top = sorted(header_stats.items(), key=lambda x: -x[1])[:15]
    for h, c in top:
        print(f"    {h}: {c}")

    return results


def extract_from_def_files() -> dict:
    """mingw-w64 .def dosyalarından export isimleri çıkar.

    .def dosyaları doğrudan DLL export listelerini verir — en güvenilir kaynak.
    Format:
        LIBRARY kernel32
        EXPORTS
          CreateProcessW
          ExitProcess
    """
    results = {}

    for def_dir in DEF_DIRS:
        if not def_dir.exists():
            continue
        for deffile in def_dir.rglob("*.def"):
            try:
                content = deffile.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # LIBRARY satırından DLL adını çıkar
            lib_match = re.search(r'^\s*LIBRARY\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
            if lib_match:
                lib_name = lib_match.group(1).strip('"\'').lower()
                # .dll, .exe, .sys uzantılarını kaldır
                for ext in (".dll", ".exe", ".sys", ".drv", ".ocx"):
                    lib_name = lib_name.replace(ext, "")
            else:
                # Dosya adından tahmin
                lib_name = deffile.stem.lower()

            # EXPORTS bölümünden fonksiyon isimlerini çıkar
            in_exports = False
            for line in content.splitlines():
                stripped = line.strip()
                if re.match(r'^\s*EXPORTS\b', stripped, re.IGNORECASE):
                    in_exports = True
                    continue
                if re.match(r'^\s*LIBRARY\b', stripped, re.IGNORECASE):
                    in_exports = False
                    continue
                if not in_exports:
                    continue
                if not stripped or stripped.startswith(";"):
                    continue

                # Parse export entry: FuncName [@ordinal] [NONAME] [DATA] [== alias]
                parts = stripped.split()
                if not parts:
                    continue

                name = parts[0]
                # Bazı satırlarda @ordinal prefix olabiliyor
                if name.startswith("@"):
                    continue

                # "func == _func" aliasing
                if "==" in stripped:
                    name = parts[0]

                if is_valid_func_name(name):
                    if name not in results:
                        results[name] = {
                            "lib": lib_name,
                            "category": "win_api",
                        }

    print(f"[+] .def dosyalarından {len(results)} export çıkarıldı")
    return results


def load_existing_names() -> set:
    """Mevcut DB'lerdeki fonksiyon isimlerini yükle."""
    existing = set()
    for db_path in EXISTING_DBS:
        if not db_path.exists():
            continue
        try:
            with open(db_path) as f:
                data = json.load(f)
            sigs = data.get("signatures", {})
            existing.update(sigs.keys())
            print(f"[*] {db_path.name}: {len(sigs)} mevcut imza")
        except Exception as e:
            print(f"[!] {db_path.name} yüklenemedi: {e}")
    return existing


def build_purpose(name: str, lib: str) -> str:
    """Fonksiyon adından kısa açıklama üret (CamelCase parse)."""
    # CamelCase'i parçala
    words = re.sub(r'([A-Z])', r' \1', name).strip().split()
    # Suffix temizliği
    if words and words[-1] in ("A", "W"):
        suffix = "(ANSI)" if words[-1] == "A" else "(wide)"
        words = words[:-1]
        return " ".join(w.lower() for w in words) + f" {suffix}"
    if words and words[-1] == "Ex":
        words = words[:-1]
        return " ".join(w.lower() for w in words) + " extended"

    return " ".join(w.lower() for w in words)


def main():
    print("=" * 60)
    print("mingw-w64 Header Signature Extractor")
    print("=" * 60)

    # 1. Clone
    if not clone_repo():
        print("[!] Clone başarısız, çıkılıyor")
        sys.exit(1)

    # 2. Header'lardan çıkar
    header_funcs = extract_from_headers(HEADERS_DIR)

    # 3. .def dosyalarından çıkar
    def_funcs = extract_from_def_files()

    # 4. Birleştir (def dosyaları daha güvenilir, öncelik onlarda)
    merged = {}
    all_names = set(header_funcs.keys()) | set(def_funcs.keys())
    print(f"\n[*] Toplam benzersiz isim (birleştirilmiş): {len(all_names)}")

    for name in all_names:
        # def'ten gelen lib bilgisi daha güvenilir
        if name in def_funcs:
            lib = def_funcs[name]["lib"]
            category = def_funcs[name].get("category", "win_api")
            header = header_funcs[name]["header"] if name in header_funcs else None
        else:
            lib = header_funcs[name]["lib"]
            category = header_funcs[name].get("category", "win_api")
            header = header_funcs[name].get("header")

        purpose = build_purpose(name, lib)
        entry = {
            "lib": lib,
            "purpose": purpose,
            "category": category,
        }
        merged[name] = entry

    print(f"[+] Birleştirilmiş: {len(merged)} fonksiyon")

    # 5. Mevcut DB ile dedup
    existing = load_existing_names()
    net_new = {k: v for k, v in merged.items() if k not in existing}
    print(f"\n[*] Mevcut DB'lerde: {len(existing)} isim")
    print(f"[+] Net yeni: {len(net_new)} fonksiyon")
    print(f"[*] Overlap: {len(merged) - len(net_new)}")

    # 6. Lib dağılımı (net new)
    lib_counts = defaultdict(int)
    for v in net_new.values():
        lib_counts[v["lib"]] += 1
    print(f"\n[*] Net yeni — DLL dağılımı (top 20):")
    for lib, count in sorted(lib_counts.items(), key=lambda x: -x[1])[:20]:
        print(f"    {lib}: {count}")

    # 7. Çıktı yaz
    output = {
        "meta": {
            "generator": "karadul-sig-gen-mingw-headers",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "source": "mingw-w64 headers + def files",
            "total_extracted": len(merged),
            "net_new": len(net_new),
            "deduped_against": [p.name for p in EXISTING_DBS],
        },
        "signatures": dict(sorted(net_new.items())),
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    size_mb = OUTPUT_FILE.stat().st_size / (1024 * 1024)
    print(f"\n[+] Yazıldı: {OUTPUT_FILE}")
    print(f"    Boyut: {size_mb:.1f} MB")
    print(f"    Net new signatures: {len(net_new)}")

    # 8. Temizlik
    print(f"\n[*] Temizleniyor: {CLONE_DIR}")
    shutil.rmtree(CLONE_DIR, ignore_errors=True)
    print("[+] Temizlendi")

    print("\n" + "=" * 60)
    print(f"SONUÇ: {len(net_new)} net yeni Windows API sembolü eklendi")
    print("=" * 60)


if __name__ == "__main__":
    main()
