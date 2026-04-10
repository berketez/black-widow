#!/usr/bin/env python3
"""
Generate Windows API signatures from REAL Windows 11 DLLs.

Strategy:
1. Fetch DLL metadata from Winbindex (winbindex.m417z.com)
2. Download actual DLLs from Microsoft Symbol Server
3. Parse PE export tables with pefile
4. Output signature JSON

Author: Karadul sig-gen
"""

import json
import os
import sys
import time
import gzip
import struct
import tempfile
import shutil
import urllib.request
import urllib.error
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import pefile
except ImportError:
    print("ERROR: pefile not installed. Run: pip install pefile")
    sys.exit(1)

# ── Configuration ──────────────────────────────────────────────────────
OUTPUT_FILE = Path(__file__).parent.parent / "sigs" / "windows_real_exports.json"
COMBINED_FILE = Path(__file__).parent.parent / "sigs" / "combined_1M.json"
TEMP_DIR = Path(tempfile.mkdtemp(prefix="karadul-windll-"))

WINBINDEX_BASE = "https://winbindex.m417z.com/data/by_filename_compressed"
SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"

# Target DLLs - top Windows system DLLs by export count
TARGET_DLLS = [
    # Core NT / Kernel
    "ntdll.dll", "kernel32.dll", "kernelbase.dll",
    # User interface
    "user32.dll", "gdi32.dll", "gdi32full.dll",
    # Security / Registry
    "advapi32.dll", "sechost.dll",
    # COM / OLE
    "ole32.dll", "oleaut32.dll", "combase.dll", "rpcrt4.dll",
    # C Runtime
    "msvcrt.dll", "ucrtbase.dll",
    # Shell
    "shell32.dll", "shlwapi.dll",
    # Network
    "ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll",
    "iphlpapi.dll", "dnsapi.dll", "netapi32.dll", "mswsock.dll",
    # Crypto
    "crypt32.dll", "bcrypt.dll", "ncrypt.dll", "secur32.dll", "sspicli.dll",
    # Graphics / DirectX
    "d3d11.dll", "dxgi.dll", "d2d1.dll", "d3d9.dll", "ddraw.dll",
    "dwrite.dll", "d3d10.dll", "d3d12.dll",
    # Setup / Config
    "setupapi.dll", "cfgmgr32.dll", "devobj.dll",
    # Print / Multimedia
    "winspool.drv", "winmm.dll",
    # Misc system
    "cabinet.dll", "msi.dll", "version.dll",
    "dbghelp.dll", "imagehlp.dll",
    "psapi.dll", "pdh.dll",
    "authz.dll", "wevtapi.dll", "tdh.dll",
    "powrprof.dll", "wtsapi32.dll", "userenv.dll",
    "cldapi.dll", "propsys.dll", "sxs.dll",
    # WinSock / Firewall
    "fwpuclnt.dll", "nsi.dll",
    # Windows Runtime
    "comctl32.dll", "comdlg32.dll",
    # NLS / Locale
    "normaliz.dll", "winnls32.dll",
    # Task Scheduler / Services
    "taskschd.dll", "wintrust.dll",
    # Performance
    "ntmarta.dll",
    # Kernel driver exports (ntoskrnl is special)
    "ntoskrnl.exe",
    # Extra important ones
    "mscoree.dll", "msvcp_win.dll",
    "imm32.dll", "uxtheme.dll", "dwmapi.dll",
    "wldp.dll", "cryptbase.dll", "cryptsp.dll",
    "profapi.dll", "wintypes.dll",
    "mfplat.dll", "mf.dll", "mfreadwrite.dll",
    "dxcore.dll", "xinput1_4.dll",
    "virtdisk.dll", "vssapi.dll",
    "wlanapi.dll", "bluetoothapis.dll",
    "webservices.dll", "httpapi.dll",
    "avrt.dll", "dsound.dll",
    "cimfs.dll", "wer.dll",
    "esent.dll", "jetoledb.dll",
    "ndfapi.dll", "firewallapi.dll",
    "ktmw32.dll", "resutils.dll",
    "activeds.dll", "netutils.dll",
]

# Category mapping based on DLL name
DLL_CATEGORIES = {
    "ntdll.dll": "win_nt", "ntoskrnl.exe": "win_nt",
    "kernel32.dll": "win_kernel", "kernelbase.dll": "win_kernel",
    "user32.dll": "win_ui", "gdi32.dll": "win_gdi", "gdi32full.dll": "win_gdi",
    "advapi32.dll": "win_security", "sechost.dll": "win_security",
    "ole32.dll": "win_com", "oleaut32.dll": "win_com", "combase.dll": "win_com", "rpcrt4.dll": "win_com",
    "msvcrt.dll": "win_crt", "ucrtbase.dll": "win_crt",
    "shell32.dll": "win_shell", "shlwapi.dll": "win_shell",
    "ws2_32.dll": "win_net", "wininet.dll": "win_net", "winhttp.dll": "win_net",
    "urlmon.dll": "win_net", "iphlpapi.dll": "win_net", "dnsapi.dll": "win_net",
    "netapi32.dll": "win_net", "mswsock.dll": "win_net",
    "crypt32.dll": "win_crypto", "bcrypt.dll": "win_crypto", "ncrypt.dll": "win_crypto",
    "secur32.dll": "win_crypto", "sspicli.dll": "win_crypto",
    "d3d11.dll": "win_dx", "dxgi.dll": "win_dx", "d2d1.dll": "win_dx",
    "d3d9.dll": "win_dx", "ddraw.dll": "win_dx", "dwrite.dll": "win_dx",
    "d3d10.dll": "win_dx", "d3d12.dll": "win_dx", "dxcore.dll": "win_dx",
    "setupapi.dll": "win_setup", "cfgmgr32.dll": "win_setup", "devobj.dll": "win_setup",
    "msi.dll": "win_setup", "cabinet.dll": "win_setup",
    "winspool.drv": "win_print", "winmm.dll": "win_mm",
    "comctl32.dll": "win_ui", "comdlg32.dll": "win_ui",
    "imm32.dll": "win_ui", "uxtheme.dll": "win_ui", "dwmapi.dll": "win_ui",
}
DEFAULT_CATEGORY = "win_dll"

# ── Helpers ────────────────────────────────────────────────────────────

def log(msg):
    print(f"  {msg}", flush=True)


def fetch_winbindex_info(dll_name):
    """Fetch DLL metadata from Winbindex. Returns (timestamp, virtualsize) for latest Win11 x64."""
    url = f"{WINBINDEX_BASE}/{dll_name}.json.gz"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Karadul/1.7"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
        data = json.loads(gzip.decompress(raw))
    except Exception as e:
        return None, None, str(e)

    # Find latest Windows 11 x64 entry
    best = None
    best_ver = ""
    for sha, info in data.items():
        fi = info.get("fileInfo", {})
        # x64 only (machineType 34404 = AMD64)
        if fi.get("machineType") != 34404:
            continue
        wv = info.get("windowsVersions", {})
        for ver_key in ["11-24H2", "11-23H2", "11-22H2", "1124H2", "1123H2"]:
            if ver_key in wv:
                ver_str = fi.get("version", "")
                if ver_str > best_ver:
                    best_ver = ver_str
                    best = fi
                break

    if not best:
        # Fallback: any x64 version
        for sha, info in data.items():
            fi = info.get("fileInfo", {})
            if fi.get("machineType") == 34404:
                best = fi
                break

    if not best:
        return None, None, "No x64 entry found"

    ts = best.get("timestamp", 0)
    vs = best.get("virtualSize", 0)
    return ts, vs, None


def download_dll_from_symbol_server(dll_name, timestamp, virtual_size, dest_path):
    """Download DLL from Microsoft Symbol Server."""
    url_id = f"{timestamp:08X}{virtual_size:x}"
    url = f"{SYMBOL_SERVER}/{dll_name}/{url_id}/{dll_name}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            content = resp.read()
        with open(dest_path, "wb") as f:
            f.write(content)
        return True, None
    except Exception as e:
        return False, str(e)


def parse_exports(dll_path):
    """Parse PE export table. Returns list of export names."""
    exports = []
    try:
        pe = pefile.PE(dll_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode("utf-8", errors="replace")
                    exports.append(name)
        pe.close()
    except Exception as e:
        return exports, str(e)
    return exports, None


def process_dll(dll_name):
    """Full pipeline for one DLL: fetch metadata -> download -> parse exports."""
    # Step 1: Get metadata from Winbindex
    ts, vs, err = fetch_winbindex_info(dll_name)
    if err:
        return dll_name, [], f"winbindex: {err}"

    # Step 2: Download from Symbol Server
    dest = TEMP_DIR / dll_name
    ok, err = download_dll_from_symbol_server(dll_name, ts, vs, dest)
    if not ok:
        return dll_name, [], f"download: {err}"

    # Step 3: Parse exports
    exports, err = parse_exports(dest)
    if err:
        return dll_name, exports, f"parse: {err} (got {len(exports)} exports)"

    # Cleanup
    try:
        dest.unlink()
    except:
        pass

    return dll_name, exports, None


# ── Hardcoded fallback for known DLL timestamps ───────────────────────
# If Winbindex is slow/down, use these known-good values
KNOWN_DLL_INFO = {
    # (timestamp, virtualSize) - from Winbindex Windows 11 22H2 x64
    # Will be populated as we discover them
}


# ── Alternative: Direct download attempt without Winbindex ────────────
def try_direct_download_with_known_hashes(dll_name):
    """Try to download DLL using various known timestamp combos."""
    # For some well-known DLLs, multiple timestamps work
    # This is a fallback if Winbindex is down
    pass


# ── Main ──────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Karadul Windows Real DLL Export Signature Generator")
    print("=" * 70)
    print(f"Target DLLs: {len(TARGET_DLLS)}")
    print(f"Temp dir: {TEMP_DIR}")
    print()

    all_sigs = {}
    stats = {"success": 0, "failed": 0, "total_exports": 0}
    failed_dlls = []

    # Process DLLs with thread pool (parallel downloads)
    # Use 4 threads to be polite to Microsoft servers
    print("[1/3] Fetching metadata & downloading DLLs from Microsoft...")
    print()

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(process_dll, dll): dll for dll in TARGET_DLLS}

        for future in as_completed(futures):
            dll_name = futures[future]
            try:
                name, exports, err = future.result()
            except Exception as e:
                name = dll_name
                exports = []
                err = str(e)

            lib_name = name.rsplit(".", 1)[0]  # ntdll.dll -> ntdll
            category = DLL_CATEGORIES.get(name, DEFAULT_CATEGORY)

            if err:
                log(f"FAIL {name}: {err}")
                failed_dlls.append((name, err))
                stats["failed"] += 1
            else:
                log(f"OK   {name}: {len(exports)} exports")
                stats["success"] += 1

            for exp_name in exports:
                if exp_name not in all_sigs:
                    all_sigs[exp_name] = {
                        "lib": lib_name,
                        "purpose": "",
                        "category": category,
                    }
                stats["total_exports"] += 1

    print()
    print(f"[2/3] Processing results...")
    print(f"  Successful DLLs: {stats['success']}")
    print(f"  Failed DLLs: {stats['failed']}")
    print(f"  Total exports: {stats['total_exports']}")
    print(f"  Unique signatures: {len(all_sigs)}")

    # Count net new vs combined
    net_new = 0
    if COMBINED_FILE.exists():
        try:
            with open(COMBINED_FILE) as f:
                combined = json.load(f)
            sigs_data = combined.get("signatures", [])
            if isinstance(sigs_data, list):
                # List format: [{"name": "...", ...}, ...]
                combined_sigs = set(item["name"] for item in sigs_data if isinstance(item, dict) and "name" in item)
            elif isinstance(sigs_data, dict):
                combined_sigs = set(sigs_data.keys())
            else:
                combined_sigs = set()
            net_new = len(set(all_sigs.keys()) - combined_sigs)
            print(f"  Net new vs combined_1M: {net_new}")
        except Exception as e:
            print(f"  Warning: could not compare with combined: {e}")

    # Build output
    output = {
        "meta": {
            "generator": "karadul-sig-gen-windows-real",
            "date": time.strftime("%Y-%m-%d"),
            "source": "Windows 11 DLL exports (Microsoft Symbol Server)",
            "total_exports": len(all_sigs),
            "successful_dlls": stats["success"],
            "failed_dlls": stats["failed"],
            "net_new_vs_combined": net_new,
        },
        "signatures": dict(sorted(all_sigs.items())),
    }

    print()
    print(f"[3/3] Writing {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"  Written: {len(all_sigs)} signatures")

    # Report failed DLLs
    if failed_dlls:
        print()
        print("Failed DLLs:")
        for name, err in sorted(failed_dlls):
            print(f"  {name}: {err}")

    # Cleanup
    print()
    print("Cleaning up temp files...")
    shutil.rmtree(TEMP_DIR, ignore_errors=True)

    print()
    print("=" * 70)
    print(f"DONE: {len(all_sigs)} unique exports from {stats['success']} DLLs")
    print(f"Output: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
