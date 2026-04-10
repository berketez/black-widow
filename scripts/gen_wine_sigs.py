#!/usr/bin/env python3
"""
gen_wine_sigs.py - Wine ve ReactOS kaynaklarindan Windows DLL export signature cikarma.

Wine .spec dosyalari ve ReactOS .def/.spec dosyalari parse edilir.
Her DLL'in export listesi cikarilir, dedup yapilir, JSON'a yazilir.

Kaynak:
  - Wine: https://gitlab.winehq.org/wine/wine.git (shallow clone)
  - ReactOS: https://github.com/nicedoc/reactos.git (shallow clone)

Cikti: /Users/apple/Desktop/black-widow/sigs/wine_dll_exports.json
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from datetime import date

# ===== Konfiguerasyon =====
WINE_REPO = "https://gitlab.winehq.org/wine/wine.git"
REACTOS_REPO = "https://github.com/nicedoc/reactos.git"  # Fallback: https://github.com/nicedoc/reactos.git
REACTOS_REPO_ALT = "https://github.com/nicedoc/reactos.git"
WINE_DIR = Path("/tmp/wine-source")
REACTOS_DIR = Path("/tmp/reactos-source")
OUTPUT = Path("/Users/apple/Desktop/black-widow/sigs/wine_dll_exports.json")
COMBINED_DB = Path("/Users/apple/Desktop/black-widow/sigs/combined_1M.json")

# ===== Kategori Mapping: DLL adi -> kategori =====
# Tam eslesme ve prefix eslesmesi ayri tutulur
DLL_CATEGORY_EXACT = {
    "kernel32": "win_core",
    "kernelbase": "win_core",
    "ntdll": "win_core",
    "ntoskrnl.exe": "win_core",
    "hal": "win_core",
    "ntkrnlpa": "win_core",
    "user32": "win_gui",
    "gdi32": "win_gui",
    "gdiplus": "win_gui",
    "comctl32": "win_gui",
    "comdlg32": "win_gui",
    "uxtheme": "win_gui",
    "dwmapi": "win_gui",
    "imm32": "win_gui",
    "advapi32": "win_security",
    "secur32": "win_security",
    "sechost": "win_security",
    "authz": "win_security",
    "ws2_32": "win_network",
    "winhttp": "win_network",
    "wininet": "win_network",
    "urlmon": "win_network",
    "iphlpapi": "win_network",
    "dnsapi": "win_network",
    "dhcpcsvc": "win_network",
    "netapi32": "win_network",
    "mswsock": "win_network",
    "httpapi": "win_network",
    "webservices": "win_network",
    "ole32": "win_com",
    "oleaut32": "win_com",
    "combase": "win_com",
    "rpcrt4": "win_com",
    "propsys": "win_com",
    "dxgi": "win_directx",
    "d2d1": "win_directx",
    "dwrite": "win_directx",
    "xinput1_3": "win_directx",
    "xinput1_4": "win_directx",
    "xinput9_1_0": "win_directx",
    "xaudio2_7": "win_directx",
    "xaudio2_8": "win_directx",
    "xaudio2_9": "win_directx",
    "x3daudio1_7": "win_directx",
    "crypt32": "win_crypto",
    "bcrypt": "win_crypto",
    "ncrypt": "win_crypto",
    "wintrust": "win_crypto",
    "rsaenh": "win_crypto",
    "dssenh": "win_crypto",
    "shell32": "win_shell",
    "shlwapi": "win_shell",
    "cabinet": "win_shell",
    "msvcrt": "win_crt",
    "ucrtbase": "win_crt",
    "msvcp60": "win_crt",
    "concrt140": "win_crt",
    "vcruntime140": "win_crt",
    "msi": "win_install",
    "setupapi": "win_install",
    "winspool.drv": "win_print",
    "winspool": "win_print",
    "winmm": "win_multimedia",
    "mmdevapi": "win_multimedia",
    "dsound": "win_multimedia",
    "quartz": "win_multimedia",
    "mf": "win_multimedia",
    "mfplat": "win_multimedia",
    "mfreadwrite": "win_multimedia",
    "mfplay": "win_multimedia",
    "evr": "win_multimedia",
    "avifil32": "win_multimedia",
    "msacm32": "win_multimedia",
    "version": "win_misc",
    "psapi": "win_process",
    "dbghelp": "win_debug",
    "dbgcore": "win_debug",
    "imagehlp": "win_debug",
    "pdh": "win_perf",
    "powrprof": "win_power",
    "taskschd": "win_sched",
    "wevtapi": "win_event",
    "wbemprox": "win_wmi",
    "wmiutils": "win_wmi",
    "oledb32": "win_db",
    "odbc32": "win_db",
    "cfgmgr32": "win_device",
    "hid": "win_device",
    "newdev": "win_device",
    "opengl32": "win_graphics",
    "vulkan-1": "win_graphics",
    "opencl": "win_compute",
    "wldap32": "win_network",
    "tapi32": "win_network",
    "fwpuclnt": "win_network",
    "wpcap": "win_network",
    "windowscodecs": "win_multimedia",
    "mscms": "win_multimedia",
    "inetcomm": "win_network",
    "mshtml": "win_gui",
    "chakra": "win_scripting",
    "jscript": "win_scripting",
    "vbscript": "win_scripting",
    "wbemdisp": "win_wmi",
    "wbemprox": "win_wmi",
    "wmiutils": "win_wmi",
    "taskschd": "win_sched",
    "mstask": "win_sched",
    "apphelp": "win_compat",
    "mscoree": "win_dotnet",
    "mscorwks": "win_dotnet",
    "clr": "win_dotnet",
    "fusion": "win_dotnet",
    "ntdsapi": "win_directory",
    "activeds": "win_directory",
    "adsldpc": "win_directory",
    "esent": "win_db",
    "bluetoothapis": "win_device",
    "bthprops.cpl": "win_device",
}

# Prefix bazli kategori (d3d9, d3d10, d3d11, d3d12, d3dcompiler_* vs.)
DLL_CATEGORY_PREFIX = [
    ("d3d", "win_directx"),
    ("dxgi", "win_directx"),
    ("xaudio", "win_directx"),
    ("x3daudio", "win_directx"),
    ("msvcp", "win_crt"),
    ("msvcr", "win_crt"),
    ("vcomp", "win_crt"),
    ("api-ms-win-crt", "win_crt"),
    ("api-ms-win-core", "win_core"),
    ("api-ms-win-security", "win_security"),
    ("api-ms-win", "win_core"),
    ("ext-ms-win", "win_core"),
]


def get_dll_category(dll_name: str) -> str:
    """DLL adindan kategori belirle."""
    lower = dll_name.lower().replace(".dll", "").replace(".drv", "")
    # Tam eslesme
    if lower in DLL_CATEGORY_EXACT:
        return DLL_CATEGORY_EXACT[lower]
    # Prefix
    for prefix, cat in DLL_CATEGORY_PREFIX:
        if lower.startswith(prefix):
            return cat
    return "win_dll"


# ===== Bilinen Fonksiyonlar icin Purpose Dict (300+) =====
KNOWN_PURPOSES = {
    # -- kernel32 / core --
    "CreateFileW": "Create or open file",
    "CreateFileA": "Create or open file (ANSI)",
    "ReadFile": "Read data from file",
    "WriteFile": "Write data to file",
    "CloseHandle": "Close open handle",
    "VirtualAlloc": "Allocate virtual memory",
    "VirtualAllocEx": "Allocate virtual memory in another process",
    "VirtualFree": "Free virtual memory",
    "VirtualFreeEx": "Free virtual memory in another process",
    "VirtualProtect": "Change memory page protection",
    "VirtualProtectEx": "Change memory protection in another process",
    "VirtualQuery": "Query virtual memory information",
    "VirtualQueryEx": "Query virtual memory in another process",
    "HeapAlloc": "Allocate heap memory",
    "HeapFree": "Free heap memory",
    "HeapReAlloc": "Reallocate heap memory",
    "HeapCreate": "Create private heap",
    "HeapDestroy": "Destroy private heap",
    "HeapSize": "Get heap block size",
    "GetProcessHeap": "Get default process heap",
    "GlobalAlloc": "Allocate global memory",
    "GlobalFree": "Free global memory",
    "GlobalLock": "Lock global memory",
    "GlobalUnlock": "Unlock global memory",
    "LocalAlloc": "Allocate local memory",
    "LocalFree": "Free local memory",
    "CreateProcessW": "Create new process",
    "CreateProcessA": "Create new process (ANSI)",
    "OpenProcess": "Open existing process",
    "TerminateProcess": "Terminate process",
    "ExitProcess": "Exit current process",
    "GetExitCodeProcess": "Get process exit code",
    "GetCurrentProcess": "Get current process pseudo-handle",
    "GetCurrentProcessId": "Get current process ID",
    "GetProcessId": "Get process ID from handle",
    "CreateThread": "Create new thread",
    "CreateRemoteThread": "Create thread in another process",
    "CreateRemoteThreadEx": "Create thread in another process (extended)",
    "ExitThread": "Exit current thread",
    "TerminateThread": "Terminate thread",
    "SuspendThread": "Suspend thread execution",
    "ResumeThread": "Resume suspended thread",
    "GetCurrentThread": "Get current thread pseudo-handle",
    "GetCurrentThreadId": "Get current thread ID",
    "GetThreadId": "Get thread ID from handle",
    "GetThreadContext": "Get thread CPU context/registers",
    "SetThreadContext": "Set thread CPU context/registers",
    "SwitchToThread": "Yield to another thread",
    "Sleep": "Suspend execution for milliseconds",
    "SleepEx": "Suspend execution (alertable)",
    "WaitForSingleObject": "Wait for single synchronization object",
    "WaitForSingleObjectEx": "Wait for single object (alertable)",
    "WaitForMultipleObjects": "Wait for multiple synchronization objects",
    "WaitForMultipleObjectsEx": "Wait for multiple objects (alertable)",
    "CreateMutexW": "Create named mutex",
    "CreateMutexA": "Create named mutex (ANSI)",
    "CreateMutexExW": "Create mutex (extended)",
    "OpenMutexW": "Open existing mutex",
    "ReleaseMutex": "Release mutex ownership",
    "CreateEventW": "Create event object",
    "CreateEventA": "Create event object (ANSI)",
    "SetEvent": "Set event to signaled",
    "ResetEvent": "Reset event to non-signaled",
    "PulseEvent": "Pulse event object",
    "CreateSemaphoreW": "Create semaphore",
    "CreateSemaphoreA": "Create semaphore (ANSI)",
    "ReleaseSemaphore": "Release semaphore",
    "InitializeCriticalSection": "Initialize critical section",
    "EnterCriticalSection": "Enter critical section",
    "LeaveCriticalSection": "Leave critical section",
    "DeleteCriticalSection": "Delete critical section",
    "TryEnterCriticalSection": "Try to enter critical section",
    "InitializeSRWLock": "Initialize slim reader/writer lock",
    "AcquireSRWLockExclusive": "Acquire SRW lock exclusive",
    "AcquireSRWLockShared": "Acquire SRW lock shared",
    "ReleaseSRWLockExclusive": "Release SRW lock exclusive",
    "ReleaseSRWLockShared": "Release SRW lock shared",
    "TryAcquireSRWLockExclusive": "Try acquire SRW lock exclusive",
    "TryAcquireSRWLockShared": "Try acquire SRW lock shared",
    "InitializeConditionVariable": "Initialize condition variable",
    "SleepConditionVariableSRW": "Sleep on condition variable with SRW",
    "SleepConditionVariableCS": "Sleep on condition variable with CS",
    "WakeConditionVariable": "Wake one waiting thread",
    "WakeAllConditionVariable": "Wake all waiting threads",
    "InterlockedIncrement": "Atomic increment",
    "InterlockedDecrement": "Atomic decrement",
    "InterlockedExchange": "Atomic exchange",
    "InterlockedCompareExchange": "Atomic compare-and-swap",
    "LoadLibraryW": "Load DLL into process",
    "LoadLibraryA": "Load DLL into process (ANSI)",
    "LoadLibraryExW": "Load DLL with flags",
    "LoadLibraryExA": "Load DLL with flags (ANSI)",
    "FreeLibrary": "Unload DLL from process",
    "GetProcAddress": "Get function address from DLL",
    "GetModuleHandleW": "Get handle to loaded module",
    "GetModuleHandleA": "Get handle to loaded module (ANSI)",
    "GetModuleHandleExW": "Get module handle (extended)",
    "GetModuleFileNameW": "Get module file path",
    "GetModuleFileNameA": "Get module file path (ANSI)",
    "GetLastError": "Get last Win32 error code",
    "SetLastError": "Set last Win32 error code",
    "FormatMessageW": "Format error message string",
    "FormatMessageA": "Format error message string (ANSI)",
    "OutputDebugStringW": "Send string to debugger",
    "OutputDebugStringA": "Send string to debugger (ANSI)",
    "IsDebuggerPresent": "Check if debugger is attached",
    "CheckRemoteDebuggerPresent": "Check for remote debugger",
    "DebugBreak": "Trigger breakpoint exception",
    "GetSystemTime": "Get current UTC time",
    "GetLocalTime": "Get current local time",
    "GetSystemTimeAsFileTime": "Get UTC time as FILETIME",
    "GetTickCount": "Get milliseconds since boot",
    "GetTickCount64": "Get milliseconds since boot (64-bit)",
    "QueryPerformanceCounter": "Get high-resolution timer value",
    "QueryPerformanceFrequency": "Get timer frequency",
    "FileTimeToSystemTime": "Convert FILETIME to SYSTEMTIME",
    "SystemTimeToFileTime": "Convert SYSTEMTIME to FILETIME",
    "GetCommandLineW": "Get process command line",
    "GetCommandLineA": "Get process command line (ANSI)",
    "GetEnvironmentVariableW": "Get environment variable",
    "GetEnvironmentVariableA": "Get environment variable (ANSI)",
    "SetEnvironmentVariableW": "Set environment variable",
    "GetStartupInfoW": "Get process startup info",
    "GetSystemInfo": "Get system hardware info",
    "GetNativeSystemInfo": "Get native system info",
    "GetVersionExW": "Get Windows version info",
    "IsWow64Process": "Check if 32-bit on 64-bit OS",
    "Wow64DisableWow64FsRedirection": "Disable WOW64 filesystem redirection",
    "GetComputerNameW": "Get computer name",
    "GetUserNameW": "Get current user name",
    "GetWindowsDirectoryW": "Get Windows directory path",
    "GetSystemDirectoryW": "Get system directory path",
    "GetTempPathW": "Get temp directory path",
    "DeleteFileW": "Delete file",
    "DeleteFileA": "Delete file (ANSI)",
    "CopyFileW": "Copy file",
    "MoveFileW": "Move or rename file",
    "MoveFileExW": "Move file with options",
    "CreateDirectoryW": "Create directory",
    "RemoveDirectoryW": "Remove directory",
    "FindFirstFileW": "Begin file search",
    "FindNextFileW": "Continue file search",
    "FindClose": "End file search",
    "GetFileAttributesW": "Get file attributes",
    "SetFileAttributesW": "Set file attributes",
    "GetFileSize": "Get file size",
    "GetFileSizeEx": "Get file size (64-bit)",
    "SetFilePointer": "Set file read/write position",
    "SetFilePointerEx": "Set file position (64-bit)",
    "FlushFileBuffers": "Flush file write buffers",
    "SetEndOfFile": "Set end of file at current position",
    "LockFile": "Lock file region",
    "UnlockFile": "Unlock file region",
    "DeviceIoControl": "Send device I/O control code",
    "CreatePipe": "Create anonymous pipe",
    "CreateNamedPipeW": "Create named pipe",
    "ConnectNamedPipe": "Wait for pipe client",
    "DisconnectNamedPipe": "Disconnect pipe",
    "PeekNamedPipe": "Preview pipe data without reading",
    "TransactNamedPipe": "Write then read pipe",
    "CreateFileMappingW": "Create file mapping object",
    "OpenFileMappingW": "Open file mapping object",
    "MapViewOfFile": "Map file view into memory",
    "MapViewOfFileEx": "Map file view at specific address",
    "UnmapViewOfFile": "Unmap file view from memory",
    "FlushViewOfFile": "Flush mapped file view",
    "DuplicateHandle": "Duplicate handle",
    "GetHandleInformation": "Get handle flags",
    "SetHandleInformation": "Set handle flags",
    "GetStdHandle": "Get standard handle (stdin/out/err)",
    "SetStdHandle": "Set standard handle",
    "MultiByteToWideChar": "Convert multibyte to UTF-16",
    "WideCharToMultiByte": "Convert UTF-16 to multibyte",
    "GetACP": "Get ANSI code page",
    "GetOEMCP": "Get OEM code page",
    "IsValidCodePage": "Check if code page is valid",
    "TlsAlloc": "Allocate thread-local storage slot",
    "TlsFree": "Free thread-local storage slot",
    "TlsGetValue": "Get TLS value",
    "TlsSetValue": "Set TLS value",
    "FlsAlloc": "Allocate fiber-local storage slot",
    "FlsFree": "Free fiber-local storage slot",
    "FlsGetValue": "Get FLS value",
    "FlsSetValue": "Set FLS value",
    "QueueUserWorkItem": "Queue work item to thread pool",
    "RegisterWaitForSingleObject": "Register wait callback",
    "CreateTimerQueue": "Create timer queue",
    "CreateTimerQueueTimer": "Create timer queue timer",
    "DeleteTimerQueueTimer": "Delete timer queue timer",
    "EncodePointer": "Encode pointer for security",
    "DecodePointer": "Decode encoded pointer",
    "AddVectoredExceptionHandler": "Add vectored exception handler",
    "RemoveVectoredExceptionHandler": "Remove vectored exception handler",
    "SetUnhandledExceptionFilter": "Set unhandled exception filter",
    "RaiseException": "Raise exception",
    "RtlUnwind": "Unwind stack frames",
    "GetProcessTimes": "Get process timing information",

    # -- ntdll --
    "NtCreateFile": "Create or open file (NT)",
    "NtOpenFile": "Open file (NT)",
    "NtReadFile": "Read file (NT)",
    "NtWriteFile": "Write file (NT)",
    "NtClose": "Close handle (NT)",
    "NtQueryInformationProcess": "Query process info (NT)",
    "NtQueryInformationThread": "Query thread info (NT)",
    "NtQueryInformationFile": "Query file info (NT)",
    "NtSetInformationFile": "Set file info (NT)",
    "NtQuerySystemInformation": "Query system info (NT)",
    "NtAllocateVirtualMemory": "Allocate virtual memory (NT)",
    "NtFreeVirtualMemory": "Free virtual memory (NT)",
    "NtProtectVirtualMemory": "Change memory protection (NT)",
    "NtQueryVirtualMemory": "Query virtual memory (NT)",
    "NtCreateSection": "Create memory section (NT)",
    "NtMapViewOfSection": "Map section into address space (NT)",
    "NtUnmapViewOfSection": "Unmap section from address space (NT)",
    "NtOpenProcess": "Open process by ID (NT)",
    "NtTerminateProcess": "Terminate process (NT)",
    "NtCreateThread": "Create thread (NT)",
    "NtCreateThreadEx": "Create thread extended (NT)",
    "NtTerminateThread": "Terminate thread (NT)",
    "NtSuspendThread": "Suspend thread (NT)",
    "NtResumeThread": "Resume thread (NT)",
    "NtGetContextThread": "Get thread context (NT)",
    "NtSetContextThread": "Set thread context (NT)",
    "NtQueueApcThread": "Queue APC to thread (NT)",
    "NtCreateEvent": "Create event object (NT)",
    "NtSetEvent": "Set event (NT)",
    "NtWaitForSingleObject": "Wait for single object (NT)",
    "NtWaitForMultipleObjects": "Wait for multiple objects (NT)",
    "NtDelayExecution": "Delay execution / sleep (NT)",
    "NtCreateKey": "Create registry key (NT)",
    "NtOpenKey": "Open registry key (NT)",
    "NtSetValueKey": "Set registry value (NT)",
    "NtQueryValueKey": "Query registry value (NT)",
    "NtEnumerateKey": "Enumerate registry subkeys (NT)",
    "NtEnumerateValueKey": "Enumerate registry values (NT)",
    "NtDeleteKey": "Delete registry key (NT)",
    "NtLoadDriver": "Load kernel driver (NT)",
    "NtUnloadDriver": "Unload kernel driver (NT)",
    "NtDeviceIoControlFile": "Send IOCTL to device (NT)",
    "NtCreateNamedPipeFile": "Create named pipe (NT)",
    "NtCreateMutant": "Create mutex (NT)",
    "NtOpenMutant": "Open mutex (NT)",
    "NtCreateSemaphore": "Create semaphore (NT)",
    "NtOpenSemaphore": "Open semaphore (NT)",
    "NtCreateTimer": "Create timer (NT)",
    "NtDuplicateObject": "Duplicate handle (NT)",
    "NtQueryObject": "Query object attributes (NT)",
    "NtSetInformationProcess": "Set process info (NT)",
    "NtSetInformationThread": "Set thread info (NT)",
    "NtContinue": "Continue after exception (NT)",
    "NtRaiseException": "Raise exception (NT)",
    "NtRaiseHardError": "Raise hard error (NT)",
    "RtlInitUnicodeString": "Initialize UNICODE_STRING",
    "RtlFreeUnicodeString": "Free UNICODE_STRING buffer",
    "RtlCopyUnicodeString": "Copy UNICODE_STRING",
    "RtlCompareUnicodeString": "Compare UNICODE_STRING",
    "RtlInitAnsiString": "Initialize ANSI_STRING",
    "RtlAnsiStringToUnicodeString": "Convert ANSI to Unicode string",
    "RtlUnicodeStringToAnsiString": "Convert Unicode to ANSI string",
    "RtlGetVersion": "Get OS version info",
    "RtlCreateHeap": "Create heap",
    "RtlAllocateHeap": "Allocate from heap",
    "RtlFreeHeap": "Free heap allocation",
    "RtlDecompressBuffer": "Decompress data buffer",
    "RtlCompressBuffer": "Compress data buffer",
    "RtlAddVectoredExceptionHandler": "Add vectored exception handler",
    "RtlRemoveVectoredExceptionHandler": "Remove vectored exception handler",
    "LdrLoadDll": "Load DLL via loader",
    "LdrGetProcedureAddress": "Get function address via loader",
    "LdrGetDllHandle": "Get DLL handle via loader",
    "LdrUnloadDll": "Unload DLL via loader",

    # -- user32 --
    "CreateWindowExW": "Create window (extended)",
    "CreateWindowExA": "Create window (extended, ANSI)",
    "DestroyWindow": "Destroy window",
    "ShowWindow": "Show/hide window",
    "UpdateWindow": "Update window client area",
    "MoveWindow": "Move and resize window",
    "SetWindowPos": "Set window position and size",
    "GetWindowRect": "Get window rectangle",
    "GetClientRect": "Get client area rectangle",
    "FindWindowW": "Find window by class/title",
    "FindWindowExW": "Find child window",
    "GetForegroundWindow": "Get foreground window handle",
    "SetForegroundWindow": "Set foreground window",
    "GetDesktopWindow": "Get desktop window handle",
    "EnumWindows": "Enumerate top-level windows",
    "EnumChildWindows": "Enumerate child windows",
    "GetWindowTextW": "Get window title text",
    "SetWindowTextW": "Set window title text",
    "GetWindowLongW": "Get window attribute",
    "SetWindowLongW": "Set window attribute",
    "GetWindowLongPtrW": "Get window attribute (pointer-size)",
    "SetWindowLongPtrW": "Set window attribute (pointer-size)",
    "GetClassNameW": "Get window class name",
    "RegisterClassExW": "Register window class (extended)",
    "UnregisterClassW": "Unregister window class",
    "DefWindowProcW": "Default window procedure",
    "CallWindowProcW": "Call window procedure",
    "SendMessageW": "Send message to window (blocking)",
    "SendMessageA": "Send message to window (ANSI)",
    "PostMessageW": "Post message to window (async)",
    "PostMessageA": "Post message to window (ANSI, async)",
    "GetMessageW": "Get message from queue",
    "PeekMessageW": "Peek message without removing",
    "TranslateMessage": "Translate virtual-key message",
    "DispatchMessageW": "Dispatch message to window proc",
    "PostQuitMessage": "Post WM_QUIT to message queue",
    "MessageBoxW": "Display message box",
    "MessageBoxA": "Display message box (ANSI)",
    "GetDC": "Get device context for window",
    "ReleaseDC": "Release device context",
    "BeginPaint": "Begin window painting",
    "EndPaint": "End window painting",
    "InvalidateRect": "Invalidate window rectangle",
    "GetCursorPos": "Get mouse cursor position",
    "SetCursorPos": "Set mouse cursor position",
    "SetCursor": "Set mouse cursor shape",
    "ShowCursor": "Show/hide mouse cursor",
    "GetKeyState": "Get key state (up/down/toggled)",
    "GetAsyncKeyState": "Get async key state",
    "MapVirtualKeyW": "Map virtual key to scan code",
    "SetTimer": "Create timer for window",
    "KillTimer": "Destroy window timer",
    "GetSystemMetrics": "Get system display metrics",
    "SystemParametersInfoW": "Get/set system parameters",
    "SetWindowsHookExW": "Install Windows hook",
    "UnhookWindowsHookEx": "Remove Windows hook",
    "CallNextHookEx": "Call next hook in chain",
    "GetClipboardData": "Get clipboard data",
    "SetClipboardData": "Set clipboard data",
    "OpenClipboard": "Open clipboard",
    "CloseClipboard": "Close clipboard",
    "EmptyClipboard": "Empty clipboard contents",
    "keybd_event": "Simulate keyboard input",
    "mouse_event": "Simulate mouse input",
    "SendInput": "Send synthesized input events",
    "TrackPopupMenu": "Display popup menu",
    "CreateMenu": "Create empty menu",
    "CreatePopupMenu": "Create popup menu",
    "InsertMenuItemW": "Insert menu item",
    "LoadIconW": "Load icon resource",
    "LoadCursorW": "Load cursor resource",
    "LoadImageW": "Load icon/cursor/bitmap",
    "DrawTextW": "Draw formatted text",
    "FillRect": "Fill rectangle with brush",

    # -- advapi32 --
    "RegOpenKeyExW": "Open registry key",
    "RegOpenKeyExA": "Open registry key (ANSI)",
    "RegCreateKeyExW": "Create or open registry key",
    "RegCloseKey": "Close registry key",
    "RegQueryValueExW": "Query registry value",
    "RegQueryValueExA": "Query registry value (ANSI)",
    "RegSetValueExW": "Set registry value",
    "RegSetValueExA": "Set registry value (ANSI)",
    "RegDeleteKeyW": "Delete registry key",
    "RegDeleteValueW": "Delete registry value",
    "RegEnumKeyExW": "Enumerate registry subkeys",
    "RegEnumValueW": "Enumerate registry values",
    "OpenProcessToken": "Open process access token",
    "OpenThreadToken": "Open thread access token",
    "GetTokenInformation": "Get access token info",
    "AdjustTokenPrivileges": "Enable/disable token privileges",
    "LookupPrivilegeValueW": "Look up privilege LUID",
    "LookupAccountSidW": "Look up account by SID",
    "OpenSCManagerW": "Open service control manager",
    "OpenServiceW": "Open service handle",
    "CreateServiceW": "Create new service",
    "StartServiceW": "Start service",
    "ControlService": "Send control to service",
    "DeleteService": "Delete service",
    "QueryServiceStatusEx": "Query service status",
    "ChangeServiceConfigW": "Change service config",
    "StartServiceCtrlDispatcherW": "Start service dispatcher",
    "RegisterServiceCtrlHandlerExW": "Register service handler",
    "SetServiceStatus": "Set service status",
    "CryptAcquireContextW": "Acquire crypto provider context",
    "CryptReleaseContext": "Release crypto context",
    "CryptGenRandom": "Generate random bytes",
    "CryptCreateHash": "Create hash object",
    "CryptHashData": "Hash data",
    "CryptGetHashParam": "Get hash parameter",
    "CryptDestroyHash": "Destroy hash object",
    "CryptEncrypt": "Encrypt data",
    "CryptDecrypt": "Decrypt data",
    "CryptImportKey": "Import crypto key",
    "CryptExportKey": "Export crypto key",
    "CryptGenKey": "Generate crypto key",
    "CryptDestroyKey": "Destroy crypto key",
    "InitiateSystemShutdownExW": "Initiate system shutdown",
    "LogonUserW": "Log on user to local computer",
    "ImpersonateLoggedOnUser": "Impersonate logged-on user",
    "RevertToSelf": "End impersonation",
    "GetUserNameW": "Get current user name",
    "DuplicateTokenEx": "Duplicate access token",
    "ConvertSidToStringSidW": "Convert SID to string",
    "ConvertStringSidToSidW": "Convert string to SID",
    "SetSecurityDescriptorDacl": "Set DACL on security descriptor",
    "InitializeSecurityDescriptor": "Initialize security descriptor",
    "AddAccessAllowedAce": "Add allowed ACE to ACL",
    "InitializeAcl": "Initialize ACL",

    # -- ws2_32 --
    "WSAStartup": "Initialize Winsock",
    "WSACleanup": "Terminate Winsock",
    "WSAGetLastError": "Get last Winsock error",
    "socket": "Create socket",
    "closesocket": "Close socket",
    "bind": "Bind socket to address",
    "listen": "Listen for connections",
    "accept": "Accept incoming connection",
    "connect": "Connect to remote host",
    "send": "Send data on connected socket",
    "recv": "Receive data on socket",
    "sendto": "Send data to specific address",
    "recvfrom": "Receive data with sender info",
    "select": "Monitor socket readiness",
    "WSASocketW": "Create socket (extended)",
    "WSASend": "Send with overlapped I/O",
    "WSARecv": "Receive with overlapped I/O",
    "WSAConnect": "Connect (extended)",
    "WSAAccept": "Accept (conditional)",
    "WSAEventSelect": "Event-based socket notification",
    "WSAAsyncSelect": "Async socket notification",
    "WSAWaitForMultipleEvents": "Wait for socket events",
    "WSACreateEvent": "Create socket event",
    "WSACloseEvent": "Close socket event",
    "WSAEnumNetworkEvents": "Enumerate network events",
    "WSAIoctl": "Socket I/O control",
    "getaddrinfo": "Resolve hostname to address",
    "freeaddrinfo": "Free address info list",
    "getnameinfo": "Resolve address to hostname",
    "gethostbyname": "Get host by name (legacy)",
    "gethostname": "Get local hostname",
    "inet_addr": "Convert IP string to address",
    "inet_ntoa": "Convert address to IP string",
    "htons": "Host to network byte order (short)",
    "htonl": "Host to network byte order (long)",
    "ntohs": "Network to host byte order (short)",
    "ntohl": "Network to host byte order (long)",
    "setsockopt": "Set socket option",
    "getsockopt": "Get socket option",
    "ioctlsocket": "Socket I/O control",
    "shutdown": "Shut down socket operations",

    # -- ole32 / COM --
    "CoInitialize": "Initialize COM (STA)",
    "CoInitializeEx": "Initialize COM with model",
    "CoUninitialize": "Uninitialize COM",
    "CoCreateInstance": "Create COM object instance",
    "CoCreateInstanceEx": "Create COM instance (extended)",
    "CoGetClassObject": "Get COM class factory",
    "CoMarshalInterface": "Marshal COM interface",
    "CoUnmarshalInterface": "Unmarshal COM interface",
    "CoTaskMemAlloc": "Allocate COM task memory",
    "CoTaskMemFree": "Free COM task memory",
    "OleInitialize": "Initialize OLE",
    "OleUninitialize": "Uninitialize OLE",
    "StringFromCLSID": "Convert CLSID to string",
    "CLSIDFromString": "Convert string to CLSID",
    "StringFromGUID2": "Convert GUID to string",
    "IIDFromString": "Convert string to IID",
    "CoRegisterClassObject": "Register COM class object",
    "CoRevokeClassObject": "Revoke COM class object",

    # -- oleaut32 --
    "SysAllocString": "Allocate BSTR string",
    "SysFreeString": "Free BSTR string",
    "SysStringLen": "Get BSTR length",
    "SysAllocStringLen": "Allocate BSTR with length",
    "SysReAllocString": "Reallocate BSTR string",
    "VariantInit": "Initialize VARIANT",
    "VariantClear": "Clear VARIANT",
    "VariantCopy": "Copy VARIANT",
    "VariantChangeType": "Change VARIANT type",
    "SafeArrayCreate": "Create SAFEARRAY",
    "SafeArrayDestroy": "Destroy SAFEARRAY",
    "SafeArrayAccessData": "Access SAFEARRAY data",
    "SafeArrayUnaccessData": "Release SAFEARRAY access",
    "LoadTypeLib": "Load type library",
    "RegisterTypeLib": "Register type library",
    "DispGetIDsOfNames": "Get dispatch IDs by name",
    "DispInvoke": "Invoke IDispatch method",

    # -- shell32 --
    "ShellExecuteW": "Execute/open file or URL",
    "ShellExecuteExW": "Execute file (extended)",
    "SHGetFolderPathW": "Get special folder path",
    "SHGetKnownFolderPath": "Get known folder path",
    "SHGetSpecialFolderPathW": "Get special folder path (legacy)",
    "SHCreateDirectoryExW": "Create directory recursively",
    "SHFileOperationW": "Copy/move/delete files",
    "SHBrowseForFolderW": "Browse for folder dialog",
    "SHGetPathFromIDListW": "Get path from PIDL",
    "SHGetFileInfoW": "Get file info and icon",
    "DragAcceptFiles": "Enable drag-drop for window",
    "DragQueryFileW": "Query dropped file",
    "DragFinish": "Free drag-drop resources",
    "ExtractIconExW": "Extract icon from file",
    "SHChangeNotify": "Notify shell of change",
    "CommandLineToArgvW": "Parse command line to argv",
    "IsUserAnAdmin": "Check if user is administrator",

    # -- crypt32 / bcrypt --
    "CertOpenStore": "Open certificate store",
    "CertCloseStore": "Close certificate store",
    "CertFindCertificateInStore": "Find certificate in store",
    "CertGetCertificateChain": "Build certificate chain",
    "CertFreeCertificateContext": "Free certificate context",
    "CertEnumCertificatesInStore": "Enumerate certificates",
    "CryptDecodeObjectEx": "Decode ASN.1 object",
    "CryptEncodeObjectEx": "Encode ASN.1 object",
    "CryptStringToBinaryW": "Decode Base64/hex string",
    "CryptBinaryToStringW": "Encode to Base64/hex string",
    "CryptProtectData": "Encrypt data (DPAPI)",
    "CryptUnprotectData": "Decrypt data (DPAPI)",
    "PFXImportCertStore": "Import PFX certificate store",
    "BCryptOpenAlgorithmProvider": "Open crypto algorithm",
    "BCryptCloseAlgorithmProvider": "Close crypto algorithm",
    "BCryptCreateHash": "Create hash object (BCrypt)",
    "BCryptHashData": "Hash data (BCrypt)",
    "BCryptFinishHash": "Finish hash (BCrypt)",
    "BCryptDestroyHash": "Destroy hash object (BCrypt)",
    "BCryptGenerateSymmetricKey": "Generate symmetric key",
    "BCryptEncrypt": "Encrypt data (BCrypt)",
    "BCryptDecrypt": "Decrypt data (BCrypt)",
    "BCryptGenRandom": "Generate random bytes (BCrypt)",
    "BCryptDestroyKey": "Destroy key (BCrypt)",

    # -- dbghelp --
    "SymInitialize": "Initialize symbol handler",
    "SymCleanup": "Cleanup symbol handler",
    "SymLoadModuleEx": "Load module symbols",
    "SymFromAddr": "Get symbol from address",
    "SymFromName": "Get symbol from name",
    "SymGetLineFromAddr64": "Get source line from address",
    "StackWalk64": "Walk call stack",
    "MiniDumpWriteDump": "Write minidump file",
    "SymEnumSymbols": "Enumerate symbols",
    "UnDecorateSymbolName": "Undecorate C++ symbol name",
    "SymSetOptions": "Set symbol options",
    "ImageNtHeader": "Get PE NT headers",

    # -- psapi --
    "EnumProcesses": "Enumerate running processes",
    "EnumProcessModules": "Enumerate process modules",
    "EnumProcessModulesEx": "Enumerate process modules (extended)",
    "GetModuleBaseNameW": "Get module base name",
    "GetModuleFileNameExW": "Get module file name",
    "GetProcessMemoryInfo": "Get process memory statistics",
    "GetMappedFileNameW": "Get mapped file name from address",

    # -- wininet / winhttp --
    "InternetOpenW": "Initialize WinINet",
    "InternetConnectW": "Connect to server",
    "HttpOpenRequestW": "Create HTTP request",
    "HttpSendRequestW": "Send HTTP request",
    "InternetReadFile": "Read internet data",
    "InternetCloseHandle": "Close internet handle",
    "InternetOpenUrlW": "Open URL directly",
    "InternetSetOptionW": "Set internet option",
    "InternetQueryOptionW": "Query internet option",
    "WinHttpOpen": "Initialize WinHTTP",
    "WinHttpConnect": "Connect to server (WinHTTP)",
    "WinHttpOpenRequest": "Open HTTP request (WinHTTP)",
    "WinHttpSendRequest": "Send request (WinHTTP)",
    "WinHttpReceiveResponse": "Receive response (WinHTTP)",
    "WinHttpReadData": "Read response data (WinHTTP)",
    "WinHttpCloseHandle": "Close WinHTTP handle",
    "WinHttpSetOption": "Set WinHTTP option",
    "WinHttpQueryHeaders": "Query response headers",
    "WinHttpCrackUrl": "Parse URL components",
}


def clone_repo(url: str, dest: Path) -> bool:
    """Repo'yu shallow clone et. Zaten varsa atla."""
    if dest.exists():
        print(f"  [SKIP] {dest} zaten mevcut, tekrar klonlanmiyor.")
        return True
    print(f"  [CLONE] {url} -> {dest}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", str(url), str(dest)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  [ERROR] Clone basarisiz: {result.stderr[:300]}")
        return False
    return True


def parse_wine_spec(filepath: Path, dll_name: str) -> dict:
    """
    Wine .spec dosyasini parse et.
    Her satir:
      @ stdcall FuncName(args) [forward]
      @ cdecl FuncName(args)
      @ stub FuncName
      @ extern VarName
      123 stdcall FuncName(args) -- ordinal export (atlanir)

    -private suffix'li satirlar dahil edilir (internal export ama yine de export).
    """
    exports = {}
    category = get_dll_category(dll_name)

    try:
        text = filepath.read_text(errors="replace")
    except Exception as e:
        print(f"  [WARN] Okunamiyor {filepath}: {e}")
        return exports

    for line in text.splitlines():
        line = line.strip()
        # Bos satir veya yorum
        if not line or line.startswith("#"):
            continue

        # Ordinal export'lari atla (satir numara ile basliyorsa)
        # @ ile baslayanlar "next ordinal" demek, onlar OK
        parts = line.split()
        if len(parts) < 3:
            continue

        ordinal_or_at = parts[0]
        # Sayisal ordinal -> atla (isimsiz export riski yuksek)
        if ordinal_or_at != "@":
            # Sayiyla baslamis olabilir ama isim de olabilir
            # "123 stdcall FuncName(...)" -> ordinal, ama ismi var
            # Bunlari da alalim ama eger isim yoksa atlayalim
            try:
                int(ordinal_or_at)
                # Ordinal export - ama ismi varsa aliyoruz
                call_conv = parts[1]
                if call_conv in ("stdcall", "cdecl", "varargs", "thiscall", "fastcall"):
                    # Fonksiyon adini cikar
                    raw_name = parts[2]
                    func_name = raw_name.split("(")[0]
                    if not func_name or func_name.startswith("-"):
                        continue
                else:
                    continue
            except ValueError:
                continue
        else:
            # @ stdcall/cdecl/stub/extern ...
            call_conv = parts[1]

            # -private flag'i kaldir
            if call_conv == "-private":
                if len(parts) < 4:
                    continue
                call_conv = parts[2]
                raw_name = parts[3] if len(parts) > 3 else ""
            elif call_conv in ("stdcall", "cdecl", "varargs", "thiscall", "fastcall"):
                raw_name = parts[2] if len(parts) > 2 else ""
            elif call_conv == "stub":
                raw_name = parts[2] if len(parts) > 2 else ""
            elif call_conv == "extern":
                raw_name = parts[2] if len(parts) > 2 else ""
            else:
                # Bilinmeyen format, atla
                continue

            func_name = raw_name.split("(")[0]
            if not func_name or func_name.startswith("-") or func_name.startswith("#"):
                continue

        # -norelay, -private gibi suffix'leri temizle
        func_name = func_name.replace("-norelay", "").replace("-private", "")

        # Isimsiz/gecersiz adlari atla
        if not func_name or not func_name[0].isalpha() and func_name[0] != "_":
            continue

        # @ordinal (saf numara) atlandi, burada isim olmali
        purpose = KNOWN_PURPOSES.get(func_name, "")
        exports[func_name] = {
            "lib": dll_name,
            "purpose": purpose,
            "category": category,
        }

    return exports


def parse_reactos_def(filepath: Path, dll_name: str) -> dict:
    """
    ReactOS .def dosyasini parse et.
    Format:
      EXPORTS
      FuncName@28
      FuncName=InternalName @123
      FuncName @456 NONAME
      FuncName
      ; comment
    """
    exports = {}
    category = get_dll_category(dll_name)
    in_exports = False

    try:
        text = filepath.read_text(errors="replace")
    except Exception as e:
        print(f"  [WARN] Okunamiyor {filepath}: {e}")
        return exports

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        if line.upper().startswith("EXPORTS"):
            in_exports = True
            continue

        if line.upper().startswith("LIBRARY"):
            continue

        if not in_exports:
            continue

        # NONAME olanlar ordinal-only -> atla
        if "NONAME" in line.upper():
            continue

        # FuncName@28 veya FuncName=... veya FuncName @123
        # @ isareti: stdcall decoration (parametre boyutu) veya ordinal
        parts = line.split()
        raw_name = parts[0]

        # = isareti: FuncName=InternalName
        if "=" in raw_name:
            raw_name = raw_name.split("=")[0]

        # @28 decoration'i temizle
        if "@" in raw_name:
            raw_name = raw_name.split("@")[0]

        # Gecersiz
        if not raw_name or not (raw_name[0].isalpha() or raw_name[0] == "_"):
            continue

        purpose = KNOWN_PURPOSES.get(raw_name, "")
        exports[raw_name] = {
            "lib": dll_name,
            "purpose": purpose,
            "category": category,
        }

    return exports


def dll_name_from_spec_path(path: Path) -> str:
    """
    Dizin adindan DLL adini cikar.
    Wine: dlls/kernel32/kernel32.spec -> kernel32
    ReactOS: dll/win32/kernel32/kernel32.spec -> kernel32
    Genelde: parent dizin adi
    """
    # .spec dosyasinin stem'ini kullan, parent dir ile karsilastir
    stem = path.stem
    parent = path.parent.name
    # Wine'da stem == parent (kernel32.spec in kernel32/)
    # ReactOS'ta da benzer
    return stem if stem == parent else parent


# Ana Windows DLL'leri - bu listede olan DLL'ler oncelikli
# (Ayni fonksiyon birden fazla DLL'de export edildiginde en onemli DLL kazanir)
PRIMARY_DLLS = {
    "kernel32", "kernelbase", "ntdll", "ntoskrnl.exe",
    "user32", "gdi32", "gdiplus",
    "advapi32", "secur32", "sechost",
    "ws2_32", "wsock32", "winhttp", "wininet",
    "ole32", "oleaut32", "combase", "rpcrt4",
    "shell32", "shlwapi",
    "crypt32", "bcrypt", "ncrypt",
    "msvcrt", "ucrtbase",
    "dbghelp", "psapi", "imagehlp",
    "setupapi", "msi",
    "d3d9", "d3d10", "d3d11", "d3d12", "dxgi",
    "winmm", "dsound",
    "version", "iphlpapi", "netapi32",
    "winspool.drv",
}


def collect_wine_exports(wine_dir: Path) -> dict:
    """Wine kaynak kodundan tum .spec export'larini topla.

    Oncelik sistemi: Ana DLL'ler (kernel32, ntdll, user32 vb.) yardimci
    DLL'lerden (unicows, api-ms-win-* vb.) daha yuksek oncelikli.
    Ayni fonksiyon birden fazla DLL'de varsa, ana DLL kazanir.
    """
    all_exports = {}
    export_is_primary = {}  # func_name -> True/False (primary DLL'den mi geldi)
    spec_files = sorted(wine_dir.rglob("*.spec"))
    print(f"  Wine: {len(spec_files)} .spec dosyasi bulundu")

    for spec in spec_files:
        # Sadece dlls/ altindakileri al (test/*.spec vs atla)
        rel = spec.relative_to(wine_dir)
        if not str(rel).startswith("dlls"):
            continue

        dll_name = dll_name_from_spec_path(spec)

        # Test spec dosyalarini atla
        if dll_name.lower() in ("tests", "test", "crosstest"):
            continue
        # "tests" dizinindeki spec'leri atla
        if "/tests/" in str(spec):
            continue

        is_primary = dll_name.lower() in PRIMARY_DLLS
        exports = parse_wine_spec(spec, dll_name)

        for func_name, info in exports.items():
            if func_name not in all_exports:
                # Yeni fonksiyon, direkt ekle
                all_exports[func_name] = info
                export_is_primary[func_name] = is_primary
            elif is_primary and not export_is_primary.get(func_name, False):
                # Mevcut secondary DLL'den, yeni primary DLL'den -> degistir
                all_exports[func_name] = info
                export_is_primary[func_name] = True
            # else: ya zaten primary'den geldi, ya da ikisi de secondary -> ilkini tut

    return all_exports


def collect_reactos_exports(reactos_dir: Path) -> dict:
    """ReactOS kaynak kodundan .spec ve .def export'larini topla."""
    all_exports = {}

    # .spec dosyalari
    spec_files = sorted(reactos_dir.rglob("*.spec"))
    print(f"  ReactOS: {len(spec_files)} .spec dosyasi bulundu")
    for spec in spec_files:
        dll_name = dll_name_from_spec_path(spec)
        exports = parse_wine_spec(spec, dll_name)  # Ayni format
        if exports:
            all_exports.update(exports)

    # .def dosyalari
    def_files = sorted(reactos_dir.rglob("*.def"))
    print(f"  ReactOS: {len(def_files)} .def dosyasi bulundu")
    for deffile in def_files:
        dll_name = deffile.stem
        exports = parse_reactos_def(deffile, dll_name)
        if exports:
            # Sadece henuz olmayanlari ekle (Wine oncelikli)
            for name, info in exports.items():
                if name not in all_exports:
                    all_exports[name] = info

    return all_exports


def load_existing_db(path: Path) -> set:
    """Mevcut combined DB'den key set'i yukle.

    Combined DB formati:
      {"signatures": [{"name": "func", "library": "lib", ...}, ...]}
    veya:
      {"signatures": {"func": {...}, ...}}
    """
    if not path.exists():
        return set()
    try:
        with open(path) as f:
            data = json.load(f)
        sigs = data.get("signatures", {})
        if isinstance(sigs, dict):
            return set(sigs.keys())
        elif isinstance(sigs, list):
            # List of dicts with "name" key
            return {item["name"] for item in sigs if isinstance(item, dict) and "name" in item}
        return set()
    except Exception as e:
        print(f"  [WARN] Mevcut DB okunamiyor: {e}")
        return set()


def main():
    print("=" * 60)
    print("Karadul Signature Generator: Wine + ReactOS DLL Exports")
    print("=" * 60)

    # 1. Clone repos
    print("\n[1/5] Repo'lar klonlaniyor...")
    wine_ok = clone_repo(WINE_REPO, WINE_DIR)
    reactos_ok = clone_repo(REACTOS_REPO, REACTOS_DIR)

    if not wine_ok and not reactos_ok:
        print("[FATAL] Hicbir repo klonlanamadi!")
        sys.exit(1)

    # 2. Parse exports
    print("\n[2/5] Export'lar parse ediliyor...")
    all_sigs = {}

    if wine_ok:
        wine_exports = collect_wine_exports(WINE_DIR)
        print(f"  Wine: {len(wine_exports)} export cikarildi")
        all_sigs.update(wine_exports)

    if reactos_ok:
        reactos_exports = collect_reactos_exports(REACTOS_DIR)
        print(f"  ReactOS: {len(reactos_exports)} export cikarildi")
        # ReactOS sadece Wine'da olmayanlar icin
        before = len(all_sigs)
        for name, info in reactos_exports.items():
            if name not in all_sigs:
                all_sigs[name] = info
        print(f"  ReactOS net ek: {len(all_sigs) - before}")

    print(f"\n  TOPLAM (Wine + ReactOS merged): {len(all_sigs)}")

    # 3. Dedup vs mevcut DB
    print("\n[3/5] Mevcut DB ile dedup kontrolu...")
    existing_keys = load_existing_db(COMBINED_DB)
    net_new = {k: v for k, v in all_sigs.items() if k not in existing_keys}
    already = len(all_sigs) - len(net_new)
    print(f"  Mevcut DB'de zaten var: {already}")
    print(f"  Net new (yeni): {len(net_new)}")

    # 4. Save
    print("\n[4/5] Kaydediliyor...")
    output_data = {
        "meta": {
            "generator": "karadul-sig-gen-wine",
            "date": str(date.today()),
            "source": "Wine + ReactOS DLL exports",
            "total_exports": len(all_sigs),
            "net_new_vs_combined": len(net_new),
        },
        "signatures": all_sigs,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    file_size_mb = OUTPUT.stat().st_size / (1024 * 1024)
    print(f"  Kaydedildi: {OUTPUT}")
    print(f"  Dosya boyutu: {file_size_mb:.1f} MB")

    # 5. Stats
    print("\n[5/5] Istatistikler:")
    # Kategori dagilimi
    cat_counts = {}
    for info in all_sigs.values():
        cat = info["category"]
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat:20s}: {count:6d}")

    # DLL dagilimi (top 20)
    lib_counts = {}
    for info in all_sigs.values():
        lib = info["lib"]
        lib_counts[lib] = lib_counts.get(lib, 0) + 1

    print(f"\n  Top 20 DLL (toplam {len(lib_counts)} farkli DLL):")
    for lib, count in sorted(lib_counts.items(), key=lambda x: -x[1])[:20]:
        print(f"    {lib:30s}: {count:5d}")

    # Purpose coverage
    with_purpose = sum(1 for v in all_sigs.values() if v["purpose"])
    print(f"\n  Purpose coverage: {with_purpose}/{len(all_sigs)} ({100*with_purpose/max(len(all_sigs),1):.1f}%)")

    # Cleanup
    print("\n[CLEANUP] /tmp/ repo'lari siliniyor...")
    if WINE_DIR.exists():
        shutil.rmtree(WINE_DIR, ignore_errors=True)
        print(f"  {WINE_DIR} silindi")
    if REACTOS_DIR.exists():
        shutil.rmtree(REACTOS_DIR, ignore_errors=True)
        print(f"  {REACTOS_DIR} silindi")

    print("\n[DONE]")
    print(f"  Toplam export: {len(all_sigs)}")
    print(f"  Net new: {len(net_new)}")
    print(f"  Cikti: {OUTPUT}")


if __name__ == "__main__":
    main()
