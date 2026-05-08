"""Windows API category signatures (sig_db Faz A4).

Windows API category signatures - sig_db Faz A4 migrasyonu (ADR 0007).

Kaynak: karadul/analyzers/signature_db.py
  - _WIN32_KERNEL32_SIGNATURES       (60 entry,  satir 3937-4019)
  - _WIN32_WS2_32_SIGNATURES         (19 entry,  satir 4026-4057)
  - _WIN32_ADVAPI32_SIGNATURES       (20 entry,  satir 4065-4093)
  - _WIN32_USER32_GDI32_SIGNATURES   (23 entry,  satir 4101-4138)
  - _WIN32_NTDLL_SIGNATURES          (14 entry,  satir 4146-4170)
  - _WIN32_EXT_SIGNATURES            (373 entry, satir 4890-5323)

Toplam: 509 signature.

ADR 0007 v1.13 Dalga 2 Faz A4 - Grup "Windows API". Veri parity testleri
``tests/test_sigdb_windows_api_extended_migration.py`` icinde dogrulanir.

Bu modul signature_db.py'a dokunmadan calisir; signature_db.py icindeki
orijinal _WIN32_* dict'leri SILINMEMISTIR (rollback / shadow legacy bandi
korunur). v1.13 sonrasi Faz A-DELETE'te legacy gövdeler dismantle edilir.

Anahtar isimleri orijinal dict adlariyla uyumludur:
  ``win32_kernel32_signatures``      <-> ``_WIN32_KERNEL32_SIGNATURES``
  ``win32_ws2_32_signatures``        <-> ``_WIN32_WS2_32_SIGNATURES``
  ``win32_advapi32_signatures``      <-> ``_WIN32_ADVAPI32_SIGNATURES``
  ``win32_user32_gdi32_signatures``  <-> ``_WIN32_USER32_GDI32_SIGNATURES``
  ``win32_ntdll_signatures``         <-> ``_WIN32_NTDLL_SIGNATURES``
  ``win32_ext_signatures``           <-> ``_WIN32_EXT_SIGNATURES``
"""

from __future__ import annotations

from typing import Any



# -------------------------------------------------------------------------
# kernel32 (60 entry) - File I/O, Process, Memory, Thread, Sync, Module,
# Error, System info, Timing, Debug. Kaynak: signature_db.py satir 3937-4019.
# -------------------------------------------------------------------------
_WIN32_KERNEL32_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # File I/O
    "CreateFileA": {"lib": "kernel32", "purpose": "open/create file (ANSI)", "category": "win_file"},
    "CreateFileW": {"lib": "kernel32", "purpose": "open/create file (Unicode)", "category": "win_file"},
    "ReadFile": {"lib": "kernel32", "purpose": "read data from file or I/O device", "category": "win_file"},
    "WriteFile": {"lib": "kernel32", "purpose": "write data to file or I/O device", "category": "win_file"},
    "CloseHandle": {"lib": "kernel32", "purpose": "close an open object handle", "category": "win_file"},

    # Process management
    "CreateProcessA": {"lib": "kernel32", "purpose": "create new process (ANSI)", "category": "win_process"},
    "CreateProcessW": {"lib": "kernel32", "purpose": "create new process (Unicode)", "category": "win_process"},
    "TerminateProcess": {"lib": "kernel32", "purpose": "terminate a process", "category": "win_process"},
    "ExitProcess": {"lib": "kernel32", "purpose": "end calling process and all threads", "category": "win_process"},
    "GetExitCodeProcess": {"lib": "kernel32", "purpose": "get termination status of process", "category": "win_process"},

    # Virtual memory
    "VirtualAlloc": {"lib": "kernel32", "purpose": "reserve/commit virtual memory pages", "category": "win_memory"},
    "VirtualFree": {"lib": "kernel32", "purpose": "release/decommit virtual memory pages", "category": "win_memory"},
    "VirtualProtect": {"lib": "kernel32", "purpose": "change access protection on memory pages", "category": "win_memory"},
    "VirtualQuery": {"lib": "kernel32", "purpose": "query information about memory pages", "category": "win_memory"},

    # Heap
    "HeapCreate": {"lib": "kernel32", "purpose": "create private heap object", "category": "win_memory"},
    "HeapDestroy": {"lib": "kernel32", "purpose": "destroy private heap object", "category": "win_memory"},
    "HeapAlloc": {"lib": "kernel32", "purpose": "allocate memory block from heap", "category": "win_memory"},
    "HeapReAlloc": {"lib": "kernel32", "purpose": "reallocate memory block from heap", "category": "win_memory"},
    "HeapFree": {"lib": "kernel32", "purpose": "free memory block allocated from heap", "category": "win_memory"},

    # Thread management
    "CreateThread": {"lib": "kernel32", "purpose": "create new thread in calling process", "category": "win_thread"},
    "ExitThread": {"lib": "kernel32", "purpose": "end calling thread", "category": "win_thread"},
    "SuspendThread": {"lib": "kernel32", "purpose": "suspend a thread", "category": "win_thread"},
    "ResumeThread": {"lib": "kernel32", "purpose": "decrement thread suspend count", "category": "win_thread"},
    "WaitForSingleObject": {"lib": "kernel32", "purpose": "wait until object is signaled or timeout", "category": "win_sync"},
    "WaitForMultipleObjects": {"lib": "kernel32", "purpose": "wait for multiple objects to be signaled", "category": "win_sync"},

    # Synchronization primitives
    "CreateMutexA": {"lib": "kernel32", "purpose": "create named/unnamed mutex (ANSI)", "category": "win_sync"},
    "ReleaseMutex": {"lib": "kernel32", "purpose": "release ownership of mutex", "category": "win_sync"},
    "CreateEventA": {"lib": "kernel32", "purpose": "create named/unnamed event (ANSI)", "category": "win_sync"},
    "SetEvent": {"lib": "kernel32", "purpose": "set event object to signaled state", "category": "win_sync"},
    "ResetEvent": {"lib": "kernel32", "purpose": "set event object to nonsignaled state", "category": "win_sync"},
    "CreateSemaphoreA": {"lib": "kernel32", "purpose": "create named/unnamed semaphore (ANSI)", "category": "win_sync"},
    "ReleaseSemaphore": {"lib": "kernel32", "purpose": "increase semaphore count", "category": "win_sync"},
    "InitializeCriticalSection": {"lib": "kernel32", "purpose": "initialize critical section object", "category": "win_sync"},
    "EnterCriticalSection": {"lib": "kernel32", "purpose": "enter critical section (blocking)", "category": "win_sync"},
    "LeaveCriticalSection": {"lib": "kernel32", "purpose": "leave critical section", "category": "win_sync"},
    "DeleteCriticalSection": {"lib": "kernel32", "purpose": "release critical section resources", "category": "win_sync"},

    # Module / dynamic loading
    "GetModuleHandleA": {"lib": "kernel32", "purpose": "get handle to loaded module (ANSI)", "category": "win_module"},
    "GetModuleHandleW": {"lib": "kernel32", "purpose": "get handle to loaded module (Unicode)", "category": "win_module"},
    "GetProcAddress": {"lib": "kernel32", "purpose": "get address of exported function", "category": "win_module"},
    "LoadLibraryA": {"lib": "kernel32", "purpose": "load DLL into process (ANSI)", "category": "win_module"},
    "LoadLibraryW": {"lib": "kernel32", "purpose": "load DLL into process (Unicode)", "category": "win_module"},
    "FreeLibrary": {"lib": "kernel32", "purpose": "unload DLL from process", "category": "win_module"},

    # Error handling
    "GetLastError": {"lib": "kernel32", "purpose": "get last Win32 error code", "category": "win_error"},
    "SetLastError": {"lib": "kernel32", "purpose": "set last Win32 error code", "category": "win_error"},
    "FormatMessageA": {"lib": "kernel32", "purpose": "format error message string (ANSI)", "category": "win_error"},

    # System info / timing
    "GetSystemInfo": {"lib": "kernel32", "purpose": "get system hardware information", "category": "win_system"},
    "GetVersionExA": {"lib": "kernel32", "purpose": "get OS version information (ANSI)", "category": "win_system"},
    "GetTickCount": {"lib": "kernel32", "purpose": "get milliseconds since system start (32-bit)", "category": "win_time"},
    "GetTickCount64": {"lib": "kernel32", "purpose": "get milliseconds since system start (64-bit)", "category": "win_time"},
    "QueryPerformanceCounter": {"lib": "kernel32", "purpose": "query high-resolution performance counter", "category": "win_time"},
    "QueryPerformanceFrequency": {"lib": "kernel32", "purpose": "get performance counter frequency", "category": "win_time"},
    "Sleep": {"lib": "kernel32", "purpose": "suspend thread execution for milliseconds", "category": "win_time"},
    "SleepEx": {"lib": "kernel32", "purpose": "suspend thread execution (alertable)", "category": "win_time"},

    # Process / thread info
    "GetCurrentProcess": {"lib": "kernel32", "purpose": "get pseudo handle of current process", "category": "win_process"},
    "GetCurrentProcessId": {"lib": "kernel32", "purpose": "get PID of calling process", "category": "win_process"},
    "GetCurrentThread": {"lib": "kernel32", "purpose": "get pseudo handle of current thread", "category": "win_thread"},
    "GetCurrentThreadId": {"lib": "kernel32", "purpose": "get TID of calling thread", "category": "win_thread"},

    # Debug
    "OutputDebugStringA": {"lib": "kernel32", "purpose": "send string to debugger (ANSI)", "category": "win_debug"},
    "IsDebuggerPresent": {"lib": "kernel32", "purpose": "check if process is being debugged", "category": "win_debug"},
    "DebugBreak": {"lib": "kernel32", "purpose": "cause breakpoint exception in process", "category": "win_debug"},
}

# -------------------------------------------------------------------------
# ws2_32 - Winsock (19 entry). Kaynak: signature_db.py satir 4026-4057.
# -------------------------------------------------------------------------
_WIN32_WS2_32_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Startup / cleanup
    "WSAStartup": {"lib": "ws2_32", "purpose": "initialize Winsock DLL", "category": "win_network"},
    "WSACleanup": {"lib": "ws2_32", "purpose": "terminate Winsock DLL usage", "category": "win_network"},
    "WSAGetLastError": {"lib": "ws2_32", "purpose": "get last Winsock error code", "category": "win_network"},

    # Socket basics
    "closesocket": {"lib": "ws2_32", "purpose": "close a socket", "category": "win_network"},

    # Data transfer
    "send": {"lib": "ws2_32", "purpose": "send data on connected socket", "category": "win_network"},
    "recv": {"lib": "ws2_32", "purpose": "receive data from connected socket", "category": "win_network"},
    "sendto": {"lib": "ws2_32", "purpose": "send data to specific destination", "category": "win_network"},
    "recvfrom": {"lib": "ws2_32", "purpose": "receive data and source address", "category": "win_network"},

    # Async / event-based I/O
    "select": {"lib": "ws2_32", "purpose": "monitor sockets for readability/writability", "category": "win_network"},
    "WSAEventSelect": {"lib": "ws2_32", "purpose": "associate event object with network events", "category": "win_network"},
    "WSAWaitForMultipleEvents": {"lib": "ws2_32", "purpose": "wait for multiple Winsock events", "category": "win_network"},

    # Socket control
    "ioctlsocket": {"lib": "ws2_32", "purpose": "control socket I/O mode", "category": "win_network"},
    "getaddrinfo": {"lib": "ws2_32", "purpose": "resolve host/service to address (protocol-independent)", "category": "win_network"},
    "freeaddrinfo": {"lib": "ws2_32", "purpose": "free addrinfo linked list", "category": "win_network"},
    "gethostbyname": {"lib": "ws2_32", "purpose": "resolve hostname to address (deprecated)", "category": "win_network"},

    # Address conversion
    "inet_addr": {"lib": "ws2_32", "purpose": "convert dotted-decimal IPv4 to in_addr", "category": "win_network"},
    "inet_ntoa": {"lib": "ws2_32", "purpose": "convert in_addr to dotted-decimal string", "category": "win_network"},
    "htons": {"lib": "ws2_32", "purpose": "host-to-network byte order (short)", "category": "win_network"},
    "ntohs": {"lib": "ws2_32", "purpose": "network-to-host byte order (short)", "category": "win_network"},
}

# -------------------------------------------------------------------------
# advapi32 (20 entry) - Registry, Token/Privilege, CryptoAPI legacy, Service
# control. Kaynak: signature_db.py satir 4065-4093.
# -------------------------------------------------------------------------
_WIN32_ADVAPI32_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Registry
    "RegOpenKeyExA": {"lib": "advapi32", "purpose": "open registry key (ANSI)", "category": "win_registry"},
    "RegCloseKey": {"lib": "advapi32", "purpose": "close registry key handle", "category": "win_registry"},
    "RegQueryValueExA": {"lib": "advapi32", "purpose": "query registry value data (ANSI)", "category": "win_registry"},
    "RegSetValueExA": {"lib": "advapi32", "purpose": "set registry value data (ANSI)", "category": "win_registry"},
    "RegDeleteValueA": {"lib": "advapi32", "purpose": "delete registry value (ANSI)", "category": "win_registry"},
    "RegCreateKeyExA": {"lib": "advapi32", "purpose": "create or open registry key (ANSI)", "category": "win_registry"},
    "RegEnumKeyExA": {"lib": "advapi32", "purpose": "enumerate registry subkeys (ANSI)", "category": "win_registry"},
    "RegEnumValueA": {"lib": "advapi32", "purpose": "enumerate registry values (ANSI)", "category": "win_registry"},

    # Token / privilege
    "OpenProcessToken": {"lib": "advapi32", "purpose": "open access token of a process", "category": "win_security"},
    "GetTokenInformation": {"lib": "advapi32", "purpose": "query process token information", "category": "win_security"},
    "AdjustTokenPrivileges": {"lib": "advapi32", "purpose": "enable/disable token privileges", "category": "win_security"},
    "LookupPrivilegeValueA": {"lib": "advapi32", "purpose": "look up privilege LUID (ANSI)", "category": "win_security"},

    # Cryptography (legacy CryptoAPI)
    "CryptAcquireContextA": {"lib": "advapi32", "purpose": "acquire handle to crypto provider (ANSI)", "category": "win_crypto"},
    "CryptReleaseContext": {"lib": "advapi32", "purpose": "release crypto provider handle", "category": "win_crypto"},
    "CryptGenRandom": {"lib": "advapi32", "purpose": "generate cryptographic random bytes", "category": "win_crypto"},
    "CryptCreateHash": {"lib": "advapi32", "purpose": "create hash object", "category": "win_crypto"},
    "CryptHashData": {"lib": "advapi32", "purpose": "add data to hash object", "category": "win_crypto"},

    # Service control
    "StartServiceCtrlDispatcherA": {"lib": "advapi32", "purpose": "connect service process to SCM (ANSI)", "category": "win_service"},
    "RegisterServiceCtrlHandlerA": {"lib": "advapi32", "purpose": "register service control handler (ANSI)", "category": "win_service"},
    "SetServiceStatus": {"lib": "advapi32", "purpose": "update service status to SCM", "category": "win_service"},
}

# -------------------------------------------------------------------------
# user32 + gdi32 (23 entry) - Window, Message loop, Class/Procedure, Dialog,
# DC, Timer, Window queries. Kaynak: signature_db.py satir 4101-4138.
# -------------------------------------------------------------------------
_WIN32_USER32_GDI32_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Window management
    "CreateWindowExA": {"lib": "user32", "purpose": "create overlapped/popup/child window (ANSI)", "category": "win_gui"},
    "DestroyWindow": {"lib": "user32", "purpose": "destroy a window", "category": "win_gui"},
    "ShowWindow": {"lib": "user32", "purpose": "set window show state", "category": "win_gui"},
    "UpdateWindow": {"lib": "user32", "purpose": "send WM_PAINT if update region non-empty", "category": "win_gui"},

    # Message loop
    "GetMessageA": {"lib": "user32", "purpose": "retrieve message from queue (ANSI)", "category": "win_msg"},
    "TranslateMessage": {"lib": "user32", "purpose": "translate virtual-key messages to character messages", "category": "win_msg"},
    "DispatchMessageA": {"lib": "user32", "purpose": "dispatch message to window procedure (ANSI)", "category": "win_msg"},
    "PostMessageA": {"lib": "user32", "purpose": "post message to thread message queue (ANSI)", "category": "win_msg"},
    "SendMessageA": {"lib": "user32", "purpose": "send message directly to window procedure (ANSI)", "category": "win_msg"},
    "PostQuitMessage": {"lib": "user32", "purpose": "post WM_QUIT to message queue", "category": "win_msg"},

    # Window class / procedure
    "DefWindowProcA": {"lib": "user32", "purpose": "default window procedure (ANSI)", "category": "win_gui"},
    "RegisterClassExA": {"lib": "user32", "purpose": "register window class (ANSI)", "category": "win_gui"},

    # Dialog
    "MessageBoxA": {"lib": "user32", "purpose": "display modal dialog box (ANSI)", "category": "win_gui"},
    "MessageBoxW": {"lib": "user32", "purpose": "display modal dialog box (Unicode)", "category": "win_gui"},

    # Device context (GDI)
    "GetDC": {"lib": "user32", "purpose": "get device context for window client area", "category": "win_gdi"},
    "ReleaseDC": {"lib": "user32", "purpose": "release device context", "category": "win_gdi"},
    "BeginPaint": {"lib": "user32", "purpose": "prepare window for painting", "category": "win_gdi"},
    "EndPaint": {"lib": "user32", "purpose": "mark end of painting in window", "category": "win_gdi"},

    # Timer
    "SetTimer": {"lib": "user32", "purpose": "create timer with specified interval", "category": "win_gui"},
    "KillTimer": {"lib": "user32", "purpose": "destroy a timer", "category": "win_gui"},

    # Window queries
    "GetDesktopWindow": {"lib": "user32", "purpose": "get handle to desktop window", "category": "win_gui"},
    "GetForegroundWindow": {"lib": "user32", "purpose": "get handle to foreground window", "category": "win_gui"},
    "SetForegroundWindow": {"lib": "user32", "purpose": "bring window to foreground", "category": "win_gui"},
}

# -------------------------------------------------------------------------
# ntdll (14 entry) - Native API, lowest user-mode layer below Win32 subsystem.
# Kaynak: signature_db.py satir 4146-4170.
# -------------------------------------------------------------------------
_WIN32_NTDLL_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # File I/O
    "NtCreateFile": {"lib": "ntdll", "purpose": "native file open/create (below CreateFile)", "category": "win_native"},
    "NtReadFile": {"lib": "ntdll", "purpose": "native file read", "category": "win_native"},
    "NtWriteFile": {"lib": "ntdll", "purpose": "native file write", "category": "win_native"},
    "NtClose": {"lib": "ntdll", "purpose": "native handle close", "category": "win_native"},

    # Virtual memory
    "NtAllocateVirtualMemory": {"lib": "ntdll", "purpose": "native virtual memory allocate", "category": "win_native"},
    "NtFreeVirtualMemory": {"lib": "ntdll", "purpose": "native virtual memory free", "category": "win_native"},
    "NtProtectVirtualMemory": {"lib": "ntdll", "purpose": "native virtual memory protect", "category": "win_native"},

    # System / process info
    "NtQuerySystemInformation": {"lib": "ntdll", "purpose": "query system information classes", "category": "win_native"},
    "NtQueryInformationProcess": {"lib": "ntdll", "purpose": "query process information classes", "category": "win_native"},

    # Unicode string
    "RtlInitUnicodeString": {"lib": "ntdll", "purpose": "initialize UNICODE_STRING structure", "category": "win_native"},
    "RtlFreeUnicodeString": {"lib": "ntdll", "purpose": "free UNICODE_STRING buffer", "category": "win_native"},

    # Thread / process
    "NtCreateThread": {"lib": "ntdll", "purpose": "native thread creation", "category": "win_native"},
    "NtTerminateThread": {"lib": "ntdll", "purpose": "native thread termination", "category": "win_native"},
    "NtTerminateProcess": {"lib": "ntdll", "purpose": "native process termination", "category": "win_native"},
}

# -------------------------------------------------------------------------
# Windows API Extended (373 entry) - kernel32/ws2_32/advapi32/user32/gdi32
# genisletme + crypt32, ole32, oleaut32, shell32, version, comctl32, winhttp,
# wininet, bcrypt, psapi, dbghelp, iphlpapi, secur32.
# Kaynak: signature_db.py satir 4890-5323.
# -------------------------------------------------------------------------
_WIN32_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- kernel32 extended ---
    "CreateFileTransactedW": {"lib": "kernel32", "purpose": "create file within transaction (Unicode)", "category": "win_file"},
    "SetFilePointer": {"lib": "kernel32", "purpose": "move file pointer position", "category": "win_file"},
    "SetFilePointerEx": {"lib": "kernel32", "purpose": "move file pointer (64-bit)", "category": "win_file"},
    "GetFileSize": {"lib": "kernel32", "purpose": "get file size (32-bit)", "category": "win_file"},
    "GetFileSizeEx": {"lib": "kernel32", "purpose": "get file size (64-bit)", "category": "win_file"},
    "SetEndOfFile": {"lib": "kernel32", "purpose": "truncate or extend file at current position", "category": "win_file"},
    "FlushFileBuffers": {"lib": "kernel32", "purpose": "flush file buffers to disk", "category": "win_file"},
    "LockFile": {"lib": "kernel32", "purpose": "lock region of file for exclusive access", "category": "win_file"},
    "UnlockFile": {"lib": "kernel32", "purpose": "unlock previously locked file region", "category": "win_file"},
    "GetFileAttributesA": {"lib": "kernel32", "purpose": "get file attributes (ANSI)", "category": "win_file"},
    "GetFileAttributesW": {"lib": "kernel32", "purpose": "get file attributes (Unicode)", "category": "win_file"},
    "SetFileAttributesA": {"lib": "kernel32", "purpose": "set file attributes (ANSI)", "category": "win_file"},
    "SetFileAttributesW": {"lib": "kernel32", "purpose": "set file attributes (Unicode)", "category": "win_file"},
    "GetFileType": {"lib": "kernel32", "purpose": "determine type of file object", "category": "win_file"},
    "CreateDirectoryA": {"lib": "kernel32", "purpose": "create directory (ANSI)", "category": "win_file"},
    "CreateDirectoryW": {"lib": "kernel32", "purpose": "create directory (Unicode)", "category": "win_file"},
    "RemoveDirectoryA": {"lib": "kernel32", "purpose": "remove empty directory (ANSI)", "category": "win_file"},
    "RemoveDirectoryW": {"lib": "kernel32", "purpose": "remove empty directory (Unicode)", "category": "win_file"},
    "DeleteFileA": {"lib": "kernel32", "purpose": "delete file (ANSI)", "category": "win_file"},
    "DeleteFileW": {"lib": "kernel32", "purpose": "delete file (Unicode)", "category": "win_file"},
    "CopyFileA": {"lib": "kernel32", "purpose": "copy file (ANSI)", "category": "win_file"},
    "CopyFileW": {"lib": "kernel32", "purpose": "copy file (Unicode)", "category": "win_file"},
    "MoveFileA": {"lib": "kernel32", "purpose": "move or rename file (ANSI)", "category": "win_file"},
    "MoveFileW": {"lib": "kernel32", "purpose": "move or rename file (Unicode)", "category": "win_file"},
    "MoveFileExA": {"lib": "kernel32", "purpose": "move file with options (ANSI)", "category": "win_file"},
    "MoveFileExW": {"lib": "kernel32", "purpose": "move file with options (Unicode)", "category": "win_file"},
    "FindFirstFileA": {"lib": "kernel32", "purpose": "start file search (ANSI)", "category": "win_file"},
    "FindFirstFileW": {"lib": "kernel32", "purpose": "start file search (Unicode)", "category": "win_file"},
    "FindNextFileA": {"lib": "kernel32", "purpose": "continue file search (ANSI)", "category": "win_file"},
    "FindNextFileW": {"lib": "kernel32", "purpose": "continue file search (Unicode)", "category": "win_file"},
    "FindClose": {"lib": "kernel32", "purpose": "close file search handle", "category": "win_file"},
    "GetFullPathNameA": {"lib": "kernel32", "purpose": "get full path name (ANSI)", "category": "win_file"},
    "GetFullPathNameW": {"lib": "kernel32", "purpose": "get full path name (Unicode)", "category": "win_file"},
    "GetTempPathA": {"lib": "kernel32", "purpose": "get temporary directory path (ANSI)", "category": "win_file"},
    "GetTempPathW": {"lib": "kernel32", "purpose": "get temporary directory path (Unicode)", "category": "win_file"},
    "GetTempFileNameA": {"lib": "kernel32", "purpose": "create temporary file name (ANSI)", "category": "win_file"},
    "GetTempFileNameW": {"lib": "kernel32", "purpose": "create temporary file name (Unicode)", "category": "win_file"},
    "GetLongPathNameA": {"lib": "kernel32", "purpose": "convert short path to long (ANSI)", "category": "win_file"},
    "GetLongPathNameW": {"lib": "kernel32", "purpose": "convert short path to long (Unicode)", "category": "win_file"},

    # --- kernel32: File mapping ---
    "CreateFileMappingA": {"lib": "kernel32", "purpose": "create file mapping object (ANSI)", "category": "win_memory"},
    "CreateFileMappingW": {"lib": "kernel32", "purpose": "create file mapping object (Unicode)", "category": "win_memory"},
    "MapViewOfFile": {"lib": "kernel32", "purpose": "map view of file into address space", "category": "win_memory"},
    "MapViewOfFileEx": {"lib": "kernel32", "purpose": "map view at specified address", "category": "win_memory"},
    "UnmapViewOfFile": {"lib": "kernel32", "purpose": "unmap view of file from address space", "category": "win_memory"},
    "FlushViewOfFile": {"lib": "kernel32", "purpose": "flush dirty pages of mapped view to disk", "category": "win_memory"},

    # --- kernel32: Interlocked operations ---
    "InterlockedIncrement": {"lib": "kernel32", "purpose": "atomic increment", "category": "win_sync"},
    "InterlockedDecrement": {"lib": "kernel32", "purpose": "atomic decrement", "category": "win_sync"},
    "InterlockedExchange": {"lib": "kernel32", "purpose": "atomic exchange", "category": "win_sync"},
    "InterlockedCompareExchange": {"lib": "kernel32", "purpose": "atomic compare-and-swap", "category": "win_sync"},

    # --- kernel32: Console I/O ---
    "GetStdHandle": {"lib": "kernel32", "purpose": "get standard I/O handle (stdin/stdout/stderr)", "category": "win_io"},
    "WriteConsoleA": {"lib": "kernel32", "purpose": "write to console output buffer (ANSI)", "category": "win_io"},
    "WriteConsoleW": {"lib": "kernel32", "purpose": "write to console output buffer (Unicode)", "category": "win_io"},
    "ReadConsoleA": {"lib": "kernel32", "purpose": "read from console input buffer (ANSI)", "category": "win_io"},
    "ReadConsoleW": {"lib": "kernel32", "purpose": "read from console input buffer (Unicode)", "category": "win_io"},
    "SetConsoleTextAttribute": {"lib": "kernel32", "purpose": "set console text color/attributes", "category": "win_io"},
    "AllocConsole": {"lib": "kernel32", "purpose": "allocate new console for process", "category": "win_io"},
    "FreeConsole": {"lib": "kernel32", "purpose": "detach process from console", "category": "win_io"},

    # --- kernel32: Environment / Path ---
    "GetEnvironmentVariableA": {"lib": "kernel32", "purpose": "get environment variable (ANSI)", "category": "win_system"},
    "GetEnvironmentVariableW": {"lib": "kernel32", "purpose": "get environment variable (Unicode)", "category": "win_system"},
    "SetEnvironmentVariableA": {"lib": "kernel32", "purpose": "set environment variable (ANSI)", "category": "win_system"},
    "SetEnvironmentVariableW": {"lib": "kernel32", "purpose": "set environment variable (Unicode)", "category": "win_system"},
    "GetModuleFileNameA": {"lib": "kernel32", "purpose": "get path of loaded module (ANSI)", "category": "win_module"},
    "GetModuleFileNameW": {"lib": "kernel32", "purpose": "get path of loaded module (Unicode)", "category": "win_module"},
    "GetSystemDirectoryA": {"lib": "kernel32", "purpose": "get system directory path (ANSI)", "category": "win_system"},
    "GetSystemDirectoryW": {"lib": "kernel32", "purpose": "get system directory path (Unicode)", "category": "win_system"},
    "GetWindowsDirectoryA": {"lib": "kernel32", "purpose": "get Windows directory path (ANSI)", "category": "win_system"},
    "GetWindowsDirectoryW": {"lib": "kernel32", "purpose": "get Windows directory path (Unicode)", "category": "win_system"},
    "GetComputerNameA": {"lib": "kernel32", "purpose": "get NetBIOS computer name (ANSI)", "category": "win_system"},
    "GetComputerNameW": {"lib": "kernel32", "purpose": "get NetBIOS computer name (Unicode)", "category": "win_system"},

    # --- kernel32: Thread pool ---
    "CreateThreadpoolWork": {"lib": "kernel32", "purpose": "create thread pool work object", "category": "win_thread"},
    "SubmitThreadpoolWork": {"lib": "kernel32", "purpose": "submit work to thread pool", "category": "win_thread"},
    "CloseThreadpoolWork": {"lib": "kernel32", "purpose": "close thread pool work object", "category": "win_thread"},
    "WaitForThreadpoolWorkCallbacks": {"lib": "kernel32", "purpose": "wait for outstanding thread pool callbacks", "category": "win_thread"},
    "CreateThreadpoolTimer": {"lib": "kernel32", "purpose": "create thread pool timer", "category": "win_thread"},
    "SetThreadpoolTimer": {"lib": "kernel32", "purpose": "set thread pool timer due time", "category": "win_thread"},
    "TlsAlloc": {"lib": "kernel32", "purpose": "allocate thread-local storage index", "category": "win_thread"},
    "TlsFree": {"lib": "kernel32", "purpose": "free thread-local storage index", "category": "win_thread"},
    "TlsGetValue": {"lib": "kernel32", "purpose": "get value in TLS slot", "category": "win_thread"},
    "TlsSetValue": {"lib": "kernel32", "purpose": "set value in TLS slot", "category": "win_thread"},

    # --- kernel32: I/O Completion Ports ---
    "CreateIoCompletionPort": {"lib": "kernel32", "purpose": "create/associate I/O completion port", "category": "win_io"},
    "GetQueuedCompletionStatus": {"lib": "kernel32", "purpose": "dequeue I/O completion packet", "category": "win_io"},
    "PostQueuedCompletionStatus": {"lib": "kernel32", "purpose": "post completion packet to port", "category": "win_io"},
    "GetQueuedCompletionStatusEx": {"lib": "kernel32", "purpose": "dequeue multiple completion packets", "category": "win_io"},

    # --- kernel32: Pipes ---
    "CreatePipe": {"lib": "kernel32", "purpose": "create anonymous pipe", "category": "win_io"},
    "CreateNamedPipeA": {"lib": "kernel32", "purpose": "create named pipe instance (ANSI)", "category": "win_io"},
    "CreateNamedPipeW": {"lib": "kernel32", "purpose": "create named pipe instance (Unicode)", "category": "win_io"},
    "ConnectNamedPipe": {"lib": "kernel32", "purpose": "wait for client to connect to named pipe", "category": "win_io"},
    "DisconnectNamedPipe": {"lib": "kernel32", "purpose": "disconnect server end of named pipe", "category": "win_io"},
    "PeekNamedPipe": {"lib": "kernel32", "purpose": "peek data from named pipe without removing", "category": "win_io"},
    "TransactNamedPipe": {"lib": "kernel32", "purpose": "write then read on named pipe", "category": "win_io"},

    # --- kernel32: Fiber ---
    "ConvertThreadToFiber": {"lib": "kernel32", "purpose": "convert thread to fiber", "category": "win_thread"},
    "CreateFiber": {"lib": "kernel32", "purpose": "create fiber in current thread", "category": "win_thread"},
    "SwitchToFiber": {"lib": "kernel32", "purpose": "switch execution to specified fiber", "category": "win_thread"},
    "DeleteFiber": {"lib": "kernel32", "purpose": "delete fiber", "category": "win_thread"},

    # --- ws2_32 extended ---
    "WSASocketA": {"lib": "ws2_32", "purpose": "create socket with WSA options (ANSI)", "category": "win_network"},
    "WSASocketW": {"lib": "ws2_32", "purpose": "create socket with WSA options (Unicode)", "category": "win_network"},
    "WSAConnect": {"lib": "ws2_32", "purpose": "establish connection with WSA extensions", "category": "win_network"},
    "WSASend": {"lib": "ws2_32", "purpose": "send data using overlapped I/O", "category": "win_network"},
    "WSARecv": {"lib": "ws2_32", "purpose": "receive data using overlapped I/O", "category": "win_network"},
    "WSASendTo": {"lib": "ws2_32", "purpose": "send datagram using overlapped I/O", "category": "win_network"},
    "WSARecvFrom": {"lib": "ws2_32", "purpose": "receive datagram using overlapped I/O", "category": "win_network"},
    "WSAIoctl": {"lib": "ws2_32", "purpose": "control socket I/O mode (extended)", "category": "win_network"},
    "WSAAsyncSelect": {"lib": "ws2_32", "purpose": "request async notification for socket events", "category": "win_network"},
    "WSAEnumNetworkEvents": {"lib": "ws2_32", "purpose": "enumerate network events for socket", "category": "win_network"},
    "WSAAddressToStringA": {"lib": "ws2_32", "purpose": "convert socket address to string (ANSI)", "category": "win_network"},
    "WSAStringToAddressA": {"lib": "ws2_32", "purpose": "convert string to socket address (ANSI)", "category": "win_network"},
    "InetPtonW": {"lib": "ws2_32", "purpose": "convert IP string to binary (Unicode)", "category": "win_network"},
    "InetNtopW": {"lib": "ws2_32", "purpose": "convert binary IP to string (Unicode)", "category": "win_network"},

    # --- advapi32 extended ---
    "RegOpenKeyExW": {"lib": "advapi32", "purpose": "open registry key (Unicode)", "category": "win_registry"},
    "RegQueryValueExW": {"lib": "advapi32", "purpose": "query registry value data (Unicode)", "category": "win_registry"},
    "RegSetValueExW": {"lib": "advapi32", "purpose": "set registry value data (Unicode)", "category": "win_registry"},
    "RegDeleteValueW": {"lib": "advapi32", "purpose": "delete registry value (Unicode)", "category": "win_registry"},
    "RegDeleteKeyExA": {"lib": "advapi32", "purpose": "delete registry key (ANSI, 64-bit aware)", "category": "win_registry"},
    "RegDeleteKeyExW": {"lib": "advapi32", "purpose": "delete registry key (Unicode, 64-bit aware)", "category": "win_registry"},
    "RegCreateKeyExW": {"lib": "advapi32", "purpose": "create or open registry key (Unicode)", "category": "win_registry"},
    "RegEnumKeyExW": {"lib": "advapi32", "purpose": "enumerate registry subkeys (Unicode)", "category": "win_registry"},
    "RegEnumValueW": {"lib": "advapi32", "purpose": "enumerate registry values (Unicode)", "category": "win_registry"},
    "RegNotifyChangeKeyValue": {"lib": "advapi32", "purpose": "notify on registry key change", "category": "win_registry"},
    "RegFlushKey": {"lib": "advapi32", "purpose": "flush registry key to disk", "category": "win_registry"},
    "RegLoadKeyA": {"lib": "advapi32", "purpose": "load registry hive from file (ANSI)", "category": "win_registry"},
    "RegUnLoadKeyA": {"lib": "advapi32", "purpose": "unload registry hive (ANSI)", "category": "win_registry"},
    "RegSaveKeyA": {"lib": "advapi32", "purpose": "save registry key to file (ANSI)", "category": "win_registry"},
    "RegRestoreKeyA": {"lib": "advapi32", "purpose": "restore registry key from file (ANSI)", "category": "win_registry"},

    # --- advapi32: Security extended ---
    "OpenThreadToken": {"lib": "advapi32", "purpose": "open access token of thread", "category": "win_security"},
    "DuplicateToken": {"lib": "advapi32", "purpose": "duplicate access token", "category": "win_security"},
    "DuplicateTokenEx": {"lib": "advapi32", "purpose": "duplicate token with options", "category": "win_security"},
    "ImpersonateLoggedOnUser": {"lib": "advapi32", "purpose": "impersonate logged-on user token", "category": "win_security"},
    "RevertToSelf": {"lib": "advapi32", "purpose": "stop impersonation", "category": "win_security"},
    "LogonUserA": {"lib": "advapi32", "purpose": "logon user to obtain token (ANSI)", "category": "win_security"},
    "LogonUserW": {"lib": "advapi32", "purpose": "logon user to obtain token (Unicode)", "category": "win_security"},
    "CreateProcessAsUserA": {"lib": "advapi32", "purpose": "create process as another user (ANSI)", "category": "win_security"},
    "CreateProcessAsUserW": {"lib": "advapi32", "purpose": "create process as another user (Unicode)", "category": "win_security"},
    "CreateServiceA": {"lib": "advapi32", "purpose": "create Windows service (ANSI)", "category": "win_service"},
    "CreateServiceW": {"lib": "advapi32", "purpose": "create Windows service (Unicode)", "category": "win_service"},
    "OpenServiceA": {"lib": "advapi32", "purpose": "open existing service (ANSI)", "category": "win_service"},
    "OpenServiceW": {"lib": "advapi32", "purpose": "open existing service (Unicode)", "category": "win_service"},
    "OpenSCManagerA": {"lib": "advapi32", "purpose": "open service control manager (ANSI)", "category": "win_service"},
    "OpenSCManagerW": {"lib": "advapi32", "purpose": "open service control manager (Unicode)", "category": "win_service"},
    "StartServiceA": {"lib": "advapi32", "purpose": "start a service (ANSI)", "category": "win_service"},
    "ControlService": {"lib": "advapi32", "purpose": "send control code to service", "category": "win_service"},
    "DeleteService": {"lib": "advapi32", "purpose": "mark service for deletion", "category": "win_service"},
    "QueryServiceStatusEx": {"lib": "advapi32", "purpose": "query extended service status", "category": "win_service"},
    "ChangeServiceConfigA": {"lib": "advapi32", "purpose": "change service configuration (ANSI)", "category": "win_service"},
    "CryptEncrypt": {"lib": "advapi32", "purpose": "encrypt data (CryptoAPI)", "category": "win_crypto"},
    "CryptDecrypt": {"lib": "advapi32", "purpose": "decrypt data (CryptoAPI)", "category": "win_crypto"},
    "CryptGetHashParam": {"lib": "advapi32", "purpose": "get hash parameter value", "category": "win_crypto"},
    "CryptSignHashA": {"lib": "advapi32", "purpose": "sign hash value (ANSI)", "category": "win_crypto"},
    "CryptVerifySignatureA": {"lib": "advapi32", "purpose": "verify hash signature (ANSI)", "category": "win_crypto"},
    "CryptImportKey": {"lib": "advapi32", "purpose": "import crypto key from blob", "category": "win_crypto"},
    "CryptExportKey": {"lib": "advapi32", "purpose": "export crypto key to blob", "category": "win_crypto"},
    "CryptGenKey": {"lib": "advapi32", "purpose": "generate random crypto key", "category": "win_crypto"},
    "CryptDestroyKey": {"lib": "advapi32", "purpose": "destroy crypto key handle", "category": "win_crypto"},
    "CryptDestroyHash": {"lib": "advapi32", "purpose": "destroy hash object handle", "category": "win_crypto"},
    "CryptDeriveKey": {"lib": "advapi32", "purpose": "derive key from password hash", "category": "win_crypto"},

    # --- advapi32: Event log ---
    "OpenEventLogA": {"lib": "advapi32", "purpose": "open event log (ANSI)", "category": "win_eventlog"},
    "CloseEventLog": {"lib": "advapi32", "purpose": "close event log handle", "category": "win_eventlog"},
    "ReadEventLogA": {"lib": "advapi32", "purpose": "read event log entries (ANSI)", "category": "win_eventlog"},
    "ReportEventA": {"lib": "advapi32", "purpose": "write event log entry (ANSI)", "category": "win_eventlog"},

    # --- user32 extended ---
    "CreateWindowExW": {"lib": "user32", "purpose": "create window (Unicode)", "category": "win_gui"},
    "RegisterClassExW": {"lib": "user32", "purpose": "register window class (Unicode)", "category": "win_gui"},
    "DefWindowProcW": {"lib": "user32", "purpose": "default window procedure (Unicode)", "category": "win_gui"},
    "GetMessageW": {"lib": "user32", "purpose": "retrieve message from queue (Unicode)", "category": "win_msg"},
    "PeekMessageA": {"lib": "user32", "purpose": "peek at message without removing (ANSI)", "category": "win_msg"},
    "PeekMessageW": {"lib": "user32", "purpose": "peek at message without removing (Unicode)", "category": "win_msg"},
    "DispatchMessageW": {"lib": "user32", "purpose": "dispatch message to window procedure (Unicode)", "category": "win_msg"},
    "PostMessageW": {"lib": "user32", "purpose": "post message to thread queue (Unicode)", "category": "win_msg"},
    "SendMessageW": {"lib": "user32", "purpose": "send message to window procedure (Unicode)", "category": "win_msg"},
    "GetWindowTextA": {"lib": "user32", "purpose": "get window title bar text (ANSI)", "category": "win_gui"},
    "GetWindowTextW": {"lib": "user32", "purpose": "get window title bar text (Unicode)", "category": "win_gui"},
    "SetWindowTextA": {"lib": "user32", "purpose": "set window title bar text (ANSI)", "category": "win_gui"},
    "SetWindowTextW": {"lib": "user32", "purpose": "set window title bar text (Unicode)", "category": "win_gui"},
    "GetWindowRect": {"lib": "user32", "purpose": "get window bounding rectangle", "category": "win_gui"},
    "GetClientRect": {"lib": "user32", "purpose": "get window client area rectangle", "category": "win_gui"},
    "MoveWindow": {"lib": "user32", "purpose": "change window position and size", "category": "win_gui"},
    "SetWindowPos": {"lib": "user32", "purpose": "change size/position/Z-order", "category": "win_gui"},
    "EnumWindows": {"lib": "user32", "purpose": "enumerate all top-level windows", "category": "win_gui"},
    "FindWindowA": {"lib": "user32", "purpose": "find window by class and title (ANSI)", "category": "win_gui"},
    "FindWindowW": {"lib": "user32", "purpose": "find window by class and title (Unicode)", "category": "win_gui"},
    "GetWindowLongA": {"lib": "user32", "purpose": "get window attribute (ANSI)", "category": "win_gui"},
    "SetWindowLongA": {"lib": "user32", "purpose": "set window attribute (ANSI)", "category": "win_gui"},
    "GetClassNameA": {"lib": "user32", "purpose": "get window class name (ANSI)", "category": "win_gui"},
    "IsWindow": {"lib": "user32", "purpose": "check if handle is valid window", "category": "win_gui"},
    "IsWindowVisible": {"lib": "user32", "purpose": "check if window is visible", "category": "win_gui"},
    "EnableWindow": {"lib": "user32", "purpose": "enable or disable window input", "category": "win_gui"},

    # --- user32: Clipboard ---
    "OpenClipboard": {"lib": "user32", "purpose": "open clipboard for examination", "category": "win_clipboard"},
    "CloseClipboard": {"lib": "user32", "purpose": "close clipboard", "category": "win_clipboard"},
    "GetClipboardData": {"lib": "user32", "purpose": "retrieve clipboard data", "category": "win_clipboard"},
    "SetClipboardData": {"lib": "user32", "purpose": "place data on clipboard", "category": "win_clipboard"},
    "EmptyClipboard": {"lib": "user32", "purpose": "empty clipboard contents", "category": "win_clipboard"},

    # --- user32: Input ---
    "GetAsyncKeyState": {"lib": "user32", "purpose": "check if key is pressed (async)", "category": "win_input"},
    "GetKeyState": {"lib": "user32", "purpose": "get key state from message queue", "category": "win_input"},
    "keybd_event": {"lib": "user32", "purpose": "synthesize keyboard input (deprecated)", "category": "win_input"},
    "mouse_event": {"lib": "user32", "purpose": "synthesize mouse input (deprecated)", "category": "win_input"},
    "SendInput": {"lib": "user32", "purpose": "synthesize keyboard/mouse input", "category": "win_input"},
    "SetWindowsHookExA": {"lib": "user32", "purpose": "install hook procedure (ANSI)", "category": "win_hook"},
    "SetWindowsHookExW": {"lib": "user32", "purpose": "install hook procedure (Unicode)", "category": "win_hook"},
    "UnhookWindowsHookEx": {"lib": "user32", "purpose": "remove hook procedure", "category": "win_hook"},
    "CallNextHookEx": {"lib": "user32", "purpose": "pass hook info to next procedure", "category": "win_hook"},
    "GetCursorPos": {"lib": "user32", "purpose": "get cursor position", "category": "win_input"},
    "SetCursorPos": {"lib": "user32", "purpose": "set cursor position", "category": "win_input"},

    # --- gdi32 ---
    "CreateCompatibleDC": {"lib": "gdi32", "purpose": "create memory device context", "category": "win_gdi"},
    "CreateCompatibleBitmap": {"lib": "gdi32", "purpose": "create bitmap compatible with DC", "category": "win_gdi"},
    "SelectObject": {"lib": "gdi32", "purpose": "select GDI object into DC", "category": "win_gdi"},
    "DeleteObject": {"lib": "gdi32", "purpose": "delete GDI object", "category": "win_gdi"},
    "DeleteDC": {"lib": "gdi32", "purpose": "delete device context", "category": "win_gdi"},
    "BitBlt": {"lib": "gdi32", "purpose": "bit-block transfer between DCs", "category": "win_gdi"},
    "StretchBlt": {"lib": "gdi32", "purpose": "stretch bit-block transfer", "category": "win_gdi"},
    "CreateFontA": {"lib": "gdi32", "purpose": "create logical font (ANSI)", "category": "win_gdi"},
    "CreateFontW": {"lib": "gdi32", "purpose": "create logical font (Unicode)", "category": "win_gdi"},
    "TextOutA": {"lib": "gdi32", "purpose": "draw text string at position (ANSI)", "category": "win_gdi"},
    "TextOutW": {"lib": "gdi32", "purpose": "draw text string at position (Unicode)", "category": "win_gdi"},
    "CreatePen": {"lib": "gdi32", "purpose": "create GDI pen object", "category": "win_gdi"},
    "CreateSolidBrush": {"lib": "gdi32", "purpose": "create solid color brush", "category": "win_gdi"},
    "Rectangle": {"lib": "gdi32", "purpose": "draw rectangle", "category": "win_gdi"},
    "Ellipse": {"lib": "gdi32", "purpose": "draw ellipse", "category": "win_gdi"},
    "LineTo": {"lib": "gdi32", "purpose": "draw line from current position", "category": "win_gdi"},
    "MoveToEx": {"lib": "gdi32", "purpose": "move current position", "category": "win_gdi"},
    "SetPixel": {"lib": "gdi32", "purpose": "set pixel color at point", "category": "win_gdi"},
    "GetPixel": {"lib": "gdi32", "purpose": "get pixel color at point", "category": "win_gdi"},
    "GetDeviceCaps": {"lib": "gdi32", "purpose": "get device capability value", "category": "win_gdi"},

    # --- ntdll extended ---
    "NtOpenProcess": {"lib": "ntdll", "purpose": "native open process by PID", "category": "win_native"},
    "NtOpenThread": {"lib": "ntdll", "purpose": "native open thread by TID", "category": "win_native"},
    "NtQueryVirtualMemory": {"lib": "ntdll", "purpose": "query virtual memory region info", "category": "win_native"},
    "NtCreateSection": {"lib": "ntdll", "purpose": "create section object (file mapping)", "category": "win_native"},
    "NtMapViewOfSection": {"lib": "ntdll", "purpose": "native map section view", "category": "win_native"},
    "NtUnmapViewOfSection": {"lib": "ntdll", "purpose": "native unmap section view", "category": "win_native"},
    "NtSetInformationThread": {"lib": "ntdll", "purpose": "set thread information class", "category": "win_native"},
    "NtQueryInformationThread": {"lib": "ntdll", "purpose": "query thread information class", "category": "win_native"},
    "NtSetInformationProcess": {"lib": "ntdll", "purpose": "set process information class", "category": "win_native"},
    "NtDelayExecution": {"lib": "ntdll", "purpose": "native sleep (NtDelayExecution)", "category": "win_native"},
    "NtWaitForSingleObject": {"lib": "ntdll", "purpose": "native wait for object", "category": "win_native"},
    "NtSignalAndWaitForSingleObject": {"lib": "ntdll", "purpose": "signal object and wait atomically", "category": "win_native"},
    "NtCreateEvent": {"lib": "ntdll", "purpose": "native create event object", "category": "win_native"},
    "NtCreateMutant": {"lib": "ntdll", "purpose": "native create mutex object", "category": "win_native"},
    "NtQueryObject": {"lib": "ntdll", "purpose": "query object attributes", "category": "win_native"},
    "NtDuplicateObject": {"lib": "ntdll", "purpose": "duplicate handle between processes", "category": "win_native"},
    "NtQueryDirectoryFile": {"lib": "ntdll", "purpose": "native directory enumeration", "category": "win_native"},
    "NtDeviceIoControlFile": {"lib": "ntdll", "purpose": "native device I/O control", "category": "win_native"},
    "NtCreateKey": {"lib": "ntdll", "purpose": "native create registry key", "category": "win_native"},
    "NtOpenKey": {"lib": "ntdll", "purpose": "native open registry key", "category": "win_native"},
    "NtQueryValueKey": {"lib": "ntdll", "purpose": "native query registry value", "category": "win_native"},
    "NtSetValueKey": {"lib": "ntdll", "purpose": "native set registry value", "category": "win_native"},
    "LdrLoadDll": {"lib": "ntdll", "purpose": "native DLL loading (below LoadLibrary)", "category": "win_native"},
    "LdrGetProcedureAddress": {"lib": "ntdll", "purpose": "native export resolution (below GetProcAddress)", "category": "win_native"},
    "LdrGetDllHandle": {"lib": "ntdll", "purpose": "native get DLL base address", "category": "win_native"},
    "RtlCreateUserThread": {"lib": "ntdll", "purpose": "create thread in target process", "category": "win_native"},
    "RtlCopyMemory": {"lib": "ntdll", "purpose": "copy memory block", "category": "win_native"},
    "RtlZeroMemory": {"lib": "ntdll", "purpose": "zero memory block", "category": "win_native"},
    "RtlMoveMemory": {"lib": "ntdll", "purpose": "move memory block (overlap-safe)", "category": "win_native"},
    "RtlCompareMemory": {"lib": "ntdll", "purpose": "compare memory blocks", "category": "win_native"},
    "NtSystemDebugControl": {"lib": "ntdll", "purpose": "kernel debug control operations", "category": "win_native"},

    # --- shell32 ---
    "ShellExecuteA": {"lib": "shell32", "purpose": "open/run file or URL (ANSI)", "category": "win_shell"},
    "ShellExecuteW": {"lib": "shell32", "purpose": "open/run file or URL (Unicode)", "category": "win_shell"},
    "ShellExecuteExA": {"lib": "shell32", "purpose": "extended shell execute (ANSI)", "category": "win_shell"},
    "ShellExecuteExW": {"lib": "shell32", "purpose": "extended shell execute (Unicode)", "category": "win_shell"},
    "SHGetFolderPathA": {"lib": "shell32", "purpose": "get special folder path (ANSI)", "category": "win_shell"},
    "SHGetFolderPathW": {"lib": "shell32", "purpose": "get special folder path (Unicode)", "category": "win_shell"},
    "SHGetKnownFolderPath": {"lib": "shell32", "purpose": "get known folder path (Vista+)", "category": "win_shell"},
    "SHCreateDirectoryExA": {"lib": "shell32", "purpose": "create directory tree (ANSI)", "category": "win_shell"},
    "SHFileOperationA": {"lib": "shell32", "purpose": "copy/move/rename/delete files (ANSI)", "category": "win_shell"},
    "SHFileOperationW": {"lib": "shell32", "purpose": "copy/move/rename/delete files (Unicode)", "category": "win_shell"},
    "DragQueryFileA": {"lib": "shell32", "purpose": "get dropped file path (ANSI)", "category": "win_shell"},
    "SHBrowseForFolderA": {"lib": "shell32", "purpose": "display folder browser dialog (ANSI)", "category": "win_shell"},
    "SHGetPathFromIDListA": {"lib": "shell32", "purpose": "convert PIDL to path (ANSI)", "category": "win_shell"},

    # --- ole32 / COM ---
    "CoInitialize": {"lib": "ole32", "purpose": "initialize COM library (STA)", "category": "win_com"},
    "CoInitializeEx": {"lib": "ole32", "purpose": "initialize COM library with concurrency model", "category": "win_com"},
    "CoUninitialize": {"lib": "ole32", "purpose": "uninitialize COM library", "category": "win_com"},
    "CoCreateInstance": {"lib": "ole32", "purpose": "create COM object instance", "category": "win_com"},
    "CoGetClassObject": {"lib": "ole32", "purpose": "get COM class factory", "category": "win_com"},
    "CoTaskMemAlloc": {"lib": "ole32", "purpose": "allocate COM task memory", "category": "win_com"},
    "CoTaskMemFree": {"lib": "ole32", "purpose": "free COM task memory", "category": "win_com"},
    "CoMarshalInterThreadInterfaceInStream": {"lib": "ole32", "purpose": "marshal COM interface across threads", "category": "win_com"},
    "StringFromCLSID": {"lib": "ole32", "purpose": "convert CLSID to string", "category": "win_com"},
    "CLSIDFromString": {"lib": "ole32", "purpose": "convert string to CLSID", "category": "win_com"},
    "StringFromGUID2": {"lib": "ole32", "purpose": "convert GUID to string", "category": "win_com"},

    # --- oleaut32 ---
    "SysAllocString": {"lib": "oleaut32", "purpose": "allocate BSTR string", "category": "win_com"},
    "SysFreeString": {"lib": "oleaut32", "purpose": "free BSTR string", "category": "win_com"},
    "SysStringLen": {"lib": "oleaut32", "purpose": "get BSTR length", "category": "win_com"},
    "VariantInit": {"lib": "oleaut32", "purpose": "initialize VARIANT structure", "category": "win_com"},
    "VariantClear": {"lib": "oleaut32", "purpose": "clear VARIANT and release resources", "category": "win_com"},
    "VariantChangeType": {"lib": "oleaut32", "purpose": "convert VARIANT to different type", "category": "win_com"},
    "SafeArrayCreate": {"lib": "oleaut32", "purpose": "create OLE safe array", "category": "win_com"},
    "SafeArrayDestroy": {"lib": "oleaut32", "purpose": "destroy OLE safe array", "category": "win_com"},
    "SafeArrayAccessData": {"lib": "oleaut32", "purpose": "lock safe array and get data pointer", "category": "win_com"},
    "SafeArrayUnaccessData": {"lib": "oleaut32", "purpose": "unlock safe array", "category": "win_com"},

    # --- crypt32 ---
    "CertOpenStore": {"lib": "crypt32", "purpose": "open certificate store", "category": "win_crypto"},
    "CertCloseStore": {"lib": "crypt32", "purpose": "close certificate store", "category": "win_crypto"},
    "CertFindCertificateInStore": {"lib": "crypt32", "purpose": "find certificate in store", "category": "win_crypto"},
    "CertGetCertificateChain": {"lib": "crypt32", "purpose": "build certificate chain", "category": "win_crypto"},
    "CertVerifyCertificateChainPolicy": {"lib": "crypt32", "purpose": "verify certificate chain policy", "category": "win_crypto"},
    "CertFreeCertificateContext": {"lib": "crypt32", "purpose": "free certificate context", "category": "win_crypto"},
    "CertDuplicateCertificateContext": {"lib": "crypt32", "purpose": "duplicate certificate context", "category": "win_crypto"},
    "CryptStringToBinaryA": {"lib": "crypt32", "purpose": "decode base64/hex string to binary (ANSI)", "category": "win_crypto"},
    "CryptBinaryToStringA": {"lib": "crypt32", "purpose": "encode binary to base64/hex string (ANSI)", "category": "win_crypto"},
    "CryptDecodeObjectEx": {"lib": "crypt32", "purpose": "decode ASN.1 structure", "category": "win_crypto"},
    "CryptEncodeObjectEx": {"lib": "crypt32", "purpose": "encode to ASN.1 structure", "category": "win_crypto"},
    "CryptProtectData": {"lib": "crypt32", "purpose": "encrypt data using DPAPI", "category": "win_crypto"},
    "CryptUnprotectData": {"lib": "crypt32", "purpose": "decrypt DPAPI-protected data", "category": "win_crypto"},
    "PFXImportCertStore": {"lib": "crypt32", "purpose": "import PFX/PKCS#12 certificate", "category": "win_crypto"},
    "PFXExportCertStoreEx": {"lib": "crypt32", "purpose": "export certificate store as PFX", "category": "win_crypto"},

    # --- bcrypt (CNG - Cryptography Next Generation) ---
    "BCryptOpenAlgorithmProvider": {"lib": "bcrypt", "purpose": "open CNG algorithm provider", "category": "win_crypto"},
    "BCryptCloseAlgorithmProvider": {"lib": "bcrypt", "purpose": "close CNG algorithm provider", "category": "win_crypto"},
    "BCryptGenerateSymmetricKey": {"lib": "bcrypt", "purpose": "generate CNG symmetric key", "category": "win_crypto"},
    "BCryptEncrypt": {"lib": "bcrypt", "purpose": "CNG symmetric encryption", "category": "win_crypto"},
    "BCryptDecrypt": {"lib": "bcrypt", "purpose": "CNG symmetric decryption", "category": "win_crypto"},
    "BCryptCreateHash": {"lib": "bcrypt", "purpose": "create CNG hash object", "category": "win_crypto"},
    "BCryptHashData": {"lib": "bcrypt", "purpose": "add data to CNG hash", "category": "win_crypto"},
    "BCryptFinishHash": {"lib": "bcrypt", "purpose": "finalize CNG hash computation", "category": "win_crypto"},
    "BCryptDestroyHash": {"lib": "bcrypt", "purpose": "destroy CNG hash object", "category": "win_crypto"},
    "BCryptDestroyKey": {"lib": "bcrypt", "purpose": "destroy CNG key object", "category": "win_crypto"},
    "BCryptGenRandom": {"lib": "bcrypt", "purpose": "generate CNG random bytes", "category": "win_crypto"},
    "BCryptGenerateKeyPair": {"lib": "bcrypt", "purpose": "generate CNG asymmetric key pair", "category": "win_crypto"},
    "BCryptFinalizeKeyPair": {"lib": "bcrypt", "purpose": "finalize CNG key pair generation", "category": "win_crypto"},
    "BCryptSignHash": {"lib": "bcrypt", "purpose": "CNG digital signature creation", "category": "win_crypto"},
    "BCryptVerifySignature": {"lib": "bcrypt", "purpose": "CNG digital signature verification", "category": "win_crypto"},
    "BCryptDeriveKey": {"lib": "bcrypt", "purpose": "CNG key derivation", "category": "win_crypto"},
    "BCryptExportKey": {"lib": "bcrypt", "purpose": "export CNG key to blob", "category": "win_crypto"},
    "BCryptImportKey": {"lib": "bcrypt", "purpose": "import CNG key from blob", "category": "win_crypto"},

    # --- winhttp ---
    "WinHttpOpen": {"lib": "winhttp", "purpose": "initialize WinHTTP session", "category": "win_http"},
    "WinHttpConnect": {"lib": "winhttp", "purpose": "connect to HTTP server", "category": "win_http"},
    "WinHttpOpenRequest": {"lib": "winhttp", "purpose": "create HTTP request handle", "category": "win_http"},
    "WinHttpSendRequest": {"lib": "winhttp", "purpose": "send HTTP request", "category": "win_http"},
    "WinHttpReceiveResponse": {"lib": "winhttp", "purpose": "receive HTTP response", "category": "win_http"},
    "WinHttpReadData": {"lib": "winhttp", "purpose": "read HTTP response data", "category": "win_http"},
    "WinHttpQueryHeaders": {"lib": "winhttp", "purpose": "query HTTP response headers", "category": "win_http"},
    "WinHttpCloseHandle": {"lib": "winhttp", "purpose": "close WinHTTP handle", "category": "win_http"},
    "WinHttpSetOption": {"lib": "winhttp", "purpose": "set WinHTTP option", "category": "win_http"},
    "WinHttpQueryDataAvailable": {"lib": "winhttp", "purpose": "query amount of available data", "category": "win_http"},
    "WinHttpCrackUrl": {"lib": "winhttp", "purpose": "parse URL into components", "category": "win_http"},
    "WinHttpAddRequestHeaders": {"lib": "winhttp", "purpose": "add HTTP request headers", "category": "win_http"},

    # --- wininet ---
    "InternetOpenA": {"lib": "wininet", "purpose": "initialize WinINet session (ANSI)", "category": "win_http"},
    "InternetOpenW": {"lib": "wininet", "purpose": "initialize WinINet session (Unicode)", "category": "win_http"},
    "InternetConnectA": {"lib": "wininet", "purpose": "connect to server (ANSI)", "category": "win_http"},
    "InternetOpenUrlA": {"lib": "wininet", "purpose": "open URL (ANSI)", "category": "win_http"},
    "InternetReadFile": {"lib": "wininet", "purpose": "read data from internet handle", "category": "win_http"},
    "InternetWriteFile": {"lib": "wininet", "purpose": "write data to internet handle", "category": "win_http"},
    "InternetCloseHandle": {"lib": "wininet", "purpose": "close internet handle", "category": "win_http"},
    "HttpOpenRequestA": {"lib": "wininet", "purpose": "create HTTP request (ANSI)", "category": "win_http"},
    "HttpSendRequestA": {"lib": "wininet", "purpose": "send HTTP request (ANSI)", "category": "win_http"},
    "HttpQueryInfoA": {"lib": "wininet", "purpose": "query HTTP header info (ANSI)", "category": "win_http"},
    "InternetSetOptionA": {"lib": "wininet", "purpose": "set internet option (ANSI)", "category": "win_http"},
    "InternetQueryOptionA": {"lib": "wininet", "purpose": "query internet option (ANSI)", "category": "win_http"},

    # --- version.dll ---
    "GetFileVersionInfoA": {"lib": "version", "purpose": "get file version info (ANSI)", "category": "win_system"},
    "GetFileVersionInfoW": {"lib": "version", "purpose": "get file version info (Unicode)", "category": "win_system"},
    "GetFileVersionInfoSizeA": {"lib": "version", "purpose": "get version info buffer size (ANSI)", "category": "win_system"},
    "VerQueryValueA": {"lib": "version", "purpose": "query version info value (ANSI)", "category": "win_system"},
    "VerQueryValueW": {"lib": "version", "purpose": "query version info value (Unicode)", "category": "win_system"},

    # --- psapi ---
    "EnumProcesses": {"lib": "psapi", "purpose": "enumerate running process IDs", "category": "win_process"},
    "EnumProcessModules": {"lib": "psapi", "purpose": "enumerate modules in process", "category": "win_process"},
    "EnumProcessModulesEx": {"lib": "psapi", "purpose": "enumerate modules with filter", "category": "win_process"},
    "GetModuleBaseNameA": {"lib": "psapi", "purpose": "get module base name (ANSI)", "category": "win_process"},
    "GetModuleFileNameExA": {"lib": "psapi", "purpose": "get module file name in process (ANSI)", "category": "win_process"},
    "GetProcessMemoryInfo": {"lib": "psapi", "purpose": "get process memory usage info", "category": "win_process"},

    # --- dbghelp ---
    "SymInitialize": {"lib": "dbghelp", "purpose": "initialize symbol handler", "category": "win_debug"},
    "SymCleanup": {"lib": "dbghelp", "purpose": "cleanup symbol handler", "category": "win_debug"},
    "SymFromAddr": {"lib": "dbghelp", "purpose": "get symbol from address", "category": "win_debug"},
    "SymLoadModuleEx": {"lib": "dbghelp", "purpose": "load debug symbols for module", "category": "win_debug"},
    "StackWalk64": {"lib": "dbghelp", "purpose": "walk call stack frames", "category": "win_debug"},
    "MiniDumpWriteDump": {"lib": "dbghelp", "purpose": "write process minidump file", "category": "win_debug"},
    "UnDecorateSymbolName": {"lib": "dbghelp", "purpose": "undecorate C++ mangled name", "category": "win_debug"},

    # --- iphlpapi ---
    "GetAdaptersInfo": {"lib": "iphlpapi", "purpose": "get network adapter information", "category": "win_network"},
    "GetAdaptersAddresses": {"lib": "iphlpapi", "purpose": "get network adapter addresses", "category": "win_network"},
    "GetTcpTable": {"lib": "iphlpapi", "purpose": "get TCP connection table", "category": "win_network"},
    "GetUdpTable": {"lib": "iphlpapi", "purpose": "get UDP endpoint table", "category": "win_network"},
    "GetBestRoute": {"lib": "iphlpapi", "purpose": "get best route for destination", "category": "win_network"},
    "GetIpForwardTable": {"lib": "iphlpapi", "purpose": "get IP routing table", "category": "win_network"},

    # --- secur32 ---
    "AcquireCredentialsHandleA": {"lib": "secur32", "purpose": "acquire SSPI credentials (ANSI)", "category": "win_security"},
    "InitializeSecurityContextA": {"lib": "secur32", "purpose": "initialize SSPI security context (ANSI)", "category": "win_security"},
    "AcceptSecurityContext": {"lib": "secur32", "purpose": "accept SSPI security context", "category": "win_security"},
    "FreeCredentialsHandle": {"lib": "secur32", "purpose": "free SSPI credentials handle", "category": "win_security"},
    "DeleteSecurityContext": {"lib": "secur32", "purpose": "delete SSPI security context", "category": "win_security"},
    "EncryptMessage": {"lib": "secur32", "purpose": "SSPI encrypt message", "category": "win_security"},
    "DecryptMessage": {"lib": "secur32", "purpose": "SSPI decrypt message", "category": "win_security"},
}


# -------------------------------------------------------------------------

# Dispatcher hook - sigdb_builtin.get_category("...") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur.
# -------------------------------------------------------------------------

SIGNATURES: dict[str, Any] = {
    "win32_kernel32_signatures": _WIN32_KERNEL32_SIGNATURES_DATA,
    "win32_ws2_32_signatures": _WIN32_WS2_32_SIGNATURES_DATA,
    "win32_advapi32_signatures": _WIN32_ADVAPI32_SIGNATURES_DATA,
    "win32_user32_gdi32_signatures": _WIN32_USER32_GDI32_SIGNATURES_DATA,
    "win32_ntdll_signatures": _WIN32_NTDLL_SIGNATURES_DATA,
    "win32_ext_signatures": _WIN32_EXT_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
