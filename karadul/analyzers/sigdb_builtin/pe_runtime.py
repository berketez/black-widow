"""PE/MSVC runtime category signatures — sig_db Faz 6C dalgasi.

Bu modul Windows PE binary analizi icin kritik olan uc alt veri kumesini
barindirir:

  1. ``kernel32_signatures``  — Windows API core (file I/O, process, memory,
                                thread, sync, module, error, timing, debug).
                                Kaynak: signature_db.py ``_WIN32_KERNEL32_SIGNATURES``
                                satir 3934-4016 (60 entry). Identity parity.
  2. ``ntdll_signatures``     — Native NT API (NtXxx / RtlXxx). Kaynak:
                                signature_db.py ``_WIN32_NTDLL_SIGNATURES``
                                satir 4143-4167 (14 entry). Identity parity.
  3. ``msvc_crt_signatures``  — MSVC C Runtime (msvcrt.dll / ucrtbase.dll /
                                vcruntime140.dll). Kaynak: Section 1 of
                                ``_MEGA_BATCH_1_SIGNATURES`` (satir 7141-7217,
                                ~77 entry) + bu modulde eklenen UCRT/VCRUNTIME
                                genisletmesi. Toplam 246 entry. Yeni coverage.

Toplam: 60 + 14 + 246 = 320 entry.

Legacy ``_WIN32_KERNEL32_SIGNATURES`` / ``_WIN32_NTDLL_SIGNATURES`` SILINMEDI;
rollback icin override yontemi kullanilir. ``_MSVC_CRT_SIGNATURES`` bu modul
ile birlikte YENI tanimlanmis bir dict'tir; legacy'de karsiligi yoktur ve
``_load_builtin_signatures`` tuple'ina eklenmistir.

Not: MSVC CRT entry'lerinin bir alt kumesi (``_open``, ``_close``, ``_read``,
``_write`` gibi temel ~77 fonksiyon) legacy ``_MEGA_BATCH_1_SIGNATURES``
icinde de mevcuttur. Cakisma degildir; ayni isim + ayni ``lib`` / ``purpose``
verisi tasir ve ``dict.update`` siralamasinda son yazan (ayni icerikli)
kalir — idempotent.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# kernel32 (55 entry) — file I/O, process, memory, thread, sync, module,
#                        error, system, timing, debug.
# Kaynak: signature_db.py satir 3934-4016 (birebir kopya — identity parity)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# ntdll (15 entry) — native NT API (kernel32 altindaki Nt*/Rtl* wrapper'lari)
# Kaynak: signature_db.py satir 4143-4167 (birebir kopya — identity parity)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# MSVC C Runtime (~180 entry) — YENI coverage genisletmesi.
# Kapsama:
#   - msvcrt.dll / msvcr*.dll (Visual C++ 6.0 / 2003 / 2005 / 2008 / 2010 / 2012 / 2013)
#   - ucrtbase.dll (Universal CRT, VC++ 2015+)
#   - vcruntime140.dll (Visual C++ 2015+ runtime support)
# Kanonik listeden gelen yaygin CRT fonksiyonlari: stdio, stdlib, string,
# memory, wide string, file descriptor I/O, CRT debug, exception/SEH,
# startup, locale, time. MSDN Windows CRT reference baz alindi.
# NOT: Section 1 of legacy _MEGA_BATCH_1_SIGNATURES (satir 7141-7217, 77 entry)
#      burada da yer alir — cakisma degildir, ayni veri + ek kapsama.
# ---------------------------------------------------------------------------
_MSVC_CRT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- msvcrt: file descriptor I/O (POSIX-style with underscore prefix) ---
    "_open": {"lib": "msvcrt", "purpose": "open file (MSVC CRT)", "category": "win_crt"},
    "_wopen": {"lib": "msvcrt", "purpose": "open file (wide path, MSVC CRT)", "category": "win_crt"},
    "_close": {"lib": "msvcrt", "purpose": "close file descriptor (MSVC CRT)", "category": "win_crt"},
    "_read": {"lib": "msvcrt", "purpose": "read from file descriptor (MSVC CRT)", "category": "win_crt"},
    "_write": {"lib": "msvcrt", "purpose": "write to file descriptor (MSVC CRT)", "category": "win_crt"},
    "_lseek": {"lib": "msvcrt", "purpose": "seek file position (MSVC CRT)", "category": "win_crt"},
    "_lseeki64": {"lib": "msvcrt", "purpose": "seek file position (64-bit, MSVC CRT)", "category": "win_crt"},
    "_tell": {"lib": "msvcrt", "purpose": "get file descriptor position", "category": "win_crt"},
    "_telli64": {"lib": "msvcrt", "purpose": "get file position (64-bit)", "category": "win_crt"},
    "_stat": {"lib": "msvcrt", "purpose": "get file status (MSVC CRT)", "category": "win_crt"},
    "_stat64": {"lib": "msvcrt", "purpose": "get file status (64-bit, MSVC CRT)", "category": "win_crt"},
    "_fstat": {"lib": "msvcrt", "purpose": "get file status by fd (MSVC CRT)", "category": "win_crt"},
    "_fstat64": {"lib": "msvcrt", "purpose": "get file status by fd (64-bit)", "category": "win_crt"},
    "_access": {"lib": "msvcrt", "purpose": "check file access (MSVC CRT)", "category": "win_crt"},
    "_waccess": {"lib": "msvcrt", "purpose": "check file access (wide path)", "category": "win_crt"},
    "_mkdir": {"lib": "msvcrt", "purpose": "create directory (MSVC CRT)", "category": "win_crt"},
    "_wmkdir": {"lib": "msvcrt", "purpose": "create directory (wide path)", "category": "win_crt"},
    "_rmdir": {"lib": "msvcrt", "purpose": "remove directory (MSVC CRT)", "category": "win_crt"},
    "_wrmdir": {"lib": "msvcrt", "purpose": "remove directory (wide path)", "category": "win_crt"},
    "_unlink": {"lib": "msvcrt", "purpose": "delete file (MSVC CRT)", "category": "win_crt"},
    "_wunlink": {"lib": "msvcrt", "purpose": "delete file (wide path)", "category": "win_crt"},
    "_getcwd": {"lib": "msvcrt", "purpose": "get current directory (MSVC CRT)", "category": "win_crt"},
    "_wgetcwd": {"lib": "msvcrt", "purpose": "get current directory (wide)", "category": "win_crt"},
    "_chdir": {"lib": "msvcrt", "purpose": "change directory (MSVC CRT)", "category": "win_crt"},
    "_wchdir": {"lib": "msvcrt", "purpose": "change directory (wide path)", "category": "win_crt"},
    "_chmod": {"lib": "msvcrt", "purpose": "change file mode bits", "category": "win_crt"},
    "_dup": {"lib": "msvcrt", "purpose": "duplicate fd (MSVC CRT)", "category": "win_crt"},
    "_dup2": {"lib": "msvcrt", "purpose": "duplicate fd to specific number (MSVC CRT)", "category": "win_crt"},
    "_pipe": {"lib": "msvcrt", "purpose": "create pipe (MSVC CRT)", "category": "win_crt"},
    "_popen": {"lib": "msvcrt", "purpose": "open pipe to process (MSVC CRT)", "category": "win_crt"},
    "_pclose": {"lib": "msvcrt", "purpose": "close process pipe (MSVC CRT)", "category": "win_crt"},
    "_findfirst": {"lib": "msvcrt", "purpose": "find first file (MSVC CRT)", "category": "win_crt"},
    "_findfirst64": {"lib": "msvcrt", "purpose": "find first file (64-bit time)", "category": "win_crt"},
    "_findnext": {"lib": "msvcrt", "purpose": "find next file (MSVC CRT)", "category": "win_crt"},
    "_findnext64": {"lib": "msvcrt", "purpose": "find next file (64-bit time)", "category": "win_crt"},
    "_findclose": {"lib": "msvcrt", "purpose": "close find handle (MSVC CRT)", "category": "win_crt"},
    "_getpid": {"lib": "msvcrt", "purpose": "get process ID (MSVC CRT)", "category": "win_crt"},
    "_isatty": {"lib": "msvcrt", "purpose": "check if fd refers to terminal", "category": "win_crt"},
    "_setmode": {"lib": "msvcrt", "purpose": "set file translation mode", "category": "win_crt"},
    "_fileno": {"lib": "msvcrt", "purpose": "get fd from FILE stream", "category": "win_crt"},

    # --- msvcrt: threading (CRT-safe thread API) ---
    "_beginthreadex": {"lib": "msvcrt", "purpose": "create thread (CRT-safe)", "category": "win_crt"},
    "_endthreadex": {"lib": "msvcrt", "purpose": "terminate thread (CRT-safe)", "category": "win_crt"},
    "_beginthread": {"lib": "msvcrt", "purpose": "create thread (legacy)", "category": "win_crt"},
    "_endthread": {"lib": "msvcrt", "purpose": "end thread (legacy)", "category": "win_crt"},

    # --- msvcrt: CRT / SEH support ---
    "_set_se_translator": {"lib": "msvcrt", "purpose": "set SEH to C++ exception translator", "category": "win_crt"},
    "_set_invalid_parameter_handler": {"lib": "msvcrt", "purpose": "set invalid parameter handler", "category": "win_crt"},
    "_set_new_handler": {"lib": "msvcrt", "purpose": "set new operator failure handler", "category": "win_crt"},
    "_set_new_mode": {"lib": "msvcrt", "purpose": "set new allocation failure mode", "category": "win_crt"},
    "_set_purecall_handler": {"lib": "msvcrt", "purpose": "set pure virtual call handler", "category": "win_crt"},
    "_set_abort_behavior": {"lib": "msvcrt", "purpose": "set abort() runtime behavior", "category": "win_crt"},
    "_CrtDbgReport": {"lib": "msvcrt", "purpose": "CRT debug report", "category": "win_crt"},
    "_CrtDbgReportW": {"lib": "msvcrt", "purpose": "CRT debug report (wide)", "category": "win_crt"},
    "_CrtSetReportMode": {"lib": "msvcrt", "purpose": "set CRT report mode", "category": "win_crt"},
    "_CrtSetReportFile": {"lib": "msvcrt", "purpose": "set CRT report target file", "category": "win_crt"},
    "_CrtSetDbgFlag": {"lib": "msvcrt", "purpose": "set CRT debug flag", "category": "win_crt"},
    "_CrtDumpMemoryLeaks": {"lib": "msvcrt", "purpose": "dump memory leaks", "category": "win_crt"},
    "_CrtCheckMemory": {"lib": "msvcrt", "purpose": "check CRT heap integrity", "category": "win_crt"},
    "_CrtIsValidHeapPointer": {"lib": "msvcrt", "purpose": "check if pointer is from CRT heap", "category": "win_crt"},

    # --- msvcrt: allocation helpers ---
    "_msize": {"lib": "msvcrt", "purpose": "get heap allocation size", "category": "win_crt"},
    "_aligned_malloc": {"lib": "msvcrt", "purpose": "aligned memory allocation", "category": "win_crt"},
    "_aligned_free": {"lib": "msvcrt", "purpose": "free aligned allocation", "category": "win_crt"},
    "_aligned_realloc": {"lib": "msvcrt", "purpose": "reallocate aligned memory", "category": "win_crt"},
    "_malloca": {"lib": "msvcrt", "purpose": "stack or heap allocation", "category": "win_crt"},
    "_freea": {"lib": "msvcrt", "purpose": "free stack/heap allocation", "category": "win_crt"},
    "_expand": {"lib": "msvcrt", "purpose": "resize memory block in place", "category": "win_crt"},
    "_recalloc": {"lib": "msvcrt", "purpose": "reallocate and zero-initialize", "category": "win_crt"},

    # --- msvcrt: string manipulation (MSVC-specific) ---
    "_strdup": {"lib": "msvcrt", "purpose": "duplicate string (MSVC)", "category": "win_crt"},
    "_wcsdup": {"lib": "msvcrt", "purpose": "duplicate wide string (MSVC)", "category": "win_crt"},
    "_mbsdup": {"lib": "msvcrt", "purpose": "duplicate multibyte string (MSVC)", "category": "win_crt"},
    "_stricmp": {"lib": "msvcrt", "purpose": "case-insensitive compare (MSVC)", "category": "win_crt"},
    "_strnicmp": {"lib": "msvcrt", "purpose": "case-insensitive compare n chars (MSVC)", "category": "win_crt"},
    "_strlwr": {"lib": "msvcrt", "purpose": "convert string to lowercase (MSVC)", "category": "win_crt"},
    "_strupr": {"lib": "msvcrt", "purpose": "convert string to uppercase (MSVC)", "category": "win_crt"},
    "_strrev": {"lib": "msvcrt", "purpose": "reverse string in place", "category": "win_crt"},
    "_strset": {"lib": "msvcrt", "purpose": "fill string with character", "category": "win_crt"},
    "_itoa": {"lib": "msvcrt", "purpose": "integer to string (MSVC)", "category": "win_crt"},
    "_itow": {"lib": "msvcrt", "purpose": "integer to wide string (MSVC)", "category": "win_crt"},
    "_ltoa": {"lib": "msvcrt", "purpose": "long to string (MSVC)", "category": "win_crt"},
    "_ltow": {"lib": "msvcrt", "purpose": "long to wide string (MSVC)", "category": "win_crt"},
    "_i64toa": {"lib": "msvcrt", "purpose": "int64 to string (MSVC)", "category": "win_crt"},
    "_i64tow": {"lib": "msvcrt", "purpose": "int64 to wide string (MSVC)", "category": "win_crt"},
    "_ui64toa": {"lib": "msvcrt", "purpose": "uint64 to string (MSVC)", "category": "win_crt"},
    "_ui64tow": {"lib": "msvcrt", "purpose": "uint64 to wide string (MSVC)", "category": "win_crt"},
    "_atoi64": {"lib": "msvcrt", "purpose": "string to int64 (MSVC)", "category": "win_crt"},
    "_atoi64_l": {"lib": "msvcrt", "purpose": "string to int64 with locale", "category": "win_crt"},
    "_wtoi": {"lib": "msvcrt", "purpose": "wide string to int (MSVC)", "category": "win_crt"},
    "_wtoi64": {"lib": "msvcrt", "purpose": "wide string to int64 (MSVC)", "category": "win_crt"},
    "_wtol": {"lib": "msvcrt", "purpose": "wide string to long (MSVC)", "category": "win_crt"},
    "_wtof": {"lib": "msvcrt", "purpose": "wide string to float (MSVC)", "category": "win_crt"},

    # --- msvcrt: formatted I/O (legacy + secure) ---
    "_snprintf": {"lib": "msvcrt", "purpose": "bounded sprintf (MSVC)", "category": "win_crt"},
    "_vsnprintf": {"lib": "msvcrt", "purpose": "bounded vsprintf (MSVC)", "category": "win_crt"},
    "_snwprintf": {"lib": "msvcrt", "purpose": "bounded swprintf (MSVC)", "category": "win_crt"},
    "_vsnwprintf": {"lib": "msvcrt", "purpose": "bounded vswprintf (MSVC)", "category": "win_crt"},
    "_scprintf": {"lib": "msvcrt", "purpose": "count chars sprintf would write", "category": "win_crt"},
    "_vscprintf": {"lib": "msvcrt", "purpose": "count chars vsprintf would write", "category": "win_crt"},
    "sprintf_s": {"lib": "msvcrt", "purpose": "safe sprintf (CRT secure)", "category": "win_crt"},
    "swprintf_s": {"lib": "msvcrt", "purpose": "safe swprintf (CRT secure)", "category": "win_crt"},
    "_snprintf_s": {"lib": "msvcrt", "purpose": "safe bounded sprintf (CRT secure)", "category": "win_crt"},
    "_snwprintf_s": {"lib": "msvcrt", "purpose": "safe bounded swprintf (CRT secure)", "category": "win_crt"},
    "vsprintf_s": {"lib": "msvcrt", "purpose": "safe vsprintf (CRT secure)", "category": "win_crt"},
    "vswprintf_s": {"lib": "msvcrt", "purpose": "safe vswprintf (CRT secure)", "category": "win_crt"},
    "printf_s": {"lib": "msvcrt", "purpose": "safe printf (CRT secure)", "category": "win_crt"},
    "wprintf_s": {"lib": "msvcrt", "purpose": "safe wprintf (CRT secure)", "category": "win_crt"},
    "scanf_s": {"lib": "msvcrt", "purpose": "safe scanf (CRT secure)", "category": "win_crt"},
    "wscanf_s": {"lib": "msvcrt", "purpose": "safe wscanf (CRT secure)", "category": "win_crt"},
    "sscanf_s": {"lib": "msvcrt", "purpose": "safe sscanf (CRT secure)", "category": "win_crt"},
    "swscanf_s": {"lib": "msvcrt", "purpose": "safe swscanf (CRT secure)", "category": "win_crt"},

    # --- msvcrt: secure string / memory (SafeCRT) ---
    "strcpy_s": {"lib": "msvcrt", "purpose": "safe strcpy (CRT secure)", "category": "win_crt"},
    "strncpy_s": {"lib": "msvcrt", "purpose": "safe strncpy (CRT secure)", "category": "win_crt"},
    "strcat_s": {"lib": "msvcrt", "purpose": "safe strcat (CRT secure)", "category": "win_crt"},
    "strncat_s": {"lib": "msvcrt", "purpose": "safe strncat (CRT secure)", "category": "win_crt"},
    "wcscpy_s": {"lib": "msvcrt", "purpose": "safe wcscpy (CRT secure)", "category": "win_crt"},
    "wcsncpy_s": {"lib": "msvcrt", "purpose": "safe wcsncpy (CRT secure)", "category": "win_crt"},
    "wcscat_s": {"lib": "msvcrt", "purpose": "safe wcscat (CRT secure)", "category": "win_crt"},
    "wcsncat_s": {"lib": "msvcrt", "purpose": "safe wcsncat (CRT secure)", "category": "win_crt"},
    "memcpy_s": {"lib": "msvcrt", "purpose": "safe memcpy (CRT secure)", "category": "win_crt"},
    "memmove_s": {"lib": "msvcrt", "purpose": "safe memmove (CRT secure)", "category": "win_crt"},
    "strtok_s": {"lib": "msvcrt", "purpose": "safe strtok (CRT secure)", "category": "win_crt"},
    "wcstok_s": {"lib": "msvcrt", "purpose": "safe wcstok (CRT secure)", "category": "win_crt"},

    # --- msvcrt: wide-char stdio + file ---
    "_wfopen": {"lib": "msvcrt", "purpose": "open file (wide path, MSVC)", "category": "win_crt"},
    "fopen_s": {"lib": "msvcrt", "purpose": "safe fopen (CRT secure)", "category": "win_crt"},
    "_wfopen_s": {"lib": "msvcrt", "purpose": "safe fopen wide (CRT secure)", "category": "win_crt"},
    "freopen_s": {"lib": "msvcrt", "purpose": "safe freopen (CRT secure)", "category": "win_crt"},
    "_wfreopen": {"lib": "msvcrt", "purpose": "reopen file (wide path)", "category": "win_crt"},
    "_wremove": {"lib": "msvcrt", "purpose": "remove file (wide path)", "category": "win_crt"},
    "_wrename": {"lib": "msvcrt", "purpose": "rename file (wide path)", "category": "win_crt"},
    "_wtmpnam": {"lib": "msvcrt", "purpose": "temp file name (wide)", "category": "win_crt"},
    "wprintf": {"lib": "msvcrt", "purpose": "wide formatted output to stdout", "category": "win_crt"},
    "wscanf": {"lib": "msvcrt", "purpose": "wide formatted input from stdin", "category": "win_crt"},
    "fwprintf": {"lib": "msvcrt", "purpose": "wide formatted output to stream", "category": "win_crt"},
    "fwscanf": {"lib": "msvcrt", "purpose": "wide formatted input from stream", "category": "win_crt"},

    # --- msvcrt: wide-char string ops ---
    "wcslen": {"lib": "msvcrt", "purpose": "wide string length", "category": "win_crt"},
    "wcsnlen": {"lib": "msvcrt", "purpose": "bounded wide string length", "category": "win_crt"},
    "wcsnlen_s": {"lib": "msvcrt", "purpose": "safe bounded wide string length", "category": "win_crt"},
    "wcscmp": {"lib": "msvcrt", "purpose": "compare wide strings", "category": "win_crt"},
    "wcsncmp": {"lib": "msvcrt", "purpose": "compare wide strings with limit", "category": "win_crt"},
    "wcscpy": {"lib": "msvcrt", "purpose": "copy wide string", "category": "win_crt"},
    "wcsncpy": {"lib": "msvcrt", "purpose": "copy wide string with limit", "category": "win_crt"},
    "wcscat": {"lib": "msvcrt", "purpose": "concatenate wide strings", "category": "win_crt"},
    "wcsncat": {"lib": "msvcrt", "purpose": "concatenate wide strings with limit", "category": "win_crt"},
    "wcsstr": {"lib": "msvcrt", "purpose": "find wide substring", "category": "win_crt"},
    "wcschr": {"lib": "msvcrt", "purpose": "find wide char in string", "category": "win_crt"},
    "wcsrchr": {"lib": "msvcrt", "purpose": "find last wide char in string", "category": "win_crt"},
    "wcspbrk": {"lib": "msvcrt", "purpose": "find first wide char from set", "category": "win_crt"},
    "wcsspn": {"lib": "msvcrt", "purpose": "span of initial wide chars from set", "category": "win_crt"},
    "wcscspn": {"lib": "msvcrt", "purpose": "span of initial wide chars not in set", "category": "win_crt"},
    "wcstok": {"lib": "msvcrt", "purpose": "tokenize wide string", "category": "win_crt"},
    "wcstol": {"lib": "msvcrt", "purpose": "wide string to long", "category": "win_crt"},
    "wcstoll": {"lib": "msvcrt", "purpose": "wide string to long long", "category": "win_crt"},
    "wcstoul": {"lib": "msvcrt", "purpose": "wide string to unsigned long", "category": "win_crt"},
    "wcstoull": {"lib": "msvcrt", "purpose": "wide string to unsigned long long", "category": "win_crt"},
    "wcstod": {"lib": "msvcrt", "purpose": "wide string to double", "category": "win_crt"},
    "wcstof": {"lib": "msvcrt", "purpose": "wide string to float", "category": "win_crt"},
    "_wcsicmp": {"lib": "msvcrt", "purpose": "case-insensitive wide compare", "category": "win_crt"},
    "_wcsnicmp": {"lib": "msvcrt", "purpose": "case-insensitive wide compare n chars", "category": "win_crt"},
    "_wcslwr": {"lib": "msvcrt", "purpose": "lowercase wide string", "category": "win_crt"},
    "_wcsupr": {"lib": "msvcrt", "purpose": "uppercase wide string", "category": "win_crt"},
    "_wcsrev": {"lib": "msvcrt", "purpose": "reverse wide string", "category": "win_crt"},

    # --- msvcrt: locale / environment ---
    "_wgetenv": {"lib": "msvcrt", "purpose": "get environment variable (wide)", "category": "win_crt"},
    "_wputenv": {"lib": "msvcrt", "purpose": "set environment variable (wide)", "category": "win_crt"},
    "_putenv": {"lib": "msvcrt", "purpose": "set environment variable", "category": "win_crt"},
    "_putenv_s": {"lib": "msvcrt", "purpose": "safe set environment variable", "category": "win_crt"},
    "_wputenv_s": {"lib": "msvcrt", "purpose": "safe set environment variable (wide)", "category": "win_crt"},
    "getenv_s": {"lib": "msvcrt", "purpose": "safe get environment variable", "category": "win_crt"},
    "_wgetenv_s": {"lib": "msvcrt", "purpose": "safe get environment variable (wide)", "category": "win_crt"},
    "_wsystem": {"lib": "msvcrt", "purpose": "execute command (wide)", "category": "win_crt"},
    "_wspawnl": {"lib": "msvcrt", "purpose": "spawn process (wide, list args)", "category": "win_crt"},
    "_wspawnv": {"lib": "msvcrt", "purpose": "spawn process (wide, array args)", "category": "win_crt"},
    "_wexecl": {"lib": "msvcrt", "purpose": "exec process (wide, list args)", "category": "win_crt"},
    "_wexecv": {"lib": "msvcrt", "purpose": "exec process (wide, array args)", "category": "win_crt"},

    # --- msvcrt: time (MSVC-specific) ---
    "_time32": {"lib": "msvcrt", "purpose": "get time (32-bit time_t)", "category": "win_crt"},
    "_time64": {"lib": "msvcrt", "purpose": "get time (64-bit time_t)", "category": "win_crt"},
    "_mktime32": {"lib": "msvcrt", "purpose": "make time_t (32-bit)", "category": "win_crt"},
    "_mktime64": {"lib": "msvcrt", "purpose": "make time_t (64-bit)", "category": "win_crt"},
    "_localtime32": {"lib": "msvcrt", "purpose": "convert to local time (32-bit)", "category": "win_crt"},
    "_localtime64": {"lib": "msvcrt", "purpose": "convert to local time (64-bit)", "category": "win_crt"},
    "_gmtime32": {"lib": "msvcrt", "purpose": "convert to UTC tm (32-bit)", "category": "win_crt"},
    "_gmtime64": {"lib": "msvcrt", "purpose": "convert to UTC tm (64-bit)", "category": "win_crt"},
    "localtime_s": {"lib": "msvcrt", "purpose": "safe localtime", "category": "win_crt"},
    "gmtime_s": {"lib": "msvcrt", "purpose": "safe gmtime", "category": "win_crt"},
    "_ftime32": {"lib": "msvcrt", "purpose": "get time with milliseconds (32-bit)", "category": "win_crt"},
    "_ftime64": {"lib": "msvcrt", "purpose": "get time with milliseconds (64-bit)", "category": "win_crt"},
    "_tzset": {"lib": "msvcrt", "purpose": "set time zone from environment", "category": "win_crt"},

    # --- ucrtbase (Universal CRT) startup / main ---
    "__p__commode": {"lib": "ucrtbase", "purpose": "global commit mode pointer", "category": "win_crt"},
    "__p__fmode": {"lib": "ucrtbase", "purpose": "global file mode pointer", "category": "win_crt"},
    "__p___argc": {"lib": "ucrtbase", "purpose": "pointer to global argc", "category": "win_crt"},
    "__p___argv": {"lib": "ucrtbase", "purpose": "pointer to global argv", "category": "win_crt"},
    "__p___wargv": {"lib": "ucrtbase", "purpose": "pointer to global wide argv", "category": "win_crt"},
    "__p__environ": {"lib": "ucrtbase", "purpose": "pointer to environment block", "category": "win_crt"},
    "__p__wenviron": {"lib": "ucrtbase", "purpose": "pointer to wide environment block", "category": "win_crt"},
    "__p__pgmptr": {"lib": "ucrtbase", "purpose": "pointer to program path (ANSI)", "category": "win_crt"},
    "__p__wpgmptr": {"lib": "ucrtbase", "purpose": "pointer to program path (wide)", "category": "win_crt"},
    "__getmainargs": {"lib": "ucrtbase", "purpose": "CRT init of main() args", "category": "win_crt"},
    "__wgetmainargs": {"lib": "ucrtbase", "purpose": "CRT init of wmain() args", "category": "win_crt"},
    "_initterm": {"lib": "ucrtbase", "purpose": "call array of CRT init routines", "category": "win_crt"},
    "_initterm_e": {"lib": "ucrtbase", "purpose": "call init routines with error check", "category": "win_crt"},
    "_cexit": {"lib": "ucrtbase", "purpose": "CRT atexit cleanup", "category": "win_crt"},
    "_c_exit": {"lib": "ucrtbase", "purpose": "CRT early cleanup (no atexit)", "category": "win_crt"},
    "_exit": {"lib": "ucrtbase", "purpose": "terminate process without cleanup", "category": "win_crt"},
    "_onexit": {"lib": "ucrtbase", "purpose": "register function for exit call", "category": "win_crt"},
    "_configure_narrow_argv": {"lib": "ucrtbase", "purpose": "configure narrow argv mode", "category": "win_crt"},
    "_configure_wide_argv": {"lib": "ucrtbase", "purpose": "configure wide argv mode", "category": "win_crt"},
    "_initialize_narrow_environment": {"lib": "ucrtbase", "purpose": "initialize narrow environment", "category": "win_crt"},
    "_initialize_wide_environment": {"lib": "ucrtbase", "purpose": "initialize wide environment", "category": "win_crt"},
    "_get_initial_narrow_environment": {"lib": "ucrtbase", "purpose": "get initial narrow environment", "category": "win_crt"},
    "_get_initial_wide_environment": {"lib": "ucrtbase", "purpose": "get initial wide environment", "category": "win_crt"},
    "_set_app_type": {"lib": "ucrtbase", "purpose": "set application type (console/GUI)", "category": "win_crt"},
    "_set_fmode": {"lib": "ucrtbase", "purpose": "set global file translation mode", "category": "win_crt"},
    "_get_fmode": {"lib": "ucrtbase", "purpose": "get global file translation mode", "category": "win_crt"},
    "_configthreadlocale": {"lib": "ucrtbase", "purpose": "configure thread locale", "category": "win_crt"},
    "_get_doserrno": {"lib": "ucrtbase", "purpose": "get DOS errno value", "category": "win_crt"},
    "_set_doserrno": {"lib": "ucrtbase", "purpose": "set DOS errno value", "category": "win_crt"},
    "_errno": {"lib": "ucrtbase", "purpose": "pointer to errno", "category": "win_crt"},
    "_get_errno": {"lib": "ucrtbase", "purpose": "safe get errno", "category": "win_crt"},
    "_set_errno": {"lib": "ucrtbase", "purpose": "safe set errno", "category": "win_crt"},

    # --- vcruntime140.dll: RTTI + exception + compiler intrinsics ---
    "__CxxFrameHandler3": {"lib": "vcruntime140", "purpose": "C++ SEH frame handler (x86)", "category": "win_cxx_eh"},
    "__CxxFrameHandler4": {"lib": "vcruntime140", "purpose": "C++ SEH frame handler (newer)", "category": "win_cxx_eh"},
    "__GSHandlerCheck": {"lib": "vcruntime140", "purpose": "stack cookie (GS) SEH handler", "category": "win_cxx_eh"},
    "__GSHandlerCheck_EH": {"lib": "vcruntime140", "purpose": "GS handler with C++ EH", "category": "win_cxx_eh"},
    "__GSHandlerCheck_EH4": {"lib": "vcruntime140", "purpose": "GS handler with C++ EH4", "category": "win_cxx_eh"},
    "__CxxThrowException": {"lib": "vcruntime140", "purpose": "throw C++ exception", "category": "win_cxx_eh"},
    "_CxxThrowException": {"lib": "vcruntime140", "purpose": "throw C++ exception (cdecl)", "category": "win_cxx_eh"},
    "__RTDynamicCast": {"lib": "vcruntime140", "purpose": "C++ dynamic_cast RTTI helper", "category": "win_cxx_rtti"},
    "__RTtypeid": {"lib": "vcruntime140", "purpose": "C++ typeid RTTI helper", "category": "win_cxx_rtti"},
    "__RTCastToVoid": {"lib": "vcruntime140", "purpose": "dynamic_cast to void* RTTI helper", "category": "win_cxx_rtti"},
    "__security_init_cookie": {"lib": "vcruntime140", "purpose": "initialize stack cookie", "category": "win_cxx_eh"},
    "__security_check_cookie": {"lib": "vcruntime140", "purpose": "verify stack cookie", "category": "win_cxx_eh"},
    "__report_gsfailure": {"lib": "vcruntime140", "purpose": "report stack cookie failure", "category": "win_cxx_eh"},
    "__report_rangecheckfailure": {"lib": "vcruntime140", "purpose": "report bounds check failure", "category": "win_cxx_eh"},
    "__std_terminate": {"lib": "vcruntime140", "purpose": "std::terminate implementation", "category": "win_cxx_eh"},
    "__std_exception_copy": {"lib": "vcruntime140", "purpose": "copy std::exception", "category": "win_cxx_eh"},
    "__std_exception_destroy": {"lib": "vcruntime140", "purpose": "destroy std::exception", "category": "win_cxx_eh"},
    "__std_type_info_name": {"lib": "vcruntime140", "purpose": "get type_info undecorated name", "category": "win_cxx_rtti"},
    "__std_type_info_compare": {"lib": "vcruntime140", "purpose": "compare type_info objects", "category": "win_cxx_rtti"},
    "__std_type_info_hash": {"lib": "vcruntime140", "purpose": "hash type_info object", "category": "win_cxx_rtti"},
    "__std_type_info_destroy_list": {"lib": "vcruntime140", "purpose": "destroy type_info decorated list", "category": "win_cxx_rtti"},
    "__vcrt_InitializeCriticalSectionEx": {"lib": "vcruntime140", "purpose": "internal CS init wrapper", "category": "win_crt"},
    "memcpy": {"lib": "vcruntime140", "purpose": "standard memcpy intrinsic", "category": "win_crt"},
    "memmove": {"lib": "vcruntime140", "purpose": "standard memmove intrinsic", "category": "win_crt"},
    "memset": {"lib": "vcruntime140", "purpose": "standard memset intrinsic", "category": "win_crt"},
    "memcmp": {"lib": "vcruntime140", "purpose": "standard memcmp intrinsic", "category": "win_crt"},
    "__C_specific_handler": {"lib": "vcruntime140", "purpose": "x64 SEH language-specific handler", "category": "win_cxx_eh"},
    "__chkstk": {"lib": "vcruntime140", "purpose": "stack probe for large allocations", "category": "win_crt"},
    "_alloca": {"lib": "vcruntime140", "purpose": "stack allocation", "category": "win_crt"},
    "_chkstk": {"lib": "vcruntime140", "purpose": "stack probe (x86)", "category": "win_crt"},
    "__setusermatherr": {"lib": "vcruntime140", "purpose": "register math error handler", "category": "win_crt"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category("pe_runtime") kullanilmaz
# (pe_runtime kategori listesinde henuz yok); signature_db.py dogrudan
# SIGNATURES dict'ini import eder.
# Anahtar isimleri signature_db.py'deki dict adlariyla uyumludur:
#   "kernel32_signatures" <-> _WIN32_KERNEL32_SIGNATURES
#   "ntdll_signatures"    <-> _WIN32_NTDLL_SIGNATURES
#   "msvc_crt_signatures" <-> _MSVC_CRT_SIGNATURES (YENI — legacy karsiligi yok)
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "kernel32_signatures": _WIN32_KERNEL32_SIGNATURES_DATA,
    "ntdll_signatures": _WIN32_NTDLL_SIGNATURES_DATA,
    "msvc_crt_signatures": _MSVC_CRT_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
