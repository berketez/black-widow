"""Genisletilmis API combo pattern ve single API hint tanimlari.

c_namer.py tarafindan import edilir.  200+ combo pattern, 200+ single hint.
Bu dosya LLM olmadan isim cikarmak icin kullanilan saf heuristik veritabanidir.

Kaynaklar:
- POSIX/libc standart API'ler
- macOS CoreFoundation, Objective-C runtime, GCD
- OpenSSL / LibreSSL
- Steam / Valve icsel API'ler
- zlib, protobuf, SQLite
- C++ STL (demangled) pattern'ler
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# API Combo Patterns
# Her kayit: (frozenset(api_calls), suggested_name, confidence)
# En spesifik pattern'ler (daha fazla eleman) onde olmali
# ---------------------------------------------------------------------------

COMBO_PATTERNS: list[tuple[frozenset[str], str, float]] = [
    # ===================================================================
    # NETWORK - TCP/UDP/Socket
    # ===================================================================
    (frozenset({"socket", "connect", "send", "recv"}), "network_roundtrip", 0.85),
    (frozenset({"socket", "connect", "send"}), "send_network_request", 0.8),
    (frozenset({"socket", "connect", "recv"}), "receive_network_data", 0.8),
    (frozenset({"socket", "bind", "listen", "accept"}), "start_server_socket", 0.8),
    (frozenset({"socket", "bind", "listen"}), "setup_listener", 0.75),
    (frozenset({"socket", "connect"}), "connect_socket", 0.75),
    (frozenset({"socket", "setsockopt", "bind"}), "configure_and_bind_socket", 0.8),
    (frozenset({"socket", "setsockopt", "connect"}), "configure_and_connect", 0.8),
    (frozenset({"socket", "setsockopt"}), "configure_socket", 0.7),
    (frozenset({"send", "recv"}), "network_io", 0.65),
    (frozenset({"sendto", "recvfrom"}), "udp_io", 0.7),
    (frozenset({"sendmsg", "recvmsg"}), "message_io", 0.7),
    (frozenset({"sendto"}), "send_udp_packet", 0.6),
    (frozenset({"sendmsg"}), "send_message", 0.6),
    (frozenset({"recvmsg"}), "receive_message", 0.6),
    (frozenset({"getaddrinfo", "socket", "connect"}), "connect_to_host", 0.8),
    (frozenset({"getaddrinfo", "freeaddrinfo"}), "resolve_address", 0.7),
    (frozenset({"getaddrinfo"}), "resolve_address", 0.65),
    (frozenset({"gethostbyname"}), "resolve_hostname", 0.65),
    (frozenset({"getsockname"}), "get_socket_address", 0.65),
    (frozenset({"getsockopt"}), "get_socket_option", 0.65),
    (frozenset({"htons", "inet_addr"}), "prepare_sockaddr", 0.65),
    (frozenset({"select"}), "wait_for_io", 0.6),
    (frozenset({"poll"}), "poll_descriptors", 0.6),
    (frozenset({"kqueue", "kevent"}), "setup_kqueue", 0.75),
    (frozenset({"kevent"}), "wait_for_events", 0.65),
    (frozenset({"shutdown", "close"}), "shutdown_connection", 0.7),
    (frozenset({"shutdown"}), "shutdown_socket", 0.6),

    # ===================================================================
    # FILE I/O
    # ===================================================================
    (frozenset({"fopen", "fread", "fclose"}), "read_file", 0.8),
    (frozenset({"fopen", "fwrite", "fclose"}), "write_file", 0.8),
    (frozenset({"fopen", "fgets", "fclose"}), "read_file_lines", 0.8),
    (frozenset({"fopen", "fprintf", "fclose"}), "write_formatted_file", 0.8),
    (frozenset({"fopen", "fread", "fseek", "fclose"}), "read_file_with_seek", 0.85),
    (frozenset({"fopen", "fseek", "ftell", "fclose"}), "get_file_size", 0.8),
    (frozenset({"fopen", "fseek", "ftell"}), "get_file_size", 0.7),
    (frozenset({"fopen", "fwrite"}), "write_to_file", 0.7),
    (frozenset({"fopen", "fread"}), "read_from_file", 0.7),
    (frozenset({"fopen", "fgets"}), "read_lines_from_file", 0.7),
    (frozenset({"fopen", "fputs", "fclose"}), "write_string_to_file", 0.8),
    (frozenset({"open", "read", "close"}), "read_raw_file", 0.75),
    (frozenset({"open", "write", "close"}), "write_raw_file", 0.75),
    (frozenset({"open", "read"}), "read_from_fd", 0.65),
    (frozenset({"open", "write"}), "write_to_fd", 0.65),
    (frozenset({"open", "lseek", "read"}), "read_file_at_offset", 0.75),
    (frozenset({"open", "fstat"}), "open_and_stat_file", 0.7),
    (frozenset({"stat", "access"}), "check_file_access", 0.7),
    (frozenset({"stat", "chmod"}), "check_and_set_permissions", 0.7),
    (frozenset({"stat"}), "stat_file", 0.55),
    (frozenset({"fstat"}), "stat_fd", 0.55),
    (frozenset({"lstat"}), "stat_link", 0.55),
    (frozenset({"access"}), "check_access", 0.55),
    (frozenset({"opendir", "readdir", "closedir"}), "list_directory", 0.8),
    (frozenset({"opendir", "readdir"}), "scan_directory", 0.75),
    (frozenset({"scandir", "alphasort"}), "list_directory_sorted", 0.8),
    (frozenset({"scandir"}), "scan_directory", 0.7),
    (frozenset({"mkdir", "chmod"}), "create_directory_with_perms", 0.75),
    (frozenset({"mkdir"}), "create_directory", 0.65),
    (frozenset({"rmdir"}), "remove_directory", 0.65),
    (frozenset({"unlink"}), "delete_file", 0.6),
    (frozenset({"remove"}), "remove_file", 0.6),
    (frozenset({"rename"}), "rename_file", 0.6),
    (frozenset({"link", "symlink"}), "create_link", 0.7),
    (frozenset({"symlink"}), "create_symlink", 0.65),
    (frozenset({"readlink"}), "read_symlink", 0.65),
    (frozenset({"realpath"}), "resolve_path", 0.65),
    (frozenset({"mmap", "munmap"}), "map_file_memory", 0.75),
    (frozenset({"flock"}), "lock_file", 0.65),
    (frozenset({"fcntl"}), "file_control", 0.55),
    (frozenset({"fsync"}), "sync_file", 0.6),
    (frozenset({"fflush"}), "flush_file", 0.55),
    (frozenset({"feof", "ferror"}), "check_stream_status", 0.7),
    (frozenset({"fileno"}), "get_file_descriptor", 0.6),
    (frozenset({"setvbuf"}), "set_file_buffering", 0.65),
    (frozenset({"rewind"}), "rewind_file", 0.55),
    (frozenset({"getxattr", "setxattr"}), "manage_extended_attrs", 0.75),
    (frozenset({"getxattr"}), "get_extended_attr", 0.65),
    (frozenset({"setxattr"}), "set_extended_attr", 0.65),
    (frozenset({"removexattr"}), "remove_extended_attr", 0.65),
    (frozenset({"copyfile"}), "copy_file", 0.7),
    (frozenset({"copyfile", "copyfile_state_alloc", "copyfile_state_free"}), "copy_file_with_state", 0.8),
    (frozenset({"utime", "utimes"}), "set_file_times", 0.7),
    (frozenset({"utime"}), "set_file_time", 0.6),
    (frozenset({"utimes"}), "set_file_times", 0.6),
    (frozenset({"futimes"}), "set_fd_times", 0.6),
    (frozenset({"chown"}), "change_file_owner", 0.6),
    (frozenset({"chmod"}), "change_file_mode", 0.6),
    (frozenset({"mkfifo"}), "create_named_pipe", 0.7),

    # ===================================================================
    # MEMORY
    # ===================================================================
    (frozenset({"malloc", "memcpy", "free"}), "copy_buffer", 0.75),
    (frozenset({"malloc", "memset", "free"}), "allocate_temp_buffer", 0.7),
    (frozenset({"malloc", "memset"}), "allocate_zeroed", 0.7),
    (frozenset({"malloc", "memcpy"}), "duplicate_buffer", 0.7),
    (frozenset({"malloc", "free"}), "manage_memory", 0.6),
    (frozenset({"calloc", "free"}), "manage_zeroed_memory", 0.6),
    (frozenset({"calloc"}), "allocate_zeroed_array", 0.55),
    (frozenset({"realloc", "free"}), "resize_or_free_buffer", 0.65),
    (frozenset({"realloc"}), "resize_buffer", 0.55),
    (frozenset({"posix_memalign"}), "allocate_aligned", 0.7),
    (frozenset({"mmap", "mprotect"}), "setup_memory_mapping", 0.7),
    (frozenset({"malloc_size"}), "get_allocation_size", 0.65),
    (frozenset({"bzero"}), "zero_memory", 0.6),
    (frozenset({"memset_pattern16"}), "fill_memory_pattern", 0.65),

    # ===================================================================
    # STRING OPERATIONS
    # ===================================================================
    (frozenset({"strlen", "malloc", "strcpy"}), "duplicate_string", 0.8),
    (frozenset({"strlen", "malloc", "memcpy"}), "duplicate_string", 0.75),
    (frozenset({"strlen", "strcpy"}), "copy_string", 0.7),
    (frozenset({"strlen", "strcat"}), "concat_string", 0.7),
    (frozenset({"strlen", "strncpy"}), "copy_string_bounded", 0.7),
    (frozenset({"strcmp"}), "compare_strings", 0.6),
    (frozenset({"strncmp"}), "compare_strings_n", 0.6),
    (frozenset({"strcasecmp"}), "compare_strings_nocase", 0.65),
    (frozenset({"strncasecmp"}), "compare_strings_n_nocase", 0.65),
    (frozenset({"strstr"}), "find_substring", 0.6),
    (frozenset({"strcasestr"}), "find_substring_nocase", 0.65),
    (frozenset({"strchr"}), "find_char_in_string", 0.6),
    (frozenset({"strrchr"}), "find_last_char", 0.6),
    (frozenset({"strpbrk"}), "find_any_char", 0.6),
    (frozenset({"strspn", "strcspn"}), "scan_string_chars", 0.7),
    (frozenset({"strcspn"}), "count_until_char", 0.6),
    (frozenset({"strspn"}), "count_matching_chars", 0.6),
    (frozenset({"strtok"}), "tokenize_string", 0.65),
    (frozenset({"sprintf"}), "format_string", 0.55),
    (frozenset({"snprintf"}), "format_string_safe", 0.55),
    (frozenset({"sscanf"}), "parse_formatted_string", 0.65),
    (frozenset({"atoi"}), "parse_integer", 0.6),
    (frozenset({"atoll"}), "parse_long_integer", 0.6),
    (frozenset({"strtol"}), "parse_long", 0.6),
    (frozenset({"strtoll"}), "parse_long_long", 0.6),
    (frozenset({"strtoul"}), "parse_unsigned_long", 0.6),
    (frozenset({"strtoull"}), "parse_unsigned_long_long", 0.6),
    (frozenset({"strtod"}), "parse_double", 0.6),
    (frozenset({"strtof"}), "parse_float", 0.6),
    (frozenset({"tolower"}), "to_lowercase", 0.55),
    (frozenset({"toupper"}), "to_uppercase", 0.55),
    (frozenset({"vasprintf"}), "format_string_va", 0.6),
    (frozenset({"vsnprintf"}), "format_string_va_safe", 0.6),
    (frozenset({"swprintf"}), "format_wide_string", 0.6),
    (frozenset({"wcscmp"}), "compare_wide_strings", 0.6),
    (frozenset({"wcscpy"}), "copy_wide_string", 0.6),
    (frozenset({"wcslen"}), "wide_string_length", 0.55),
    (frozenset({"wcsncpy"}), "copy_wide_string_bounded", 0.6),
    (frozenset({"wcschr"}), "find_wide_char", 0.6),
    (frozenset({"wcstol", "wcstoll"}), "parse_wide_long", 0.65),

    # ===================================================================
    # PROCESS
    # ===================================================================
    (frozenset({"fork", "execve", "waitpid"}), "spawn_and_wait", 0.85),
    (frozenset({"posix_spawn"}), "spawn_process", 0.75),
    (frozenset({"fork", "execve"}), "spawn_process", 0.8),
    (frozenset({"fork", "exec"}), "spawn_process", 0.8),
    (frozenset({"fork", "execv"}), "spawn_process_v", 0.8),
    (frozenset({"fork", "waitpid"}), "fork_and_wait", 0.8),
    (frozenset({"execv"}), "exec_program", 0.65),
    (frozenset({"system"}), "run_shell_command", 0.65),
    (frozenset({"popen", "pclose"}), "run_piped_command", 0.75),
    (frozenset({"popen", "fgets", "pclose"}), "read_command_output", 0.8),
    (frozenset({"pipe", "fork"}), "setup_ipc_pipe", 0.75),
    (frozenset({"pipe"}), "create_pipe", 0.6),
    (frozenset({"kill"}), "send_signal", 0.6),
    (frozenset({"signal", "sigaction"}), "setup_signal_handler", 0.7),
    (frozenset({"sigaction"}), "install_signal_handler", 0.65),
    (frozenset({"signal"}), "set_signal_handler", 0.6),
    (frozenset({"sigprocmask"}), "mask_signals", 0.65),
    (frozenset({"waitpid"}), "wait_for_child", 0.6),
    (frozenset({"waitid"}), "wait_for_child_id", 0.6),
    (frozenset({"exit"}), "terminate_process", 0.5),
    (frozenset({"abort"}), "abort_process", 0.55),
    (frozenset({"atexit"}), "register_exit_handler", 0.65),
    (frozenset({"getpid"}), "get_process_id", 0.55),
    (frozenset({"getuid", "geteuid"}), "get_user_ids", 0.7),
    (frozenset({"getenv"}), "get_environment_var", 0.6),
    (frozenset({"setenv"}), "set_environment_var", 0.6),
    (frozenset({"getenv", "setenv"}), "manage_environment", 0.7),
    (frozenset({"getcwd"}), "get_working_directory", 0.65),
    (frozenset({"chdir"}), "change_directory", 0.6),
    (frozenset({"getrlimit", "setrlimit"}), "manage_resource_limits", 0.7),
    (frozenset({"getrlimit"}), "get_resource_limit", 0.6),
    (frozenset({"setrlimit"}), "set_resource_limit", 0.6),
    (frozenset({"sysctl"}), "query_sysctl", 0.65),
    (frozenset({"backtrace", "backtrace_symbols"}), "capture_stack_trace", 0.8),

    # ===================================================================
    # THREAD / SYNCHRONIZATION
    # ===================================================================
    (frozenset({"pthread_create", "pthread_join"}), "run_thread", 0.75),
    (frozenset({"pthread_create"}), "create_thread", 0.7),
    (frozenset({"pthread_join"}), "join_thread", 0.65),
    (frozenset({"pthread_mutex_lock", "pthread_mutex_unlock"}), "synchronized_access", 0.7),
    (frozenset({"pthread_mutex_init", "pthread_mutex_destroy"}), "manage_mutex", 0.7),
    (frozenset({"pthread_mutex_init"}), "init_mutex", 0.6),
    (frozenset({"pthread_mutex_lock"}), "lock_mutex", 0.55),
    (frozenset({"pthread_mutex_unlock"}), "unlock_mutex", 0.55),
    (frozenset({"pthread_mutex_trylock"}), "try_lock_mutex", 0.6),
    (frozenset({"pthread_cond_wait", "pthread_cond_signal"}), "condition_wait_signal", 0.7),
    (frozenset({"pthread_cond_broadcast"}), "broadcast_condition", 0.65),
    (frozenset({"pthread_cond_wait"}), "wait_on_condition", 0.6),
    (frozenset({"pthread_cond_timedwait_relative_np"}), "timed_wait_condition", 0.65),
    (frozenset({"pthread_rwlock_rdlock", "pthread_rwlock_unlock"}), "read_locked_access", 0.7),
    (frozenset({"pthread_rwlock_wrlock", "pthread_rwlock_unlock"}), "write_locked_access", 0.7),
    (frozenset({"pthread_rwlock_init", "pthread_rwlock_destroy"}), "manage_rwlock", 0.7),
    (frozenset({"pthread_key_create", "pthread_setspecific"}), "setup_thread_local", 0.75),
    (frozenset({"pthread_getspecific"}), "get_thread_local", 0.6),
    (frozenset({"pthread_setspecific"}), "set_thread_local", 0.6),
    (frozenset({"pthread_once"}), "thread_once_init", 0.65),
    (frozenset({"pthread_self"}), "get_current_thread", 0.55),
    (frozenset({"pthread_kill"}), "signal_thread", 0.6),
    (frozenset({"pthread_equal"}), "compare_threads", 0.6),
    (frozenset({"pthread_attr_init", "pthread_attr_setstacksize", "pthread_create"}), "create_thread_with_stack", 0.8),
    (frozenset({"pthread_atfork"}), "register_fork_handlers", 0.7),
    (frozenset({"sched_yield"}), "yield_thread", 0.6),
    (frozenset({"semget", "semop"}), "semaphore_operation", 0.7),
    (frozenset({"semget", "semctl"}), "manage_semaphore", 0.7),

    # ===================================================================
    # CRYPTO / SSL / SECURITY
    # ===================================================================
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_connect"}), "ssl_connect", 0.8),
    (frozenset({"SSL_CTX_new", "SSL_new"}), "create_ssl_session", 0.75),
    (frozenset({"SSL_read", "SSL_write"}), "ssl_io", 0.75),
    (frozenset({"EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal"}), "encrypt_data", 0.8),
    (frozenset({"EVP_DecryptInit", "EVP_DecryptUpdate", "EVP_DecryptFinal"}), "decrypt_data", 0.8),
    (frozenset({"EVP_DigestInit", "EVP_DigestUpdate", "EVP_DigestFinal"}), "compute_hash", 0.8),
    (frozenset({"EVP_MD_CTX_new", "EVP_DigestInit", "EVP_DigestUpdate", "EVP_DigestFinal"}), "compute_digest", 0.85),
    (frozenset({"EVP_CIPHER_CTX_new", "EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal"}), "encrypt_with_context", 0.85),
    (frozenset({"EVP_CIPHER_CTX_new", "EVP_DecryptInit", "EVP_DecryptUpdate", "EVP_DecryptFinal"}), "decrypt_with_context", 0.85),
    (frozenset({"MD5_Init", "MD5_Update", "MD5_Final"}), "compute_md5", 0.8),
    (frozenset({"SHA1_Init", "SHA1_Update", "SHA1_Final"}), "compute_sha1", 0.8),
    (frozenset({"SHA256_Init", "SHA256_Update", "SHA256_Final"}), "compute_sha256", 0.8),
    (frozenset({"HMAC_Init", "HMAC_Update", "HMAC_Final"}), "compute_hmac", 0.8),
    (frozenset({"RSA_new", "RSA_public_encrypt"}), "rsa_encrypt", 0.8),
    (frozenset({"RSA_new", "RSA_private_decrypt"}), "rsa_decrypt", 0.8),
    # macOS Security framework
    (frozenset({"SecCertificateCreateWithData", "SecTrustCreateWithCertificates"}), "create_trust_chain", 0.8),
    (frozenset({"SecTrustCreateWithCertificates", "SecTrustEvaluate"}), "evaluate_trust", 0.8),
    (frozenset({"SecPolicyCreateBasicX509"}), "create_x509_policy", 0.7),
    (frozenset({"SecCertificateCreateWithData"}), "create_certificate", 0.65),
    (frozenset({"SecTrustEvaluate"}), "evaluate_certificate_trust", 0.65),

    # ===================================================================
    # macOS / ObjC / CoreFoundation
    # ===================================================================
    (frozenset({"objc_msgSend", "objc_getClass"}), "objc_dispatch", 0.65),
    (frozenset({"objc_msgSend", "objc_alloc"}), "objc_create_and_call", 0.65),
    (frozenset({"objc_alloc", "objc_msgSend"}), "objc_alloc_init", 0.65),
    (frozenset({"objc_retain", "objc_release"}), "objc_retain_release", 0.6),
    (frozenset({"objc_autoreleasePoolPush", "objc_autoreleasePoolPop"}), "autorelease_scope", 0.75),
    (frozenset({"CFRelease"}), "release_cf_object", 0.5),
    (frozenset({"CFStringCreateWithCString", "CFRelease"}), "create_temp_cfstring", 0.7),
    (frozenset({"CFStringCreateWithCString"}), "create_cfstring", 0.65),
    (frozenset({"CFStringGetCString"}), "get_cstring_from_cf", 0.65),
    (frozenset({"CFStringGetCStringPtr"}), "get_cstring_ptr", 0.6),
    (frozenset({"CFStringCompare"}), "compare_cfstrings", 0.65),
    (frozenset({"CFStringCreateMutable", "CFStringAppendCString"}), "build_cfstring", 0.75),
    (frozenset({"CFStringCreateWithFormat"}), "format_cfstring", 0.65),
    (frozenset({"CFStringCreateWithBytes"}), "create_cfstring_from_bytes", 0.65),
    (frozenset({"CFArrayCreate"}), "create_cfarray", 0.65),
    (frozenset({"CFArrayCreateMutable", "CFArrayAppendValue"}), "build_cfarray", 0.75),
    (frozenset({"CFArrayGetCount", "CFArrayGetValueAtIndex"}), "iterate_cfarray", 0.75),
    (frozenset({"CFArrayGetValueAtIndex"}), "get_cfarray_element", 0.6),
    (frozenset({"CFArrayGetCount"}), "count_cfarray", 0.55),
    (frozenset({"CFDictionaryCreateMutable", "CFDictionarySetValue"}), "build_cfdictionary", 0.75),
    (frozenset({"CFDictionaryGetValue"}), "get_cfdictionary_value", 0.6),
    (frozenset({"CFDictionarySetValue"}), "set_cfdictionary_value", 0.6),
    (frozenset({"CFNumberCreate"}), "create_cfnumber", 0.6),
    (frozenset({"CFNumberGetValue"}), "get_cfnumber_value", 0.6),
    (frozenset({"CFGetTypeID"}), "get_cf_type_id", 0.55),
    (frozenset({"CFEqual"}), "compare_cf_objects", 0.6),
    (frozenset({"CFPropertyListCreateFromXMLData"}), "parse_plist_xml", 0.75),
    (frozenset({"CFPropertyListCreateXMLData"}), "serialize_plist_xml", 0.75),
    (frozenset({"CFURLCreateFromFileSystemRepresentation"}), "create_file_url", 0.7),
    (frozenset({"CFURLCreateWithFileSystemPath"}), "create_file_url_from_path", 0.7),
    (frozenset({"CFURLCreateWithBytes"}), "create_url_from_bytes", 0.65),
    (frozenset({"CFURLCreateDataAndPropertiesFromResource"}), "read_url_resource", 0.7),
    (frozenset({"CFURLWriteDataAndPropertiesToResource"}), "write_url_resource", 0.7),
    (frozenset({"CFDataCreateWithBytesNoCopy"}), "wrap_bytes_as_cfdata", 0.65),
    (frozenset({"CFRunLoopGetCurrent", "CFRunLoopRunInMode"}), "run_event_loop", 0.75),
    (frozenset({"CFRunLoopAddSource", "CFRunLoopGetCurrent"}), "add_runloop_source", 0.75),
    (frozenset({"CFRunLoopSourceInvalidate"}), "invalidate_runloop_source", 0.65),
    # macOS proxy
    (frozenset({"SCDynamicStoreCopyProxies"}), "get_system_proxy_settings", 0.75),
    (frozenset({"CFNetworkCopyProxiesForURL"}), "get_proxies_for_url", 0.75),
    (frozenset({"CFNetworkCopyProxiesForAutoConfigurationScript"}), "get_proxies_from_pac", 0.75),

    # GCD (Grand Central Dispatch)
    (frozenset({"dispatch_get_global_queue", "dispatch_group_async_f"}), "dispatch_group_task", 0.75),
    (frozenset({"dispatch_group_create", "dispatch_group_async_f"}), "create_and_dispatch_group", 0.75),
    (frozenset({"dispatch_once_f"}), "dispatch_once", 0.6),
    (frozenset({"dispatch_source_create", "dispatch_source_set_event_handler_f"}), "create_dispatch_source", 0.75),
    (frozenset({"dispatch_source_create", "dispatch_resume"}), "create_and_start_dispatch_source", 0.75),
    (frozenset({"dispatch_source_cancel"}), "cancel_dispatch_source", 0.6),
    (frozenset({"dispatch_suspend", "dispatch_resume"}), "toggle_dispatch", 0.65),

    # NSObject / Foundation
    (frozenset({"NSLog"}), "log_message", 0.55),
    (frozenset({"NSGetArgc", "NSGetArgv"}), "get_program_arguments", 0.8),
    (frozenset({"NSGetExecutablePath"}), "get_executable_path", 0.75),

    # IOKit / DiskArbitration / Launch Services
    (frozenset({"FSPathMakeRef", "LSCopyKindStringForRef"}), "get_file_kind", 0.75),

    # Mach ports
    (frozenset({"mach_port_allocate", "mach_port_deallocate"}), "manage_mach_port", 0.75),
    (frozenset({"mach_port_allocate"}), "allocate_mach_port", 0.65),
    (frozenset({"mach_port_deallocate"}), "deallocate_mach_port", 0.65),
    (frozenset({"mach_msg"}), "send_mach_message", 0.65),
    (frozenset({"mach_port_type"}), "check_mach_port_type", 0.6),
    (frozenset({"mach_task_self_"}), "get_task_self", 0.55),
    (frozenset({"mach_timebase_info", "mach_continuous_time"}), "get_high_res_time", 0.75),
    (frozenset({"mach_continuous_time"}), "get_continuous_time", 0.65),

    # Bootstrap
    (frozenset({"bootstrap_look_up"}), "lookup_bootstrap_service", 0.7),

    # Launch Services
    (frozenset({"launch_data_alloc", "launch_data_dict_insert", "launch_msg"}), "send_launch_message", 0.8),
    (frozenset({"launch_data_new_string"}), "create_launch_string", 0.6),

    # ucontext (fiber/coroutine)
    (frozenset({"getcontext", "makecontext", "setcontext"}), "setup_coroutine", 0.8),
    (frozenset({"getcontext", "makecontext"}), "create_context", 0.75),
    (frozenset({"setcontext"}), "switch_context", 0.6),
    (frozenset({"setjmp", "longjmp"}), "exception_jump", 0.65),
    (frozenset({"sigsetjmp", "siglongjmp"}), "signal_safe_jump", 0.7),

    # ===================================================================
    # DYNAMIC LOADING
    # ===================================================================
    (frozenset({"dlopen", "dlsym", "dlclose"}), "use_dynamic_library", 0.8),
    (frozenset({"dlopen", "dlsym"}), "load_dynamic_library", 0.8),
    (frozenset({"dlclose"}), "unload_library", 0.6),
    (frozenset({"dladdr"}), "get_symbol_address_info", 0.65),
    (frozenset({"dlerror"}), "check_dl_error", 0.6),

    # ===================================================================
    # TIME
    # ===================================================================
    (frozenset({"time", "localtime_r"}), "get_local_time", 0.7),
    (frozenset({"time", "gmtime_r"}), "get_utc_time", 0.7),
    (frozenset({"time", "gmtime"}), "get_utc_time", 0.7),
    (frozenset({"gettimeofday"}), "get_precise_time", 0.6),
    (frozenset({"clock_gettime"}), "get_clock_time", 0.6),
    (frozenset({"strftime"}), "format_time_string", 0.65),
    (frozenset({"strptime"}), "parse_time_string", 0.65),
    (frozenset({"mktime"}), "convert_to_timestamp", 0.65),
    (frozenset({"timegm"}), "convert_to_utc_timestamp", 0.65),
    (frozenset({"ctime_r"}), "time_to_string", 0.6),
    (frozenset({"localtime_r", "strftime"}), "format_local_time", 0.75),
    (frozenset({"gmtime_r", "strftime"}), "format_utc_time", 0.75),
    (frozenset({"nanosleep"}), "sleep_nanoseconds", 0.6),
    (frozenset({"usleep"}), "sleep_microseconds", 0.6),

    # ===================================================================
    # I/O / TERMINAL
    # ===================================================================
    (frozenset({"printf"}), "print_output", 0.45),
    (frozenset({"puts"}), "print_line", 0.45),
    (frozenset({"dprintf"}), "write_to_fd_formatted", 0.6),
    (frozenset({"fprintf"}), "write_formatted", 0.5),
    (frozenset({"vfprintf"}), "write_formatted_va", 0.5),
    (frozenset({"scanf"}), "read_input", 0.55),
    (frozenset({"fgets"}), "read_line", 0.5),
    (frozenset({"getchar"}), "read_char", 0.5),
    (frozenset({"ioctl"}), "device_control", 0.55),
    (frozenset({"tcgetattr", "tcsetattr"}), "configure_terminal", 0.75),

    # ===================================================================
    # ERROR
    # ===================================================================
    (frozenset({"perror"}), "print_error", 0.55),
    (frozenset({"strerror"}), "get_error_string", 0.55),

    # ===================================================================
    # SORTING / SEARCH
    # ===================================================================
    (frozenset({"qsort"}), "sort_array", 0.65),
    (frozenset({"memchr"}), "find_byte_in_memory", 0.6),
    (frozenset({"memcmp"}), "compare_memory", 0.6),

    # ===================================================================
    # C++ EXCEPTION HANDLING
    # ===================================================================
    (frozenset({"__cxa_allocate_exception", "__cxa_throw"}), "throw_exception", 0.8),
    (frozenset({"__cxa_begin_catch", "__cxa_end_catch"}), "catch_exception", 0.75),
    (frozenset({"__cxa_rethrow"}), "rethrow_exception", 0.7),
    (frozenset({"cxa_allocate_exception", "cxa_throw"}), "throw_exception", 0.8),
    (frozenset({"cxa_begin_catch", "cxa_end_catch"}), "catch_exception", 0.75),
    (frozenset({"cxa_guard_acquire", "cxa_guard_release"}), "static_init_guard", 0.75),

    # ===================================================================
    # C++ STD LIBRARY (stripped symbols, common patterns)
    # ===================================================================
    (frozenset({"Znwm", "ZdlPv"}), "cpp_new_delete", 0.65),
    (frozenset({"Znwm"}), "cpp_new", 0.55),
    (frozenset({"Znam"}), "cpp_new_array", 0.55),
    (frozenset({"ZdlPv"}), "cpp_delete", 0.5),
    (frozenset({"ZdaPv"}), "cpp_delete_array", 0.5),

    # ===================================================================
    # STEAM / VALVE SPECIFIC
    # ===================================================================
    (frozenset({"Breakpad_SetSteamID"}), "set_breakpad_steam_id", 0.85),
    (frozenset({"SteamAPI_Init", "SteamAPI_Shutdown"}), "steam_lifecycle", 0.85),
    (frozenset({"SteamAPI_Init"}), "steam_init", 0.8),
    (frozenset({"SteamAPI_Shutdown"}), "steam_shutdown", 0.8),
    (frozenset({"SteamAPI_RunCallbacks"}), "steam_pump_callbacks", 0.8),
    (frozenset({"SteamAPI_RegisterCallback", "SteamAPI_UnregisterCallback"}), "steam_manage_callback", 0.8),
    (frozenset({"SteamAPI_RegisterCallback"}), "steam_register_callback", 0.75),
    (frozenset({"SteamAPI_UnregisterCallback"}), "steam_unregister_callback", 0.75),
    (frozenset({"SteamAPI_RegisterCallResult", "SteamAPI_UnregisterCallResult"}), "steam_manage_call_result", 0.8),
    (frozenset({"SteamAPI_ISteamClient"}), "steam_get_client", 0.75),
    (frozenset({"SteamAPI_ISteamUser"}), "steam_get_user", 0.75),
    (frozenset({"SteamAPI_ISteamFriends"}), "steam_get_friends", 0.75),
    (frozenset({"SteamAPI_ISteamMatchmaking"}), "steam_get_matchmaking", 0.75),
    (frozenset({"SteamAPI_ISteamNetworking"}), "steam_get_networking", 0.75),
    (frozenset({"SteamAPI_ISteamUtils"}), "steam_get_utils", 0.75),
    (frozenset({"SteamAPI_ISteamApps"}), "steam_get_apps", 0.75),
    (frozenset({"SteamAPI_ISteamUGC"}), "steam_get_ugc", 0.75),
    (frozenset({"SteamAPI_ISteamRemoteStorage"}), "steam_get_remote_storage", 0.75),
    (frozenset({"SteamAPI_ISteamHTTP"}), "steam_get_http", 0.75),
    (frozenset({"SteamAPI_ISteamInventory"}), "steam_get_inventory", 0.75),
    (frozenset({"SteamAPI_ISteamController"}), "steam_get_controller", 0.75),
    (frozenset({"SteamAPI_ISteamScreenshots"}), "steam_get_screenshots", 0.75),
    (frozenset({"SteamAPI_GetHSteamPipe", "SteamAPI_GetHSteamUser"}), "steam_get_pipe_and_user", 0.8),
    (frozenset({"SteamAPI_GetHSteamPipe"}), "steam_get_pipe", 0.7),
    (frozenset({"SteamAPI_GetHSteamUser"}), "steam_get_user_handle", 0.7),
    (frozenset({"SteamGameServer_Init", "SteamGameServer_Shutdown"}), "game_server_lifecycle", 0.85),
    (frozenset({"SteamGameServer_Init"}), "game_server_init", 0.8),
    (frozenset({"SteamGameServer_Shutdown"}), "game_server_shutdown", 0.8),
    (frozenset({"SteamGameServer_RunCallbacks"}), "game_server_pump", 0.8),
    (frozenset({"Breakpad_SetSteamID", "Breakpad_SteamSetSteamID"}), "breakpad_set_ids", 0.85),
    (frozenset({"Breakpad_SteamMiniDumpInit"}), "breakpad_init_minidump", 0.8),
    (frozenset({"Breakpad_SteamWriteMiniDumpUsingExceptionInfoWithBuildId"}), "breakpad_write_minidump", 0.85),

    # ===================================================================
    # ZLIB / COMPRESSION
    # ===================================================================
    (frozenset({"deflateInit", "deflate", "deflateEnd"}), "compress_data_zlib", 0.85),
    (frozenset({"deflateInit2", "deflate", "deflateEnd"}), "compress_data_zlib_advanced", 0.85),
    (frozenset({"inflateInit", "inflate", "inflateEnd"}), "decompress_data_zlib", 0.85),
    (frozenset({"inflateInit2", "inflate", "inflateEnd"}), "decompress_data_zlib_advanced", 0.85),
    (frozenset({"compress", "uncompress"}), "zlib_compress_uncompress", 0.8),
    (frozenset({"compress"}), "zlib_compress", 0.7),
    (frozenset({"compress2"}), "zlib_compress_level", 0.7),
    (frozenset({"uncompress"}), "zlib_uncompress", 0.7),
    (frozenset({"uncompress2"}), "zlib_uncompress_sized", 0.7),
    (frozenset({"deflateInit", "deflate"}), "zlib_deflate_stream", 0.75),
    (frozenset({"inflateInit", "inflate"}), "zlib_inflate_stream", 0.75),
    (frozenset({"gzopen", "gzwrite", "gzclose"}), "write_gzip_file", 0.85),
    (frozenset({"gzopen", "gzread", "gzclose"}), "read_gzip_file", 0.85),
    (frozenset({"gzopen", "gzgets", "gzclose"}), "read_gzip_lines", 0.85),
    (frozenset({"gzopen", "gzclose"}), "open_close_gzip", 0.7),
    (frozenset({"crc32"}), "compute_crc32", 0.65),
    (frozenset({"adler32"}), "compute_adler32", 0.65),
    (frozenset({"compressBound"}), "get_compress_bound", 0.65),

    # ===================================================================
    # PROTOBUF (Google Protocol Buffers)
    # ===================================================================
    (frozenset({"protobuf_c_message_pack", "protobuf_c_message_unpack"}), "protobuf_serialize_deserialize", 0.85),
    (frozenset({"protobuf_c_message_pack"}), "protobuf_serialize", 0.8),
    (frozenset({"protobuf_c_message_unpack"}), "protobuf_deserialize", 0.8),
    (frozenset({"protobuf_c_message_free_unpacked"}), "protobuf_free", 0.7),
    (frozenset({"protobuf_c_message_get_packed_size"}), "protobuf_get_size", 0.7),
    (frozenset({"protobuf_c_message_init"}), "protobuf_init_message", 0.7),

    # ===================================================================
    # SQLITE
    # ===================================================================
    (frozenset({"sqlite3_open", "sqlite3_close"}), "sqlite_open_close", 0.8),
    (frozenset({"sqlite3_open", "sqlite3_exec", "sqlite3_close"}), "sqlite_exec_query", 0.85),
    (frozenset({"sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize"}), "sqlite_prepared_query", 0.85),
    (frozenset({"sqlite3_prepare_v2", "sqlite3_bind_text", "sqlite3_step", "sqlite3_finalize"}), "sqlite_parameterized_query", 0.9),
    (frozenset({"sqlite3_prepare_v2", "sqlite3_bind_int", "sqlite3_step", "sqlite3_finalize"}), "sqlite_parameterized_query_int", 0.9),
    (frozenset({"sqlite3_open_v2", "sqlite3_close_v2"}), "sqlite_open_close_v2", 0.8),
    (frozenset({"sqlite3_exec"}), "sqlite_exec", 0.7),
    (frozenset({"sqlite3_prepare_v2", "sqlite3_step"}), "sqlite_prepare_step", 0.75),
    (frozenset({"sqlite3_column_text", "sqlite3_column_int"}), "sqlite_read_columns", 0.75),
    (frozenset({"sqlite3_column_text"}), "sqlite_read_text_column", 0.65),
    (frozenset({"sqlite3_column_int"}), "sqlite_read_int_column", 0.65),
    (frozenset({"sqlite3_column_blob"}), "sqlite_read_blob_column", 0.65),
    (frozenset({"sqlite3_column_count"}), "sqlite_get_column_count", 0.6),
    (frozenset({"sqlite3_errmsg"}), "sqlite_get_error", 0.6),
    (frozenset({"sqlite3_free"}), "sqlite_free_memory", 0.55),
    (frozenset({"sqlite3_bind_text"}), "sqlite_bind_text", 0.6),
    (frozenset({"sqlite3_bind_int"}), "sqlite_bind_int", 0.6),
    (frozenset({"sqlite3_bind_blob"}), "sqlite_bind_blob", 0.6),
    (frozenset({"sqlite3_reset"}), "sqlite_reset_stmt", 0.6),
    (frozenset({"sqlite3_changes"}), "sqlite_get_changes", 0.6),
    (frozenset({"sqlite3_last_insert_rowid"}), "sqlite_last_insert_id", 0.65),
    (frozenset({"sqlite3_busy_timeout"}), "sqlite_set_busy_timeout", 0.65),

    # ===================================================================
    # REGEX / PCRE
    # ===================================================================
    (frozenset({"regcomp", "regexec", "regfree"}), "regex_match_and_free", 0.85),
    (frozenset({"regcomp", "regexec"}), "regex_match", 0.8),
    (frozenset({"regcomp"}), "compile_regex", 0.7),
    (frozenset({"regexec"}), "execute_regex", 0.65),
    (frozenset({"regerror"}), "get_regex_error", 0.6),

    # ===================================================================
    # LOCALE / INTERNATIONALIZATION
    # ===================================================================
    (frozenset({"setlocale", "gettext"}), "setup_localization", 0.75),
    (frozenset({"gettext"}), "translate_string", 0.6),
    (frozenset({"ngettext"}), "translate_plural", 0.65),
    (frozenset({"setlocale"}), "set_locale", 0.6),
    (frozenset({"iconv_open", "iconv", "iconv_close"}), "convert_encoding", 0.85),
    (frozenset({"iconv_open", "iconv_close"}), "manage_encoding_converter", 0.75),

    # ===================================================================
    # RANDOM / ENTROPY
    # ===================================================================
    (frozenset({"arc4random"}), "get_random_value", 0.65),
    (frozenset({"arc4random_buf"}), "fill_random_bytes", 0.7),
    (frozenset({"arc4random_uniform"}), "get_random_uniform", 0.65),
    (frozenset({"getrandom"}), "get_system_random", 0.65),
    (frozenset({"RAND_bytes"}), "get_openssl_random", 0.7),
    (frozenset({"SecRandomCopyBytes"}), "get_secure_random", 0.75),
    (frozenset({"srand", "rand"}), "setup_prng", 0.6),

    # ===================================================================
    # SHARED MEMORY / IPC
    # ===================================================================
    (frozenset({"shm_open", "mmap", "shm_unlink"}), "shared_memory_lifecycle", 0.85),
    (frozenset({"shm_open", "mmap"}), "open_shared_memory", 0.8),
    (frozenset({"shm_unlink"}), "unlink_shared_memory", 0.65),
    (frozenset({"msgget", "msgsnd", "msgrcv"}), "message_queue_io", 0.8),
    (frozenset({"msgget", "msgsnd"}), "send_message_queue", 0.75),
    (frozenset({"msgget", "msgrcv"}), "receive_message_queue", 0.75),
    (frozenset({"shmget", "shmat", "shmdt"}), "sysv_shared_memory", 0.8),
    (frozenset({"shmget", "shmat"}), "attach_shared_memory", 0.75),
    (frozenset({"shmdt"}), "detach_shared_memory", 0.6),

    # ===================================================================
    # NOTIFICATION / EVENT (macOS)
    # ===================================================================
    (frozenset({"notify_register_dispatch", "notify_cancel"}), "manage_notification", 0.75),
    (frozenset({"notify_register_dispatch"}), "register_notification", 0.7),
    (frozenset({"notify_post"}), "post_notification", 0.65),
    (frozenset({"CFNotificationCenterAddObserver", "CFNotificationCenterRemoveObserver"}), "manage_cf_notification", 0.8),
    (frozenset({"CFNotificationCenterPostNotification"}), "post_cf_notification", 0.7),

    # ===================================================================
    # KEYCHAIN (macOS)
    # ===================================================================
    (frozenset({"SecItemAdd", "SecItemDelete"}), "manage_keychain_item", 0.8),
    (frozenset({"SecItemCopyMatching"}), "query_keychain", 0.75),
    (frozenset({"SecItemAdd"}), "add_keychain_item", 0.7),
    (frozenset({"SecItemUpdate"}), "update_keychain_item", 0.7),
    (frozenset({"SecItemDelete"}), "delete_keychain_item", 0.7),
    (frozenset({"SecKeychainOpen", "SecKeychainLock"}), "manage_keychain", 0.8),

    # ===================================================================
    # NETWORK - HTTP (macOS CFNetwork / curl)
    # ===================================================================
    (frozenset({"CFHTTPMessageCreateRequest", "CFReadStreamCreateForHTTPRequest"}), "create_http_request", 0.8),
    (frozenset({"CFHTTPMessageSetHeaderFieldValue"}), "set_http_header", 0.7),
    (frozenset({"CFHTTPMessageCopyHeaderFieldValue"}), "get_http_header", 0.7),
    (frozenset({"CFHTTPMessageGetResponseStatusCode"}), "get_http_status_code", 0.75),
    (frozenset({"curl_easy_init", "curl_easy_setopt", "curl_easy_perform", "curl_easy_cleanup"}), "curl_http_request", 0.9),
    (frozenset({"curl_easy_init", "curl_easy_setopt", "curl_easy_perform"}), "curl_perform_request", 0.85),
    (frozenset({"curl_easy_init", "curl_easy_cleanup"}), "curl_session", 0.75),
    (frozenset({"curl_easy_init"}), "curl_init_session", 0.65),
    (frozenset({"curl_easy_setopt"}), "curl_set_option", 0.55),
    (frozenset({"curl_easy_perform"}), "curl_execute", 0.6),
    (frozenset({"curl_easy_getinfo"}), "curl_get_info", 0.6),
    (frozenset({"curl_easy_cleanup"}), "curl_cleanup", 0.55),
    (frozenset({"curl_easy_strerror"}), "curl_error_string", 0.55),
    (frozenset({"curl_multi_init", "curl_multi_add_handle", "curl_multi_perform"}), "curl_multi_request", 0.85),
    (frozenset({"curl_slist_append"}), "curl_build_header_list", 0.6),
    (frozenset({"curl_global_init", "curl_global_cleanup"}), "curl_global_lifecycle", 0.75),

    # ===================================================================
    # JSON PARSING (jansson, cJSON, yyjson)
    # ===================================================================
    (frozenset({"json_loads", "json_decref"}), "parse_json_string", 0.8),
    (frozenset({"json_dumps"}), "serialize_to_json", 0.7),
    (frozenset({"json_object_get", "json_string_value"}), "get_json_string_field", 0.75),
    (frozenset({"json_object_get", "json_integer_value"}), "get_json_int_field", 0.75),
    (frozenset({"json_object_set_new"}), "set_json_field", 0.65),
    (frozenset({"json_array_size", "json_array_get"}), "iterate_json_array", 0.75),
    (frozenset({"cJSON_Parse", "cJSON_Delete"}), "cjson_parse_and_free", 0.8),
    (frozenset({"cJSON_Parse"}), "cjson_parse", 0.7),
    (frozenset({"cJSON_Print"}), "cjson_serialize", 0.7),
    (frozenset({"cJSON_GetObjectItem"}), "cjson_get_field", 0.65),
    (frozenset({"cJSON_CreateObject", "cJSON_AddStringToObject"}), "cjson_build_object", 0.75),

    # ===================================================================
    # VALVE SOURCE ENGINE SPECIFIC
    # ===================================================================
    (frozenset({"ConVar_Register"}), "register_convar", 0.8),
    (frozenset({"ConCommand_Register"}), "register_concommand", 0.8),
    (frozenset({"CreateInterface"}), "create_engine_interface", 0.8),
    (frozenset({"Msg"}), "engine_log_message", 0.5),
    (frozenset({"Warning"}), "engine_log_warning", 0.55),
    (frozenset({"DevMsg"}), "engine_dev_message", 0.55),
    (frozenset({"DevWarning"}), "engine_dev_warning", 0.55),
    (frozenset({"Error"}), "engine_fatal_error", 0.55),
    (frozenset({"Plat_FloatTime"}), "get_engine_time", 0.7),
    (frozenset({"Plat_MSTime"}), "get_engine_time_ms", 0.7),
    (frozenset({"KeyValues", "FindKey"}), "keyvalues_lookup", 0.7),
    (frozenset({"KeyValues", "GetString"}), "keyvalues_get_string", 0.7),
    (frozenset({"KeyValues", "GetInt"}), "keyvalues_get_int", 0.7),
    (frozenset({"V_snprintf"}), "valve_format_string", 0.6),
    (frozenset({"V_strncpy"}), "valve_copy_string", 0.6),
    (frozenset({"V_strcmp"}), "valve_compare_strings", 0.55),
    (frozenset({"V_stricmp"}), "valve_compare_strings_nocase", 0.6),
    (frozenset({"CUtlBuffer"}), "valve_utl_buffer", 0.6),
    (frozenset({"CUtlVector"}), "valve_utl_vector", 0.6),
    (frozenset({"CUtlString"}), "valve_utl_string", 0.6),
    (frozenset({"CUtlMap"}), "valve_utl_map", 0.6),
    (frozenset({"CUtlMemory"}), "valve_utl_memory", 0.6),
    (frozenset({"CUtlDict"}), "valve_utl_dict", 0.6),
    (frozenset({"ThreadSleep"}), "valve_thread_sleep", 0.6),

    # ===================================================================
    # CoreGraphics -- CGRect / CGPoint / CGSize geometry helpers
    # ===================================================================
    (frozenset({"CGRectGetWidth", "CGRectGetHeight", "CGRectGetMinX", "CGRectGetMinY"}), "compute_rect_geometry", 0.80),
    (frozenset({"CGRectGetWidth", "CGRectGetHeight", "CGRectGetMaxX", "CGRectGetMaxY"}), "compute_rect_max_bounds", 0.80),
    (frozenset({"CGRectGetWidth", "CGRectGetHeight", "CGRectGetMinX", "CGRectGetMaxY"}), "compute_rect_bounds", 0.80),
    (frozenset({"CGRectGetWidth", "CGRectGetHeight", "CGRectGetMaxX", "CGRectGetMinY"}), "compute_rect_bounds_alt", 0.80),
    (frozenset({"CGRectGetWidth", "CGRectGetMinX", "CGRectGetMaxX"}), "compute_rect_horizontal", 0.75),
    (frozenset({"CGRectGetHeight", "CGRectGetMinY", "CGRectGetMaxY"}), "compute_rect_vertical", 0.75),
    (frozenset({"CGRectGetWidth", "CGRectGetHeight"}), "get_rect_dimensions", 0.75),
    (frozenset({"CGRectGetMinX", "CGRectGetMinY"}), "get_rect_origin", 0.75),
    (frozenset({"CGRectGetMaxX", "CGRectGetMaxY"}), "get_rect_max_point", 0.75),
    (frozenset({"CGRectGetMidX", "CGRectGetMidY"}), "get_rect_center", 0.75),
    (frozenset({"CGRectEqualToRect"}), "check_rect_equality", 0.70),
    (frozenset({"CGRectIntersectsRect"}), "check_rect_intersection", 0.70),
    (frozenset({"CGRectContainsPoint"}), "check_point_in_rect", 0.70),
    (frozenset({"CGRectContainsRect"}), "check_rect_contains_rect", 0.70),
    (frozenset({"CGRectUnion"}), "compute_rect_union", 0.70),
    (frozenset({"CGRectIntersection"}), "compute_rect_intersection", 0.70),
    (frozenset({"CGRectInset"}), "compute_rect_inset", 0.70),
    (frozenset({"CGRectOffset"}), "compute_rect_offset", 0.70),
    (frozenset({"CGRectStandardize"}), "standardize_rect", 0.70),
    (frozenset({"CGRectIsNull"}), "check_rect_null", 0.70),
    (frozenset({"CGRectIsEmpty"}), "check_rect_empty", 0.70),
    (frozenset({"CGSizeMake"}), "create_size", 0.65),
    (frozenset({"CGPointMake"}), "create_point", 0.65),
    (frozenset({"CGRectMake"}), "create_rect", 0.65),

    # ===================================================================
    # Swift Runtime -- memory management, protocol, metadata
    # ===================================================================
    (frozenset({"swift_allocObject", "swift_release"}), "swift_alloc_release", 0.75),
    (frozenset({"swift_allocObject", "swift_retain"}), "swift_alloc_retain", 0.75),
    (frozenset({"swift_allocObject"}), "swift_allocate_object", 0.70),
    (frozenset({"swift_retain", "swift_release"}), "swift_retain_release_cycle", 0.70),
    (frozenset({"swift_getWitnessTable"}), "swift_protocol_witness_lookup", 0.75),
    (frozenset({"swift_initStaticObject"}), "swift_lazy_static_init", 0.75),
    (frozenset({"swift_once"}), "swift_once_init", 0.70),
    (frozenset({"swift_beginAccess", "swift_endAccess"}), "swift_exclusive_access", 0.75),
    (frozenset({"swift_beginAccess"}), "swift_begin_exclusive_access", 0.70),
    (frozenset({"swift_deallocClassInstance"}), "swift_dealloc_instance", 0.70),
    (frozenset({"swift_isUniquelyReferenced_nonNull_native"}), "swift_check_unique_ref", 0.70),
    (frozenset({"swift_bridgeObjectRetain", "swift_bridgeObjectRelease"}), "swift_bridge_retain_release", 0.70),
    (frozenset({"swift_bridgeObjectRelease"}), "swift_bridge_release", 0.65),
    (frozenset({"swift_bridgeObjectRetain"}), "swift_bridge_retain", 0.65),
    (frozenset({"swift_arrayInitWithCopy"}), "swift_copy_array", 0.70),
    (frozenset({"swift_getObjCClassMetadata"}), "swift_get_objc_metadata", 0.70),

    # Swift + ObjC bridge pattern
    (frozenset({"objc_opt_self", "swift_getObjCClassMetadata"}), "swift_objc_class_lookup", 0.75),

    # ===================================================================
    # NSAccessibility -- macOS accessibility helpers
    # ===================================================================
    (frozenset({"NSAccessibilityRoleAttribute", "NSAccessibilitySubroleAttribute"}), "get_accessibility_role", 0.75),
    (frozenset({"NSAccessibilityPositionAttribute", "NSAccessibilitySizeAttribute"}), "get_accessibility_geometry", 0.75),

    # ===================================================================
    # Swift Hashable / Equatable protocol witnesses
    # ===================================================================
    (frozenset({"combine", "finalize", "init"}), "swift_hash_combine", 0.75),
    (frozenset({"hash", "combine"}), "swift_compute_hash", 0.70),

    # ===================================================================
    # Swift String bridge
    # ===================================================================
    (frozenset({"stringCompareWithSmolCheck", "swift_bridgeObjectRelease"}), "swift_compare_strings_bridged", 0.75),
    (frozenset({"stringCompareWithSmolCheck"}), "swift_compare_strings", 0.70),
]


# ---------------------------------------------------------------------------
# Single API Hints
# Her kayit: api_name -> (suggested_prefix, confidence)
# ---------------------------------------------------------------------------

SINGLE_API_HINTS: dict[str, tuple[str, float]] = {
    # Memory
    "malloc": ("alloc_", 0.45),
    "calloc": ("alloc_", 0.45),
    "free": ("cleanup_", 0.45),
    "realloc": ("resize_", 0.45),
    "memcpy": ("copy_", 0.45),
    "memset": ("init_", 0.45),
    "memmove": ("move_", 0.45),
    "posix_memalign": ("aligned_alloc_", 0.5),
    "bzero": ("zero_", 0.45),
    "mmap": ("map_", 0.5),
    "munmap": ("unmap_", 0.5),

    # I/O
    "printf": ("print_", 0.35),
    "fprintf": ("write_", 0.4),
    "sprintf": ("format_", 0.4),
    "snprintf": ("format_", 0.4),
    "dprintf": ("fd_write_", 0.45),
    "puts": ("print_", 0.35),
    "fputs": ("write_str_", 0.4),
    "fputc": ("write_char_", 0.4),
    "scanf": ("read_", 0.4),

    # File I/O
    "fopen": ("open_", 0.45),
    "fclose": ("close_", 0.45),
    "fread": ("read_", 0.45),
    "fwrite": ("write_", 0.45),
    "fgets": ("readline_", 0.45),
    "fseek": ("seek_", 0.4),
    "ftell": ("tell_pos_", 0.4),
    "fflush": ("flush_", 0.4),
    "fileno": ("get_fd_", 0.4),
    "open": ("open_fd_", 0.45),
    "close": ("close_fd_", 0.4),
    "read": ("read_fd_", 0.45),
    "write": ("write_fd_", 0.45),
    "lseek": ("seek_fd_", 0.4),
    "stat": ("stat_", 0.45),
    "fstat": ("fstat_", 0.45),
    "lstat": ("lstat_", 0.45),
    "access": ("check_", 0.4),
    "unlink": ("delete_", 0.45),
    "remove": ("remove_", 0.45),
    "rename": ("rename_", 0.45),
    "mkdir": ("mkdir_", 0.45),
    "rmdir": ("rmdir_", 0.45),
    "opendir": ("listdir_", 0.45),
    "readdir": ("readdir_", 0.45),
    "scandir": ("scandir_", 0.5),
    "readlink": ("readlink_", 0.45),
    "realpath": ("resolve_", 0.45),
    "symlink": ("symlink_", 0.45),
    "link": ("hardlink_", 0.45),
    "chmod": ("chmod_", 0.4),
    "chown": ("chown_", 0.4),
    "flock": ("flock_", 0.45),
    "fcntl": ("fcntl_", 0.4),
    "fsync": ("sync_", 0.4),
    "copyfile": ("copy_file_", 0.5),
    "mkfifo": ("mkfifo_", 0.5),
    "getxattr": ("get_xattr_", 0.5),
    "setxattr": ("set_xattr_", 0.5),
    "removexattr": ("rm_xattr_", 0.5),

    # Network
    "socket": ("net_", 0.45),
    "connect": ("connect_", 0.45),
    "bind": ("bind_", 0.45),
    "listen": ("listen_", 0.45),
    "accept": ("accept_", 0.45),
    "send": ("send_", 0.45),
    "recv": ("receive_", 0.45),
    "sendto": ("sendto_", 0.45),
    "sendmsg": ("sendmsg_", 0.45),
    "recvmsg": ("recvmsg_", 0.45),
    "setsockopt": ("setsockopt_", 0.45),
    "getsockopt": ("getsockopt_", 0.45),
    "getsockname": ("getsockname_", 0.45),
    "getaddrinfo": ("resolve_", 0.45),
    "shutdown": ("shutdown_", 0.45),
    "poll": ("poll_", 0.45),
    "select": ("select_", 0.4),
    "kevent": ("kevent_", 0.5),
    "kqueue": ("kqueue_", 0.5),

    # Process
    "fork": ("spawn_", 0.45),
    "execve": ("exec_", 0.45),
    "execv": ("exec_", 0.45),
    "posix_spawn": ("spawn_", 0.5),
    "system": ("shell_", 0.45),
    "popen": ("pipe_cmd_", 0.45),
    "kill": ("kill_", 0.45),
    "getpid": ("getpid_", 0.4),
    "getenv": ("getenv_", 0.45),
    "setenv": ("setenv_", 0.45),
    "getcwd": ("getcwd_", 0.45),
    "chdir": ("chdir_", 0.4),
    "sysctl": ("sysctl_", 0.5),

    # Thread
    "pthread_create": ("thread_", 0.45),
    "pthread_join": ("join_", 0.45),
    "pthread_mutex_lock": ("lock_", 0.4),
    "pthread_mutex_unlock": ("unlock_", 0.4),
    "pthread_mutex_init": ("init_mutex_", 0.45),
    "pthread_cond_wait": ("cond_wait_", 0.45),
    "pthread_cond_signal": ("cond_signal_", 0.45),
    "pthread_once": ("once_init_", 0.45),
    "sched_yield": ("yield_", 0.45),

    # ObjC
    "objc_msgSend": ("objc_call_", 0.35),
    "objc_alloc": ("objc_alloc_", 0.4),
    "objc_retain": ("objc_retain_", 0.35),
    "objc_release": ("objc_release_", 0.35),

    # CoreFoundation
    "CFRelease": ("cf_release_", 0.35),
    "CFStringCreateWithCString": ("create_cfstr_", 0.5),
    "CFStringGetCString": ("get_cfstr_", 0.5),
    "CFStringGetCStringPtr": ("get_cfstr_ptr_", 0.5),
    "CFStringCompare": ("compare_cfstr_", 0.5),
    "CFArrayCreate": ("cf_array_", 0.45),
    "CFArrayAppendValue": ("cf_array_append_", 0.45),
    "CFArrayGetCount": ("cf_array_count_", 0.45),
    "CFArrayGetValueAtIndex": ("cf_array_get_", 0.45),
    "CFDictionaryCreateMutable": ("cf_dict_create_", 0.45),
    "CFDictionaryGetValue": ("cf_dict_get_", 0.45),
    "CFDictionarySetValue": ("cf_dict_set_", 0.45),
    "CFNumberCreate": ("cf_num_create_", 0.45),
    "CFNumberGetValue": ("cf_num_get_", 0.45),
    "CFPropertyListCreateFromXMLData": ("parse_plist_", 0.55),
    "CFURLCreateFromFileSystemRepresentation": ("create_url_", 0.5),
    "CFRunLoopRunInMode": ("run_loop_", 0.5),

    # GCD
    "dispatch_get_global_queue": ("dispatch_", 0.4),
    "dispatch_group_async_f": ("dispatch_group_", 0.45),
    "dispatch_once_f": ("once_", 0.45),
    "dispatch_source_create": ("dispatch_src_", 0.45),
    "dispatch_resume": ("dispatch_resume_", 0.4),
    "dispatch_suspend": ("dispatch_suspend_", 0.4),

    # Dynamic loading
    "dlopen": ("load_lib_", 0.5),
    "dlsym": ("resolve_sym_", 0.5),
    "dlclose": ("unload_lib_", 0.5),
    "dladdr": ("addr_info_", 0.5),

    # SSL
    "SSL_connect": ("ssl_", 0.45),
    "SSL_read": ("ssl_read_", 0.45),
    "SSL_write": ("ssl_write_", 0.45),
    "SSL_CTX_new": ("ssl_ctx_", 0.45),
    "SSL_new": ("ssl_new_", 0.45),

    # Security framework
    "SecCertificateCreateWithData": ("sec_cert_", 0.55),
    "SecTrustCreateWithCertificates": ("sec_trust_", 0.55),
    "SecTrustEvaluate": ("sec_eval_", 0.55),
    "SecPolicyCreateBasicX509": ("sec_policy_", 0.55),

    # Mach
    "mach_msg": ("mach_msg_", 0.5),
    "mach_port_allocate": ("mach_port_", 0.5),
    "mach_port_deallocate": ("mach_port_dealloc_", 0.5),
    "mach_continuous_time": ("mach_time_", 0.45),
    "mach_timebase_info": ("mach_timebase_", 0.45),

    # Bootstrap / Launch
    "bootstrap_look_up": ("bootstrap_", 0.55),
    "launch_msg": ("launchd_", 0.55),

    # Time
    "time": ("time_", 0.35),
    "gettimeofday": ("gettime_", 0.4),
    "strftime": ("fmt_time_", 0.45),
    "strptime": ("parse_time_", 0.45),
    "mktime": ("mktime_", 0.4),
    "localtime_r": ("localtime_", 0.4),
    "gmtime_r": ("gmtime_", 0.4),
    "nanosleep": ("sleep_", 0.4),
    "usleep": ("usleep_", 0.4),

    # Error
    "perror": ("perror_", 0.4),
    "strerror": ("strerror_", 0.4),

    # String
    "strlen": ("strlen_", 0.35),
    "strcmp": ("compare_", 0.4),
    "strncmp": ("compare_", 0.4),
    "strcasecmp": ("compare_nocase_", 0.45),
    "strcpy": ("copy_str_", 0.4),
    "strncpy": ("copy_str_", 0.4),
    "strcat": ("concat_", 0.4),
    "strncat": ("concat_", 0.4),
    "strstr": ("search_str_", 0.4),
    "strcasestr": ("search_str_nocase_", 0.45),
    "strchr": ("find_char_", 0.4),
    "strrchr": ("find_last_char_", 0.4),
    "strtok": ("tokenize_", 0.45),
    "sscanf": ("parse_", 0.45),
    "atoi": ("parse_int_", 0.45),
    "atoll": ("parse_ll_", 0.45),
    "strtol": ("parse_long_", 0.45),
    "strtoul": ("parse_ulong_", 0.45),
    "strtod": ("parse_double_", 0.45),
    "tolower": ("tolower_", 0.35),
    "toupper": ("toupper_", 0.35),

    # Sorting
    "qsort": ("sort_", 0.5),

    # Context / Coroutine
    "getcontext": ("context_", 0.45),
    "makecontext": ("make_context_", 0.5),
    "setcontext": ("set_context_", 0.45),

    # Backtrace
    "backtrace": ("backtrace_", 0.5),
    "backtrace_symbols": ("bt_symbols_", 0.5),

    # C++ runtime
    "cxa_throw": ("throw_", 0.5),
    "cxa_begin_catch": ("catch_", 0.45),
    "__cxa_throw": ("throw_", 0.5),
    "__cxa_begin_catch": ("catch_", 0.45),
    "terminate": ("terminate_", 0.45),

    # Steam / Valve
    "SteamAPI_Init": ("steam_init_", 0.6),
    "SteamAPI_Shutdown": ("steam_shutdown_", 0.6),
    "SteamAPI_RunCallbacks": ("steam_pump_", 0.55),
    "SteamAPI_RegisterCallback": ("steam_reg_cb_", 0.55),
    "SteamAPI_UnregisterCallback": ("steam_unreg_cb_", 0.55),
    "SteamGameServer_Init": ("gs_init_", 0.6),
    "SteamGameServer_Shutdown": ("gs_shutdown_", 0.6),
    "SteamGameServer_RunCallbacks": ("gs_pump_", 0.55),
    "Breakpad_SetSteamID": ("breakpad_", 0.55),
    "Breakpad_SteamMiniDumpInit": ("breakpad_init_", 0.55),
    "CreateInterface": ("interface_create_", 0.55),
    "ConVar_Register": ("convar_", 0.5),
    "ConCommand_Register": ("concmd_", 0.5),
    "Msg": ("engine_msg_", 0.35),
    "Warning": ("engine_warn_", 0.35),
    "DevMsg": ("engine_devmsg_", 0.4),
    "Error": ("engine_error_", 0.4),
    "Plat_FloatTime": ("plat_time_", 0.5),
    "V_snprintf": ("valve_fmt_", 0.45),
    "V_strncpy": ("valve_copy_", 0.45),
    "V_stricmp": ("valve_cmp_", 0.45),

    # zlib
    "deflateInit": ("zlib_deflate_", 0.5),
    "deflateInit2": ("zlib_deflate_", 0.5),
    "inflate": ("zlib_inflate_", 0.45),
    "inflateInit": ("zlib_inflate_", 0.5),
    "inflateInit2": ("zlib_inflate_", 0.5),
    "deflate": ("zlib_deflate_", 0.45),
    "deflateEnd": ("zlib_end_", 0.45),
    "inflateEnd": ("zlib_end_", 0.45),
    "compress": ("compress_", 0.45),
    "compress2": ("compress_", 0.45),
    "uncompress": ("uncompress_", 0.45),
    "gzopen": ("gz_open_", 0.5),
    "gzread": ("gz_read_", 0.5),
    "gzwrite": ("gz_write_", 0.5),
    "gzclose": ("gz_close_", 0.5),
    "crc32": ("crc_", 0.45),
    "adler32": ("adler_", 0.45),

    # protobuf
    "protobuf_c_message_pack": ("pb_pack_", 0.55),
    "protobuf_c_message_unpack": ("pb_unpack_", 0.55),
    "protobuf_c_message_free_unpacked": ("pb_free_", 0.5),
    "protobuf_c_message_init": ("pb_init_", 0.5),

    # sqlite
    "sqlite3_open": ("sqlite_open_", 0.55),
    "sqlite3_close": ("sqlite_close_", 0.5),
    "sqlite3_exec": ("sqlite_exec_", 0.55),
    "sqlite3_prepare_v2": ("sqlite_prepare_", 0.55),
    "sqlite3_step": ("sqlite_step_", 0.5),
    "sqlite3_finalize": ("sqlite_finalize_", 0.5),
    "sqlite3_bind_text": ("sqlite_bind_", 0.5),
    "sqlite3_bind_int": ("sqlite_bind_", 0.5),
    "sqlite3_column_text": ("sqlite_col_", 0.5),
    "sqlite3_column_int": ("sqlite_col_", 0.5),
    "sqlite3_errmsg": ("sqlite_err_", 0.5),
    "sqlite3_last_insert_rowid": ("sqlite_lastid_", 0.55),

    # curl
    "curl_easy_init": ("curl_init_", 0.55),
    "curl_easy_setopt": ("curl_opt_", 0.5),
    "curl_easy_perform": ("curl_exec_", 0.55),
    "curl_easy_cleanup": ("curl_cleanup_", 0.5),
    "curl_easy_getinfo": ("curl_info_", 0.5),
    "curl_easy_strerror": ("curl_err_", 0.5),
    "curl_global_init": ("curl_global_", 0.5),
    "curl_slist_append": ("curl_list_", 0.45),

    # regex
    "regcomp": ("regex_compile_", 0.5),
    "regexec": ("regex_exec_", 0.5),
    "regfree": ("regex_free_", 0.45),
    "regerror": ("regex_err_", 0.45),

    # JSON
    "json_loads": ("json_parse_", 0.5),
    "json_dumps": ("json_dump_", 0.5),
    "json_object_get": ("json_get_", 0.45),
    "json_decref": ("json_free_", 0.45),
    "cJSON_Parse": ("cjson_parse_", 0.5),
    "cJSON_Print": ("cjson_print_", 0.5),
    "cJSON_Delete": ("cjson_free_", 0.45),
    "cJSON_GetObjectItem": ("cjson_get_", 0.45),

    # Random
    "arc4random": ("random_", 0.4),
    "arc4random_buf": ("random_buf_", 0.45),
    "arc4random_uniform": ("random_uniform_", 0.45),
    "SecRandomCopyBytes": ("sec_random_", 0.5),
    "RAND_bytes": ("ssl_random_", 0.5),

    # Keychain
    "SecItemAdd": ("keychain_add_", 0.55),
    "SecItemCopyMatching": ("keychain_query_", 0.55),
    "SecItemUpdate": ("keychain_update_", 0.55),
    "SecItemDelete": ("keychain_delete_", 0.55),

    # Encoding
    "iconv_open": ("iconv_open_", 0.5),
    "iconv": ("iconv_", 0.45),
    "iconv_close": ("iconv_close_", 0.5),

    # Shared memory
    "shm_open": ("shm_open_", 0.5),
    "shm_unlink": ("shm_unlink_", 0.5),
    "shmget": ("sysv_shm_", 0.5),
    "shmat": ("sysv_shm_attach_", 0.5),
    "shmdt": ("sysv_shm_detach_", 0.5),

    # CoreGraphics
    "CGRectGetWidth": ("rect_width_", 0.55),
    "CGRectGetHeight": ("rect_height_", 0.55),
    "CGRectGetMinX": ("rect_minx_", 0.50),
    "CGRectGetMinY": ("rect_miny_", 0.50),
    "CGRectGetMaxX": ("rect_maxx_", 0.50),
    "CGRectGetMaxY": ("rect_maxy_", 0.50),
    "CGRectGetMidX": ("rect_midx_", 0.50),
    "CGRectGetMidY": ("rect_midy_", 0.50),
    "CGRectEqualToRect": ("rect_equal_", 0.55),
    "CGRectIntersectsRect": ("rect_intersect_", 0.55),
    "CGRectContainsPoint": ("rect_contains_", 0.55),
    "CGRectContainsRect": ("rect_contains_rect_", 0.55),
    "CGRectUnion": ("rect_union_", 0.55),
    "CGRectIntersection": ("rect_intersection_", 0.55),
    "CGRectIsNull": ("rect_null_check_", 0.50),
    "CGRectIsEmpty": ("rect_empty_check_", 0.50),

    # Swift runtime
    "swift_allocObject": ("swift_alloc_", 0.50),
    "swift_retain": ("swift_retain_", 0.45),
    "swift_release": ("swift_release_", 0.45),
    "swift_deallocClassInstance": ("swift_dealloc_", 0.50),
    "swift_getWitnessTable": ("swift_witness_", 0.55),
    "swift_initStaticObject": ("swift_static_init_", 0.55),
    "swift_once": ("swift_once_", 0.50),
    "swift_beginAccess": ("swift_access_", 0.50),
    "swift_endAccess": ("swift_end_access_", 0.45),
    "swift_isUniquelyReferenced_nonNull_native": ("swift_unique_ref_", 0.55),
    "swift_bridgeObjectRetain": ("swift_bridge_retain_", 0.45),
    "swift_bridgeObjectRelease": ("swift_bridge_release_", 0.45),
    "swift_arrayInitWithCopy": ("swift_array_copy_", 0.50),
    "swift_getObjCClassMetadata": ("swift_objc_meta_", 0.50),

    # ObjC runtime (with underscore-stripped names)
    "objc_opt_self": ("objc_self_", 0.45),

    # NSScreen / NSWorkspace
    "NSScreenNumberForScreen": ("screen_number_", 0.55),
}


# ---------------------------------------------------------------------------
# String-to-name pattern'ler: agresif keyword extraction icin
# String'de gorulurse -> fonksiyon isminde kullan
# ---------------------------------------------------------------------------

# Steam/Valve specific keyword -> fonksiyon isim ipucu
STEAM_KEYWORDS: dict[str, str] = {
    "ipc": "ipc",
    "IPC": "ipc",
    "steam": "steam",
    "Steam": "steam",
    "STEAM": "steam",
    "valve": "valve",
    "Valve": "valve",
    "VAC": "vac",
    "vac": "vac",
    "bootstrap": "bootstrap",
    "bootstrapper": "bootstrapper",
    "breakpad": "breakpad",
    "Breakpad": "breakpad",
    "protobuf": "protobuf",
    "Protobuf": "protobuf",
    "steamclient": "steam_client",
    "SteamClient": "steam_client",
    "overlay": "overlay",
    "Overlay": "overlay",
    "workshop": "workshop",
    "Workshop": "workshop",
    "appinfo": "app_info",
    "AppInfo": "app_info",
    "gameserver": "game_server",
    "GameServer": "game_server",
    "matchmaking": "matchmaking",
    "Matchmaking": "matchmaking",
    "networking": "networking",
    "Networking": "networking",
    "lobby": "lobby",
    "Lobby": "lobby",
    "leaderboard": "leaderboard",
    "Leaderboard": "leaderboard",
    "achievement": "achievement",
    "Achievement": "achievement",
    "inventory": "inventory",
    "Inventory": "inventory",
    "controller": "controller",
    "Controller": "controller",
    "screenshot": "screenshot",
    "Screenshot": "screenshot",
    "ugc": "ugc",
    "UGC": "ugc",
    "depot": "depot",
    "Depot": "depot",
    "manifest": "manifest",
    "Manifest": "manifest",
    "download": "download",
    "Download": "download",
    "upload": "upload",
    "Upload": "upload",
    "install": "install",
    "Install": "install",
    "uninstall": "uninstall",
    "Uninstall": "uninstall",
    "update": "update",
    "Update": "update",
    "login": "login",
    "Login": "login",
    "logout": "logout",
    "Logout": "logout",
    "auth": "auth",
    "Auth": "auth",
    "ticket": "ticket",
    "Ticket": "ticket",
    "token": "token",
    "Token": "token",
    "session": "session",
    "Session": "session",
    "license": "license",
    "License": "license",
    "cloud": "cloud",
    "Cloud": "cloud",
    "friends": "friends",
    "Friends": "friends",
    "chat": "chat",
    "Chat": "chat",
    "voice": "voice",
    "Voice": "voice",
    "p2p": "p2p",
    "P2P": "p2p",
    "sentry": "sentry",
    "Sentry": "sentry",
    "cellid": "cell_id",
    "CellID": "cell_id",
}

# URL path component -> fonksiyon isim ipucu
URL_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/api/v\d+/(\w+)"), "api"),
    (re.compile(r"https?://[^/]+/(\w+)"), "http"),
    (re.compile(r"/auth"), "auth"),
    (re.compile(r"/login"), "login"),
    (re.compile(r"/token"), "token"),
    (re.compile(r"/steam"), "steam"),
    (re.compile(r"\.proto(?:buf)?$"), "protobuf"),
    (re.compile(r"\.json$"), "json"),
    (re.compile(r"\.xml$"), "xml"),
    (re.compile(r"\.vdf$"), "vdf"),
    (re.compile(r"\.cfg$"), "config"),
    (re.compile(r"\.log$"), "log"),
    (re.compile(r"\.pak$"), "package"),
    (re.compile(r"\.gcf$"), "cache"),
]

# Hata mesaji pattern -> fonksiyon isim ipucu (grup-bazli ekstraksiyon yap: None = capture grubu kullan)
ERROR_HINTS: list[tuple[re.Pattern[str], str | None]] = [
    (re.compile(r"(?:error|failed|failure|cannot|unable|couldn't|can't)\s+(?:to\s+)?(\w+)", re.I), None),  # extract verb
    (re.compile(r"(?:Error|ERROR):\s*(\w+)", re.I), None),
]

# Log fonksiyon isim mesajlari (None = capture grubu kullan)
LOG_HINTS: list[tuple[re.Pattern[str], str | None]] = [
    (re.compile(r"(\w+)::\s*(\w+)"), None),  # ClassName::MethodName
    (re.compile(r"^(\w+)\s*\(\)"), None),  # FuncName()
    (re.compile(r"Entering\s+(\w+)"), None),
    (re.compile(r"Leaving\s+(\w+)"), None),
]
