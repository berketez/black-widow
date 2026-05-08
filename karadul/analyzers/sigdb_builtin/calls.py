"""Calls category signatures — sig_db Faz 2 migration (özel yapı).

Kaynak: karadul/analyzers/signature_db.py
  - _STRING_REFERENCE_SIGNATURES (246 entry, satir 6613-6931)
    dict[frozenset[str], tuple[str, str, str]]
    -> (matched_name, library, purpose)

  - _CALL_PATTERN_SIGNATURES     ( 98 entry, satir 6941-7241)
    list[tuple[frozenset[str], str, str, str, float]]
    -> (callee_set, matched_name, library, purpose, confidence)

DİKKAT: Bu kategori diğerlerinden FARKLI yapıdadır.
- ``string_reference`` katmanı **frozenset anahtarli dict**'tir
  (dict[str, dict[str, str]] DEĞİL).
- ``call_pattern`` katmanı **tuple listesi**'dir (dict DEĞİL).
- Yapilar matchlemek icin set semantigine ihtiyac duyar; bu nedenle
  dict[str, ...] formuna donusturulmemistir.

Yapı:
- ``SIGNATURES`` ust dict iki alt-anahtara ayrilmistir:
    * ``"string_reference"`` -> ``STRING_REFERENCE_SIGNATURES``
    * ``"call_pattern"``     -> ``CALL_PATTERN_SIGNATURES``
- Ayni veriler yalın isimle de export edilir
  (``STRING_REFERENCE_SIGNATURES``, ``CALL_PATTERN_SIGNATURES``) —
  signature_db.py override icin bu isimleri kullanir.

Faz 1 placeholder'i (bos ``SIGNATURES = {}``) ile uyumluluk: ``SIGNATURES``
hala ``dict[str, Any]``; sadece icerigi dolduruldu.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Katman 2: String Reference Signatures (246 entry)
# ---------------------------------------------------------------------------
# frozenset(string_keywords) -> (matched_name, library, purpose)
# Bir fonksiyon bu string'lerin HEPSINI referans olarak kullaniyorsa eslestir.
# Kaynak: signature_db.py satir 6613-6931
STRING_REFERENCE_SIGNATURES: dict[frozenset[str], tuple[str, str, str]] = {
    # (matched_name, library, purpose)

    # OpenSSL string patterns
    frozenset({"BIO_new", "SSL_CTX_new"}): ("ssl_ctx_setup", "openssl", "TLS context setup"),
    frozenset({"EVP_CIPHER_CTX", "EVP_EncryptInit"}): ("evp_encrypt_setup", "openssl", "cipher encryption init"),
    frozenset({"EVP_CIPHER_CTX", "EVP_DecryptInit"}): ("evp_decrypt_setup", "openssl", "cipher decryption init"),
    frozenset({"SSL_connect", "SSL_set_fd"}): ("tls_client_connect", "openssl", "TLS client connection"),
    frozenset({"SSL_accept", "SSL_set_fd"}): ("tls_server_accept", "openssl", "TLS server accept"),
    frozenset({"X509_STORE", "X509_verify_cert"}): ("x509_cert_verify", "openssl", "certificate verification"),
    frozenset({"PEM_read_bio", "X509"}): ("pem_cert_read", "openssl", "PEM certificate reading"),
    frozenset({"SHA256_Init", "SHA256_Update", "SHA256_Final"}): ("sha256_hash", "openssl", "SHA-256 computation"),
    frozenset({"SHA1_Init", "SHA1_Update", "SHA1_Final"}): ("sha1_hash", "openssl", "SHA-1 computation"),
    frozenset({"MD5_Init", "MD5_Update", "MD5_Final"}): ("md5_hash", "openssl", "MD5 computation"),
    frozenset({"HMAC_Init_ex", "HMAC_Update", "HMAC_Final"}): ("hmac_compute", "openssl", "HMAC computation"),
    frozenset({"EVP_PKEY_keygen_init", "EVP_PKEY_keygen"}): ("key_generation", "openssl", "key generation"),
    frozenset({"ECDSA_sign", "EC_KEY"}): ("ecdsa_signing", "openssl", "ECDSA signing"),
    frozenset({"RSA_public_encrypt", "RSA_size"}): ("rsa_encrypt", "openssl", "RSA encryption"),
    frozenset({"RSA_private_decrypt", "RSA_size"}): ("rsa_decrypt", "openssl", "RSA decryption"),
    frozenset({"PKCS12_parse", "EVP_PKEY"}): ("pkcs12_import", "openssl", "PKCS#12 import"),
    frozenset({"RAND_bytes", "RAND_seed"}): ("crypto_random", "openssl", "cryptographic RNG"),

    # zlib string patterns
    frozenset({"inflate", "Z_STREAM_END"}): ("zlib_decompress", "zlib", "zlib decompression"),
    frozenset({"deflate", "Z_FINISH"}): ("zlib_compress", "zlib", "zlib compression"),
    frozenset({"inflateInit", "inflate", "inflateEnd"}): ("zlib_decompress_full", "zlib", "full decompression cycle"),
    frozenset({"deflateInit", "deflate", "deflateEnd"}): ("zlib_compress_full", "zlib", "full compression cycle"),
    frozenset({"gzopen", "gzread"}): ("gzip_file_read", "zlib", "gzip file reading"),
    frozenset({"gzopen", "gzwrite"}): ("gzip_file_write", "zlib", "gzip file writing"),

    # libcurl string patterns
    frozenset({"curl_easy_init", "curl_easy_setopt", "curl_easy_perform"}): ("http_request", "libcurl", "HTTP request execution"),
    frozenset({"curl_easy_setopt", "CURLOPT_URL"}): ("curl_url_setup", "libcurl", "URL configuration"),
    frozenset({"curl_easy_setopt", "CURLOPT_POSTFIELDS"}): ("http_post_request", "libcurl", "HTTP POST request"),
    frozenset({"curl_easy_setopt", "CURLOPT_WRITEFUNCTION"}): ("curl_download_setup", "libcurl", "download callback setup"),
    frozenset({"curl_multi_init", "curl_multi_add_handle"}): ("multi_transfer_setup", "libcurl", "multi-transfer setup"),
    frozenset({"curl_ws_recv", "curl_ws_send"}): ("websocket_io", "libcurl", "WebSocket I/O"),

    # SQLite string patterns
    frozenset({"sqlite3_open", "sqlite3_exec"}): ("sqlite_exec_query", "sqlite3", "database query execution"),
    frozenset({"sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize"}): ("sqlite_prepared_query", "sqlite3", "prepared statement query"),
    frozenset({"sqlite3_bind_text", "sqlite3_step"}): ("sqlite_parameterized_query", "sqlite3", "parameterized query"),
    frozenset({"sqlite3_backup_init", "sqlite3_backup_step"}): ("sqlite_backup", "sqlite3", "online database backup"),
    frozenset({"sqlite3_blob_open", "sqlite3_blob_read"}): ("sqlite_blob_read", "sqlite3", "blob I/O"),
    frozenset({"sqlite3_key", "sqlite3_open"}): ("sqlite_encrypted_open", "sqlite3", "encrypted database open"),

    # CommonCrypto string patterns
    frozenset({"CCCrypt", "kCCEncrypt"}): ("cc_encrypt", "CommonCrypto", "symmetric encryption"),
    frozenset({"CCCrypt", "kCCDecrypt"}): ("cc_decrypt", "CommonCrypto", "symmetric decryption"),
    frozenset({"CCHmac", "kCCHmacAlgSHA256"}): ("cc_hmac_sha256", "CommonCrypto", "HMAC-SHA256"),
    frozenset({"CCKeyDerivationPBKDF", "kCCPBKDF2"}): ("cc_pbkdf2", "CommonCrypto", "PBKDF2 key derivation"),

    # Security.framework string patterns
    frozenset({"SecItemAdd", "kSecClass"}): ("keychain_store", "Security", "Keychain item storage"),
    frozenset({"SecItemCopyMatching", "kSecClass"}): ("keychain_lookup", "Security", "Keychain item lookup"),
    frozenset({"SecKeyCreateSignature", "SecKeyCreateRandomKey"}): ("digital_sign_with_keygen", "Security", "key generation + signing"),
    frozenset({"SecTrustCreateWithCertificates", "SecTrustEvaluateWithError"}): ("cert_trust_eval", "Security", "certificate trust evaluation"),
    frozenset({"SecCodeCheckValidity", "SecStaticCodeCreateWithPath"}): ("code_sign_verify", "Security", "code signature verification"),

    # Endpoint Security patterns
    frozenset({"es_new_client", "es_subscribe"}): ("es_client_setup", "EndpointSecurity", "ES client creation + subscription"),
    frozenset({"es_respond_auth_result", "es_subscribe"}): ("es_auth_handler", "EndpointSecurity", "ES authorization handler"),

    # Protobuf patterns
    frozenset({"SerializeToString", "ParseFromString"}): ("protobuf_serde", "protobuf", "protobuf serialize/deserialize"),
    frozenset({"CodedOutputStream", "WriteVarint"}): ("protobuf_encode", "protobuf", "protobuf encoding"),
    frozenset({"CodedInputStream", "ReadVarint"}): ("protobuf_decode", "protobuf", "protobuf decoding"),
    frozenset({"Arena", "CreateMessage"}): ("protobuf_arena_alloc", "protobuf", "arena-allocated message"),

    # bzip2 string patterns
    frozenset({"BZ2_bzCompressInit", "BZ2_bzCompress", "BZ2_bzCompressEnd"}): ("bzip2_compress_full", "bzip2", "full bzip2 compression cycle"),
    frozenset({"BZ2_bzDecompressInit", "BZ2_bzDecompress", "BZ2_bzDecompressEnd"}): ("bzip2_decompress_full", "bzip2", "full bzip2 decompression cycle"),
    frozenset({"BZ2_bzReadOpen", "BZ2_bzRead"}): ("bzip2_file_read", "bzip2", "bzip2 file reading"),
    frozenset({"BZ2_bzWriteOpen", "BZ2_bzWrite"}): ("bzip2_file_write", "bzip2", "bzip2 file writing"),

    # lz4 string patterns
    frozenset({"LZ4_compress_default", "LZ4_decompress_safe"}): ("lz4_roundtrip", "lz4", "LZ4 compress/decompress"),
    frozenset({"LZ4F_createCompressionContext", "LZ4F_compressBegin"}): ("lz4_frame_compress", "lz4", "LZ4 frame compression"),
    frozenset({"LZ4F_createDecompressionContext", "LZ4F_decompress"}): ("lz4_frame_decompress", "lz4", "LZ4 frame decompression"),

    # zstd string patterns
    frozenset({"ZSTD_compress", "ZSTD_decompress"}): ("zstd_roundtrip", "zstd", "zstd compress/decompress"),
    frozenset({"ZSTD_createCCtx", "ZSTD_compressCCtx"}): ("zstd_ctx_compress", "zstd", "zstd context compression"),
    frozenset({"ZSTD_createDCtx", "ZSTD_decompressDCtx"}): ("zstd_ctx_decompress", "zstd", "zstd context decompression"),
    frozenset({"ZSTD_createCStream", "ZSTD_compressStream", "ZSTD_endStream"}): ("zstd_streaming_compress", "zstd", "zstd streaming compression"),
    frozenset({"ZSTD_createDStream", "ZSTD_decompressStream"}): ("zstd_streaming_decompress", "zstd", "zstd streaming decompression"),

    # cJSON string patterns
    frozenset({"cJSON_Parse", "cJSON_Delete"}): ("cjson_parse", "cJSON", "cJSON parsing"),
    frozenset({"cJSON_CreateObject", "cJSON_AddItemToObject"}): ("cjson_build", "cJSON", "cJSON object building"),
    frozenset({"cJSON_Print", "cJSON_CreateObject"}): ("cjson_build_print", "cJSON", "cJSON build + serialize"),

    # yyjson string patterns
    frozenset({"yyjson_read", "yyjson_doc_free"}): ("yyjson_parse", "yyjson", "yyjson parsing"),
    frozenset({"yyjson_mut_doc_new", "yyjson_mut_write"}): ("yyjson_build", "yyjson", "yyjson mutable build + serialize"),

    # jansson string patterns
    frozenset({"json_loads", "json_decref"}): ("jansson_parse", "jansson", "jansson JSON parsing"),
    frozenset({"json_object", "json_object_set"}): ("jansson_build", "jansson", "jansson JSON object building"),
    frozenset({"json_dumps", "json_object"}): ("jansson_serialize", "jansson", "jansson JSON serialization"),

    # libxml2 string patterns
    frozenset({"xmlReadMemory", "xmlFreeDoc"}): ("libxml2_parse_mem", "libxml2", "libxml2 parse from memory"),
    frozenset({"xmlReadFile", "xmlFreeDoc"}): ("libxml2_parse_file", "libxml2", "libxml2 parse from file"),
    frozenset({"xmlXPathNewContext", "xmlXPathEvalExpression"}): ("libxml2_xpath", "libxml2", "libxml2 XPath query"),
    frozenset({"xmlNewDoc", "xmlNewNode", "xmlAddChild"}): ("libxml2_build_tree", "libxml2", "libxml2 tree building"),
    frozenset({"xmlSaveFormatFile", "xmlNewDoc"}): ("libxml2_save", "libxml2", "libxml2 save to file"),

    # expat string patterns
    frozenset({"XML_ParserCreate", "XML_Parse", "XML_ParserFree"}): ("expat_parse", "expat", "expat XML parsing"),
    frozenset({"XML_SetElementHandler", "XML_SetCharacterDataHandler"}): ("expat_handlers", "expat", "expat event handler setup"),

    # Networking patterns (generic)
    frozenset({"socket", "connect", "send", "recv"}): ("tcp_client", "libc", "TCP client connection"),
    frozenset({"socket", "bind", "listen", "accept"}): ("tcp_server", "libc", "TCP server setup"),
    frozenset({"getaddrinfo", "socket", "connect"}): ("dns_resolve_connect", "libc", "DNS resolve + connect"),
    frozenset({"sendto", "recvfrom", "SOCK_DGRAM"}): ("udp_io", "libc", "UDP I/O"),

    # File I/O patterns
    frozenset({"fopen", "fread", "fclose"}): ("file_read", "libc", "file reading"),
    frozenset({"fopen", "fwrite", "fclose"}): ("file_write", "libc", "file writing"),
    frozenset({"mmap", "munmap"}): ("memory_mapped_io", "libc", "memory-mapped file I/O"),
    frozenset({"opendir", "readdir", "closedir"}): ("directory_scan", "libc", "directory scanning"),

    # Process patterns
    frozenset({"fork", "exec", "waitpid"}): ("process_spawn", "libc", "process spawn + wait"),
    frozenset({"posix_spawn", "posix_spawnattr"}): ("posix_process_spawn", "libc", "POSIX process spawning"),
    frozenset({"pthread_create", "pthread_join"}): ("thread_spawn", "libpthread", "thread creation + join"),
    frozenset({"pthread_mutex_lock", "pthread_mutex_unlock"}): ("mutex_operation", "libpthread", "mutex lock/unlock"),
    frozenset({"pthread_cond_wait", "pthread_cond_signal"}): ("condition_variable", "libpthread", "condition variable wait/signal"),

    # ===================================================================
    # EXTENDED STRING REFERENCE SIGNATURES (v2 expansion)
    # ===================================================================

    # --- OpenSSL string patterns (extended) ---
    frozenset({"SSL_connect", "handshake"}): ("ssl_handshake", "openssl", "TLS handshake initiation"),
    frozenset({"certificate", "verify", "X509"}): ("verify_certificate", "openssl", "X.509 certificate verification"),
    frozenset({"private key", "PEM"}): ("load_private_key", "openssl", "PEM private key loading"),
    frozenset({"cipher", "encrypt"}): ("setup_cipher", "openssl", "cipher suite setup"),
    frozenset({"TLS", "version"}): ("check_tls_version", "openssl", "TLS version negotiation"),
    frozenset({"RAND_bytes", "random"}): ("generate_random", "openssl", "cryptographic random generation"),
    frozenset({"digest", "hash"}): ("compute_hash", "openssl", "message digest computation"),
    frozenset({"RSA", "key", "generate"}): ("generate_rsa_key", "openssl", "RSA key pair generation"),
    frozenset({"ECDSA", "sign"}): ("ecdsa_sign", "openssl", "ECDSA digital signature"),
    frozenset({"HMAC", "auth"}): ("hmac_authenticate", "openssl", "HMAC authentication"),
    frozenset({"DH_generate_parameters", "DH_generate_key"}): ("dh_key_exchange", "openssl", "Diffie-Hellman key exchange"),
    frozenset({"SSL_CTX_set_verify", "SSL_VERIFY_PEER"}): ("ssl_peer_verify", "openssl", "TLS peer certificate verification"),
    frozenset({"OCSP_basic_verify", "OCSP_response"}): ("ocsp_check", "openssl", "OCSP certificate status check"),
    frozenset({"CRL", "X509_CRL_verify"}): ("crl_verify", "openssl", "CRL verification"),
    frozenset({"BIO_new_ssl_connect", "BIO_do_connect"}): ("bio_ssl_connect", "openssl", "BIO-based SSL connection"),
    frozenset({"SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file"}): ("ssl_load_cert_key", "openssl", "load certificate and key for TLS"),
    frozenset({"SSL_CTX_set_cipher_list", "TLS_method"}): ("ssl_cipher_config", "openssl", "cipher list configuration"),
    frozenset({"PKCS7_sign", "PKCS7_verify"}): ("pkcs7_sign_verify", "openssl", "PKCS#7 signing/verification"),
    frozenset({"EVP_PKEY_derive_init", "EVP_PKEY_derive"}): ("pkey_derive", "openssl", "EVP key derivation"),
    frozenset({"SSL_read", "SSL_write"}): ("ssl_io", "openssl", "TLS read/write I/O"),
    frozenset({"SSL_get_error", "SSL_ERROR_WANT_READ"}): ("ssl_error_handling", "openssl", "TLS error handling"),
    frozenset({"X509_get_subject_name", "X509_get_issuer_name"}): ("x509_name_extract", "openssl", "X.509 name extraction"),
    frozenset({"X509_get_notBefore", "X509_get_notAfter"}): ("x509_validity_check", "openssl", "certificate validity period check"),
    frozenset({"PEM_write_bio_RSAPublicKey", "PEM_read_bio_RSAPublicKey"}): ("rsa_pem_io", "openssl", "RSA public key PEM I/O"),
    frozenset({"EVP_aes_256_gcm", "EVP_EncryptInit_ex"}): ("aes256_gcm_setup", "openssl", "AES-256-GCM initialization"),
    frozenset({"EVP_chacha20_poly1305", "EVP_EncryptInit_ex"}): ("chacha20_poly1305_setup", "openssl", "ChaCha20-Poly1305 initialization"),
    frozenset({"EC_KEY_new_by_curve_name", "NID_X9_62_prime256v1"}): ("ec_p256_key", "openssl", "P-256 elliptic curve key creation"),
    frozenset({"EVP_PKEY_CTX_new", "EVP_PKEY_sign"}): ("pkey_sign", "openssl", "EVP PKEY signing"),
    frozenset({"EVP_PKEY_CTX_new", "EVP_PKEY_verify"}): ("pkey_verify", "openssl", "EVP PKEY verification"),
    frozenset({"SSL_SESSION_get_id", "SSL_get_session"}): ("ssl_session_resume", "openssl", "TLS session ID retrieval/resume"),

    # --- SQLite string patterns (extended) ---
    frozenset({"CREATE TABLE", "sqlite"}): ("create_table", "sqlite3", "SQL CREATE TABLE"),
    frozenset({"SELECT", "FROM", "WHERE"}): ("execute_query", "sqlite3", "SQL SELECT query execution"),
    frozenset({"INSERT INTO"}): ("insert_record", "sqlite3", "SQL INSERT record"),
    frozenset({"UPDATE", "SET"}): ("update_record", "sqlite3", "SQL UPDATE record"),
    frozenset({"DELETE FROM"}): ("delete_record", "sqlite3", "SQL DELETE record"),
    frozenset({"BEGIN TRANSACTION"}): ("begin_transaction", "sqlite3", "SQL transaction begin"),
    frozenset({"PRAGMA"}): ("set_pragma", "sqlite3", "SQLite PRAGMA command"),
    frozenset({"database is locked"}): ("handle_db_lock", "sqlite3", "handle database lock contention"),
    frozenset({"CREATE INDEX", "sqlite3"}): ("create_index", "sqlite3", "SQL CREATE INDEX"),
    frozenset({"FOREIGN KEY", "REFERENCES"}): ("foreign_key_setup", "sqlite3", "foreign key constraint"),
    frozenset({"ALTER TABLE", "ADD COLUMN"}): ("alter_table", "sqlite3", "SQL ALTER TABLE"),
    frozenset({"VACUUM"}): ("vacuum_db", "sqlite3", "SQLite VACUUM optimization"),
    frozenset({"ATTACH DATABASE"}): ("attach_db", "sqlite3", "SQLite ATTACH DATABASE"),
    frozenset({"sqlite3_wal_checkpoint"}): ("wal_checkpoint", "sqlite3", "WAL checkpoint"),
    frozenset({"sqlite3_create_function"}): ("register_custom_func", "sqlite3", "register custom SQL function"),

    # --- Network string patterns (extended) ---
    frozenset({"HTTP/1.1", "GET"}): ("http_get_request", "http", "HTTP GET request construction"),
    frozenset({"HTTP/1.1", "POST"}): ("http_post_request", "http", "HTTP POST request construction"),
    frozenset({"Content-Type", "application/json"}): ("set_json_content", "http", "JSON content-type header"),
    frozenset({"Authorization", "Bearer"}): ("set_auth_header", "http", "Bearer token authorization"),
    frozenset({"WebSocket", "Upgrade"}): ("websocket_upgrade", "websocket", "WebSocket protocol upgrade"),
    frozenset({"Connection", "keep-alive"}): ("set_keepalive", "http", "HTTP keep-alive setting"),
    frozenset({"Host:", "User-Agent:"}): ("build_http_headers", "http", "HTTP header construction"),
    frozenset({"DNS", "resolve"}): ("dns_resolve", "dns", "DNS name resolution"),
    frozenset({"gRPC", "proto"}): ("grpc_call", "grpc", "gRPC remote procedure call"),
    frozenset({"HTTP/2", "SETTINGS"}): ("http2_setup", "http2", "HTTP/2 connection settings"),
    frozenset({"Content-Length", "Transfer-Encoding"}): ("http_body_framing", "http", "HTTP body framing"),
    frozenset({"Cookie", "Set-Cookie"}): ("http_cookie_handling", "http", "HTTP cookie management"),
    frozenset({"Proxy-Authorization", "CONNECT"}): ("http_proxy_connect", "http", "HTTP proxy CONNECT tunnel"),
    frozenset({"multipart/form-data", "boundary"}): ("multipart_upload", "http", "multipart form-data upload"),
    frozenset({"text/event-stream", "SSE"}): ("server_sent_events", "http", "Server-Sent Events stream"),
    frozenset({"SOCKS5", "\\x05"}): ("socks5_proxy", "network", "SOCKS5 proxy negotiation"),
    frozenset({"ICMP", "ping"}): ("icmp_ping", "network", "ICMP ping request"),
    frozenset({"ARP", "request"}): ("arp_request", "network", "ARP request"),
    frozenset({"MQTT", "CONNECT", "PUBLISH"}): ("mqtt_client", "mqtt", "MQTT publish/subscribe"),
    frozenset({"AMQP", "channel"}): ("amqp_channel", "amqp", "AMQP channel operation"),

    # --- Error/logging string patterns ---
    frozenset({"error", "failed", "errno"}): ("handle_error", "error_handling", "error handling with errno"),
    frozenset({"warning", "deprecated"}): ("log_warning", "logging", "deprecation warning logging"),
    frozenset({"debug", "trace"}): ("log_debug", "logging", "debug/trace logging"),
    frozenset({"out of memory", "alloc"}): ("handle_oom", "memory", "out-of-memory handler"),
    frozenset({"stack overflow"}): ("handle_stack_overflow", "error_handling", "stack overflow handler"),
    frozenset({"segmentation fault", "SIGSEGV"}): ("handle_sigsegv", "signal_handling", "SIGSEGV signal handler"),
    frozenset({"assertion failed"}): ("assertion_handler", "debug", "assertion failure handler"),
    frozenset({"abort", "SIGABRT"}): ("abort_handler", "signal_handling", "SIGABRT abort handler"),
    frozenset({"bus error", "SIGBUS"}): ("handle_sigbus", "signal_handling", "SIGBUS signal handler"),
    frozenset({"broken pipe", "SIGPIPE"}): ("handle_sigpipe", "signal_handling", "SIGPIPE signal handler"),
    frozenset({"floating point", "SIGFPE"}): ("handle_sigfpe", "signal_handling", "SIGFPE signal handler"),
    frozenset({"panic", "fatal"}): ("fatal_error", "error_handling", "fatal error/panic handler"),
    frozenset({"unhandled exception"}): ("unhandled_exception", "error_handling", "unhandled exception handler"),
    frozenset({"core dump", "signal"}): ("coredump_handler", "signal_handling", "core dump signal handler"),
    frozenset({"log_level", "LOG_ERR", "LOG_INFO"}): ("syslog_logging", "logging", "syslog-style logging"),

    # --- File format string patterns ---
    frozenset({"PNG", "IHDR"}): ("parse_png_header", "libpng", "PNG header parsing"),
    frozenset({"JFIF", "Exif"}): ("parse_jpeg_header", "libjpeg", "JPEG header parsing"),
    frozenset({"GIF89a", "GIF87a"}): ("parse_gif", "image", "GIF format parsing"),
    frozenset({"PDF", "%PDF"}): ("parse_pdf", "pdf", "PDF document parsing"),
    frozenset({"PK\\x03\\x04"}): ("parse_zip", "zip", "ZIP archive parsing"),
    frozenset({"<?xml", "encoding"}): ("parse_xml", "xml", "XML document parsing"),
    frozenset({"<!DOCTYPE html"}): ("parse_html", "html", "HTML document parsing"),
    frozenset({"ELF"}): ("parse_elf", "binary", "ELF binary parsing"),
    frozenset({"MZ"}): ("parse_pe", "binary", "PE/MZ binary parsing"),
    frozenset({"\\x89PNG\\r\\n"}): ("validate_png_magic", "libpng", "PNG magic byte validation"),
    frozenset({"\\xff\\xd8\\xff"}): ("validate_jpeg_magic", "libjpeg", "JPEG magic byte validation"),
    frozenset({"Mach-O", "LC_SEGMENT"}): ("parse_macho", "binary", "Mach-O binary parsing"),
    frozenset({"FAT_MAGIC", "fat_header"}): ("parse_fat_binary", "binary", "FAT/universal binary parsing"),
    frozenset({"dex\\n035"}): ("parse_dex", "binary", "Android DEX file parsing"),
    frozenset({"SQLite format 3"}): ("detect_sqlite_db", "sqlite3", "SQLite database file detection"),

    # --- Crypto string patterns ---
    frozenset({"AES", "key", "iv"}): ("aes_init", "crypto", "AES cipher initialization"),
    frozenset({"SHA256", "digest"}): ("sha256_digest", "crypto", "SHA-256 digest computation"),
    frozenset({"password", "hash", "salt"}): ("hash_password", "crypto", "password hashing with salt"),
    frozenset({"PBKDF2", "iterations"}): ("derive_key", "crypto", "PBKDF2 key derivation"),
    frozenset({"base64", "encode"}): ("base64_encode", "encoding", "Base64 encoding"),
    frozenset({"base64", "decode"}): ("base64_decode", "encoding", "Base64 decoding"),
    frozenset({"JWT", "token"}): ("process_jwt", "auth", "JWT token processing"),
    frozenset({"OAuth", "token"}): ("oauth_flow", "auth", "OAuth token flow"),
    frozenset({"bcrypt", "cost"}): ("bcrypt_hash", "crypto", "bcrypt password hashing"),
    frozenset({"scrypt", "memory"}): ("scrypt_derive", "crypto", "scrypt key derivation"),
    frozenset({"argon2", "password"}): ("argon2_hash", "crypto", "Argon2 password hashing"),
    frozenset({"ChaCha20", "nonce"}): ("chacha20_init", "crypto", "ChaCha20 stream cipher init"),
    frozenset({"Poly1305", "tag"}): ("poly1305_auth", "crypto", "Poly1305 MAC authentication"),
    frozenset({"X25519", "curve25519"}): ("x25519_exchange", "crypto", "X25519 key exchange"),
    frozenset({"Ed25519", "sign"}): ("ed25519_sign", "crypto", "Ed25519 digital signature"),

    # --- Config/settings string patterns ---
    frozenset({"config", "settings", "load"}): ("load_config", "config", "configuration loading"),
    frozenset({"default", "fallback"}): ("get_default_value", "config", "default/fallback value retrieval"),
    frozenset({".json", "parse"}): ("parse_json_config", "config", "JSON configuration parsing"),
    frozenset({".yaml", ".yml"}): ("parse_yaml_config", "config", "YAML configuration parsing"),
    frozenset({".plist"}): ("parse_plist", "apple", "Apple plist parsing"),
    frozenset({"environment", "env"}): ("read_env_var", "config", "environment variable reading"),
    frozenset({".ini", "section", "key"}): ("parse_ini_config", "config", "INI configuration parsing"),
    frozenset({".toml", "table"}): ("parse_toml_config", "config", "TOML configuration parsing"),
    frozenset({"registry", "HKEY_"}): ("read_registry", "winapi", "Windows registry access"),
    frozenset({"NSUserDefaults", "standardUserDefaults"}): ("read_user_defaults", "apple", "NSUserDefaults reading"),

    # --- Anti-RE / security string patterns ---
    frozenset({"ptrace", "PT_DENY_ATTACH"}): ("anti_debug_check", "anti_re", "anti-debug ptrace check"),
    frozenset({"debugger", "attached"}): ("detect_debugger", "anti_re", "debugger detection"),
    frozenset({"checksum", "integrity"}): ("integrity_check", "anti_tamper", "integrity/checksum verification"),
    frozenset({"jailbreak", "cydia"}): ("jailbreak_detect", "anti_re", "jailbreak detection"),
    frozenset({"frida", "substrate"}): ("detect_instrumentation", "anti_re", "instrumentation framework detection"),
    frozenset({"tamper", "modified"}): ("tamper_detection", "anti_tamper", "tamper detection"),
    frozenset({"SVC", "sysctl", "P_TRACED"}): ("sysctl_debug_check", "anti_re", "sysctl-based debug detection"),
    frozenset({"_dyld_get_image_name", "MobileSubstrate"}): ("detect_substrate", "anti_re", "MobileSubstrate injection detection"),
    frozenset({"getppid", "launchd"}): ("parent_process_check", "anti_re", "parent process validation"),
    frozenset({"obfuscat", "encrypt", "decrypt"}): ("string_obfuscation", "anti_re", "string obfuscation/deobfuscation"),

    # --- macOS / Apple framework string patterns ---
    frozenset({"NSTask", "launch"}): ("run_subprocess_cocoa", "Foundation", "NSTask subprocess launch"),
    frozenset({"CFRunLoop", "CFRunLoopRun"}): ("run_loop_setup", "CoreFoundation", "CFRunLoop main loop"),
    frozenset({"IOServiceGetMatchingService", "IORegistryEntryCreateCFProperty"}): ("iokit_property_read", "IOKit", "IOKit registry property read"),
    frozenset({"NSWorkspace", "openURL"}): ("open_url_cocoa", "AppKit", "open URL via NSWorkspace"),
    frozenset({"kext", "IOServiceMatching"}): ("iokit_kext_match", "IOKit", "IOKit kernel extension matching"),
    frozenset({"launchd", "SMJobBless"}): ("install_helper_tool", "ServiceManagement", "install privileged helper tool"),
    frozenset({"NSAppleScript", "executeAndReturnError"}): ("execute_applescript", "Foundation", "AppleScript execution"),
    frozenset({"MDQuery", "MDItemCopyAttribute"}): ("spotlight_query", "CoreServices", "Spotlight metadata query"),
    frozenset({"CGEventCreate", "CGEventPost"}): ("cg_event_injection", "CoreGraphics", "CoreGraphics event injection"),
    frozenset({"AXUIElementRef", "AXUIElementCopyAttributeValue"}): ("accessibility_query", "Accessibility", "Accessibility API query"),

    # --- Objective-C runtime patterns ---
    frozenset({"objc_msgSend", "sel_registerName"}): ("objc_dynamic_dispatch", "objc_runtime", "ObjC dynamic message dispatch"),
    frozenset({"class_addMethod", "class_replaceMethod"}): ("objc_method_swizzle", "objc_runtime", "ObjC method swizzling"),
    frozenset({"objc_getClass", "class_getInstanceMethod"}): ("objc_class_introspect", "objc_runtime", "ObjC class introspection"),
    frozenset({"object_getClassName", "NSStringFromClass"}): ("objc_class_name", "objc_runtime", "ObjC class name resolution"),
    frozenset({"method_exchangeImplementations"}): ("objc_imp_exchange", "objc_runtime", "ObjC implementation exchange"),

    # --- Swift runtime patterns ---
    frozenset({"swift_allocObject", "swift_release"}): ("swift_refcount", "swift_runtime", "Swift reference counting"),
    frozenset({"swift_dynamicCast", "swift_getTypeByMangledName"}): ("swift_type_cast", "swift_runtime", "Swift dynamic type casting"),

    # --- IPC / Mach patterns ---
    frozenset({"mach_msg", "mach_port_allocate"}): ("mach_ipc", "mach", "Mach IPC message passing"),
    frozenset({"bootstrap_look_up", "mach_port_t"}): ("mach_service_lookup", "mach", "Mach bootstrap service lookup"),
    frozenset({"xpc_dictionary_create", "xpc_connection_send_message"}): ("xpc_message_send", "libxpc", "XPC dictionary message send"),

    # --- Compression detection (generic) ---
    frozenset({"compress", "decompress", "level"}): ("generic_compress", "compression", "generic compression operation"),
    frozenset({"snappy_compress", "snappy_uncompress"}): ("snappy_roundtrip", "snappy", "Snappy compress/decompress"),
    frozenset({"brotli", "BrotliEncoder"}): ("brotli_compress", "brotli", "Brotli compression"),

    # --- Regex / string processing ---
    frozenset({"regcomp", "regexec", "regfree"}): ("posix_regex", "libc", "POSIX regex matching"),
    frozenset({"pcre2_compile", "pcre2_match"}): ("pcre2_regex", "pcre2", "PCRE2 regex matching"),
    frozenset({"fnmatch", "FNM_PATHNAME"}): ("glob_match", "libc", "filename glob matching"),
}


# ---------------------------------------------------------------------------
# Katman 3: Call Pattern Signatures (98 entry)
# ---------------------------------------------------------------------------
# (callee_set, matched_name, library, purpose, confidence)
# Fonksiyonun cagirdigi API'lerin set'ten kombinasyonu uzerinden tanimlama.
# Set olarak eslestirilir (sira ONEMSIZ).
# Kaynak: signature_db.py satir 6941-7241
CALL_PATTERN_SIGNATURES: list[tuple[frozenset[str], str, str, str, float]] = [
    # (callee_set, matched_name, library, purpose, confidence)

    # TLS client setup pattern
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_set_fd", "SSL_connect"}),
     "tls_client_connect", "openssl", "complete TLS client handshake", 0.90),

    # TLS server pattern
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_set_fd", "SSL_accept"}),
     "tls_server_accept", "openssl", "complete TLS server accept", 0.90),

    # Certificate verification chain
    (frozenset({"X509_STORE_new", "X509_STORE_add_cert", "X509_STORE_CTX_new", "X509_verify_cert"}),
     "x509_chain_verify", "openssl", "X509 certificate chain verification", 0.85),

    # SHA-256 incremental hash
    (frozenset({"SHA256_Init", "SHA256_Update", "SHA256_Final"}),
     "sha256_hash_buffer", "openssl", "SHA-256 buffer hashing", 0.92),

    # AES-GCM encrypt pattern
    (frozenset({"EVP_CIPHER_CTX_new", "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex"}),
     "aes_encrypt", "openssl", "AES encryption", 0.88),

    # AES-GCM decrypt pattern
    (frozenset({"EVP_CIPHER_CTX_new", "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex"}),
     "aes_decrypt", "openssl", "AES decryption", 0.88),

    # HMAC computation
    (frozenset({"HMAC_CTX_new", "HMAC_Init_ex", "HMAC_Update", "HMAC_Final"}),
     "hmac_compute", "openssl", "HMAC computation", 0.90),

    # RSA key generation + encryption
    (frozenset({"RSA_new", "RSA_generate_key_ex", "RSA_public_encrypt"}),
     "rsa_keygen_encrypt", "openssl", "RSA key gen + encryption", 0.85),

    # ECDH key exchange
    (frozenset({"EC_KEY_new_by_curve_name", "EC_KEY_generate_key", "ECDH_compute_key"}),
     "ecdh_key_exchange", "openssl", "ECDH key exchange", 0.88),

    # Keychain store + retrieve
    (frozenset({"SecItemAdd", "SecItemCopyMatching"}),
     "keychain_store_retrieve", "Security", "Keychain store and retrieve", 0.85),

    # Code signing verification
    (frozenset({"SecStaticCodeCreateWithPath", "SecCodeCheckValidity", "SecCodeCopySigningInformation"}),
     "codesign_verify", "Security", "code signature validation chain", 0.90),

    # Certificate trust eval
    (frozenset({"SecCertificateCreateWithData", "SecTrustCreateWithCertificates", "SecTrustEvaluateWithError"}),
     "cert_trust_evaluate", "Security", "certificate trust evaluation", 0.88),

    # CommonCrypto encrypt/decrypt
    (frozenset({"CCCryptorCreate", "CCCryptorUpdate", "CCCryptorFinal", "CCCryptorRelease"}),
     "cc_incremental_crypt", "CommonCrypto", "incremental encryption/decryption", 0.88),

    # PBKDF2 key derivation + encrypt
    (frozenset({"CCKeyDerivationPBKDF", "CCCrypt"}),
     "derive_and_encrypt", "CommonCrypto", "key derivation + encryption", 0.82),

    # SQLite open + prepared statement
    (frozenset({"sqlite3_open_v2", "sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize", "sqlite3_close"}),
     "sqlite_query_lifecycle", "sqlite3", "full query lifecycle", 0.90),

    # SQLite FTS (full-text search)
    (frozenset({"sqlite3_prepare_v2", "sqlite3_bind_text", "sqlite3_step", "sqlite3_column_text"}),
     "sqlite_text_search", "sqlite3", "text search query", 0.75),

    # SQLite transaction
    (frozenset({"sqlite3_exec", "BEGIN", "COMMIT"}),
     "sqlite_transaction", "sqlite3", "database transaction", 0.70),

    # zlib compress pipeline
    (frozenset({"deflateInit2_", "deflate", "deflateEnd"}),
     "zlib_compress_pipeline", "zlib", "zlib compression pipeline", 0.90),

    # zlib decompress pipeline
    (frozenset({"inflateInit2_", "inflate", "inflateEnd"}),
     "zlib_decompress_pipeline", "zlib", "zlib decompression pipeline", 0.90),

    # bzip2 compress pipeline
    (frozenset({"BZ2_bzCompressInit", "BZ2_bzCompress", "BZ2_bzCompressEnd"}),
     "bzip2_compress_pipeline", "bzip2", "bzip2 compression pipeline", 0.90),

    # bzip2 decompress pipeline
    (frozenset({"BZ2_bzDecompressInit", "BZ2_bzDecompress", "BZ2_bzDecompressEnd"}),
     "bzip2_decompress_pipeline", "bzip2", "bzip2 decompression pipeline", 0.90),

    # lz4 frame compress pipeline
    (frozenset({"LZ4F_createCompressionContext", "LZ4F_compressBegin", "LZ4F_compressUpdate", "LZ4F_compressEnd", "LZ4F_freeCompressionContext"}),
     "lz4_frame_compress_pipeline", "lz4", "LZ4 frame compression pipeline", 0.90),

    # lz4 frame decompress pipeline
    (frozenset({"LZ4F_createDecompressionContext", "LZ4F_decompress", "LZ4F_freeDecompressionContext"}),
     "lz4_frame_decompress_pipeline", "lz4", "LZ4 frame decompression pipeline", 0.88),

    # zstd simple compress/decompress
    (frozenset({"ZSTD_compress", "ZSTD_decompress", "ZSTD_compressBound"}),
     "zstd_simple_roundtrip", "zstd", "zstd one-shot compress/decompress", 0.85),

    # zstd streaming compress pipeline
    (frozenset({"ZSTD_createCStream", "ZSTD_initCStream", "ZSTD_compressStream", "ZSTD_endStream", "ZSTD_freeCStream"}),
     "zstd_streaming_compress_pipeline", "zstd", "zstd streaming compression pipeline", 0.90),

    # zstd streaming decompress pipeline
    (frozenset({"ZSTD_createDStream", "ZSTD_initDStream", "ZSTD_decompressStream", "ZSTD_freeDStream"}),
     "zstd_streaming_decompress_pipeline", "zstd", "zstd streaming decompression pipeline", 0.90),

    # zstd context compress
    (frozenset({"ZSTD_createCCtx", "ZSTD_compressCCtx", "ZSTD_freeCCtx"}),
     "zstd_ctx_compress_pipeline", "zstd", "zstd context-based compression", 0.88),

    # cJSON parse + use + cleanup
    (frozenset({"cJSON_Parse", "cJSON_GetObjectItem", "cJSON_Delete"}),
     "cjson_parse_access", "cJSON", "cJSON parse and access", 0.88),

    # cJSON build + print + cleanup
    (frozenset({"cJSON_CreateObject", "cJSON_AddItemToObject", "cJSON_Print", "cJSON_Delete"}),
     "cjson_build_serialize", "cJSON", "cJSON build and serialize", 0.88),

    # jansson parse + use + cleanup
    (frozenset({"json_loads", "json_object_get", "json_decref"}),
     "jansson_parse_access", "jansson", "jansson parse and access", 0.85),

    # libxml2 parse + XPath + cleanup
    (frozenset({"xmlReadMemory", "xmlXPathNewContext", "xmlXPathEvalExpression", "xmlXPathFreeObject", "xmlXPathFreeContext", "xmlFreeDoc"}),
     "libxml2_xpath_query", "libxml2", "libxml2 parse + XPath query", 0.90),

    # libxml2 tree build + save
    (frozenset({"xmlNewDoc", "xmlNewNode", "xmlAddChild", "xmlSaveFormatFile", "xmlFreeDoc"}),
     "libxml2_build_save", "libxml2", "libxml2 tree build + save", 0.88),

    # expat SAX parse
    (frozenset({"XML_ParserCreate", "XML_SetElementHandler", "XML_SetCharacterDataHandler", "XML_Parse", "XML_ParserFree"}),
     "expat_sax_parse", "expat", "expat SAX-style parsing", 0.90),

    # HTTP request with curl
    (frozenset({"curl_easy_init", "curl_easy_setopt", "curl_easy_perform", "curl_easy_cleanup"}),
     "http_request", "libcurl", "complete HTTP request", 0.92),

    # HTTP multi transfer
    (frozenset({"curl_multi_init", "curl_multi_add_handle", "curl_multi_perform", "curl_multi_cleanup"}),
     "http_multi_transfer", "libcurl", "concurrent HTTP transfers", 0.88),

    # XPC service setup
    (frozenset({"xpc_connection_create_mach_service", "xpc_connection_set_event_handler", "xpc_connection_resume"}),
     "xpc_service_connect", "libxpc", "XPC service connection", 0.88),

    # Endpoint Security client
    (frozenset({"es_new_client", "es_subscribe", "es_respond_auth_result"}),
     "es_auth_client", "EndpointSecurity", "Endpoint Security auth client", 0.92),

    # Network Extension filter
    (frozenset({"NEFilterDataProvider", "handleNewFlow"}),
     "network_filter", "NetworkExtension", "network content filter", 0.85),

    # GCD parallel execution
    (frozenset({"dispatch_queue_create", "dispatch_async", "dispatch_group_notify"}),
     "parallel_dispatch", "libdispatch", "GCD parallel execution", 0.75),

    # Process spawn + communicate
    (frozenset({"posix_spawn", "waitpid", "pipe", "dup2"}),
     "spawn_with_pipes", "libc", "process spawn with pipe I/O", 0.82),

    # Memory-mapped file read
    (frozenset({"open", "fstat", "mmap", "munmap", "close"}),
     "mmap_file_read", "libc", "memory-mapped file reading", 0.80),

    # ===================================================================
    # EXTENDED CALL PATTERN SIGNATURES (v2 expansion)
    # ===================================================================

    # --- File operations ---
    (frozenset({"fopen", "fread", "fclose"}),
     "read_file", "libc", "file reading (stdio)", 0.85),
    (frozenset({"fopen", "fwrite", "fclose"}),
     "write_file", "libc", "file writing (stdio)", 0.85),
    (frozenset({"open", "read", "close"}),
     "read_file_posix", "libc", "file reading (POSIX)", 0.80),
    (frozenset({"open", "write", "close"}),
     "write_file_posix", "libc", "file writing (POSIX)", 0.80),
    (frozenset({"stat", "access"}),
     "check_file_exists", "libc", "file existence check", 0.75),
    (frozenset({"opendir", "readdir", "closedir"}),
     "list_directory", "libc", "directory listing", 0.85),
    (frozenset({"mkdir", "chmod"}),
     "create_directory", "libc", "directory creation with permissions", 0.80),
    (frozenset({"rename", "unlink"}),
     "move_file", "libc", "file move/rename", 0.75),
    (frozenset({"flock", "open", "close"}),
     "file_locking", "libc", "file-level advisory locking", 0.80),
    (frozenset({"realpath", "stat", "access"}),
     "resolve_path", "libc", "path resolution and validation", 0.75),

    # --- Network operations ---
    (frozenset({"socket", "connect", "send", "recv"}),
     "tcp_client", "libc", "TCP client connection", 0.90),
    (frozenset({"socket", "bind", "listen", "accept"}),
     "tcp_server", "libc", "TCP server setup", 0.90),
    (frozenset({"getaddrinfo", "socket", "connect"}),
     "connect_by_hostname", "libc", "DNS-resolved connection", 0.85),
    (frozenset({"curl_easy_init", "curl_easy_setopt", "curl_easy_perform"}),
     "http_request_curl", "libcurl", "HTTP request via curl", 0.90),
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_connect"}),
     "tls_connect", "openssl", "TLS client connection", 0.90),
    (frozenset({"SSL_CTX_new", "SSL_new", "SSL_accept"}),
     "tls_accept", "openssl", "TLS server accept", 0.90),
    (frozenset({"socket", "sendto", "recvfrom"}),
     "udp_client", "libc", "UDP client communication", 0.85),
    (frozenset({"socket", "setsockopt", "SO_REUSEADDR", "bind"}),
     "server_socket_setup", "libc", "server socket with SO_REUSEADDR", 0.80),
    (frozenset({"select", "FD_SET", "FD_ISSET"}),
     "io_multiplexing_select", "libc", "I/O multiplexing via select()", 0.80),
    (frozenset({"epoll_create", "epoll_ctl", "epoll_wait"}),
     "io_multiplexing_epoll", "libc", "I/O multiplexing via epoll", 0.85),
    (frozenset({"kqueue", "kevent"}),
     "io_multiplexing_kqueue", "libc", "I/O multiplexing via kqueue", 0.85),
    (frozenset({"poll", "POLLIN", "POLLOUT"}),
     "io_multiplexing_poll", "libc", "I/O multiplexing via poll()", 0.80),

    # --- Process operations ---
    (frozenset({"fork", "execve"}),
     "spawn_process", "libc", "fork+exec process spawn", 0.85),
    (frozenset({"posix_spawn"}),
     "spawn_process_posix", "libc", "POSIX process spawn", 0.85),
    (frozenset({"pipe", "fork", "dup2"}),
     "create_pipe_child", "libc", "child process with pipe I/O", 0.90),
    (frozenset({"waitpid", "WEXITSTATUS"}),
     "wait_child_process", "libc", "wait for child process exit", 0.80),
    (frozenset({"kill", "getpid"}),
     "signal_self", "libc", "send signal to process", 0.70),
    (frozenset({"setuid", "setgid", "execve"}),
     "privileged_exec", "libc", "privilege change + exec", 0.85),

    # --- Memory patterns ---
    (frozenset({"malloc", "memcpy", "free"}),
     "copy_buffer", "libc", "heap buffer copy", 0.75),
    (frozenset({"mmap", "mprotect"}),
     "allocate_executable", "libc", "executable memory allocation", 0.80),
    (frozenset({"VirtualAlloc", "VirtualProtect"}),
     "allocate_executable_win", "winapi", "Windows executable memory allocation", 0.85),
    (frozenset({"calloc", "realloc", "free"}),
     "dynamic_array", "libc", "dynamic array management", 0.70),
    (frozenset({"mmap", "msync", "munmap"}),
     "mmap_shared_write", "libc", "memory-mapped shared write", 0.80),

    # --- Threading patterns ---
    (frozenset({"pthread_create", "pthread_join"}),
     "run_in_thread", "libpthread", "thread spawn + join", 0.80),
    (frozenset({"pthread_mutex_lock", "pthread_cond_wait", "pthread_mutex_unlock"}),
     "wait_on_condition", "libpthread", "condition variable wait under mutex", 0.85),
    (frozenset({"dispatch_async", "dispatch_get_global_queue"}),
     "async_dispatch", "libdispatch", "GCD async dispatch to global queue", 0.85),
    (frozenset({"dispatch_group_enter", "dispatch_group_leave", "dispatch_group_wait"}),
     "parallel_tasks", "libdispatch", "GCD parallel task group", 0.85),
    (frozenset({"pthread_rwlock_rdlock", "pthread_rwlock_wrlock", "pthread_rwlock_unlock"}),
     "rwlock_operation", "libpthread", "read-write lock operation", 0.85),
    (frozenset({"dispatch_semaphore_create", "dispatch_semaphore_wait", "dispatch_semaphore_signal"}),
     "gcd_semaphore", "libdispatch", "GCD semaphore synchronization", 0.85),
    (frozenset({"os_unfair_lock_lock", "os_unfair_lock_unlock"}),
     "unfair_lock", "libc", "os_unfair_lock spin lock", 0.80),

    # --- Crypto patterns ---
    (frozenset({"EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex"}),
     "encrypt_data", "openssl", "EVP symmetric encryption", 0.90),
    (frozenset({"EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex"}),
     "decrypt_data", "openssl", "EVP symmetric decryption", 0.90),
    (frozenset({"EVP_DigestInit_ex", "EVP_DigestUpdate", "EVP_DigestFinal_ex"}),
     "compute_digest", "openssl", "EVP message digest", 0.90),
    (frozenset({"CCCrypt"}),
     "symmetric_encrypt_decrypt", "CommonCrypto", "CommonCrypto symmetric cipher", 0.85),
    (frozenset({"SecKeyCreateSignature"}),
     "digital_sign", "Security", "Security.framework digital signing", 0.85),
    (frozenset({"SecKeyCreateRandomKey", "SecKeyCopyPublicKey"}),
     "generate_keypair", "Security", "asymmetric key pair generation", 0.85),
    (frozenset({"SecKeyCreateEncryptedData", "SecKeyCreateDecryptedData"}),
     "asymmetric_crypt", "Security", "asymmetric encrypt/decrypt", 0.85),

    # --- Database patterns ---
    (frozenset({"sqlite3_open", "sqlite3_exec", "sqlite3_close"}),
     "simple_db_query", "sqlite3", "simple database query lifecycle", 0.85),
    (frozenset({"sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize"}),
     "prepared_statement", "sqlite3", "prepared statement execution", 0.90),
    (frozenset({"sqlite3_bind_text", "sqlite3_step"}),
     "parameterized_query", "sqlite3", "text-parameterized query", 0.85),
    (frozenset({"sqlite3_open_v2", "sqlite3_key", "sqlite3_exec"}),
     "encrypted_db_query", "sqlite3", "encrypted database query", 0.85),
    (frozenset({"sqlite3_backup_init", "sqlite3_backup_step", "sqlite3_backup_finish"}),
     "db_backup", "sqlite3", "online database backup", 0.88),

    # --- macOS-specific patterns ---
    (frozenset({"NSTask", "setLaunchPath", "setArguments", "launch", "waitUntilExit"}),
     "nstask_run", "Foundation", "NSTask subprocess execution", 0.88),
    (frozenset({"CFNotificationCenterGetDarwinNotifyCenter", "CFNotificationCenterPostNotification"}),
     "darwin_notify", "CoreFoundation", "Darwin notification post", 0.85),
    (frozenset({"IOServiceGetMatchingServices", "IOIteratorNext", "IOObjectRelease"}),
     "iokit_iterate_services", "IOKit", "IOKit service iteration", 0.85),
    (frozenset({"SCNetworkReachabilityCreateWithName", "SCNetworkReachabilityGetFlags"}),
     "check_network_reachability", "SystemConfiguration", "network reachability check", 0.85),
    (frozenset({"CGWindowListCopyWindowInfo", "CFArrayGetCount", "CFArrayGetValueAtIndex"}),
     "enumerate_windows", "CoreGraphics", "window list enumeration", 0.80),
]


# ---------------------------------------------------------------------------
# Üst seviye SIGNATURES dispatcher dict
# ---------------------------------------------------------------------------
# Diger migrate edilmis modullerle (crypto, compression vb.) tutarli olmasi
# icin tum veriler tek bir ``SIGNATURES`` dict altinda alt-anahtarlarla
# expose edilir. Heterojen tip nedeniyle ``dict[str, Any]`` kullanilir.
#
# signature_db.py override yontemi (Faz A-DELETE sonrasi):
#   from karadul.analyzers.sigdb_builtin.calls import (
#       STRING_REFERENCE_SIGNATURES as _STRING_REFERENCE_SIGNATURES,
#       CALL_PATTERN_SIGNATURES as _CALL_PATTERN_SIGNATURES,
#   )

SIGNATURES: dict[str, Any] = {
    "string_reference": STRING_REFERENCE_SIGNATURES,
    "call_pattern": CALL_PATTERN_SIGNATURES,
}


__all__ = [
    "SIGNATURES",
    "STRING_REFERENCE_SIGNATURES",
    "CALL_PATTERN_SIGNATURES",
]
