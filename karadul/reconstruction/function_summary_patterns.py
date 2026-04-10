"""API cagri kombinasyonlarindan fonksiyon amaci cikarma.

Her fonksiyonun callee listesi, 50+ API combo pattern'iyle karsilastirilir.
En iyi eslesen ozet template'i dondurulur.

Ornek:
  callees = {socket, connect, send, recv} -> "Establishes TCP connection and exchanges data"
  callees = {EVP_EncryptInit, EVP_EncryptUpdate} -> "Performs symmetric encryption (EVP)"
"""

from __future__ import annotations

# (gerekli_api'ler, ozet_template, min_match, confidence)
# min_match: gerekli_api'lerin en az kaci bulunmali
FUNCTION_SUMMARY_PATTERNS: list[tuple[set[str], str, int, float]] = [
    # Network
    ({"socket", "connect", "send", "recv"}, "Establishes TCP connection and exchanges data", 3, 0.80),
    ({"socket", "bind", "listen", "accept"}, "TCP server: binds, listens and accepts connections", 3, 0.85),
    ({"send", "recv"}, "Sends and receives network data", 2, 0.60),
    ({"getaddrinfo", "connect"}, "Resolves address and connects", 2, 0.70),

    # File I/O
    ({"fopen", "fread", "fclose"}, "Reads data from file", 2, 0.75),
    ({"fopen", "fwrite", "fclose"}, "Writes data to file", 2, 0.75),
    ({"open", "read", "close"}, "Reads data from file descriptor", 2, 0.70),
    ({"open", "write", "close"}, "Writes data to file descriptor", 2, 0.70),
    ({"opendir", "readdir", "closedir"}, "Iterates directory entries", 2, 0.80),

    # Memory
    ({"malloc", "memcpy", "free"}, "Allocates, copies and frees memory buffer", 2, 0.65),
    ({"calloc", "free"}, "Allocates zeroed memory", 2, 0.60),
    ({"realloc"}, "Resizes memory allocation", 1, 0.55),
    ({"mmap", "munmap"}, "Maps/unmaps memory region", 2, 0.70),

    # Crypto (OpenSSL)
    ({"EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal"}, "Performs symmetric encryption (EVP)", 2, 0.90),
    ({"EVP_DecryptInit", "EVP_DecryptUpdate", "EVP_DecryptFinal"}, "Performs symmetric decryption (EVP)", 2, 0.90),
    ({"EVP_DigestInit", "EVP_DigestUpdate", "EVP_DigestFinal"}, "Computes message digest/hash (EVP)", 2, 0.90),
    ({"EVP_SignInit", "EVP_SignUpdate", "EVP_SignFinal"}, "Creates digital signature (EVP)", 2, 0.85),
    ({"EVP_VerifyInit", "EVP_VerifyUpdate", "EVP_VerifyFinal"}, "Verifies digital signature (EVP)", 2, 0.85),
    ({"SSL_new", "SSL_connect"}, "Establishes TLS/SSL connection", 2, 0.90),
    ({"SSL_read", "SSL_write"}, "Reads/writes over TLS connection", 2, 0.85),
    ({"SSL_CTX_new", "SSL_CTX_set"}, "Configures SSL/TLS context", 2, 0.80),
    ({"RSA_sign", "RSA_verify"}, "RSA sign/verify operation", 1, 0.85),
    ({"HMAC_Init", "HMAC_Update", "HMAC_Final"}, "Computes HMAC authentication code", 2, 0.85),
    ({"PEM_read", "PEM_write"}, "Reads/writes PEM encoded data", 1, 0.75),
    ({"X509_new", "X509_set"}, "Creates/configures X.509 certificate", 2, 0.80),
    ({"BIO_new", "BIO_read", "BIO_write"}, "Performs buffered I/O operation", 2, 0.70),

    # Threading
    ({"pthread_create", "pthread_join"}, "Spawns and waits for worker thread", 2, 0.75),
    ({"pthread_mutex_lock", "pthread_mutex_unlock"}, "Mutex-protected critical section", 2, 0.70),
    ({"pthread_cond_wait", "pthread_cond_signal"}, "Condition variable synchronization", 2, 0.75),

    # Process
    ({"fork", "exec"}, "Forks child process and executes program", 1, 0.80),
    ({"waitpid"}, "Waits for child process", 1, 0.65),
    ({"pipe", "dup2"}, "Sets up pipe redirection", 2, 0.75),

    # String
    ({"strlen", "strcpy", "strcat"}, "String concatenation/copy operation", 2, 0.60),
    ({"strcmp", "strncmp"}, "String comparison", 1, 0.55),
    ({"strtok", "sscanf"}, "Parses/tokenizes string input", 1, 0.60),
    ({"snprintf", "sprintf"}, "Formats string output", 1, 0.55),
    ({"regex", "regcomp", "regexec"}, "Regular expression matching", 1, 0.70),

    # Error handling
    ({"perror", "strerror"}, "Reports system error", 1, 0.65),
    ({"exit", "abort"}, "Terminates program", 1, 0.60),
    ({"setjmp", "longjmp"}, "Non-local jump (error recovery)", 1, 0.70),

    # Logging
    ({"printf", "fprintf"}, "Prints formatted output", 1, 0.40),
    ({"syslog"}, "Writes to system log", 1, 0.65),

    # ASN.1/DER (OpenSSL specific)
    ({"d2i_", "i2d_"}, "ASN.1 DER encode/decode", 1, 0.80),
    ({"ASN1_"}, "ASN.1 data manipulation", 1, 0.70),
]

# Domain keyword'ler (string sabitlerinden domain cikarma)
DOMAIN_KEYWORDS: dict[str, str] = {
    "certificate": "certificate handling",
    "cert": "certificate handling",
    "x509": "X.509 certificate",
    "http": "HTTP communication",
    "https": "HTTPS communication",
    "json": "JSON processing",
    "xml": "XML processing",
    "auth": "authentication",
    "login": "authentication",
    "password": "credential management",
    "token": "token management",
    "session": "session management",
    "database": "database operations",
    "sql": "SQL operations",
    "config": "configuration",
    "setting": "configuration",
    "cache": "caching",
    "compress": "compression",
    "encrypt": "encryption",
    "decrypt": "decryption",
    "cipher": "cipher operations",
    "hash": "hashing",
    "digest": "message digest",
    "sign": "digital signature",
    "verify": "signature verification",
    "key": "key management",
    "socket": "network socket",
    "connect": "connection establishment",
    "ssl": "SSL/TLS",
    "tls": "TLS",
}


def match_function_summary(
    callees: set[str],
    string_refs: list[str] | None = None,
) -> tuple[str, float] | None:
    """Fonksiyonun callee listesinden en iyi ozet eslesmenisini bul.

    Args:
        callees: Fonksiyonun cagirdigi API isimleri seti.
        string_refs: Fonksiyondaki string referanslari (opsiyonel, domain ipucu icin).

    Returns:
        (summary_string, confidence) veya None (hicbir pattern eslesemediyse).
    """
    best_summary = None
    best_confidence = 0.0
    best_match_count = 0

    for required_apis, summary, min_match, confidence in FUNCTION_SUMMARY_PATTERNS:
        # Prefix match: "EVP_EncryptInit" callee'si "EVP_EncryptInit_ex" ile de eslesmeli
        match_count = 0
        for req_api in required_apis:
            for callee in callees:
                callee_base = callee.lstrip("_")  # Ghidra _ prefix'ini kaldir
                if callee_base.startswith(req_api) or req_api in callee_base:
                    match_count += 1
                    break

        if match_count >= min_match and match_count > best_match_count:
            best_match_count = match_count
            best_confidence = confidence
            best_summary = summary
        elif match_count >= min_match and match_count == best_match_count and confidence > best_confidence:
            best_confidence = confidence
            best_summary = summary

    # Domain keyword zenginlestirme
    if best_summary and string_refs:
        domain_hint = _extract_domain(string_refs)
        if domain_hint and domain_hint not in best_summary.lower():
            best_summary = "%s (%s)" % (best_summary, domain_hint)

    if best_summary:
        return (best_summary, best_confidence)
    return None


def _extract_domain(string_refs: list[str]) -> str:
    """String referanslarindan domain ipucu cikar."""
    text = " ".join(str(s) for s in string_refs[:50]).lower()
    for keyword, domain in DOMAIN_KEYWORDS.items():
        if keyword in text:
            return domain
    return ""
