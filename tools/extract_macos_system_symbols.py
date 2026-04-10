#!/usr/bin/env python3
"""Extract function signatures from ALL macOS system libraries using nm.

Scans:
  - /usr/lib/*.dylib (via dyld shared cache tbd stubs)
  - macOS SDK frameworks (public + private)
  - /opt/homebrew/lib/*.dylib
  - /opt/homebrew/Cellar/*/*/lib/*.dylib
  - Runtime shared cache (via nm on framework binaries)

Output: sigs/macos_system_symbols.json in the format expected by
SignatureDB.load_external_signatures().
"""

import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "sigs"
OUTPUT_FILE = OUTPUT_DIR / "macos_system_symbols.json"

# Where to look for libraries
SCAN_PATHS = {
    "system_dylibs": ["/usr/lib"],
    "sdk_frameworks": [],  # Populated dynamically
    "sdk_private_frameworks": [],  # Populated dynamically
    "homebrew_lib": ["/opt/homebrew/lib"],
    "homebrew_cellar": ["/opt/homebrew/Cellar"],
}

# Symbol type codes that represent functions (not data)
FUNCTION_TYPES = {"T", "t", "S", "s"}
# We primarily want T (text/code section, global) but include t for completeness
# S/s = symbol in a section other than text, sometimes used for function pointers

# Minimum: only T and t are definitely functions
STRICT_FUNCTION_TYPES = {"T", "t"}

# Patterns to skip (not useful function names)
SKIP_PATTERNS = re.compile(
    r"^("
    r"_?\.objc_|"            # ObjC internal metadata
    r"_?GCC_except_table|"   # GCC exception tables
    r"__Z.*E$|"              # Some C++ template artifacts
    r"_?radr://|"            # Radar bug references
    r"_?l_OBJC_|"            # ObjC metadata labels
    r"_?__OBJC_|"            # ObjC section markers
    r"_?\$s[0-9]|"           # Swift mangled (very short/cryptic)
    r"_?\$S[0-9]|"           # Swift mangled (old convention)
    r"_?\.L|"                # Local labels
    r"_?ltmp[0-9]|"          # Local temporaries
    r"section\$|"            # Section markers
    r"_?__swift|"            # Swift metadata
    r"\$ld\$|"               # Linker directives ($ld$previous$, $ld$hide$, etc.)
    r"_?\$ld\$|"             # Linker directives with underscore prefix
    r"\$ld\$(previous|hide|install_name|weak_import)|"  # Specific linker directive types
    r"_OBJC_CLASS_\$|"       # ObjC class symbols
    r"_OBJC_METACLASS_\$|"   # ObjC metaclass symbols
    r"_OBJC_IVAR_\$|"        # ObjC ivar symbols
    r"_OBJC_EHTYPE_\$"       # ObjC exception type symbols
    r")",
    re.IGNORECASE,
)

# Useful Swift symbols: keep demangled ones but skip raw mangled
# $s = Swift 5+ mangled, $S = Swift 4.x mangled
SWIFT_MANGLED = re.compile(r"^_?\$[sS].{20,}")  # Long mangled Swift symbols

# Additional filter: symbols containing $ are typically linker/Swift artifacts
DOLLAR_SYMBOL = re.compile(r"\$")

# GUID-like symbols (hex hashes used as internal identifiers)
GUID_PATTERN = re.compile(r"^__[0-9A-Fa-f]{32}$")

# ---------------------------------------------------------------------------
# Category and purpose inference from function name
# ---------------------------------------------------------------------------

# Order matters: first match wins
CATEGORY_RULES: list[tuple[re.Pattern, str, str]] = [
    # Security / Crypto
    (re.compile(r"^(CC(Crypt|Digest|HMAC|Key|RNG|Sym|AES|DES|RC[24]|Blowfish|CAST|ECB|CBC|CTR|GCM|CCM|Pad|Reset|Update|Final|Status))"), "crypto", "CommonCrypto {}"),
    (re.compile(r"^(SecKey|SecCertificate|SecTrust|SecIdentity|SecPolicy|SecItem|SecAccess|SecACL|SecKeychain|SecPassword|SecRandom)"), "crypto", "Security.framework {}"),
    (re.compile(r"^(SSL|SSLC|SSLSet|SSLGet|SSLHandshake|SSLClose|SSLRead|SSLWrite)"), "crypto", "Secure Transport {}"),
    (re.compile(r"^(EVP_|RSA_|EC_|BN_|BIO_|PEM_|X509_|ASN1_|PKCS|DH_|DSA_|AES_|SHA[0-9]|MD[245]_|HMAC|RAND_|CRYPTO_|OPENSSL_|SSL_|TLS_|OSSL_)"), "crypto", "OpenSSL/BoringSSL {}"),
    (re.compile(r"^(ccn_|ccrsa_|ccec_|ccaes_|ccdes_|ccsha|cchmac|ccrng|ccdigest|ccmode|cczp|ccdh|ccpbkdf|ccpad)"), "crypto", "corecrypto {}"),
    (re.compile(r"^(kSec|SecCodeCopy|SecStaticCode|SecRequirement|SecTask|csops)"), "crypto", "Code Signing {}"),

    # Compression
    (re.compile(r"^(compress|uncompress|deflate|inflate|gz|crc32|adler32|zlibVersion|zError)"), "compression", "zlib {}"),
    (re.compile(r"^(BZ2_|bz)"), "compression", "bzip2 {}"),
    (re.compile(r"^(LZ4_|LZ4F_|LZ4HC_)"), "compression", "lz4 {}"),
    (re.compile(r"^(ZSTD_|ZDICT_)"), "compression", "zstd {}"),
    (re.compile(r"^(lzma_|lzma2_|xz_|LZMA)"), "compression", "lzma/xz {}"),
    (re.compile(r"^compression_"), "compression", "Apple compression {}"),
    (re.compile(r"^(BROTLI_|Brotli)"), "compression", "brotli {}"),

    # CoreFoundation
    (re.compile(r"^CF(String|Array|Dictionary|Set|Bag|Tree|Data|Date|Number|Boolean|URL|UUID|Error|Locale|Calendar|TimeZone|Run|Socket|Stream|Message|Machine|Notification|Plugin|Bundle|Preference|Property|XML|Attribute|Bit|Allocat|Copy|Release|Retain|Get|Set|Create|Show|Log|Equal|Hash|Compare|Append|Sort|Search|Remove|Insert|Replace|Contains|Count|Index|Make)"), "corefoundation", "CoreFoundation {}"),
    (re.compile(r"^CF[A-Z]"), "corefoundation", "CoreFoundation {}"),
    (re.compile(r"^__CF"), "corefoundation", "CoreFoundation internal {}"),

    # Foundation / ObjC Runtime
    (re.compile(r"^(objc_msg|objc_alloc|objc_retain|objc_release|objc_autoreleasePool|objc_setAssociated|objc_getAssociated|objc_sync|objc_store|objc_load|objc_opt|objc_class|objc_object)"), "objc_runtime", "ObjC runtime {}"),
    (re.compile(r"^(class_|method_|ivar_|property_|protocol_|sel_|object_|objc_)"), "objc_runtime", "ObjC runtime {}"),
    (re.compile(r"^(NS(Log|Allocate|Deallocate|Copy|Zone|Page|Round|Map|Hash|Create|Search|Decimal|Range|Make|Max|Min|String|Array|Dictionary|Set|Data|Date|Number|Value|Error|Exception|Thread|Lock|Condition|Operation|Timer|URL|File|Path|Process|Task|Bundle|Notification|UserDefaults|Locale|Calendar|TimeZone))"), "foundation", "Foundation {}"),
    (re.compile(r"^NS[A-Z]"), "foundation", "Foundation/AppKit {}"),
    (re.compile(r"^_NS[A-Z]"), "foundation", "Foundation/AppKit internal {}"),

    # Grand Central Dispatch
    (re.compile(r"^dispatch_"), "dispatch", "GCD {}"),
    (re.compile(r"^_dispatch_"), "dispatch", "GCD internal {}"),
    (re.compile(r"^os_unfair_lock"), "dispatch", "os_unfair_lock {}"),
    (re.compile(r"^(os_log|os_signpost|os_activity)"), "logging", "os_log {}"),

    # XPC
    (re.compile(r"^xpc_"), "ipc", "XPC {}"),
    (re.compile(r"^launch_"), "ipc", "launchd {}"),

    # IOKit
    (re.compile(r"^(IO[A-Z]|IOKit|IOMaster|IOService|IORegistry|IOIterator|IOObject|IOConnect|IONotification|IOUSB|IOHIDManager|IOPower|IOPS|IOPMAssert)"), "iokit", "IOKit {}"),

    # Network
    (re.compile(r"^nw_"), "network", "Network.framework {}"),
    (re.compile(r"^(CFNetwork|CFHTTP|CFFTP|CFHost|CFProxy|CFNetDiag|CFNetService)"), "network", "CFNetwork {}"),
    (re.compile(r"^(curl_|CURL)"), "network", "libcurl {}"),
    (re.compile(r"^(nghttp2_|nghttp3_)"), "network", "nghttp2 {}"),
    (re.compile(r"^(getaddrinfo|getnameinfo|freeaddrinfo|gai_strerror)"), "network", "DNS resolution {}"),
    (re.compile(r"^(socket|bind|listen|accept|connect|send|recv|sendto|recvfrom|sendmsg|recvmsg|shutdown|setsockopt|getsockopt|getpeername|getsockname|select|poll|epoll|kqueue|kevent)"), "network", "BSD sockets {}"),
    (re.compile(r"^(inet_|hton|ntoh|if_nametoindex|getifaddrs|freeifaddrs)"), "network", "network utility {}"),
    (re.compile(r"^(SCNetwork|SCDynamic|SCPreferences|SC[A-Z])"), "network", "SystemConfiguration {}"),
    (re.compile(r"^ne_"), "network", "NetworkExtension {}"),
    (re.compile(r"^(dns_|res_|dn_|ns_|_res_)"), "network", "DNS resolver {}"),

    # CoreGraphics / Quartz
    (re.compile(r"^CG(Context|Path|Color|Image|Layer|Font|Gradient|Shading|Pattern|PDF|DataProvider|DataConsumer|Display|Event|Window|Rect|Point|Size|AffineTransform|Bitmap|Float)"), "graphics", "CoreGraphics {}"),
    (re.compile(r"^CG[A-Z]"), "graphics", "CoreGraphics {}"),
    (re.compile(r"^(CA(Layer|Animation|Transform|Transaction|Renderer|Metal|Display|Emitter|Gradient|Replicator|Scroll|Shape|Text|Tile|Value|Constraint))"), "graphics", "CoreAnimation {}"),
    (re.compile(r"^CA[A-Z]"), "graphics", "CoreAnimation {}"),
    (re.compile(r"^(CI(Color|Context|Filter|Image|Kernel|Sampler|Vector|Feature|Detector|Face|Rectangle|QRCode|Barcode|Text))"), "graphics", "CoreImage {}"),
    (re.compile(r"^CI[A-Z]"), "graphics", "CoreImage {}"),

    # Metal
    (re.compile(r"^MTL"), "graphics", "Metal {}"),

    # CoreText
    (re.compile(r"^CT(Font|Frame|Glyph|Line|Paragraph|Run|TextTab|TypeSetter|RubyAnnotation|StringAttribute)"), "text", "CoreText {}"),
    (re.compile(r"^CT[A-Z]"), "text", "CoreText {}"),

    # CoreAudio / Audio
    (re.compile(r"^(Audio(Component|Converter|Device|File|Format|Object|Output|Queue|Session|Stream|Unit|Codec|Buffer|Hardware|ToolboxErr|ServicesErr))"), "audio", "CoreAudio {}"),
    (re.compile(r"^(AU[A-Z]|AUGraph|AudioUnit)"), "audio", "AudioUnit {}"),
    (re.compile(r"^(MusicPlayer|MusicSequence|MusicTrack|MusicEvent)"), "audio", "MIDI/Music {}"),
    (re.compile(r"^(AVAudio|AVMIDIPlayer|AVSpeech)"), "audio", "AVFoundation audio {}"),

    # CoreMedia / AVFoundation
    (re.compile(r"^CM(Sample|Block|Format|Time|Video|Audio|Buffer|Clock|Sync|Memory|Attachment|SimpleQueue|IOSurface)"), "media", "CoreMedia {}"),
    (re.compile(r"^CM[A-Z]"), "media", "CoreMedia {}"),
    (re.compile(r"^(VT(Compression|Decompression|Session|Frame|PixelTransfer|Multi|Format|Create|Copy))"), "media", "VideoToolbox {}"),
    (re.compile(r"^VT[A-Z]"), "media", "VideoToolbox {}"),
    (re.compile(r"^(CVPixelBuffer|CVImageBuffer|CVOpenGL|CVMetal|CVDisplay|CVReturn|CVBuffer|CVTime)"), "media", "CoreVideo {}"),
    (re.compile(r"^CV[A-Z]"), "media", "CoreVideo {}"),

    # CoreML / Vision / NLP
    (re.compile(r"^(MLModel|MLFeature|MLMultiArray|MLDictionary|MLSequence|MLImage|MLPrediction|MLBatchProvider|MLUpdateTask|MLParameter|MLMetricKey)"), "ml", "CoreML {}"),
    (re.compile(r"^VN(Detect|Recognize|Classify|Generate|Track|Observation|Request|Image|Sequence|FeaturePrint|CoreML|Geometry|Human|Face|Text|Barcode|Horizon|Attention|Contour|Trajectory|Stateful|Person)"), "ml", "Vision {}"),
    (re.compile(r"^NL(Tokenizer|Tagger|Model|Language|Tag|Embedding|Distance|Gazetteer)"), "ml", "NaturalLanguage {}"),

    # CoreLocation
    (re.compile(r"^CL(Location|Heading|Region|Visit|Geocoder|Placemark|Beacon|Monitor)"), "location", "CoreLocation {}"),
    (re.compile(r"^kCL"), "location", "CoreLocation constant {}"),

    # CoreBluetooth
    (re.compile(r"^CB(Central|Peripheral|Service|Characteristic|Descriptor|ATT|UUID|Manager|Peer|L2CAP)"), "bluetooth", "CoreBluetooth {}"),

    # CoreData
    (re.compile(r"^(NSManagedObject|NSPersistentStore|NSFetchRequest|NSEntityDescription|NSPredicate|NSFetchedResultsController|NSMergePolicy|NSMigration|NSMapping)"), "database", "CoreData {}"),

    # SQLite
    (re.compile(r"^sqlite3_"), "database", "SQLite {}"),

    # WebKit / JavaScript
    (re.compile(r"^(WK|WebKit|WebView|WebFrame|WebResource|WebData|WebDownload|WebHistory|WebPreferences|WebScriptObject)"), "webkit", "WebKit {}"),
    (re.compile(r"^(JSContext|JSValue|JSManagedValue|JSVirtualMachine|JSExport|JSGlobalContext|JSObject|JSString|JSClass|JSProperty|JSEvaluate)"), "javascript", "JavaScriptCore {}"),
    (re.compile(r"^JS[A-Z]"), "javascript", "JavaScriptCore {}"),

    # StoreKit
    (re.compile(r"^SK(Product|Payment|Receipt|Store|Request|Download|CloudService|Overlay|Paymentqueue)"), "storekit", "StoreKit {}"),

    # UserNotifications
    (re.compile(r"^UN(Notification|UserNotification|Calendar|TimeInterval|Location|Push|Mutable|Category|Action|TextInput)"), "notifications", "UserNotifications {}"),

    # Endpoint Security / System Extensions
    (re.compile(r"^es_"), "security", "EndpointSecurity {}"),
    (re.compile(r"^(OSSystemExtension|NEFilter|NEProvider|NEVPN|NEAppProxy|NETunnel|NEHotspot|NEDNSProxy)"), "security", "System/Network Extension {}"),

    # POSIX / libc - String operations
    (re.compile(r"^(str(len|cpy|ncpy|cat|ncat|cmp|ncmp|chr|rchr|str|tok|dup|ndup|casecmp|ncasecmp|error|ftime|ptime|xfrm|col|sep|signal|to))"), "string", "string operation {}"),
    (re.compile(r"^(wcs|wmem|wc|btowc|mbrlen|mbrtowc|wcrtomb|mbsrtowcs|wcsrtombs|mbsinit|mbtowc|wctomb)"), "string", "wide string operation {}"),
    (re.compile(r"^(sprintf|snprintf|fprintf|printf|vprintf|vsprintf|vsnprintf|vfprintf|asprintf|vasprintf|dprintf|vdprintf|sscanf|fscanf|scanf)"), "string", "formatted I/O {}"),
    (re.compile(r"^(ato[ifl]|strto[uld]|strto[iuf]|strtoll|strtoull|strtoimax|strtoumax|strtof|strtold)"), "string", "string conversion {}"),

    # POSIX / libc - Memory operations
    (re.compile(r"^(mem(cpy|move|set|cmp|chr|cchr|mem|rchr|set_s|cpy_s)|bcopy|bzero|bcmp|explicit_bzero)"), "memory", "memory operation {}"),
    (re.compile(r"^(malloc|calloc|realloc|free|valloc|memalign|posix_memalign|aligned_alloc|malloc_zone|malloc_size|malloc_good_size|malloc_create_zone|malloc_destroy_zone|mmap|munmap|mprotect|mlock|munlock|madvise|msync|mincore|brk|sbrk)"), "memory", "memory management {}"),

    # POSIX / libc - File I/O
    (re.compile(r"^(open|close|read|write|lseek|fstat|stat|lstat|ftruncate|truncate|fcntl|ioctl|dup|dup2|pipe|mkfifo|mknod|unlink|remove|rename|link|symlink|readlink|mkdir|rmdir|chdir|getcwd|chown|chmod|umask|access|faccessat)"), "file_io", "POSIX file I/O {}"),
    (re.compile(r"^(fopen|fclose|fread|fwrite|fseek|ftell|feof|ferror|clearerr|rewind|fflush|fgets|fputs|fgetc|fputc|getc|putc|getchar|putchar|gets|puts|ungetc|setvbuf|setbuf|tmpfile|tmpnam|mktemp|mkstemp|fdopen|freopen|fileno|popen|pclose)"), "file_io", "stdio file I/O {}"),
    (re.compile(r"^(opendir|closedir|readdir|rewinddir|seekdir|telldir|scandir|alphasort|glob|globfree|fnmatch|ftw|nftw|realpath|dirname|basename)"), "file_io", "directory operation {}"),

    # POSIX / libc - Process
    (re.compile(r"^(fork|vfork|exec[lv]p?e?|wait|waitpid|waitid|wait3|wait4|_exit|exit|atexit|abort|kill|raise|signal|sigaction|sigprocmask|sigpending|sigsuspend|sigsetjmp|siglongjmp|sigaltstack|sigfillset|sigemptyset|sigaddset|sigdelset|sigismember|getpid|getppid|getuid|geteuid|getgid|getegid|setuid|seteuid|setgid|setegid|setsid|setpgrp|getpgrp|setpgid|getpgid|tcgetpgrp|tcsetpgrp)"), "process", "process management {}"),
    (re.compile(r"^(posix_spawn|posix_spawnattr|posix_spawn_file_actions)"), "process", "posix_spawn {}"),
    (re.compile(r"^(system|popen|pclose|daemon|syslog|openlog|closelog|setlogmask)"), "process", "system/logging {}"),

    # Threading
    (re.compile(r"^pthread_"), "threading", "POSIX threads {}"),
    (re.compile(r"^(os_unfair_lock|OSSpinLock|OSAtomic|os_once)"), "threading", "atomic/lock {}"),
    (re.compile(r"^(thrd_|mtx_|cnd_|tss_)"), "threading", "C11 threads {}"),

    # Dynamic loading
    (re.compile(r"^(dlopen|dlclose|dlsym|dlerror|dladdr|dladdr_fini|dyld|_dyld|NSModule|NSLookupSymbol|NSCreateObjectFile|NSLinkModule|_NSGetExecutablePath)"), "dynamic_loading", "dynamic loading {}"),

    # Math
    (re.compile(r"^(sin|cos|tan|asin|acos|atan|atan2|sinh|cosh|tanh|asinh|acosh|atanh|exp|exp2|expm1|log|log2|log10|log1p|pow|sqrt|cbrt|hypot|fabs|floor|ceil|round|trunc|fmod|remainder|fma|fmax|fmin|fdim|nan|nearbyint|rint|lrint|llrint|lround|llround|erf|erfc|gamma|lgamma|tgamma|j[01n]|y[01n]|nextafter|nexttoward|copysign|signbit|fpclassify|isnan|isinf|isfinite|isnormal|frexp|ldexp|modf|scalbn|scalbln|logb|ilogb)(f|l)?$"), "math", "math function {}"),
    (re.compile(r"^(vv|vDSP_|vDSP|cblas_|catlas_|LAPACK_|clapack_|sparse_|vImage|bnns_|BNNSFilter|BNNSGraph)"), "math", "Accelerate/vDSP/BLAS/BNNS {}"),
    (re.compile(r"^(__div|__mul|__add|__sub|__neg|__float|__fix|__trunc|__extend)"), "math", "compiler math builtin {}"),

    # Locale / i18n
    (re.compile(r"^(setlocale|localeconv|newlocale|uselocale|freelocale|nl_langinfo|iconv|iconv_open|iconv_close|catopen|catclose|catgets)"), "locale", "locale/i18n {}"),
    (re.compile(r"^(u_|ucnv_|ucol_|udat_|ufmt_|umsg_|unum_|ures_|usearch_|utext_|utrans_|ubrk_|unorm_|uset_|ustring_|uchar_|uscript_|ubidi_|UCNV_|UCOL_|ICU|icu_)"), "locale", "ICU Unicode {}"),

    # Regex
    (re.compile(r"^(reg(comp|exec|free|error)|pcre2?_|tre_)"), "regex", "regex {}"),

    # Environment / misc libc
    (re.compile(r"^(getenv|setenv|unsetenv|putenv|clearenv)"), "environment", "environment {}"),
    (re.compile(r"^(time|gettimeofday|clock_gettime|clock_getres|nanosleep|usleep|sleep|gmtime|localtime|mktime|difftime|strftime|strptime|timegm|timelocal|asctime|ctime|tzset)"), "time", "time {}"),
    (re.compile(r"^(rand|srand|random|srandom|initstate|setstate|arc4random|arc4random_uniform|arc4random_buf|drand48|erand48|lrand48|nrand48|mrand48|jrand48|srand48|seed48|lcong48)"), "random", "random number {}"),

    # Sysctl / System Info
    (re.compile(r"^(sysctl|sysctlbyname|sysctlnametomib|sysconf|getrlimit|setrlimit|getrusage|getloadavg|uname|gethostname|sethostname)"), "system_info", "system info {}"),

    # Mach
    (re.compile(r"^(mach_|task_|thread_|host_|vm_|processor_|clock_|semaphore_|exc_|kern_|ipc_)"), "mach", "Mach kernel {}"),
    (re.compile(r"^(bootstrap_|launchd_|notify_|asl_)"), "mach", "system services {}"),

    # libdispatch (already covered above, but catch any remaining)
    (re.compile(r"^(Block_|_Block_)"), "blocks", "blocks runtime {}"),

    # Protobuf
    (re.compile(r"^(protobuf_|google_protobuf_|upb_|PB[A-Z])"), "serialization", "protobuf {}"),

    # JSON parsers
    (re.compile(r"^(cJSON_|yyjson_|json_|jansson_)"), "serialization", "JSON parser {}"),

    # XML parsers
    (re.compile(r"^(xml[A-Z]|xmlC|htmlC|xslt|exslt|XML_|xmlParser|xmlDoc|xmlNode|xmlAttr|xmlNs|xmlXPath)"), "serialization", "libxml2 {}"),
    (re.compile(r"^(XML_Parser|XML_Get|XML_Set|XML_Parse|XML_Stop|XML_Resume|XML_Error)"), "serialization", "expat {}"),
    (re.compile(r"^(xmlTextReader|xmlTextWriter|xmlSAX|xmlValid|xmlSchema|xmlRelax)"), "serialization", "libxml2 advanced {}"),
    (re.compile(r"^(plist_|_plist)"), "serialization", "plist {}"),

    # FlatBuffers / Cap'n Proto / MessagePack
    (re.compile(r"^(flatbuffers_|flatcc_|capnp_|msgpack_)"), "serialization", "serialization {}"),

    # gRPC
    (re.compile(r"^(grpc_|gpr_|grpcsharp_)"), "network", "gRPC {}"),

    # libuv
    (re.compile(r"^uv_"), "async_io", "libuv {}"),
    (re.compile(r"^(event_|evbuffer_|evutil_|evhttp_|evconnlistener_|bufferevent_)"), "async_io", "libevent {}"),

    # ImageIO / Image libs
    (re.compile(r"^(CGImage(Source|Destination|Metadata|Property))"), "image", "ImageIO {}"),
    (re.compile(r"^(png_|PNG_)"), "image", "libpng {}"),
    (re.compile(r"^(jpeg_|JPEG_|tjCompress|tjDecompress|tjTransform)"), "image", "libjpeg {}"),
    (re.compile(r"^(WebP|VP8)"), "image", "libwebp {}"),

    # FFmpeg / libav
    (re.compile(r"^(av_|avcodec_|avformat_|avutil_|avfilter_|avdevice_|sws_|swr_|avio_)"), "media", "FFmpeg/libav {}"),

    # SDL
    (re.compile(r"^SDL_"), "multimedia", "SDL2 {}"),

    # OpenGL
    (re.compile(r"^(gl[A-Z]|glGet|glEnable|glDisable|glBind|glGen|glDelete|glCreate|glAttach|glCompile|glLink|glUse|glDraw|glFlush|glFinish|glClear|glViewport|glScissor|glBlend|glStencil|glDepth|glTexImage|glTexSubImage|glTexParameter|glFramebuffer|glRenderbuffer)"), "graphics", "OpenGL {}"),

    # Rust std (demangled)
    (re.compile(r"^(std::|core::|alloc::|_?rust_)"), "rust", "Rust standard library {}"),

    # Go runtime
    (re.compile(r"^(runtime\.|syscall\.|os\.|net\.|fmt\.|sync\.|go_|_cgo_)"), "go", "Go runtime {}"),

    # Apple System private
    (re.compile(r"^(AAPL|Apple|apple_|MobileDevice|AMDevice|AFC)"), "apple_private", "Apple private API {}"),
    (re.compile(r"^(sandbox_|app_sandbox|rootless_)"), "security", "Sandbox {}"),
    (re.compile(r"^(csops|csproc|cs_)"), "security", "Code Signing {}"),

    # Catch remaining with simple prefix heuristics
    (re.compile(r"^_os_"), "system", "OS internal {}"),
    (re.compile(r"^__"), "internal", "internal function {}"),
]

# Library name inference from file path
def infer_library_name(path: str) -> str:
    """Extract a clean library name from a file path."""
    p = Path(path)
    name = p.stem  # e.g., libsystem_c from libsystem_c.dylib

    # Framework: /path/Foo.framework/Versions/Current/Foo -> "Foo"
    parts = p.parts
    for i, part in enumerate(parts):
        if part.endswith(".framework"):
            return part.replace(".framework", "")

    # Dylib: strip 'lib' prefix and version suffixes
    if name.startswith("lib"):
        name = name[3:]

    # Strip version numbers: libfoo.1.2.3 -> foo
    name = re.sub(r"\.\d+$", "", name)

    return name


def categorize_symbol(name: str) -> tuple[str, str]:
    """Return (category, purpose) for a function name."""
    for pattern, category, purpose_template in CATEGORY_RULES:
        m = pattern.search(name)
        if m:
            matched = m.group(0)
            purpose = purpose_template.replace("{}", matched)
            return category, purpose

    # Fallback: try to guess from prefix
    if name.startswith("_"):
        inner = name[1:]
    else:
        inner = name

    # Simple prefix guess
    prefix = inner[:3].lower()
    simple_map = {
        "str": ("string", "string operation"),
        "mem": ("memory", "memory operation"),
        "get": ("accessor", "getter function"),
        "set": ("accessor", "setter function"),
        "is_": ("predicate", "predicate function"),
        "has": ("predicate", "predicate function"),
    }
    if prefix in simple_map:
        return simple_map[prefix]

    return "misc", ""


def strip_leading_underscore(name: str) -> str:
    """Strip the Mach-O leading underscore convention."""
    if name.startswith("_") and len(name) > 1 and not name.startswith("__"):
        return name[1:]
    return name


# ---------------------------------------------------------------------------
# Library scanning
# ---------------------------------------------------------------------------

def find_sdk_path() -> str:
    """Get macOS SDK path."""
    try:
        result = subprocess.run(
            ["xcrun", "--sdk", "macosx", "--show-sdk-path"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"


def find_dylibs(directories: list[str], recursive: bool = False) -> list[str]:
    """Find all .dylib files in given directories."""
    found = []
    for d in directories:
        p = Path(d)
        if not p.exists():
            continue
        if recursive:
            for f in p.rglob("*.dylib"):
                found.append(str(f))
        else:
            for f in p.glob("*.dylib"):
                found.append(str(f))
    return found


def find_framework_binaries(framework_dirs: list[str]) -> list[str]:
    """Find framework binary files."""
    found = []
    for d in framework_dirs:
        p = Path(d)
        if not p.exists():
            continue
        for fw in p.iterdir():
            if not fw.name.endswith(".framework"):
                continue
            fw_name = fw.name.replace(".framework", "")
            # Try common locations for the binary
            candidates = [
                fw / fw_name,
                fw / "Versions" / "Current" / fw_name,
                fw / "Versions" / "A" / fw_name,
            ]
            for c in candidates:
                if c.exists():
                    found.append(str(c))
                    break
    return found


def find_tbd_files(directories: list[str]) -> list[str]:
    """Find .tbd stub files (text-based definition files in SDK)."""
    found = []
    for d in directories:
        p = Path(d)
        if not p.exists():
            continue
        for f in p.rglob("*.tbd"):
            found.append(str(f))
    return found


def extract_symbols_from_tbd(tbd_path: str) -> list[tuple[str, str]]:
    """Extract symbol names from a .tbd (text-based definition) file.

    Returns list of (symbol_name, symbol_type) tuples.
    The symbol_type is always 'T' since tbd only lists exports.
    """
    symbols = []
    try:
        with open(tbd_path, "r", errors="replace") as f:
            content = f.read()

        # TBD v4/v5 format uses YAML-like structure
        # Look for symbols/objc-classes/objc-ivars sections
        in_symbols = False
        for line in content.split("\n"):
            stripped = line.strip()

            # Detect symbol sections
            if "symbols:" in stripped or "weak-symbols:" in stripped:
                in_symbols = True
                continue
            if "objc-classes:" in stripped:
                in_symbols = False  # Skip ObjC class names
                continue
            if "objc-ivars:" in stripped:
                in_symbols = False
                continue
            if stripped.startswith("- targets:") or stripped.startswith("flags:"):
                in_symbols = False
                continue
            if stripped.startswith("...") or stripped.startswith("---"):
                in_symbols = False
                continue

            if in_symbols and stripped.startswith("- "):
                # Could be a list entry like "- _functionName"
                sym = stripped[2:].strip().rstrip(",").strip("'\"")
                if sym and not sym.startswith("(") and not sym.startswith("{"):
                    symbols.append((sym, "T"))
            elif in_symbols and "'" in stripped:
                # Inline list: symbols: [ '_foo', '_bar' ]
                for match in re.finditer(r"'([^']+)'", stripped):
                    symbols.append((match.group(1), "T"))
            elif in_symbols and "_" in stripped and not stripped.startswith("#"):
                # Simple symbol line
                for part in stripped.split(","):
                    part = part.strip().strip("[]'\" ")
                    if part.startswith("_"):
                        symbols.append((part, "T"))

    except Exception:
        pass
    return symbols


def extract_symbols_nm(binary_path: str) -> list[tuple[str, str]]:
    """Run nm -gU on a binary and return (symbol_name, type) pairs."""
    try:
        result = subprocess.run(
            ["nm", "-gU", binary_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return []
    except Exception:
        return []

    symbols = []
    for line in result.stdout.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Format: "0000000000001234 T _functionName" or "T _functionName"
        parts = line.split()
        if len(parts) >= 3:
            sym_type = parts[1]
            sym_name = parts[2]
        elif len(parts) == 2:
            sym_type = parts[0]
            sym_name = parts[1]
        else:
            continue
        if sym_type in STRICT_FUNCTION_TYPES:
            symbols.append((sym_name, sym_type))
    return symbols


def extract_symbols_nm_arch(binary_path: str) -> list[tuple[str, str]]:
    """Run nm -gU on a binary, trying arm64 arch if needed."""
    symbols = extract_symbols_nm(binary_path)
    if not symbols:
        # Try specifying arm64 architecture
        try:
            result = subprocess.run(
                ["nm", "-gU", "-arch", "arm64", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in STRICT_FUNCTION_TYPES:
                        symbols.append((parts[2], parts[1]))
                    elif len(parts) == 2 and parts[0] in STRICT_FUNCTION_TYPES:
                        symbols.append((parts[1], parts[0]))
        except Exception:
            pass
    return symbols


# ---------------------------------------------------------------------------
# Main extraction pipeline
# ---------------------------------------------------------------------------

def main():
    start_time = time.time()

    sdk_path = find_sdk_path()
    print(f"macOS SDK: {sdk_path}")

    # Collect all library paths
    all_binaries: list[tuple[str, str]] = []  # (path, source_category)
    all_tbd_files: list[tuple[str, str]] = []  # (path, source_category)

    # 1. System dylibs via TBD stubs in SDK
    sdk_usr_lib = os.path.join(sdk_path, "usr", "lib")
    print(f"\n[1/6] Scanning SDK usr/lib TBD stubs: {sdk_usr_lib}")
    tbd_files = find_tbd_files([sdk_usr_lib])
    for f in tbd_files:
        all_tbd_files.append((f, "system_dylib"))
    print(f"  Found {len(tbd_files)} .tbd files")

    # Also try actual /usr/lib (some dylibs exist here)
    print(f"\n[2/6] Scanning /usr/lib dylibs")
    usr_dylibs = find_dylibs(["/usr/lib"], recursive=True)
    for f in usr_dylibs:
        all_binaries.append((f, "system_dylib"))
    print(f"  Found {len(usr_dylibs)} dylibs")

    # 2. SDK Frameworks (public)
    sdk_frameworks_dir = os.path.join(sdk_path, "System", "Library", "Frameworks")
    print(f"\n[3/6] Scanning SDK public frameworks: {sdk_frameworks_dir}")
    fw_binaries = find_framework_binaries([sdk_frameworks_dir])
    # Also find TBD stubs in frameworks
    fw_tbds = find_tbd_files([sdk_frameworks_dir])
    for f in fw_binaries:
        all_binaries.append((f, "public_framework"))
    for f in fw_tbds:
        all_tbd_files.append((f, "public_framework"))
    print(f"  Found {len(fw_binaries)} framework binaries, {len(fw_tbds)} TBD stubs")

    # 3. SDK Private Frameworks
    sdk_private_fw_dir = os.path.join(sdk_path, "System", "Library", "PrivateFrameworks")
    print(f"\n[4/6] Scanning SDK private frameworks: {sdk_private_fw_dir}")
    priv_fw_binaries = find_framework_binaries([sdk_private_fw_dir])
    priv_fw_tbds = find_tbd_files([sdk_private_fw_dir])
    for f in priv_fw_binaries:
        all_binaries.append((f, "private_framework"))
    for f in priv_fw_tbds:
        all_tbd_files.append((f, "private_framework"))
    print(f"  Found {len(priv_fw_binaries)} private framework binaries, {len(priv_fw_tbds)} TBD stubs")

    # 4. Runtime system frameworks (actual binaries on disk)
    runtime_fw_dirs = [
        "/System/Library/Frameworks",
        "/System/Library/PrivateFrameworks",
    ]
    print(f"\n[5/6] Scanning runtime system frameworks")
    for d in runtime_fw_dirs:
        fw_bins = find_framework_binaries([d])
        for f in fw_bins:
            all_binaries.append((f, "runtime_framework"))
        print(f"  {d}: {len(fw_bins)} binaries")

    # 5. Homebrew libraries
    print(f"\n[6/6] Scanning Homebrew libraries")
    brew_dylibs = find_dylibs(["/opt/homebrew/lib"], recursive=False)
    # Also check Cellar
    cellar_dylibs = []
    cellar_path = Path("/opt/homebrew/Cellar")
    if cellar_path.exists():
        for pkg_dir in cellar_path.iterdir():
            if not pkg_dir.is_dir():
                continue
            for ver_dir in pkg_dir.iterdir():
                if not ver_dir.is_dir():
                    continue
                lib_dir = ver_dir / "lib"
                if lib_dir.exists():
                    for f in lib_dir.glob("*.dylib"):
                        cellar_dylibs.append(str(f))
    for f in brew_dylibs:
        all_binaries.append((f, "homebrew"))
    for f in cellar_dylibs:
        all_binaries.append((f, "homebrew_cellar"))
    print(f"  Found {len(brew_dylibs)} in /opt/homebrew/lib, {len(cellar_dylibs)} in Cellar")

    # ---------------------------------------------------------------------------
    # Extract symbols
    # ---------------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"Total targets: {len(all_binaries)} binaries + {len(all_tbd_files)} TBD stubs")
    print(f"{'='*60}")

    all_symbols: dict[str, dict] = {}  # name -> {lib, purpose, category, confidence}
    lib_stats: dict[str, int] = defaultdict(int)
    category_stats: dict[str, int] = defaultdict(int)
    errors = 0
    processed = 0

    # Process TBD files first (faster, text-based)
    print(f"\nProcessing {len(all_tbd_files)} TBD stub files...")
    for i, (tbd_path, source) in enumerate(all_tbd_files):
        if i % 500 == 0 and i > 0:
            print(f"  TBD progress: {i}/{len(all_tbd_files)} ({len(all_symbols)} symbols)")

        lib_name = infer_library_name(tbd_path)
        symbols = extract_symbols_from_tbd(tbd_path)

        for sym_name, sym_type in symbols:
            if SKIP_PATTERNS.match(sym_name):
                continue
            if SWIFT_MANGLED.match(sym_name):
                continue
            # Skip any symbol containing $ (linker directives, Swift mangled, ObjC artifacts)
            if DOLLAR_SYMBOL.search(sym_name):
                continue

            clean_name = strip_leading_underscore(sym_name)
            if not clean_name or len(clean_name) < 2:
                continue
            # Skip GUID-like symbols (__HEXHEXHEX...)
            if GUID_PATTERN.match(sym_name):
                continue

            if clean_name in all_symbols:
                continue

            category, purpose = categorize_symbol(clean_name)
            all_symbols[clean_name] = {
                "lib": lib_name,
                "purpose": purpose,
                "category": category,
                "confidence": 0.90,
            }
            lib_stats[lib_name] += 1
            category_stats[category] += 1

        processed += 1

    print(f"  TBD done: {len(all_symbols)} symbols from {processed} files")

    # Process binaries with nm
    print(f"\nProcessing {len(all_binaries)} binary files with nm...")
    for i, (binary_path, source) in enumerate(all_binaries):
        if i % 100 == 0 and i > 0:
            print(f"  Binary progress: {i}/{len(all_binaries)} ({len(all_symbols)} symbols)")

        lib_name = infer_library_name(binary_path)
        symbols = extract_symbols_nm_arch(binary_path)

        if not symbols:
            errors += 1
            continue

        new_in_lib = 0
        for sym_name, sym_type in symbols:
            if SKIP_PATTERNS.match(sym_name):
                continue
            if SWIFT_MANGLED.match(sym_name):
                continue
            # Skip any symbol containing $ (linker directives, Swift mangled, ObjC artifacts)
            if DOLLAR_SYMBOL.search(sym_name):
                continue

            clean_name = strip_leading_underscore(sym_name)
            if not clean_name or len(clean_name) < 2:
                continue
            # Skip GUID-like symbols (__HEXHEXHEX...)
            if GUID_PATTERN.match(sym_name):
                continue

            if clean_name in all_symbols:
                continue

            category, purpose = categorize_symbol(clean_name)
            confidence = 0.95 if source in ("public_framework", "system_dylib") else 0.85
            all_symbols[clean_name] = {
                "lib": lib_name,
                "purpose": purpose,
                "category": category,
                "confidence": confidence,
            }
            lib_stats[lib_name] += 1
            category_stats[category] += 1
            new_in_lib += 1

        processed += 1

    elapsed = time.time() - start_time

    # ---------------------------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"EXTRACTION COMPLETE")
    print(f"{'='*60}")
    print(f"Total unique symbols: {len(all_symbols):,}")
    print(f"Files processed: {processed}")
    print(f"Files with errors/no symbols: {errors}")
    print(f"Elapsed: {elapsed:.1f}s")

    print(f"\nTop 30 libraries by symbol count:")
    for lib, count in sorted(lib_stats.items(), key=lambda x: -x[1])[:30]:
        print(f"  {lib:40s} {count:>8,}")

    print(f"\nCategories:")
    for cat, count in sorted(category_stats.items(), key=lambda x: -x[1]):
        print(f"  {cat:30s} {count:>8,}")

    # ---------------------------------------------------------------------------
    # Save output
    # ---------------------------------------------------------------------------
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Format matching load_external_signatures: list of dicts
    signatures_list = []
    for name, info in sorted(all_symbols.items()):
        entry = {
            "name": name,
            "library": info["lib"],
            "category": info["category"],
            "confidence": info["confidence"],
        }
        # Only include purpose if non-empty (saves ~30% file size)
        if info["purpose"]:
            entry["purpose"] = info["purpose"]
        signatures_list.append(entry)

    output_data = {
        "meta": {
            "generator": "tools/extract_macos_system_symbols.py",
            "version": "2.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "sdk_path": sdk_path,
            "files_processed": processed,
            "errors": errors,
            "elapsed_seconds": round(elapsed, 1),
        },
        "library_stats": dict(sorted(lib_stats.items(), key=lambda x: -x[1])),
        "category_stats": dict(sorted(category_stats.items(), key=lambda x: -x[1])),
        "signatures": signatures_list,
        "total": len(signatures_list),
    }

    # Use separators without spaces for compact output (~20% smaller)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output_data, f, separators=(",", ":"))

    file_size_mb = OUTPUT_FILE.stat().st_size / (1024 * 1024)
    print(f"\nSaved: {OUTPUT_FILE}")
    print(f"File size: {file_size_mb:.1f} MB")
    print(f"Total signatures: {len(signatures_list):,}")

    # Quick validation
    if len(signatures_list) < 50000:
        print(f"\nWARNING: Only {len(signatures_list):,} signatures extracted.")
        print("Expected at least 200K. Check if SDK path and nm are working correctly.")
        print("Consider running: xcrun --sdk macosx --show-sdk-path")


if __name__ == "__main__":
    main()
