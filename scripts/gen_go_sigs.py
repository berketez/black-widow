#!/usr/bin/env python3
"""
Go Expanded Signature Generator for Karadul
============================================
Go binary'lerden (GOPCLNTAB strings) ve Go stdlib bilgisinden
fonksiyon sembollerini cikarir.

Kaynaklar:
1. Sistemdeki Go binary'ler (gh, docker, colima, arduino-cli)
   - Go binary'ler stripped olsa bile GOPCLNTAB'da tum fonksiyon isimlerini tasir
   - `strings` ile cikarilabilir
2. Mevcut go_stdlib_signatures.json ile dedup

Cikti: sigs/go_expanded.json
"""

import json
import subprocess
import re
import sys
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# --- Config ---
SIGS_DIR = Path("/Users/apple/Desktop/black-widow/sigs")
EXISTING_FILE = SIGS_DIR / "go_stdlib_signatures.json"
OUTPUT_FILE = SIGS_DIR / "go_expanded.json"

# Go binary'ler - (path, friendly_name)
GO_BINARIES = [
    ("/opt/homebrew/bin/gh", "github-cli"),
    ("/opt/homebrew/bin/docker", "docker"),
    ("/opt/homebrew/bin/colima", "colima"),
    ("/opt/homebrew/bin/arduino-cli", "arduino-cli"),
]

# --- Go symbol patterns ---
# Go exported: paket/alt.Fonksiyon veya paket/alt.(*Tip).Metod
# Go unexported: paket/alt.fonksiyon (kucuk harf)
# Runtime: runtime.xxx
GO_SYMBOL_RE = re.compile(
    r'^('
    # Standard form: pkg/path.Function or pkg/path.(*Type).Method
    r'[a-z][a-z0-9_]*/[a-z][a-z0-9_/]*\.[A-Z*(\[][A-Za-z0-9_.*()]*'
    r'|'
    # Top-level pkg: runtime.xxx, fmt.Xxx, os.Xxx, io.Xxx, sync.Xxx
    r'(?:runtime|fmt|os|io|sync|math|sort|bytes|strings|strconv|errors|context|reflect|unsafe|time|log|flag|path|hash|regexp|unicode|testing|debug|plugin|embed|maps|slices|cmp|iter)\.[A-Za-z_][A-Za-z0-9_.*()]*'
    r')$'
)

# Closure/anonymous func suffix pattern: .func1, .func2.1, etc.
CLOSURE_SUFFIX_RE = re.compile(r'\.func\d+(\.\d+)*$')

# Init function pattern
INIT_RE = re.compile(r'\.init(\.\d+)?$')

# Type metadata - skip these
TYPE_META_RE = re.compile(r'type\.\.|go:')

# Package -> category mapping
CATEGORY_MAP = {
    'runtime': 'go_runtime',
    'fmt': 'go_fmt',
    'os': 'go_os',
    'os/exec': 'go_os',
    'os/signal': 'go_os',
    'io': 'go_io',
    'io/fs': 'go_io',
    'io/ioutil': 'go_io',
    'net': 'go_net',
    'net/http': 'go_http',
    'net/url': 'go_net',
    'net/smtp': 'go_net',
    'net/mail': 'go_net',
    'net/rpc': 'go_net',
    'net/textproto': 'go_net',
    'crypto': 'go_crypto',
    'crypto/tls': 'go_crypto',
    'crypto/x509': 'go_crypto',
    'crypto/sha256': 'go_crypto',
    'crypto/sha512': 'go_crypto',
    'crypto/md5': 'go_crypto',
    'crypto/aes': 'go_crypto',
    'crypto/rsa': 'go_crypto',
    'crypto/ecdsa': 'go_crypto',
    'crypto/ed25519': 'go_crypto',
    'crypto/hmac': 'go_crypto',
    'crypto/cipher': 'go_crypto',
    'crypto/rand': 'go_crypto',
    'crypto/elliptic': 'go_crypto',
    'encoding/json': 'go_encoding',
    'encoding/xml': 'go_encoding',
    'encoding/base64': 'go_encoding',
    'encoding/hex': 'go_encoding',
    'encoding/binary': 'go_encoding',
    'encoding/csv': 'go_encoding',
    'encoding/gob': 'go_encoding',
    'encoding/pem': 'go_encoding',
    'encoding/ascii85': 'go_encoding',
    'encoding/asn1': 'go_encoding',
    'sync': 'go_sync',
    'sync/atomic': 'go_sync',
    'math': 'go_math',
    'math/big': 'go_math',
    'math/rand': 'go_math',
    'math/bits': 'go_math',
    'sort': 'go_sort',
    'strings': 'go_string',
    'bytes': 'go_string',
    'strconv': 'go_string',
    'unicode': 'go_string',
    'unicode/utf8': 'go_string',
    'unicode/utf16': 'go_string',
    'regexp': 'go_string',
    'reflect': 'go_reflect',
    'unsafe': 'go_runtime',
    'context': 'go_context',
    'errors': 'go_errors',
    'time': 'go_time',
    'log': 'go_log',
    'log/slog': 'go_log',
    'flag': 'go_cli',
    'path': 'go_path',
    'path/filepath': 'go_path',
    'hash': 'go_hash',
    'hash/crc32': 'go_hash',
    'hash/fnv': 'go_hash',
    'testing': 'go_testing',
    'debug/elf': 'go_debug',
    'debug/dwarf': 'go_debug',
    'debug/macho': 'go_debug',
    'debug/pe': 'go_debug',
    'debug/gosym': 'go_debug',
    'plugin': 'go_runtime',
    'embed': 'go_runtime',
    'syscall': 'go_syscall',
    'archive/tar': 'go_archive',
    'archive/zip': 'go_archive',
    'compress/flate': 'go_compress',
    'compress/gzip': 'go_compress',
    'compress/zlib': 'go_compress',
    'compress/bzip2': 'go_compress',
    'compress/lzw': 'go_compress',
    'bufio': 'go_io',
    'container/heap': 'go_container',
    'container/list': 'go_container',
    'container/ring': 'go_container',
    'database/sql': 'go_database',
    'database/sql/driver': 'go_database',
    'html': 'go_html',
    'html/template': 'go_html',
    'text/template': 'go_html',
    'text/scanner': 'go_string',
    'text/tabwriter': 'go_string',
    'image': 'go_image',
    'image/png': 'go_image',
    'image/jpeg': 'go_image',
    'image/color': 'go_image',
    'image/draw': 'go_image',
    'image/gif': 'go_image',
    'mime': 'go_mime',
    'mime/multipart': 'go_mime',
    'mime/quotedprintable': 'go_mime',
    'go/ast': 'go_tooling',
    'go/parser': 'go_tooling',
    'go/token': 'go_tooling',
    'go/types': 'go_tooling',
    'go/format': 'go_tooling',
    'go/build': 'go_tooling',
    'go/doc': 'go_tooling',
    'go/printer': 'go_tooling',
    'go/scanner': 'go_tooling',
    'go/constant': 'go_tooling',
    'go/importer': 'go_tooling',
    'internal': 'go_internal',
    'vendor': 'go_vendor',
    'maps': 'go_collections',
    'slices': 'go_collections',
    'cmp': 'go_collections',
    'iter': 'go_collections',
}

# 3rd party package -> category mapping
THIRD_PARTY_CATEGORIES = {
    'github.com/cli/cli': 'gh_cli',
    'github.com/docker': 'docker',
    'github.com/moby': 'docker',
    'github.com/containerd': 'container',
    'github.com/opencontainers': 'container',
    'github.com/spf13/cobra': 'go_cli',
    'github.com/spf13/viper': 'go_config',
    'github.com/spf13/pflag': 'go_cli',
    'github.com/spf13/afero': 'go_fs',
    'github.com/gorilla/mux': 'go_http',
    'github.com/gorilla/websocket': 'go_http',
    'github.com/gin-gonic': 'go_http',
    'github.com/sirupsen/logrus': 'go_log',
    'go.uber.org/zap': 'go_log',
    'google.golang.org/grpc': 'go_grpc',
    'google.golang.org/protobuf': 'go_grpc',
    'github.com/golang/protobuf': 'go_grpc',
    'k8s.io': 'go_k8s',
    'github.com/prometheus': 'go_metrics',
    'github.com/hashicorp': 'go_infra',
    'github.com/aws': 'go_cloud',
    'cloud.google.com': 'go_cloud',
    'github.com/Azure': 'go_cloud',
    'golang.org/x/crypto': 'go_crypto',
    'golang.org/x/net': 'go_net',
    'golang.org/x/sys': 'go_syscall',
    'golang.org/x/text': 'go_string',
    'golang.org/x/oauth2': 'go_auth',
    'golang.org/x/sync': 'go_sync',
    'golang.org/x/tools': 'go_tooling',
    'golang.org/x/term': 'go_cli',
    'golang.org/x/time': 'go_time',
    'github.com/stretchr/testify': 'go_testing',
    'github.com/BurntSushi/toml': 'go_config',
    'gopkg.in/yaml': 'go_config',
    'github.com/pelletier/go-toml': 'go_config',
    'github.com/go-git/go-git': 'go_git',
    'github.com/shurcooL': 'go_graphql',
    'github.com/cli/go-gh': 'gh_cli',
    'github.com/muesli': 'go_tui',
    'github.com/charmbracelet': 'go_tui',
    'github.com/mattn': 'go_util',
    'github.com/pkg/errors': 'go_errors',
    'github.com/cenkalti': 'go_util',
}

# Well-known stdlib purpose descriptions
PURPOSE_DB = {
    # runtime
    'runtime.main': 'Go program main entry (calls main.main)',
    'runtime.goexit': 'goroutine exit point',
    'runtime.gopanic': 'panic handler',
    'runtime.gorecover': 'recover handler',
    'runtime.newobject': 'allocate new object on heap',
    'runtime.newproc': 'create new goroutine (go statement)',
    'runtime.makeslice': 'allocate new slice',
    'runtime.makechan': 'create new channel',
    'runtime.makemap': 'create new map',
    'runtime.mapassign': 'assign value to map key',
    'runtime.mapaccess1': 'map lookup (single return)',
    'runtime.mapaccess2': 'map lookup (comma-ok)',
    'runtime.mapdelete': 'delete map key',
    'runtime.growslice': 'grow slice capacity',
    'runtime.memmove': 'memory copy',
    'runtime.memclrNoHeapPointers': 'zero memory (no heap pointers)',
    'runtime.gcStart': 'start garbage collection',
    'runtime.gcDrain': 'drain GC work queue',
    'runtime.mallocgc': 'allocate memory with GC',
    'runtime.convT': 'convert to interface',
    'runtime.assertI2I': 'interface type assertion',
    'runtime.chanrecv': 'channel receive',
    'runtime.chansend': 'channel send',
    'runtime.closechan': 'close channel',
    'runtime.selectgo': 'execute select statement',
    'runtime.deferreturn': 'execute deferred calls on return',
    'runtime.deferproc': 'register deferred function call',
    'runtime.systemstack': 'switch to system stack',
    'runtime.mcall': 'switch to g0 stack and call function',
    'runtime.schedule': 'goroutine scheduler main loop',
    'runtime.findrunnable': 'find a runnable goroutine',
    'runtime.execute': 'execute a goroutine',
    'runtime.gopark': 'park goroutine (put to sleep)',
    'runtime.goready': 'wake up parked goroutine',
    'runtime.lock': 'acquire runtime mutex',
    'runtime.unlock': 'release runtime mutex',
    'runtime.throw': 'fatal runtime error',
    'runtime.fatalpanic': 'unrecoverable panic',
    'runtime.printstring': 'print string to stderr',
    'runtime.printint': 'print integer to stderr',
    'runtime.Caller': 'get caller program counter and file/line',
    'runtime.Callers': 'get call stack program counters',
    'runtime.Stack': 'format goroutine stack trace',
    'runtime.GC': 'trigger garbage collection',
    'runtime.GOMAXPROCS': 'set max number of CPUs for goroutines',
    'runtime.NumGoroutine': 'return number of goroutines',
    'runtime.Gosched': 'yield the processor',
    'runtime.SetFinalizer': 'set object finalizer',
    'runtime.KeepAlive': 'keep object alive for GC',
    'runtime.ReadMemStats': 'read memory statistics',
    'runtime.LockOSThread': 'lock goroutine to OS thread',
    'runtime.UnlockOSThread': 'unlock goroutine from OS thread',
    # fmt
    'fmt.Println': 'print line to stdout',
    'fmt.Printf': 'formatted print to stdout',
    'fmt.Sprintf': 'formatted string',
    'fmt.Fprintf': 'formatted print to writer',
    'fmt.Errorf': 'formatted error',
    'fmt.Sscanf': 'scan formatted string',
    'fmt.Fscanf': 'scan formatted from reader',
    'fmt.Scanf': 'scan formatted from stdin',
    'fmt.Print': 'print to stdout',
    'fmt.Sprint': 'concatenate to string',
    'fmt.Fprint': 'print to writer',
    'fmt.Fprintln': 'print line to writer',
    'fmt.Sprintln': 'concatenate with newline to string',
    # os
    'os.Open': 'open file for reading',
    'os.Create': 'create or truncate file',
    'os.OpenFile': 'open file with flags and permissions',
    'os.Remove': 'remove file or empty directory',
    'os.RemoveAll': 'remove path recursively',
    'os.Mkdir': 'create directory',
    'os.MkdirAll': 'create directory recursively',
    'os.Rename': 'rename file or directory',
    'os.Stat': 'get file info',
    'os.Lstat': 'get file info (no symlink follow)',
    'os.Getenv': 'get environment variable',
    'os.Setenv': 'set environment variable',
    'os.Exit': 'exit process with status code',
    'os.Getwd': 'get working directory',
    'os.Chdir': 'change working directory',
    'os.ReadFile': 'read entire file',
    'os.WriteFile': 'write data to file',
    'os.Getpid': 'get process ID',
    'os.Hostname': 'get hostname',
    'os.UserHomeDir': 'get user home directory',
    'os.Executable': 'get executable path',
    'os.TempDir': 'get temp directory path',
    'os.Pipe': 'create connected pipe file descriptors',
    # io
    'io.Copy': 'copy from reader to writer',
    'io.ReadAll': 'read all bytes from reader',
    'io.WriteString': 'write string to writer',
    'io.NopCloser': 'wrap reader with no-op close',
    'io.LimitReader': 'limit reader to N bytes',
    'io.TeeReader': 'tee reader output to writer',
    'io.MultiReader': 'combine multiple readers',
    'io.MultiWriter': 'combine multiple writers',
    'io.Pipe': 'create synchronous in-memory pipe',
    # net/http
    'net/http.ListenAndServe': 'start HTTP server',
    'net/http.Get': 'HTTP GET request',
    'net/http.Post': 'HTTP POST request',
    'net/http.Handle': 'register HTTP handler',
    'net/http.HandleFunc': 'register HTTP handler function',
    'net/http.NewRequest': 'create new HTTP request',
    'net/http.Redirect': 'send HTTP redirect',
    'net/http.Error': 'send HTTP error response',
    'net/http.ServeFile': 'serve file over HTTP',
    'net/http.SetCookie': 'set HTTP cookie',
    'net/http.StatusText': 'get HTTP status text',
    # strings
    'strings.Contains': 'check if string contains substring',
    'strings.HasPrefix': 'check string prefix',
    'strings.HasSuffix': 'check string suffix',
    'strings.Split': 'split string by separator',
    'strings.Join': 'join strings with separator',
    'strings.Replace': 'replace occurrences in string',
    'strings.ReplaceAll': 'replace all occurrences in string',
    'strings.TrimSpace': 'trim whitespace from string',
    'strings.Trim': 'trim characters from string',
    'strings.ToLower': 'convert string to lowercase',
    'strings.ToUpper': 'convert string to uppercase',
    'strings.Index': 'find first index of substring',
    'strings.Count': 'count non-overlapping substrings',
    'strings.Repeat': 'repeat string N times',
    'strings.EqualFold': 'case-insensitive string comparison',
    'strings.Map': 'apply function to each rune',
    'strings.NewReader': 'create reader from string',
    'strings.NewReplacer': 'create multi-string replacer',
    # strconv
    'strconv.Atoi': 'parse string to int',
    'strconv.Itoa': 'format int to string',
    'strconv.ParseInt': 'parse string to int with base',
    'strconv.ParseFloat': 'parse string to float',
    'strconv.FormatInt': 'format int with base',
    'strconv.FormatFloat': 'format float to string',
    'strconv.ParseBool': 'parse string to bool',
    'strconv.FormatBool': 'format bool to string',
    'strconv.Quote': 'quote string with escapes',
    'strconv.Unquote': 'unquote string',
    # sync
    'sync.(*Mutex).Lock': 'acquire mutex lock',
    'sync.(*Mutex).Unlock': 'release mutex lock',
    'sync.(*RWMutex).RLock': 'acquire read lock',
    'sync.(*RWMutex).RUnlock': 'release read lock',
    'sync.(*WaitGroup).Add': 'add to waitgroup counter',
    'sync.(*WaitGroup).Done': 'decrement waitgroup counter',
    'sync.(*WaitGroup).Wait': 'wait for all goroutines',
    'sync.(*Once).Do': 'execute function exactly once',
    'sync.(*Map).Load': 'load value from concurrent map',
    'sync.(*Map).Store': 'store value in concurrent map',
    'sync.(*Map).Delete': 'delete from concurrent map',
    'sync.(*Map).Range': 'iterate concurrent map',
    'sync.(*Pool).Get': 'get object from pool',
    'sync.(*Pool).Put': 'return object to pool',
    'sync.(*Cond).Wait': 'wait for condition',
    'sync.(*Cond).Signal': 'wake one waiting goroutine',
    'sync.(*Cond).Broadcast': 'wake all waiting goroutines',
    # context
    'context.Background': 'return empty root context',
    'context.TODO': 'return placeholder context',
    'context.WithCancel': 'create cancellable context',
    'context.WithTimeout': 'create context with timeout',
    'context.WithDeadline': 'create context with deadline',
    'context.WithValue': 'create context with key-value pair',
    # encoding/json
    'encoding/json.Marshal': 'encode value to JSON bytes',
    'encoding/json.Unmarshal': 'decode JSON bytes to value',
    'encoding/json.NewEncoder': 'create JSON encoder for writer',
    'encoding/json.NewDecoder': 'create JSON decoder for reader',
    # errors
    'errors.New': 'create new error from string',
    'errors.Is': 'check if error matches target',
    'errors.As': 'find matching error in chain',
    'errors.Unwrap': 'unwrap error',
    'errors.Join': 'join multiple errors',
    # time
    'time.Now': 'get current time',
    'time.Sleep': 'sleep for duration',
    'time.After': 'channel that fires after duration',
    'time.Since': 'elapsed time since timestamp',
    'time.Until': 'duration until timestamp',
    'time.NewTicker': 'create periodic ticker',
    'time.NewTimer': 'create one-shot timer',
    'time.Parse': 'parse time string',
    'time.ParseDuration': 'parse duration string',
    # reflect
    'reflect.TypeOf': 'get reflect.Type of value',
    'reflect.ValueOf': 'get reflect.Value of value',
    'reflect.DeepEqual': 'recursive value comparison',
    # path/filepath
    'path/filepath.Join': 'join path elements',
    'path/filepath.Dir': 'get directory of path',
    'path/filepath.Base': 'get last element of path',
    'path/filepath.Ext': 'get file extension',
    'path/filepath.Abs': 'get absolute path',
    'path/filepath.Walk': 'walk directory tree',
    'path/filepath.WalkDir': 'walk directory tree (efficient)',
    'path/filepath.Glob': 'match file patterns',
    'path/filepath.Rel': 'get relative path',
    'path/filepath.Clean': 'clean path',
    # sort
    'sort.Slice': 'sort slice with less function',
    'sort.SliceStable': 'stable sort slice with less function',
    'sort.Ints': 'sort int slice',
    'sort.Strings': 'sort string slice',
    'sort.Float64s': 'sort float64 slice',
    'sort.Search': 'binary search in sorted data',
    'sort.Sort': 'sort with Sort interface',
    # bytes
    'bytes.Contains': 'check if bytes contains sub-bytes',
    'bytes.Equal': 'compare byte slices',
    'bytes.Split': 'split bytes by separator',
    'bytes.Join': 'join byte slices with separator',
    'bytes.TrimSpace': 'trim whitespace from bytes',
    'bytes.NewReader': 'create reader from byte slice',
    'bytes.NewBuffer': 'create buffer from byte slice',
    # regexp
    'regexp.MustCompile': 'compile regex pattern (panic on error)',
    'regexp.Compile': 'compile regex pattern',
    'regexp.MatchString': 'check if string matches pattern',
    'regexp.Match': 'check if bytes match pattern',
    # bufio
    'bufio.NewReader': 'create buffered reader',
    'bufio.NewWriter': 'create buffered writer',
    'bufio.NewScanner': 'create line scanner',
    # log
    'log.Fatal': 'print and exit',
    'log.Fatalf': 'formatted print and exit',
    'log.Println': 'print with timestamp',
    'log.Printf': 'formatted print with timestamp',
    'log.SetFlags': 'set log flags',
    'log.SetOutput': 'set log output writer',
    'log.SetPrefix': 'set log prefix',
    'log.New': 'create new logger',
    # math
    'math.Abs': 'absolute value',
    'math.Max': 'maximum of two floats',
    'math.Min': 'minimum of two floats',
    'math.Sqrt': 'square root',
    'math.Pow': 'power',
    'math.Floor': 'floor',
    'math.Ceil': 'ceiling',
    'math.Round': 'round to nearest integer',
    'math.Log': 'natural logarithm',
    'math.Log2': 'base-2 logarithm',
    'math.Sin': 'sine',
    'math.Cos': 'cosine',
    'math.Inf': 'positive infinity',
    'math.IsNaN': 'check if NaN',
    'math.IsInf': 'check if infinity',
    # crypto
    'crypto/sha256.Sum256': 'SHA-256 hash',
    'crypto/sha256.New': 'create SHA-256 hasher',
    'crypto/sha512.Sum512': 'SHA-512 hash',
    'crypto/md5.Sum': 'MD5 hash',
    'crypto/md5.New': 'create MD5 hasher',
    'crypto/rand.Read': 'read cryptographic random bytes',
    'crypto/tls.Dial': 'TLS dial connection',
    # archive
    'archive/zip.NewReader': 'create ZIP reader',
    'archive/zip.OpenReader': 'open ZIP file for reading',
    'archive/tar.NewReader': 'create TAR reader',
    # compress
    'compress/gzip.NewReader': 'create gzip decompressor',
    'compress/gzip.NewWriter': 'create gzip compressor',
    'compress/flate.NewReader': 'create DEFLATE decompressor',
    'compress/flate.NewWriter': 'create DEFLATE compressor',
    # testing
    'testing.(*T).Run': 'run subtest',
    'testing.(*T).Error': 'log error and continue',
    'testing.(*T).Fatal': 'log error and stop test',
    'testing.(*T).Skip': 'skip test',
    'testing.(*T).Helper': 'mark as test helper',
    'testing.(*T).Parallel': 'run test in parallel',
    'testing.(*B).Run': 'run sub-benchmark',
    'testing.(*B).ResetTimer': 'reset benchmark timer',
}


def extract_symbols_from_binary(binary_path: str) -> set:
    """Go binary'den GOPCLNTAB fonksiyon isimlerini cikar."""
    if not os.path.isfile(binary_path):
        print(f"  SKIP: {binary_path} not found")
        return set()

    try:
        result = subprocess.run(
            ['strings', binary_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"  ERROR: strings failed on {binary_path}")
            return set()
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT: strings on {binary_path}")
        return set()

    symbols = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or len(line) > 200:
            continue
        if GO_SYMBOL_RE.match(line):
            # Type metadata'yi atla
            if TYPE_META_RE.search(line):
                continue
            symbols.add(line)

    return symbols


def extract_all_go_symbols_from_binary(binary_path: str) -> set:
    """Daha genis Go sembol cikartma - vendor ve 3rd party dahil."""
    if not os.path.isfile(binary_path):
        print(f"  SKIP: {binary_path} not found")
        return set()

    try:
        result = subprocess.run(
            ['strings', binary_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return set()
    except subprocess.TimeoutExpired:
        return set()

    symbols = set()
    # Broader pattern: anything that looks like a Go function symbol
    broad_re = re.compile(
        r'^[a-z][a-z0-9_./]*\.[A-Z*(\[][A-Za-z0-9_.*()]*$'
        r'|^[a-z][a-z0-9_./]*\.\(\*[A-Z][A-Za-z0-9_]*\)\.[A-Z][A-Za-z0-9_]*$'
    )
    # Also catch vendor paths
    vendor_re = re.compile(
        r'^vendor/[a-z][a-z0-9_./-]*\.[A-Z*(\[][A-Za-z0-9_.*()]*$'
    )

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or len(line) > 250:
            continue
        if TYPE_META_RE.search(line):
            continue
        if broad_re.match(line) or vendor_re.match(line):
            symbols.add(line)

    return symbols


def classify_symbol(sym: str) -> tuple:
    """
    Sembolden (lib, category) cift dondur.
    Returns: (lib_name, category)
    """
    # Remove closure/anon suffixes for classification
    base = CLOSURE_SUFFIX_RE.sub('', sym)

    # Extract package path
    # e.g., "net/http.(*Server).ListenAndServe" -> "net/http"
    # e.g., "runtime.main" -> "runtime"
    # e.g., "github.com/spf13/cobra.(*Command).Execute" -> "github.com/spf13/cobra"
    dot_idx = _find_func_dot(base)
    if dot_idx < 0:
        return ('unknown', 'go_other')

    pkg_path = base[:dot_idx]

    # Strip vendor/ prefix for classification
    clean_pkg = pkg_path
    if clean_pkg.startswith('vendor/'):
        clean_pkg = clean_pkg[7:]

    # Check stdlib first
    if clean_pkg in CATEGORY_MAP:
        cat = CATEGORY_MAP[clean_pkg]
        lib = _pkg_to_lib(clean_pkg)
        return (lib, cat)

    # Check if it starts with a stdlib prefix
    parts = clean_pkg.split('/')
    for i in range(len(parts), 0, -1):
        prefix = '/'.join(parts[:i])
        if prefix in CATEGORY_MAP:
            cat = CATEGORY_MAP[prefix]
            lib = _pkg_to_lib(prefix)
            return (lib, cat)

    # Check 3rd party categories
    for prefix, cat in THIRD_PARTY_CATEGORIES.items():
        if clean_pkg.startswith(prefix):
            lib = _pkg_to_lib(clean_pkg)
            return (lib, cat)

    # Internal packages
    if 'internal/' in clean_pkg:
        return (_pkg_to_lib(clean_pkg), 'go_internal')

    # Fallback
    lib = _pkg_to_lib(clean_pkg)
    return (lib, 'go_other')


def _find_func_dot(sym: str) -> int:
    """
    Go sembol adindaki fonksiyon ayirici noktayi bul.
    'net/http.Get' -> 8 (net/http . Get)
    'github.com/pkg/errors.New' -> last meaningful dot
    """
    # Go'da paket yolu '/' icerir, fonksiyon adi '.' ile baslar
    # En son '/' sonrasindaki ilk '.' fonksiyon ayirici
    last_slash = sym.rfind('/')
    if last_slash >= 0:
        dot = sym.find('.', last_slash)
        return dot
    else:
        dot = sym.find('.')
        return dot


def _pkg_to_lib(pkg: str) -> str:
    """Paket yolundan kisa kutuphane adi cikart."""
    # github.com/spf13/cobra -> cobra
    # net/http -> net/http
    # golang.org/x/crypto/ssh -> x/crypto/ssh
    if pkg.startswith('github.com/'):
        parts = pkg.split('/')
        if len(parts) >= 3:
            return '/'.join(parts[2:])
    if pkg.startswith('golang.org/x/'):
        return pkg[len('golang.org/'):]
    if pkg.startswith('google.golang.org/'):
        return pkg[len('google.golang.org/'):]
    if pkg.startswith('go.uber.org/'):
        return pkg[len('go.uber.org/'):]
    if pkg.startswith('gopkg.in/'):
        return pkg[len('gopkg.in/'):]
    if pkg.startswith('cloud.google.com/'):
        return pkg[len('cloud.google.com/'):]
    return pkg


def get_purpose(sym: str) -> str:
    """Sembol icin purpose aciklama dondur."""
    # Direct lookup
    if sym in PURPOSE_DB:
        return PURPOSE_DB[sym]

    # Closure suffix strip and try again
    base = CLOSURE_SUFFIX_RE.sub('', sym)
    if base in PURPOSE_DB:
        return PURPOSE_DB[base] + ' (closure)'

    # Init function
    if INIT_RE.search(sym):
        return 'package initialization'

    # Closure
    if CLOSURE_SUFFIX_RE.search(sym):
        return 'anonymous function / closure'

    # Method patterns
    if '.(*' in sym:
        # Extract method name
        m = re.search(r'\)\.(\w+)$', sym)
        if m:
            method = m.group(1)
            method_purposes = {
                'String': 'string representation',
                'Error': 'error message',
                'Close': 'close/cleanup resource',
                'Read': 'read data',
                'Write': 'write data',
                'Reset': 'reset state',
                'Len': 'return length',
                'Less': 'comparison for sorting',
                'Swap': 'swap elements',
                'Init': 'initialize',
                'Start': 'start operation',
                'Stop': 'stop operation',
                'Serve': 'serve requests',
                'Handle': 'handle request',
                'Do': 'execute operation',
                'Run': 'run operation',
                'Flush': 'flush buffered data',
                'Marshal': 'serialize to bytes',
                'Unmarshal': 'deserialize from bytes',
                'Encode': 'encode data',
                'Decode': 'decode data',
                'Lock': 'acquire lock',
                'Unlock': 'release lock',
                'Get': 'get value',
                'Set': 'set value',
                'Add': 'add item',
                'Delete': 'delete item',
                'Remove': 'remove item',
                'Scan': 'scan/parse input',
                'Next': 'advance to next item',
                'Seek': 'seek to position',
                'Dial': 'establish connection',
                'Accept': 'accept connection',
                'Listen': 'listen for connections',
                'Connect': 'connect to server',
                'Send': 'send data',
                'Recv': 'receive data',
                'Open': 'open resource',
                'Create': 'create resource',
            }
            if method in method_purposes:
                return method_purposes[method]

    return ''


def generate_go_stdlib_comprehensive() -> dict:
    """
    Go standard library fonksiyonlarinin kapsamli listesi.
    Go kurulu olmadigi icin sabit bilgi + binary cikartma ile.
    """
    # Well-known Go stdlib functions that should be in any Go binary
    stdlib_funcs = {}

    # runtime package (her Go binary'de var)
    runtime_funcs = [
        'runtime.main', 'runtime.goexit', 'runtime.goexit0', 'runtime.goexit1',
        'runtime.gopanic', 'runtime.gorecover', 'runtime.newobject',
        'runtime.newproc', 'runtime.newproc1', 'runtime.makeslice',
        'runtime.makechan', 'runtime.makemap', 'runtime.makemap_small',
        'runtime.mapassign', 'runtime.mapassign_fast64',
        'runtime.mapassign_faststr', 'runtime.mapaccess1',
        'runtime.mapaccess1_fast64', 'runtime.mapaccess1_faststr',
        'runtime.mapaccess2', 'runtime.mapaccess2_fast64',
        'runtime.mapaccess2_faststr', 'runtime.mapdelete',
        'runtime.mapdelete_fast64', 'runtime.mapdelete_faststr',
        'runtime.growslice', 'runtime.memmove', 'runtime.memclrNoHeapPointers',
        'runtime.memclrHasPointers', 'runtime.gcStart', 'runtime.gcDrain',
        'runtime.gcBgMarkWorker', 'runtime.gcMarkDone', 'runtime.gcSweep',
        'runtime.mallocgc', 'runtime.convT', 'runtime.convT64',
        'runtime.convTstring', 'runtime.convTslice',
        'runtime.assertI2I', 'runtime.assertI2I2', 'runtime.assertE2I',
        'runtime.assertE2I2', 'runtime.chanrecv', 'runtime.chanrecv1',
        'runtime.chanrecv2', 'runtime.chansend', 'runtime.chansend1',
        'runtime.closechan', 'runtime.selectgo', 'runtime.selectnbrecv',
        'runtime.selectnbsend', 'runtime.deferreturn', 'runtime.deferproc',
        'runtime.deferprocStack', 'runtime.systemstack',
        'runtime.mcall', 'runtime.schedule', 'runtime.findrunnable',
        'runtime.execute', 'runtime.gopark', 'runtime.goready',
        'runtime.lock', 'runtime.lock2', 'runtime.unlock', 'runtime.unlock2',
        'runtime.throw', 'runtime.fatalpanic',
        'runtime.printstring', 'runtime.printint', 'runtime.printnl',
        'runtime.printhex', 'runtime.printlock', 'runtime.printunlock',
        'runtime.Caller', 'runtime.Callers', 'runtime.Stack',
        'runtime.GC', 'runtime.GOMAXPROCS', 'runtime.NumGoroutine',
        'runtime.Gosched', 'runtime.SetFinalizer', 'runtime.KeepAlive',
        'runtime.ReadMemStats', 'runtime.LockOSThread',
        'runtime.UnlockOSThread', 'runtime.NumCPU',
        'runtime.GOROOT', 'runtime.Version', 'runtime.Goexit',
        'runtime.BlockProfile', 'runtime.CPUProfile',
        'runtime.GoroutineProfile', 'runtime.MemProfile',
        'runtime.MutexProfile', 'runtime.ThreadCreateProfile',
        'runtime.SetBlockProfileRate', 'runtime.SetCPUProfileRate',
        'runtime.SetMutexProfileFraction',
        'runtime.mstart', 'runtime.mstart0', 'runtime.mstart1',
        'runtime.mexit', 'runtime.sysmon',
        'runtime.notesleep', 'runtime.notewakeup', 'runtime.noteclear',
        'runtime.procresize', 'runtime.acquirep', 'runtime.releasep',
        'runtime.stopm', 'runtime.startm', 'runtime.handoffp',
        'runtime.wakep', 'runtime.injectglist',
        'runtime.casgstatus', 'runtime.casGToWaiting',
        'runtime.typedmemmove', 'runtime.typedslicecopy',
        'runtime.stringtoslicebyte', 'runtime.slicebytetostring',
        'runtime.slicerunetostring', 'runtime.stringtoslicerune',
        'runtime.intstring', 'runtime.concatstrings',
        'runtime.rawstring', 'runtime.rawstringtmp',
        'runtime.cmpstring', 'runtime.eqstring',
        'runtime.ifaceHash', 'runtime.efaceHash',
        'runtime.memhash', 'runtime.strhash', 'runtime.nilinterhash',
        'runtime.panicIndex', 'runtime.panicSliceB',
        'runtime.panicSliceAlen', 'runtime.panicSliceAcap',
        'runtime.panicSlice3B', 'runtime.panicSlice3Alen',
        'runtime.panicSlice3Acap', 'runtime.panicSlice3C',
        'runtime.goPanicIndex', 'runtime.goPanicSliceB',
        'runtime.sigpanic', 'runtime.sigtramp',
        'runtime.aeshash', 'runtime.aeshashbody',
    ]

    for func in runtime_funcs:
        purpose = get_purpose(func)
        stdlib_funcs[func] = {
            'lib': 'runtime',
            'purpose': purpose,
            'category': 'go_runtime'
        }

    return stdlib_funcs


def main():
    print("=" * 60)
    print("Go Expanded Signature Generator for Karadul")
    print("=" * 60)

    # 1. Load existing signatures for dedup
    existing_keys = set()
    if EXISTING_FILE.exists():
        with open(EXISTING_FILE, 'r') as f:
            existing = json.load(f)
        existing_keys = set(existing.keys())
        print(f"\nExisting signatures: {len(existing_keys)}")
    else:
        print("\nNo existing go_stdlib_signatures.json found")

    # 2. Extract from Go binaries
    all_symbols = set()
    binary_sources = {}  # symbol -> source binary

    for binary_path, name in GO_BINARIES:
        print(f"\n--- Extracting from {name} ({binary_path}) ---")
        syms = extract_all_go_symbols_from_binary(binary_path)
        print(f"  Found {len(syms)} Go symbols")
        for s in syms:
            if s not in all_symbols:
                binary_sources[s] = name
            all_symbols.add(s)

    print(f"\nTotal unique symbols from binaries: {len(all_symbols)}")

    # 3. Add comprehensive stdlib list
    stdlib_manual = generate_go_stdlib_comprehensive()
    for sym in stdlib_manual:
        all_symbols.add(sym)
    print(f"Added {len(stdlib_manual)} manual stdlib entries")

    # 4. Dedup with existing
    new_symbols = all_symbols - existing_keys
    print(f"New symbols (not in existing DB): {len(new_symbols)}")

    # 5. Build signature entries
    signatures = {}
    category_counts = defaultdict(int)
    source_counts = defaultdict(int)

    for sym in sorted(new_symbols):
        lib, category = classify_symbol(sym)
        purpose = get_purpose(sym)
        source = binary_sources.get(sym, 'manual')

        signatures[sym] = {
            'lib': lib,
            'purpose': purpose,
            'category': category
        }
        category_counts[category] += 1
        source_counts[source] += 1

    # 6. Print stats
    print(f"\n{'=' * 60}")
    print(f"RESULTS")
    print(f"{'=' * 60}")
    print(f"Total new signatures: {len(signatures)}")
    print(f"\nBy category:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1])[:25]:
        print(f"  {cat}: {count}")
    print(f"\nBy source:")
    for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"  {src}: {count}")

    # 7. Write output
    output = {
        'meta': {
            'generator': 'karadul-sig-gen-go',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'total_signatures': len(signatures),
            'sources': dict(source_counts),
            'category_distribution': dict(category_counts),
            'dedup_against': str(EXISTING_FILE),
            'existing_count': len(existing_keys),
        },
        'signatures': signatures,
    }

    os.makedirs(SIGS_DIR, exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nWritten to: {OUTPUT_FILE}")
    print(f"File size: {os.path.getsize(OUTPUT_FILE) / 1024:.1f} KB")
    print(f"\nCombined coverage: {len(existing_keys) + len(signatures)} total Go signatures")


if __name__ == '__main__':
    main()
