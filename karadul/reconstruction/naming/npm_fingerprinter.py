"""NPM paket fingerprinting -- modul icerigindeki string'lere bakarak bilinen paketleri tespit eder.

30+ npm paketinin imza string'lerini icerir. Her modulu tarar,
en cok eslesen paketi bulur, confidence score hesaplar.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .result import NamingResult, _sanitize_filename

logger = logging.getLogger(__name__)


# Her paketin tanimlayici string'leri ve hedef kategorisi
KNOWN_SIGNATURES: dict[str, dict] = {
    # --- highlight.js ---
    "highlight.js": {
        "strings": [
            "registerLanguage",
            "hljs",
            "highlightBlock",
            "highlightAuto",
            "listLanguages",
            "getLanguage",
            "C_LINE_COMMENT_MODE",
            "C_BLOCK_COMMENT_MODE",
            "SHEBANG",
            "BACKSLASH_ESCAPE",
        ],
        "category": "vendor/highlight-js",
        "min_match": 3,
    },
    # --- RxJS ---
    "rxjs": {
        "strings": [
            "Observable",
            "Subscriber",
            "switchMap",
            "mergeMap",
            "Subject",
            "BehaviorSubject",
            "ReplaySubject",
            "pipe(",
            "subscribe(",
            "Subscription",
            "concatMap",
            "debounceTime",
            "distinctUntilChanged",
            "takeUntil",
        ],
        "category": "vendor/rxjs",
        "min_match": 3,
    },
    # --- AWS SDK v3 ---
    "@aws-sdk": {
        "strings": [
            "@aws-sdk/",
            "@smithy/",
            "BedrockRuntime",
            "us-east-1",
            "us-west-2",
            "AwsCredentialIdentity",
            "SdkError",
            "ServiceException",
            "S3Client",
            "DynamoDBClient",
            "EndpointV2",
            "smithy",
        ],
        "category": "vendor/aws-sdk",
        "min_match": 2,
    },
    # --- Sentry ---
    "@sentry/node": {
        "strings": [
            "@sentry/",
            "Sentry",
            "captureException",
            "captureMessage",
            "dsn",
            "beforeSend",
            "addBreadcrumb",
            "configureScope",
            "withScope",
            "startTransaction",
        ],
        "category": "vendor/sentry",
        "min_match": 2,
    },
    # --- node-forge ---
    "node-forge": {
        "strings": [
            "ByteStringBuffer",
            "forge.",
            "pkcs",
            "ASN1",
            "pki.rsa",
            "md.sha256",
            "cipher.createCipher",
            "util.encode64",
            "pem",
        ],
        "category": "vendor/node-forge",
        "min_match": 2,
    },
    # --- React ---
    "react": {
        "strings": [
            "React.createElement",
            "reconcilerVersion",
            "ReactCurrentDispatcher",
            "ReactCurrentOwner",
            "jsx(",
            "jsxs(",
            "REACT_ELEMENT_TYPE",
            "useState",
            "useEffect",
            "useCallback",
            "useMemo",
            "useRef",
            "useContext",
        ],
        "category": "vendor/react",
        "min_match": 3,
    },
    # --- Ink (React terminal UI) ---
    "ink": {
        "strings": [
            "Ink",
            "useInput",
            "measureElement",
            "useApp",
            "useStdin",
            "useStdout",
            "useFocus",
            "Static",
        ],
        "category": "vendor/ink",
        "min_match": 2,
    },
    # --- gRPC ---
    "@grpc/grpc-js": {
        "strings": [
            "@grpc/grpc-js",
            "grpc.",
            "ServerCredentials",
            "ChannelCredentials",
            "createInsecure",
            "ServiceError",
            "Metadata",
            "StatusCode",
            "CallCredentials",
            "createSsl",
        ],
        "category": "vendor/grpc",
        "min_match": 2,
    },
    # --- OpenTelemetry ---
    "opentelemetry": {
        "strings": [
            "TracerProvider",
            "SpanKind",
            "opentelemetry",
            "trace.getTracer",
            "context.active",
            "SpanStatusCode",
            "DiagLogLevel",
            "MeterProvider",
            "ProxyTracer",
        ],
        "category": "vendor/opentelemetry",
        "min_match": 2,
    },
    # --- ws (WebSocket) ---
    "ws": {
        "strings": [
            "WebSocket",
            "CONNECTING",
            "CLOSING",
            "CLOSED",
            "WebSocketServer",
            "handleUpgrade",
            "sec-websocket",
            "permessage-deflate",
        ],
        "category": "vendor/ws",
        "min_match": 3,
    },
    # --- Commander ---
    "commander": {
        "strings": [
            ".command(",
            ".description(",
            ".option(",
            ".action(",
            "Commander",
            ".parse(",
            "createCommand",
            ".requiredOption(",
        ],
        "category": "vendor/commander",
        "min_match": 3,
    },
    # --- Zod ---
    "zod": {
        "strings": [
            "z.string()",
            "z.object()",
            "z.array()",
            "ZodError",
            "ZodSchema",
            "z.number()",
            "z.boolean()",
            "z.enum(",
            "z.union(",
            "z.optional(",
            "ZodType",
            ".safeParse(",
        ],
        "category": "vendor/zod",
        "min_match": 2,
    },
    # --- mime-db ---
    "mime-db": {
        "strings": [
            "application/1d-interleaved",
            'source: "iana"',
            "source: \"iana\"",
            "application/json",
            "application/xml",
            "application/octet-stream",
            "text/html",
            "compressible",
        ],
        "category": "vendor/mime-db",
        "min_match": 3,
    },
    # --- mime-types ---
    "mime-types": {
        "strings": [
            "mime.lookup",
            "mime.extension",
            "charset",
            "contentType",
            "application/octet-stream",
        ],
        "category": "vendor/mime-types",
        "min_match": 2,
    },
    # --- semver ---
    "semver": {
        "strings": [
            "semver",
            "SemVer",
            "satisfies",
            "coerce",
            "SEMVER_SPEC_VERSION",
            "major",
            "minor",
            "patch",
            "prerelease",
            "compareBuild",
        ],
        "category": "vendor/semver",
        "min_match": 3,
    },
    # --- uuid ---
    "uuid": {
        "strings": [
            "uuid",
            "v4(",
            "v1(",
            "uuidv4",
            "rng()",
            "xxxxxxxx-xxxx",
            "crypto.randomUUID",
        ],
        "category": "vendor/uuid",
        "min_match": 2,
    },
    # --- debug ---
    "debug": {
        "strings": [
            "debug(",
            "createDebug",
            "debug.enable",
            "debug.disable",
            "DEBUG=",
            "coerce",
            "selectColor",
        ],
        "category": "vendor/debug",
        "min_match": 3,
    },
    # --- chalk ---
    "chalk": {
        "strings": [
            "chalk.",
            "ansi256",
            "ansi16",
            "bgRed",
            "bgGreen",
            "bgBlue",
            "FORCE_COLOR",
            "chalkStderr",
        ],
        "category": "vendor/chalk",
        "min_match": 3,
    },
    # --- strip-ansi ---
    "strip-ansi": {
        "strings": [
            "stripAnsi",
            "ansiRegex",
            "\\u001B",
            "\\x1B[",
        ],
        "category": "vendor/strip-ansi",
        "min_match": 2,
    },
    # --- yargs / yargs-parser ---
    "yargs": {
        "strings": [
            "yargs",
            ".demandCommand",
            ".epilogue",
            ".showHelp",
            ".wrap(",
            "nargs",
            "yargs-parser",
            ".positional(",
            "showHelpOnFail",
        ],
        "category": "vendor/yargs",
        "min_match": 3,
    },
    # --- pino (logger) ---
    "pino": {
        "strings": [
            "pino",
            "child(",
            "level:",
            "bindings",
            "serializers",
            "destination",
            "transport",
            "multistream",
        ],
        "category": "vendor/pino",
        "min_match": 3,
    },
    # --- undici (HTTP client) ---
    "undici": {
        "strings": [
            "undici",
            "Dispatcher",
            "fetch(",
            "FormData",
            "RetryAgent",
            "ProxyAgent",
            "MockPool",
            "MockClient",
            "interceptors",
        ],
        "category": "vendor/undici",
        "min_match": 3,
    },
    # --- google-auth-library ---
    "google-auth-library": {
        "strings": [
            "GoogleAuth",
            "JWT(",
            "OAuth2Client",
            "google.auth",
            "getAccessToken",
            "refreshToken",
            "googleapis.com",
            "service_account",
        ],
        "category": "vendor/google-auth",
        "min_match": 2,
    },
    # --- jsonwebtoken / jose ---
    "jsonwebtoken": {
        "strings": [
            "jwt.sign",
            "jwt.verify",
            "jwt.decode",
            "JsonWebTokenError",
            "TokenExpiredError",
            "NotBeforeError",
            "jws.",
            "JWK",
            "JWS",
            "JWE",
        ],
        "category": "vendor/jwt",
        "min_match": 2,
    },
    # --- protobuf (protobufjs) ---
    "protobufjs": {
        "strings": [
            "protobuf",
            "Root",
            "MapField",
            "OneOf",
            "FieldType",
            "google.protobuf",
            ".encode(",
            ".decode(",
            "Writer",
            "Reader",
        ],
        "category": "vendor/protobuf",
        "min_match": 3,
    },
    # --- yaml (js-yaml) ---
    "js-yaml": {
        "strings": [
            "yaml.load",
            "yaml.dump",
            "yaml.safeLoad",
            "safeDump",
            "YAML",
            "Schema",
            "DEFAULT_SCHEMA",
            "FAILSAFE_SCHEMA",
        ],
        "category": "vendor/yaml",
        "min_match": 2,
    },
    # --- dotenv ---
    "dotenv": {
        "strings": [
            "dotenv",
            ".env",
            "config()",
            "DOTENV_KEY",
            "parsed",
            "process.env",
        ],
        "category": "vendor/dotenv",
        "min_match": 3,
    },
    # --- glob / minimatch ---
    "glob": {
        "strings": [
            "glob(",
            "Glob",
            "minimatch",
            "Minimatch",
            "GLOBSTAR",
            "braceExpand",
            "makeRe",
        ],
        "category": "vendor/glob",
        "min_match": 2,
    },
    # --- cross-spawn ---
    "cross-spawn": {
        "strings": [
            "cross-spawn",
            "resolveCommand",
            "shebang",
            "PATHEXT",
            "spawn(",
            "spawnSync(",
        ],
        "category": "vendor/cross-spawn",
        "min_match": 3,
    },
    # --- fsevents / chokidar ---
    "chokidar": {
        "strings": [
            "chokidar",
            "FSWatcher",
            "watch(",
            "awaitWriteFinish",
            "ignoreInitial",
            "persistent",
            "fsevents",
        ],
        "category": "vendor/chokidar",
        "min_match": 3,
    },
    # --- tree-sitter ---
    "tree-sitter": {
        "strings": [
            "tree-sitter",
            "Parser",
            "Language",
            "SyntaxNode",
            "Tree",
            "edit(",
            "walk(",
        ],
        "category": "vendor/tree-sitter",
        "min_match": 3,
    },
    # --- diff ---
    "diff": {
        "strings": [
            "structuredPatch",
            "createPatch",
            "diffLines",
            "diffWords",
            "diffChars",
            "applyPatch",
            "parsePatch",
        ],
        "category": "vendor/diff",
        "min_match": 2,
    },
    # --- inquirer / prompts ---
    "inquirer": {
        "strings": [
            "inquirer",
            "prompt(",
            "Separator",
            "input:",
            "confirm:",
            "list:",
            "checkbox:",
            "rawlist:",
        ],
        "category": "vendor/inquirer",
        "min_match": 3,
    },
    # --- marked (Markdown renderer) ---
    "marked": {
        "strings": [
            "marked(",
            "marked.parse",
            "Lexer",
            "Tokenizer",
            "Renderer",
            "walkTokens",
            "heading",
            "paragraph",
            "blockquote",
        ],
        "category": "vendor/marked",
        "min_match": 3,
    },
    # --- @anthropic-ai/sdk ---
    "@anthropic-ai/sdk": {
        "strings": [
            "Anthropic",
            "anthropic",
            "api.anthropic.com",
            "claude-",
            "x-api-key",
            "messages.create",
            "content_block",
        ],
        "category": "vendor/anthropic-sdk",
        "min_match": 2,
    },
}


_IDENT_CHAR = re.compile(r"[A-Za-z0-9_$]")
_IDENT_BOUNDARY_BEFORE = r"(?<![A-Za-z0-9_$])"
_IDENT_BOUNDARY_AFTER = r"(?![A-Za-z0-9_$])"
# smart-webpack-unpack.mjs her modülün başına ` * Module: <paket içindeki kimlik>`
# satırı yazar. Webpack 5 adlı kimlikleri / esbuild __commonJS anahtarları
# paketleyicinin kaydettiği kaynak yolunu taşır (ör. ./node_modules/chalk/...).
_MODULE_HEADER_RE = re.compile(r"^\s*\*\s*Module:\s*(.+?)\s*$", re.MULTILINE)
_HEADER_SCAN_CHARS = 2000


def _token_pattern(token: str) -> re.Pattern[str]:
    """İmza dizgisini belirteç sınırıyla ara (BICIM-11).

    Dizginin başı/sonu tanımlayıcı karakteriyse o yana tanımlayıcı sınırı
    eklenir: ``pkcs`` artık ``pkcs8`` içinde, ``pem`` ``pemFile`` içinde,
    ``fetch(`` ``refetch(`` içinde eşleşmez. Harf duyarlı.
    """
    pre = _IDENT_BOUNDARY_BEFORE if _IDENT_CHAR.match(token[0]) else ""
    post = _IDENT_BOUNDARY_AFTER if _IDENT_CHAR.match(token[-1]) else ""
    return re.compile(pre + re.escape(token) + post)


def _bundle_path_attributes(content: str, module_id: str, pkg_name: str) -> str | None:
    """Paketin kendisi modülü ``node_modules/<paket>/`` yoluna bağlıyor mu?

    Kanıt kaynağı: modül dosyasının başlığındaki ``Module:`` kimliği (paketleyicinin
    yazdığı kaynak yolu) ya da çağıranın verdiği ham modül kimliği. Döner:
    eşleşen yol ya da None.
    """
    needle = f"node_modules/{pkg_name}/"
    head = content[:_HEADER_SCAN_CHARS]
    candidates = [m.group(1) for m in _MODULE_HEADER_RE.finditer(head)]
    candidates.append(module_id)
    for cand in candidates:
        if needle in cand.replace("\\", "/"):
            return cand
    return None


class NpmFingerprinter:
    """Her modulu bilinen npm paketleriyle eslestirir.

    Calisma mantigi:
    1. Modul dosyasini oku
    2. KNOWN_SIGNATURES sozlugundeki her paketin imza dizgilerini BELİRTEÇ
       sınırıyla ara (eskiden düz alt dizgi: ``pkcs8`` içinde ``pkcs``)
    3. En cok eslesen paketi sec (min_match esigi)
    4. "Vendor" hükmü (``vendor/<paket>`` kategorisi) yalnız GÜÇLÜ kanıtla:
       paketin kendisi modülü ``node_modules/<paket>/`` yoluna bağlıyorsa
       (modül başlığındaki ``Module:`` kimliği). Depoda yayımlanmış paketlerin
       içerik karması (hash) veritabanı yok; içerik eşitliği doğrulanamıyor.
    5. Yalnız dizgi benzerliği olan modül "vendor" SAYILMAZ (BICIM-11: zararlı
       bir modül birkaç tuzak dizgiyle ``vendor/`` altına gönderilip analistin
       önünden çekilebiliyordu). Bu benzerlik ``hints`` olarak saklanır; modül
       yapısal katmana (Layer 2) kalır.
    """

    def __init__(self, signatures: dict[str, dict] | None = None) -> None:
        self.signatures = signatures or KNOWN_SIGNATURES
        self._patterns: dict[str, list[tuple[str, re.Pattern[str]]]] = {
            pkg: [(s, _token_pattern(s)) for s in sig["strings"] if s]
            for pkg, sig in self.signatures.items()
        }
        # Son fingerprint_all koşusunun yalnız-dizgi benzerlikleri:
        # {module_id: {"package", "matched", "total", "matched_strings", "evidence"}}
        self.hints: dict[str, dict] = {}

    def fingerprint_all(self, modules_dir: Path) -> list[NamingResult]:
        """Tum modulleri tara; yalnız güçlü kanıtlı (vendor) eşleşmeleri döndür.

        Yalnız dizgi benzerliği olanlar ``self.hints``'e yazılır.
        """
        results: list[NamingResult] = []
        self.hints = {}
        js_files = sorted(modules_dir.glob("*.js"))
        total = len(js_files)

        logger.info("NpmFingerprinter: %d modul taranacak", total)

        for idx, js_file in enumerate(js_files):
            module_id = js_file.stem
            try:
                content = js_file.read_text(errors="replace")
            except Exception as exc:
                logger.warning("Dosya okunamadi: %s (%s)", js_file, exc)
                continue

            result = self._match_module(content, module_id)
            if result is not None:
                results.append(result)
            else:
                hint = self.similarity_hint(content, module_id)
                if hint is not None:
                    self.hints[module_id] = hint

            if (idx + 1) % 500 == 0:
                logger.info(
                    "NpmFingerprinter: %d/%d taranadi, %d eslesme",
                    idx + 1, total, len(results),
                )

        logger.info(
            "NpmFingerprinter tamamlandi: %d/%d modul vendor (güçlü kanıt), "
            "%d modülde yalnız dizgi benzerliği (vendor sayılmadı)",
            len(results), total, len(self.hints),
        )
        return results

    def _best_string_match(self, content: str) -> tuple[str, dict, list[str]] | None:
        """Belirteç sınırıyla en çok eşleşen paket (min_match eşiği dahil)."""
        best: tuple[str, dict, list[str]] | None = None
        best_score = 0.0
        for pkg_name, sig in self.signatures.items():
            min_match = sig.get("min_match", 2)
            hits = [s for s, pat in self._patterns[pkg_name] if pat.search(content)]
            if len(hits) < min_match:
                continue
            score = len(hits) / len(sig["strings"])
            if score > best_score:
                best_score = score
                best = (pkg_name, sig, hits)
        return best

    def similarity_hint(self, content: str, module_id: str) -> dict | None:
        """Yalnız dizgi benzerliği (vendor hükmü değil); yoksa None."""
        best = self._best_string_match(content)
        if best is None:
            return None
        pkg_name, sig, hits = best
        return {
            "package": pkg_name,
            "matched": len(hits),
            "total": len(sig["strings"]),
            "matched_strings": hits,
            "evidence": "yalnız dizgi benzerliği; paket yolu yok, içerik doğrulanmadı",
        }

    def _match_module(self, content: str, module_id: str) -> NamingResult | None:
        """Tek modülü pakete bağla: dizgi eşleşmesi + paket yolu kanıtı ŞART."""
        best = self._best_string_match(content)
        if best is None:
            return None
        pkg_name, sig, hits = best
        path = _bundle_path_attributes(content, module_id, pkg_name)
        if path is None:
            return None

        score = len(hits) / len(sig["strings"])
        # Confidence: eslesme orani, kucuk bir boost ile (max 1.0)
        confidence = min(score * 1.2, 1.0)

        # Dosya adi: paket adinin kebab-case hali
        new_filename = _sanitize_filename(pkg_name)

        return NamingResult(
            module_id=module_id,
            original_file=f"{module_id}.js",
            new_filename=new_filename,
            category=sig["category"],
            description=(
                f"Vendored {pkg_name} package (bundle path {path}; "
                f"{len(hits)}/{len(sig['strings'])} signature tokens; "
                "content not hash-verified)"
            ),
            confidence=round(confidence, 3),
            source="npm_fingerprint",
            npm_package=pkg_name,
        )
