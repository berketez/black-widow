#!/usr/bin/env node
/**
 * context-analyzer.mjs -- NSA-Grade Context-Aware Variable Analysis
 *
 * Black Widow v1.0 -- Karadul
 *
 * SCOPE-AWARE VERSION (noScope FIX):
 *   Duplicate declaration sorunu pre-process ile cozuldu.
 *   Babel scope API tam calisiyor: her degisken kendi scope'unda analiz ediliyor.
 *
 * 3 katmanli baglam analizi:
 *   Katman 1: Kullanim Baglami (Usage Context)
 *     - Nerede tanimlanmis, kac kez kullanilmis
 *     - Hangi fonksiyonlara arguman olarak gecilmis
 *     - Hangi property'lerine erisilmis
 *     - Hangi operatorlerle kullanilmis
 *
 *   Katman 2: Veri Akisi Grafigi (Data Flow)
 *     - Atama zincirini 3 seviye geriye takip et
 *     - a = require('fs') -> a = fileSystem
 *     - b = a.readFileSync(c) -> b = fileContent, c = filePath
 *
 *   Katman 3: Akilli Isimlendirme
 *     - 615+ kural ile isim uret
 *     - Confidence scoring
 *     - Cakisma kontrolu
 *     - SCOPE-AWARE: ayni isim farkli scope'larda farkli isim alabilir
 *
 * Kullanim:
 *   node --max-old-space-size=8192 context-analyzer.mjs <input.js> <output.json>
 *
 * Cikti: JSON { variables: {...}, stats: {...} }
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";

const traverse = _traverse.default || _traverse;

// ---------- CLI ----------
const args = process.argv.slice(2);
if (args.length < 2) {
  process.stdout.write(
    JSON.stringify({
      success: false,
      errors: [
        "Kullanim: node --max-old-space-size=8192 context-analyzer.mjs <input.js> <output.json>",
      ],
    }) + "\n"
  );
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputPath = resolve(args[1]);

// ---------- Kaynak oku ----------
let source;
try {
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  process.stdout.write(
    JSON.stringify({
      success: false,
      errors: [`Dosya okunamadi: ${err.message}`],
    }) + "\n"
  );
  process.exit(1);
}

// =====================================================================
// KURAL KATEGORILERi (A-G) -- 615+ kural
// =====================================================================

// A. require/import kaynaagindan
const REQUIRE_NAMES = {
  // Node.js built-in
  fs: "fileSystem",
  path: "pathUtils",
  http: "httpModule",
  https: "httpsModule",
  crypto: "cryptoModule",
  child_process: "childProcess",
  os: "operatingSystem",
  url: "urlModule",
  stream: "streamModule",
  events: "eventEmitter",
  util: "utilModule",
  net: "netModule",
  tls: "tlsModule",
  dns: "dnsModule",
  zlib: "zlibModule",
  readline: "readlineModule",
  buffer: "bufferModule",
  querystring: "queryStringModule",
  assert: "assertModule",
  vm: "vmModule",
  worker_threads: "workerThreads",
  perf_hooks: "perfHooks",
  cluster: "clusterModule",
  dgram: "dgramModule",
  punycode: "punycodeModule",
  v8: "v8Module",
  constants: "nodeConstants",
  module: "moduleSystem",
  string_decoder: "stringDecoder",
  timers: "timersModule",
  process: "processModule",
  async_hooks: "asyncHooks",
  diagnostics_channel: "diagnosticsChannel",
  inspector: "inspectorModule",
  trace_events: "traceEvents",
  wasi: "wasiModule",
  domain: "domainModule",
  repl: "replModule",
  // Node.js prefixed
  "node:fs": "fileSystem",
  "node:path": "pathUtils",
  "node:http": "httpModule",
  "node:https": "httpsModule",
  "node:crypto": "cryptoModule",
  "node:child_process": "childProcess",
  "node:os": "operatingSystem",
  "node:url": "urlModule",
  "node:stream": "streamModule",
  "node:events": "eventEmitter",
  "node:util": "utilModule",
  "node:net": "netModule",
  "node:tls": "tlsModule",
  "node:dns": "dnsModule",
  "node:zlib": "zlibModule",
  "node:readline": "readlineModule",
  "node:buffer": "bufferModule",
  "node:querystring": "queryStringModule",
  "node:assert": "assertModule",
  "node:vm": "vmModule",
  "node:worker_threads": "workerThreads",
  "node:perf_hooks": "perfHooks",
  "node:cluster": "clusterModule",
  "node:dgram": "dgramModule",
  "node:process": "processModule",
  "node:async_hooks": "asyncHooks",
  "node:diagnostics_channel": "diagnosticsChannel",
  "node:inspector": "inspectorModule",
  "node:timers": "timersModule",
  "fs/promises": "fsPromises",
  "node:fs/promises": "fsPromises",
  "stream/promises": "streamPromises",
  "timers/promises": "timersPromises",
  // NPM paketleri
  express: "expressApp",
  react: "React",
  "react-dom": "ReactDOM",
  "react-dom/client": "ReactDOMClient",
  "react-dom/server": "ReactDOMServer",
  chalk: "chalk",
  commander: "commander",
  axios: "axiosClient",
  lodash: "lodash",
  underscore: "underscore",
  moment: "moment",
  dayjs: "dayjs",
  joi: "joiValidator",
  zod: "zodSchema",
  yup: "yupSchema",
  winston: "logger",
  pino: "pinoLogger",
  bunyan: "bunyanLogger",
  dotenv: "dotenvConfig",
  cors: "corsMiddleware",
  helmet: "helmetSecurity",
  morgan: "morganLogger",
  compression: "compressionMiddleware",
  "body-parser": "bodyParser",
  "cookie-parser": "cookieParser",
  multer: "multerUpload",
  passport: "passportAuth",
  "passport-local": "localStrategy",
  "passport-jwt": "jwtStrategy",
  jsonwebtoken: "jwt",
  bcrypt: "bcryptHash",
  bcryptjs: "bcryptHash",
  mongoose: "mongooseDb",
  sequelize: "sequelizeOrm",
  knex: "knexBuilder",
  typeorm: "typeorm",
  prisma: "prismaClient",
  "@prisma/client": "prismaClient",
  pg: "postgresClient",
  mysql: "mysqlClient",
  mysql2: "mysql2Client",
  redis: "redisClient",
  ioredis: "ioredisClient",
  mongodb: "mongoClient",
  "socket.io": "socketIO",
  "socket.io-client": "socketIOClient",
  ws: "webSocketModule",
  uuid: "uuidGenerator",
  nanoid: "nanoidGenerator",
  sharp: "sharpImage",
  jimp: "jimpImage",
  nodemailer: "nodeMailer",
  "node-fetch": "nodeFetch",
  "node-cron": "nodeCron",
  cron: "cronScheduler",
  bull: "bullQueue",
  bullmq: "bullMQ",
  amqplib: "amqpConnection",
  ejs: "ejsEngine",
  pug: "pugEngine",
  handlebars: "handlebarsEngine",
  nunjucks: "nunjucksEngine",
  glob: "globMatcher",
  minimatch: "minimatch",
  semver: "semver",
  debug: "debugLogger",
  yargs: "yargsParser",
  minimist: "minimistParser",
  inquirer: "inquirerPrompt",
  ora: "oraSpinner",
  "cli-table": "cliTable",
  cheerio: "cheerioParser",
  puppeteer: "puppeteerBrowser",
  playwright: "playwrightBrowser",
  jsdom: "jsdomInstance",
  "xml2js": "xml2jsParser",
  yaml: "yamlParser",
  "js-yaml": "jsYamlParser",
  toml: "tomlParser",
  csv: "csvParser",
  "csv-parser": "csvParser",
  "csv-writer": "csvWriter",
  archiver: "archiverZip",
  "adm-zip": "admZip",
  tar: "tarModule",
  formidable: "formidableParser",
  "form-data": "formData",
  superagent: "superagentClient",
  got: "gotClient",
  bent: "bentClient",
  request: "requestClient",
  "request-promise": "requestPromise",
  bluebird: "bluebirdPromise",
  rxjs: "rxjsObservable",
  ramda: "ramda",
  immutable: "immutableModule",
  redux: "reduxStore",
  "react-redux": "reactRedux",
  mobx: "mobxStore",
  zustand: "zustandStore",
  recoil: "recoilState",
  "styled-components": "styledComponents",
  emotion: "emotionCSS",
  "@emotion/react": "emotionReact",
  "@emotion/styled": "emotionStyled",
  tailwindcss: "tailwindCSS",
  classnames: "classNames",
  clsx: "clsxHelper",
  "prop-types": "PropTypes",
  "react-router": "reactRouter",
  "react-router-dom": "reactRouterDOM",
  next: "nextModule",
  "next/router": "nextRouter",
  "next/link": "NextLink",
  "next/image": "NextImage",
  vue: "Vue",
  "vue-router": "vueRouter",
  vuex: "vuexStore",
  angular: "angularModule",
  svelte: "svelteModule",
  electron: "electronModule",
  "electron/main": "electronMain",
  "electron/renderer": "electronRenderer",
  // Test kutuphaneleri
  jest: "jestModule",
  mocha: "mochaModule",
  chai: "chaiAssert",
  sinon: "sinonMock",
  supertest: "supertestAgent",
  nock: "nockMock",
  // Build/bundler
  webpack: "webpackCompiler",
  rollup: "rollupBundler",
  esbuild: "esbuildModule",
  vite: "viteModule",
  parcel: "parcelBundler",
  babel: "babelModule",
  "@babel/core": "babelCore",
  "@babel/parser": "babelParser",
  "@babel/traverse": "babelTraverse",
  "@babel/generator": "babelGenerator",
  "@babel/types": "babelTypes",
  typescript: "typescriptCompiler",
  // Ink (CLI React)
  ink: "inkModule",
  "ink-text-input": "inkTextInput",
  "ink-select-input": "inkSelectInput",
  "ink-spinner": "inkSpinner",
};

// B. Fonksiyon parametre pozisyonundan
const PARAM_POSITION_RULES = {
  // Express middleware
  express_handler_3: ["request", "response", "nextMiddleware"],
  express_handler_4: ["error", "request", "response", "nextMiddleware"],
  // Node.js callback pattern (err, data)
  callback_2: ["error", "data"],
  callback_3: ["error", "data", "info"],
  // Array methods
  array_map_1: ["item"],
  array_map_2: ["item", "index"],
  array_map_3: ["item", "index", "array"],
  array_filter_1: ["item"],
  array_filter_2: ["item", "index"],
  array_reduce_2: ["accumulator", "currentItem"],
  array_reduce_3: ["accumulator", "currentItem", "index"],
  array_reduce_4: ["accumulator", "currentItem", "index", "array"],
  array_forEach_1: ["item"],
  array_forEach_2: ["item", "index"],
  array_find_1: ["item"],
  array_sort_2: ["itemA", "itemB"],
  // Promise
  promise_then_1: ["resolvedValue"],
  promise_catch_1: ["rejectionError"],
  // Event handler
  event_handler_1: ["event"],
  // setTimeout/setInterval
  timer_callback_0: ["timerCallback"],
};

// C. Property erisimleri -> tip hint + isim suffix
const PROPERTY_HINTS = {
  // Array
  length: { type: "array_or_string", suffix: "", confidence: 0.1 },
  map: { type: "array", suffix: "List", confidence: 0.25 },
  filter: { type: "array", suffix: "List", confidence: 0.25 },
  reduce: { type: "array", suffix: "List", confidence: 0.2 },
  push: { type: "array", suffix: "Items", confidence: 0.25 },
  pop: { type: "array", suffix: "Stack", confidence: 0.2 },
  shift: { type: "array", suffix: "Queue", confidence: 0.2 },
  unshift: { type: "array", suffix: "Queue", confidence: 0.2 },
  forEach: { type: "array", suffix: "Items", confidence: 0.25 },
  find: { type: "array", suffix: "List", confidence: 0.2 },
  findIndex: { type: "array", suffix: "List", confidence: 0.2 },
  some: { type: "array", suffix: "List", confidence: 0.2 },
  every: { type: "array", suffix: "List", confidence: 0.2 },
  flat: { type: "array", suffix: "List", confidence: 0.2 },
  flatMap: { type: "array", suffix: "List", confidence: 0.2 },
  indexOf: { type: "array_or_string", suffix: "", confidence: 0.1 },
  includes: { type: "array_or_string", suffix: "", confidence: 0.1 },
  slice: { type: "array_or_string", suffix: "", confidence: 0.1 },
  concat: { type: "array_or_string", suffix: "", confidence: 0.1 },
  splice: { type: "array", suffix: "List", confidence: 0.25 },
  sort: { type: "array", suffix: "List", confidence: 0.2 },
  reverse: { type: "array", suffix: "List", confidence: 0.15 },
  join: { type: "array", suffix: "List", confidence: 0.25 },
  entries: { type: "iterable", suffix: "", confidence: 0.1 },
  keys: { type: "object_or_map", suffix: "", confidence: 0.1 },
  values: { type: "object_or_map", suffix: "", confidence: 0.1 },
  // String
  split: { type: "string", suffix: "Text", confidence: 0.25 },
  trim: { type: "string", suffix: "Text", confidence: 0.25 },
  trimStart: { type: "string", suffix: "Text", confidence: 0.2 },
  trimEnd: { type: "string", suffix: "Text", confidence: 0.2 },
  replace: { type: "string", suffix: "Text", confidence: 0.2 },
  replaceAll: { type: "string", suffix: "Text", confidence: 0.2 },
  match: { type: "string", suffix: "Pattern", confidence: 0.2 },
  matchAll: { type: "string", suffix: "Pattern", confidence: 0.2 },
  search: { type: "string", suffix: "Text", confidence: 0.15 },
  startsWith: { type: "string", suffix: "Text", confidence: 0.25 },
  endsWith: { type: "string", suffix: "Path", confidence: 0.25 },
  toLowerCase: { type: "string", suffix: "Text", confidence: 0.3 },
  toUpperCase: { type: "string", suffix: "Text", confidence: 0.3 },
  toLocaleLowerCase: { type: "string", suffix: "Text", confidence: 0.25 },
  toLocaleUpperCase: { type: "string", suffix: "Text", confidence: 0.25 },
  charAt: { type: "string", suffix: "Text", confidence: 0.25 },
  charCodeAt: { type: "string", suffix: "Text", confidence: 0.2 },
  codePointAt: { type: "string", suffix: "Text", confidence: 0.2 },
  substring: { type: "string", suffix: "Text", confidence: 0.2 },
  substr: { type: "string", suffix: "Text", confidence: 0.2 },
  padStart: { type: "string", suffix: "Text", confidence: 0.2 },
  padEnd: { type: "string", suffix: "Text", confidence: 0.2 },
  repeat: { type: "string", suffix: "Text", confidence: 0.15 },
  normalize: { type: "string", suffix: "Text", confidence: 0.15 },
  // Promise
  then: { type: "promise", suffix: "Promise", confidence: 0.3 },
  catch: { type: "promise", suffix: "Promise", confidence: 0.3 },
  finally: { type: "promise", suffix: "Promise", confidence: 0.25 },
  // EventEmitter
  emit: { type: "event_emitter", suffix: "Emitter", confidence: 0.3 },
  on: { type: "event_emitter", suffix: "Emitter", confidence: 0.25 },
  once: { type: "event_emitter", suffix: "Emitter", confidence: 0.25 },
  off: { type: "event_emitter", suffix: "Emitter", confidence: 0.2 },
  removeListener: { type: "event_emitter", suffix: "Emitter", confidence: 0.25 },
  removeAllListeners: { type: "event_emitter", suffix: "Emitter", confidence: 0.25 },
  addListener: { type: "event_emitter", suffix: "Emitter", confidence: 0.25 },
  listenerCount: { type: "event_emitter", suffix: "Emitter", confidence: 0.2 },
  // Stream
  pipe: { type: "stream", suffix: "Stream", confidence: 0.3 },
  write: { type: "writable", suffix: "Writer", confidence: 0.2 },
  read: { type: "readable", suffix: "Reader", confidence: 0.2 },
  end: { type: "writable", suffix: "Stream", confidence: 0.15 },
  destroy: { type: "destroyable", suffix: "", confidence: 0.1 },
  close: { type: "closable", suffix: "Handle", confidence: 0.15 },
  pause: { type: "stream", suffix: "Stream", confidence: 0.2 },
  resume: { type: "stream", suffix: "Stream", confidence: 0.2 },
  unpipe: { type: "stream", suffix: "Stream", confidence: 0.2 },
  cork: { type: "writable", suffix: "Stream", confidence: 0.15 },
  uncork: { type: "writable", suffix: "Stream", confidence: 0.15 },
  // HTTP
  status: { type: "response", suffix: "Response", confidence: 0.25 },
  statusCode: { type: "response", suffix: "Response", confidence: 0.3 },
  statusMessage: { type: "response", suffix: "Response", confidence: 0.25 },
  headers: { type: "request_response", suffix: "", confidence: 0.2 },
  body: { type: "request_response", suffix: "", confidence: 0.2 },
  json: { type: "response", suffix: "Response", confidence: 0.25 },
  send: { type: "response", suffix: "Response", confidence: 0.3 },
  render: { type: "response", suffix: "View", confidence: 0.25 },
  redirect: { type: "response", suffix: "Response", confidence: 0.25 },
  cookie: { type: "response", suffix: "Response", confidence: 0.2 },
  query: { type: "request", suffix: "Request", confidence: 0.25 },
  params: { type: "request", suffix: "Request", confidence: 0.25 },
  path: { type: "url_or_file", suffix: "Path", confidence: 0.2 },
  url: { type: "request", suffix: "Url", confidence: 0.25 },
  method: { type: "request", suffix: "Request", confidence: 0.2 },
  hostname: { type: "request", suffix: "Request", confidence: 0.2 },
  protocol: { type: "request", suffix: "Request", confidence: 0.15 },
  // Object common properties
  name: { type: "named", suffix: "", confidence: 0.1 },
  type: { type: "typed", suffix: "", confidence: 0.1 },
  value: { type: "valued", suffix: "", confidence: 0.1 },
  key: { type: "keyed", suffix: "Key", confidence: 0.15 },
  id: { type: "identified", suffix: "Id", confidence: 0.2 },
  // Error
  message: { type: "error_or_message", suffix: "Message", confidence: 0.2 },
  stack: { type: "error", suffix: "Error", confidence: 0.3 },
  code: { type: "error_or_status", suffix: "Code", confidence: 0.15 },
  cause: { type: "error", suffix: "Error", confidence: 0.2 },
  // Config/options
  config: { type: "config", suffix: "Config", confidence: 0.2 },
  options: { type: "options", suffix: "Options", confidence: 0.2 },
  settings: { type: "config", suffix: "Settings", confidence: 0.2 },
  env: { type: "environment", suffix: "Env", confidence: 0.2 },
  // DOM
  innerHTML: { type: "dom_element", suffix: "Element", confidence: 0.3 },
  outerHTML: { type: "dom_element", suffix: "Element", confidence: 0.3 },
  textContent: { type: "dom_element", suffix: "Element", confidence: 0.3 },
  className: { type: "dom_element", suffix: "Element", confidence: 0.3 },
  classList: { type: "dom_element", suffix: "Element", confidence: 0.25 },
  style: { type: "dom_element", suffix: "Element", confidence: 0.2 },
  appendChild: { type: "dom_element", suffix: "Element", confidence: 0.3 },
  removeChild: { type: "dom_element", suffix: "Element", confidence: 0.25 },
  insertBefore: { type: "dom_element", suffix: "Element", confidence: 0.25 },
  querySelector: { type: "dom_element", suffix: "Element", confidence: 0.3 },
  querySelectorAll: { type: "dom_element", suffix: "Element", confidence: 0.25 },
  getElementById: { type: "dom_element", suffix: "Document", confidence: 0.3 },
  getElementsByClassName: { type: "dom_element", suffix: "Document", confidence: 0.25 },
  addEventListener: { type: "dom_element", suffix: "Element", confidence: 0.3 },
  removeEventListener: { type: "dom_element", suffix: "Element", confidence: 0.25 },
  setAttribute: { type: "dom_element", suffix: "Element", confidence: 0.25 },
  getAttribute: { type: "dom_element", suffix: "Element", confidence: 0.25 },
  dataset: { type: "dom_element", suffix: "Element", confidence: 0.2 },
  parentNode: { type: "dom_element", suffix: "Element", confidence: 0.2 },
  childNodes: { type: "dom_element", suffix: "Element", confidence: 0.2 },
  children: { type: "dom_element", suffix: "Element", confidence: 0.2 },
  nextSibling: { type: "dom_element", suffix: "Element", confidence: 0.2 },
  previousSibling: { type: "dom_element", suffix: "Element", confidence: 0.2 },
  // Map/Set
  get: { type: "map_or_object", suffix: "", confidence: 0.1 },
  set: { type: "map_or_object", suffix: "", confidence: 0.1 },
  has: { type: "map_set", suffix: "", confidence: 0.15 },
  delete: { type: "map_set", suffix: "", confidence: 0.1 },
  clear: { type: "map_set", suffix: "", confidence: 0.1 },
  size: { type: "map_set", suffix: "", confidence: 0.15 },
  add: { type: "set", suffix: "Set", confidence: 0.2 },
  // Class
  prototype: { type: "class", suffix: "Prototype", confidence: 0.2 },
  constructor: { type: "class", suffix: "Constructor", confidence: 0.2 },
  super: { type: "class", suffix: "Parent", confidence: 0.15 },
  // Functional
  call: { type: "function", suffix: "Fn", confidence: 0.15 },
  apply: { type: "function", suffix: "Fn", confidence: 0.15 },
  bind: { type: "function", suffix: "Fn", confidence: 0.2 },
  // JSON / serialization
  toJSON: { type: "serializable", suffix: "", confidence: 0.15 },
  toString: { type: "any", suffix: "", confidence: 0.05 },
  valueOf: { type: "any", suffix: "", confidence: 0.05 },
  // Iterator
  next: { type: "iterator", suffix: "Iterator", confidence: 0.2 },
  done: { type: "iterator_result", suffix: "", confidence: 0.15 },
  [Symbol.iterator]: { type: "iterable", suffix: "Iterable", confidence: 0.2 },
};

// D. Operatorler ve kontrol akisindan tip cikarimi
const TYPE_CHECKS = {
  string: { suffix: "Str", confidence: 0.2 },
  number: { suffix: "Num", confidence: 0.2 },
  boolean: { suffix: "Flag", confidence: 0.2 },
  function: { suffix: "Fn", confidence: 0.25 },
  object: { suffix: "Obj", confidence: 0.1 },
  undefined: { suffix: "Optional", confidence: 0.1 },
  symbol: { suffix: "Sym", confidence: 0.2 },
  bigint: { suffix: "BigInt", confidence: 0.2 },
};

const INSTANCEOF_NAMES = {
  Error: { name: "error", confidence: 0.3 },
  TypeError: { name: "typeError", confidence: 0.3 },
  RangeError: { name: "rangeError", confidence: 0.3 },
  ReferenceError: { name: "refError", confidence: 0.3 },
  SyntaxError: { name: "syntaxError", confidence: 0.3 },
  Array: { name: "items", confidence: 0.25 },
  Map: { name: "mapInstance", confidence: 0.25 },
  Set: { name: "setInstance", confidence: 0.25 },
  WeakMap: { name: "weakMapInstance", confidence: 0.25 },
  WeakSet: { name: "weakSetInstance", confidence: 0.25 },
  Date: { name: "dateInstance", confidence: 0.25 },
  RegExp: { name: "pattern", confidence: 0.25 },
  Buffer: { name: "buffer", confidence: 0.25 },
  Promise: { name: "promiseInstance", confidence: 0.25 },
  EventEmitter: { name: "emitter", confidence: 0.25 },
  ReadableStream: { name: "readStream", confidence: 0.25 },
  WritableStream: { name: "writeStream", confidence: 0.25 },
  URL: { name: "urlInstance", confidence: 0.25 },
  AbortController: { name: "abortController", confidence: 0.25 },
  AbortSignal: { name: "abortSignal", confidence: 0.25 },
  Request: { name: "fetchRequest", confidence: 0.25 },
  Response: { name: "fetchResponse", confidence: 0.25 },
  Headers: { name: "httpHeaders", confidence: 0.25 },
  FormData: { name: "formData", confidence: 0.25 },
  Blob: { name: "blobData", confidence: 0.25 },
  File: { name: "fileData", confidence: 0.25 },
  ArrayBuffer: { name: "arrayBuffer", confidence: 0.25 },
  SharedArrayBuffer: { name: "sharedBuffer", confidence: 0.25 },
  DataView: { name: "dataView", confidence: 0.25 },
  Uint8Array: { name: "uint8Data", confidence: 0.25 },
  Int32Array: { name: "int32Data", confidence: 0.25 },
  Float64Array: { name: "float64Data", confidence: 0.25 },
};

// E. Atama kaynagindan isim cikarimi
const CONSTRUCTOR_NAMES = {
  Map: "mapInstance",
  Set: "setInstance",
  WeakMap: "weakMapRef",
  WeakSet: "weakSetRef",
  Date: "timestamp",
  RegExp: "pattern",
  Error: "error",
  TypeError: "typeError",
  RangeError: "rangeError",
  ReferenceError: "refError",
  SyntaxError: "syntaxError",
  URL: "urlInstance",
  URLSearchParams: "searchParams",
  Headers: "httpHeaders",
  Request: "fetchRequest",
  Response: "fetchResponse",
  FormData: "formData",
  Blob: "blobData",
  File: "fileObj",
  AbortController: "abortController",
  ReadableStream: "readStream",
  WritableStream: "writeStream",
  TransformStream: "transformStream",
  TextEncoder: "textEncoder",
  TextDecoder: "textDecoder",
  Buffer: "buffer",
  EventEmitter: "emitter",
  Promise: "promiseInstance",
  Proxy: "proxyHandler",
  ArrayBuffer: "arrayBuffer",
  SharedArrayBuffer: "sharedBuffer",
  DataView: "dataView",
  Uint8Array: "uint8Data",
  Int8Array: "int8Data",
  Uint16Array: "uint16Data",
  Int16Array: "int16Data",
  Uint32Array: "uint32Data",
  Int32Array: "int32Data",
  Float32Array: "float32Data",
  Float64Array: "float64Data",
  BigInt64Array: "bigInt64Data",
  BigUint64Array: "bigUint64Data",
  Worker: "workerThread",
  MessageChannel: "messageChannel",
  MessagePort: "messagePort",
  BroadcastChannel: "broadcastChannel",
  WebSocket: "webSocket",
  XMLHttpRequest: "xhrRequest",
  IntersectionObserver: "intersectionObserver",
  MutationObserver: "mutationObserver",
  ResizeObserver: "resizeObserver",
  PerformanceObserver: "perfObserver",
};

const GLOBAL_FUNCTION_RETURNS = {
  // JSON
  "JSON.parse": "parsedData",
  "JSON.stringify": "jsonString",
  // Object
  "Object.create": "createdObject",
  "Object.keys": "objectKeys",
  "Object.values": "objectValues",
  "Object.entries": "objectEntries",
  "Object.assign": "mergedObject",
  "Object.freeze": "frozenObject",
  "Object.seal": "sealedObject",
  "Object.defineProperty": "definedProp",
  "Object.defineProperties": "definedProps",
  "Object.getOwnPropertyNames": "propNames",
  "Object.getOwnPropertyDescriptor": "propDescriptor",
  "Object.getOwnPropertyDescriptors": "propDescriptors",
  "Object.getPrototypeOf": "protoObject",
  "Object.fromEntries": "objectFromEntries",
  // Array
  "Array.from": "arrayFromIterable",
  "Array.of": "newArray",
  "Array.isArray": "isArrayCheck",
  // String
  "String.fromCharCode": "charString",
  "String.fromCodePoint": "codePointString",
  // Number
  "Number.parseInt": "parsedInt",
  "Number.parseFloat": "parsedFloat",
  "Number.isFinite": "isFiniteCheck",
  "Number.isNaN": "isNaNCheck",
  "Number.isInteger": "isIntegerCheck",
  // Math
  "Math.floor": "flooredValue",
  "Math.ceil": "ceiledValue",
  "Math.round": "roundedValue",
  "Math.abs": "absoluteValue",
  "Math.max": "maxValue",
  "Math.min": "minValue",
  "Math.random": "randomValue",
  "Math.sqrt": "sqrtValue",
  "Math.pow": "powValue",
  "Math.log": "logValue",
  "Math.sign": "signValue",
  "Math.trunc": "truncatedValue",
  // Global
  parseInt: "parsedInt",
  parseFloat: "parsedFloat",
  String: "stringValue",
  Number: "numericValue",
  Boolean: "booleanValue",
  BigInt: "bigIntValue",
  Symbol: "symbolValue",
  encodeURIComponent: "encodedComponent",
  decodeURIComponent: "decodedComponent",
  encodeURI: "encodedUri",
  decodeURI: "decodedUri",
  btoa: "base64Encoded",
  atob: "base64Decoded",
  setTimeout: "timeoutId",
  setInterval: "intervalId",
  setImmediate: "immediateId",
  requestAnimationFrame: "animFrameId",
  fetch: "fetchResponse",
  require: null, // ozel olarak ele alinir
};

// F. Fonksiyon isimlerinden parametre isimleri
const FUNCTION_PARAM_NAMES = {
  // DOM
  addEventListener: ["eventName", "eventHandler", "listenerOptions"],
  removeEventListener: ["eventName", "eventHandler", "listenerOptions"],
  // Timer
  setTimeout: ["timerCallback", "delayMs"],
  setInterval: ["intervalCallback", "intervalMs"],
  setImmediate: ["immediateCallback"],
  // fs
  readFile: ["filePath", "readOptions", "readCallback"],
  readFileSync: ["filePath", "readOptions"],
  writeFile: ["filePath", "fileData", "writeOptions", "writeCallback"],
  writeFileSync: ["filePath", "fileData", "writeOptions"],
  appendFile: ["filePath", "appendData", "appendOptions", "appendCallback"],
  appendFileSync: ["filePath", "appendData", "appendOptions"],
  unlink: ["filePath", "unlinkCallback"],
  unlinkSync: ["filePath"],
  readdir: ["dirPath", "readDirOptions", "readDirCallback"],
  readdirSync: ["dirPath", "readDirOptions"],
  mkdir: ["dirPath", "mkdirOptions", "mkdirCallback"],
  mkdirSync: ["dirPath", "mkdirOptions"],
  stat: ["filePath", "statCallback"],
  statSync: ["filePath"],
  lstat: ["filePath", "lstatCallback"],
  lstatSync: ["filePath"],
  rename: ["oldPath", "newPath", "renameCallback"],
  renameSync: ["oldPath", "newPath"],
  copyFile: ["sourcePath", "destPath", "copyFlags", "copyCallback"],
  copyFileSync: ["sourcePath", "destPath", "copyFlags"],
  access: ["filePath", "accessMode", "accessCallback"],
  accessSync: ["filePath", "accessMode"],
  existsSync: ["checkPath"],
  createReadStream: ["streamPath", "streamOptions"],
  createWriteStream: ["streamPath", "streamOptions"],
  watch: ["watchPath", "watchOptions", "watchCallback"],
  watchFile: ["watchPath", "watchOptions", "watchCallback"],
  // path
  join: null,
  resolve: null,
  relative: ["fromPath", "toPath"],
  dirname: ["inputPath"],
  basename: ["inputPath", "extension"],
  extname: ["inputPath"],
  parse: ["inputPath"],
  format: ["pathObject"],
  normalize: ["inputPath"],
  isAbsolute: ["checkPath"],
  // http
  createServer: ["requestHandler"],
  listen: ["portNumber", "hostname", "listenCallback"],
  request: ["requestOptions", "responseCallback"],
  get: ["requestUrl", "responseCallback"],
  // Express
  use: ["middlewareFn"],
  // Promise
  all: ["promiseList"],
  allSettled: ["promiseList"],
  any: ["promiseList"],
  race: ["promiseList"],
  reject: ["rejectReason"],
  // EventEmitter
  on: ["eventName", "eventListener"],
  once: ["eventName", "eventListener"],
  emit: ["eventName"],
  off: ["eventName", "eventListener"],
  removeListener: ["eventName", "eventListener"],
  // Array
  from: ["iterable", "mapFn"],
  of: null,
  isArray: ["checkValue"],
  // Console
  log: null,
  warn: null,
  error: null,
  info: null,
  debug: null,
  // JSON
  stringify: ["sourceValue", "replacer", "indentation"],
};

// G. React/Ink specifik
const REACT_HOOKS = {
  useState: { returns: ["stateValue", "setStateValue"], confidence: 0.3 },
  useEffect: { params: ["effectCallback", "dependencies"], confidence: 0.25 },
  useCallback: { params: ["memoizedCallback", "dependencies"], confidence: 0.25 },
  useMemo: { params: ["computeValue", "dependencies"], confidence: 0.25 },
  useRef: { returns: "refObject", confidence: 0.25 },
  useContext: { returns: "contextValue", confidence: 0.25 },
  useReducer: { returns: ["state", "dispatch"], confidence: 0.3 },
  useLayoutEffect: { params: ["layoutEffect", "dependencies"], confidence: 0.2 },
  useImperativeHandle: { params: ["refHandle", "createHandle", "dependencies"], confidence: 0.2 },
  useDebugValue: { params: ["debugValue"], confidence: 0.15 },
  useId: { returns: "uniqueId", confidence: 0.2 },
  useTransition: { returns: ["isPending", "startTransition"], confidence: 0.25 },
  useDeferredValue: { returns: "deferredValue", confidence: 0.2 },
  useSyncExternalStore: {
    params: ["subscribe", "getSnapshot", "getServerSnapshot"],
    returns: "storeSnapshot",
    confidence: 0.2,
  },
  useInsertionEffect: { params: ["insertionEffect", "dependencies"], confidence: 0.15 },
};

const REACT_ELEMENT_PARAMS = {
  createElement: ["componentType", "componentProps", "childElements"],
  cloneElement: ["sourceElement", "mergedProps", "childElements"],
  createRef: [],
  forwardRef: ["renderFunction"],
  memo: ["memoizedComponent", "areEqual"],
  lazy: ["importFactory"],
};

// =====================================================================
// PHASE 0: PARSE + DUPLICATE DECLARATION PRE-PROCESS
// =====================================================================

let ast;
const errors = [];
try {
  ast = parse(source, {
    sourceType: "unambiguous",
    allowReturnOutsideFunction: true,
    allowSuperOutsideMethod: true,
    allowImportExportEverywhere: true,
    errorRecovery: true,
    plugins: [
      "jsx",
      "typescript",
      "decorators-legacy",
      "classProperties",
      "classPrivateProperties",
      "classPrivateMethods",
      "dynamicImport",
      "optionalChaining",
      "nullishCoalescingOperator",
      "logicalAssignment",
      "numericSeparator",
      "optionalCatchBinding",
      "throwExpressions",
      "topLevelAwait",
      "exportDefaultFrom",
      "exportNamespaceFrom",
      "asyncGenerators",
      "objectRestSpread",
      "importMeta",
      "importAssertions",
    ],
  });
} catch (err) {
  process.stdout.write(
    JSON.stringify({
      success: false,
      errors: [`Parse hatasi: ${err.message}`],
    }) + "\n"
  );
  process.exit(0);
}

// =====================================================================
// PHASE 0.5: FIX DUPLICATE DECLARATIONS
// =====================================================================
// esbuild ciktisinda ayni scope'ta const util, const util gibi
// duplicate declarations var. Babel scope bunu "Duplicate declaration"
// hatasi ile reddediyor.
//
// Cozum: ilk declaration'i koru, sonrakileri AssignmentExpression'a donustur.
// Bu pre-process pass'i noScope: true ile calisiyor (duplicate'ler yuzunden
// scope acamayiz), ama SADECE duplicate'leri temizliyor.

let duplicatesFixed = 0;

try {
  traverse(ast, {
    noScope: true,

    VariableDeclaration(path) {
      const declarations = path.node.declarations;
      const kind = path.node.kind;

      let scopeBlock;
      if (kind === "var") {
        scopeBlock = findFunctionScope(path);
      } else {
        scopeBlock = findBlockScope(path);
      }

      if (!scopeBlock) scopeBlock = ast;

      if (!scopeBlock._seenVarNames) {
        scopeBlock._seenVarNames = new Map();
      }
      const seen = scopeBlock._seenVarNames;

      const toConvert = [];

      for (let i = 0; i < declarations.length; i++) {
        const decl = declarations[i];
        if (!decl.id || decl.id.type !== "Identifier") continue;

        const name = decl.id.name;

        if (seen.has(name)) {
          toConvert.push({ index: i, decl });
          duplicatesFixed++;
        } else {
          seen.set(name, kind);
        }
      }

      if (toConvert.length === 0) return;

      if (toConvert.length === declarations.length) {
        const assignments = toConvert.map(({ decl }) => {
          if (decl.init) {
            return t.assignmentExpression("=", t.identifier(decl.id.name), decl.init);
          }
          return null;
        }).filter(Boolean);

        if (assignments.length === 0) {
          // BUG FIX: init'siz declaration'lari silmemeli!
          // `var s;` gibi declaration'lar ileride kullaniliyor olabilir.
          // Silmek yerine birakiyoruz -- zaten duplicate oldugu icin
          // ilk declaration scope'ta kayitli, ikincisi gereksiz ama zararsiz.
          // Sadece `var` keyword'unu koruyoruz, declaration'i silmiyoruz.
          // NOT: path.remove() YAPMA! ReferenceError'a yol acar.
          return;
        }

        // ForStatement.init pozisyonunda ExpressionStatement kullanilamaz
        const isForInit = path.parent?.type === "ForStatement" && path.parent.init === path.node;
        const isForInLeft = (path.parent?.type === "ForInStatement" || path.parent?.type === "ForOfStatement") && path.parent.left === path.node;

        if (isForInit || isForInLeft) {
          if (assignments.length === 1) {
            try { path.replaceWith(assignments[0]); } catch(_) { path.node.kind = "var"; }
          } else {
            try { path.replaceWith(t.sequenceExpression(assignments)); } catch(_) { path.node.kind = "var"; }
          }
        } else {
          if (assignments.length === 1) {
            try { path.replaceWith(t.expressionStatement(assignments[0])); } catch(_) { path.node.kind = "var"; }
          } else {
            try { path.replaceWith(t.expressionStatement(t.sequenceExpression(assignments))); } catch(_) { path.node.kind = "var"; }
          }
        }
        return;
      }

      // Sadece bazi declarator'lar duplicate
      const assignmentExprs = [];
      for (const { index, decl } of toConvert.reverse()) {
        declarations.splice(index, 1);
        if (decl.init) {
          assignmentExprs.push(
            t.assignmentExpression("=", t.identifier(decl.id.name), decl.init)
          );
        }
      }

      if (assignmentExprs.length > 0) {
        const isForInit = path.parent?.type === "ForStatement" && path.parent.init === path.node;
        if (isForInit) return; // For init'te insertBefore calismaz, declarator'lari zaten cikardik

        try {
          const stmts = assignmentExprs.map(a => t.expressionStatement(a));
          for (const stmt of stmts.reverse()) {
            path.insertBefore(stmt);
          }
        } catch (_) {
          path.node.kind = "var";
          for (const { decl } of toConvert) {
            declarations.push(decl);
          }
        }
      }
    },
  });
} catch (err) {
  errors.push(`Duplicate fix pass hatasi: ${err.message}`);
}

function findFunctionScope(path) {
  let current = path.parentPath;
  while (current) {
    const type = current.node?.type;
    if (
      type === "FunctionDeclaration" ||
      type === "FunctionExpression" ||
      type === "ArrowFunctionExpression" ||
      type === "Program"
    ) {
      return current.node;
    }
    current = current.parentPath;
  }
  return null;
}

function findBlockScope(path) {
  let current = path.parentPath;
  while (current) {
    const type = current.node?.type;
    if (
      type === "FunctionDeclaration" ||
      type === "FunctionExpression" ||
      type === "ArrowFunctionExpression" ||
      type === "Program" ||
      type === "BlockStatement" ||
      type === "ForStatement" ||
      type === "ForInStatement" ||
      type === "ForOfStatement" ||
      type === "SwitchStatement"
    ) {
      return current.node;
    }
    current = current.parentPath;
  }
  return null;
}

// Gecici _seenVarNames property'lerini temizle
traverse(ast, {
  noScope: true,
  enter(path) {
    if (path.node._seenVarNames) {
      delete path.node._seenVarNames;
    }
  },
});

// ------------------------------------------------------------------
// PHASE 0.6: DUPLICATE FUNCTION PARAMETER FIX
// ------------------------------------------------------------------
// function az(items, items) gibi duplicate parametreleri duzelter.
// Strict mode'da SyntaxError -- suffix ekleyerek cozulur.

let duplicateParamsFixed = 0;

try {
  traverse(ast, {
    noScope: true,
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression|ClassMethod|ObjectMethod"(path) {
      const params = path.node.params;
      if (!params || params.length < 2) return;

      const seenNames = new Set();
      for (let i = 0; i < params.length; i++) {
        const param = params[i];
        if (!param) continue;

        if (param.type === "Identifier") {
          if (seenNames.has(param.name)) {
            let suffix = 2;
            let newName = `${param.name}_${suffix}`;
            while (seenNames.has(newName)) {
              suffix++;
              newName = `${param.name}_${suffix}`;
            }
            param.name = newName;
            seenNames.add(newName);
            duplicateParamsFixed++;
          } else {
            seenNames.add(param.name);
          }
        } else if (param.type === "AssignmentPattern" && param.left?.type === "Identifier") {
          const name = param.left.name;
          if (seenNames.has(name)) {
            let suffix = 2;
            let newName = `${name}_${suffix}`;
            while (seenNames.has(newName)) {
              suffix++;
              newName = `${name}_${suffix}`;
            }
            param.left.name = newName;
            seenNames.add(newName);
            duplicateParamsFixed++;
          } else {
            seenNames.add(name);
          }
        }
      }
    },
  });
} catch (err) {
  errors.push(`Duplicate param fix hatasi: ${err.message}`);
}

console.error(`[pre-process] ${duplicatesFixed} duplicate declaration, ${duplicateParamsFixed} duplicate param duzeltildi`);

// =====================================================================
// PHASE 0.75: BABEL SCOPE MONKEY-PATCH
// =====================================================================
// Pre-process tum duplicate'leri temizleyemeyebilir (edge cases).
// Babel'in Scope.registerBinding() metodunu patch'leyerek
// "Duplicate declaration" hatasini sessizce yutmasini sagliyoruz.
// Bu sayede scope-aware traverse HER DURUMDA calisir.

try {
  // Babel'in Scope class'ini bul
  const scopeModule = await import("@babel/traverse");
  const Scope = (scopeModule.default || scopeModule).Scope ||
    Object.values(scopeModule).find(v => v?.prototype?.registerBinding);

  if (Scope?.prototype?.registerBinding) {
    const originalRegisterBinding = Scope.prototype.registerBinding;
    Scope.prototype.registerBinding = function(kind, path, bindingPath) {
      try {
        return originalRegisterBinding.call(this, kind, path, bindingPath);
      } catch (err) {
        if (err.message?.includes("Duplicate declaration")) {
          // Sessizce atla -- duplicate binding'i kayit etme
          return;
        }
        throw err;
      }
    };
    console.error("[scope-patch] Scope.registerBinding patched -- duplicate declarations tolere edilecek");
  } else {
    // Scope class bulunamadi -- dogrudan node_modules'tan import et
    try {
      const { Scope: S2 } = await import("/Users/apple/Desktop/black-widow/scripts/node_modules/@babel/traverse/lib/scope/index.js");
      if (S2?.prototype?.registerBinding) {
        const orig = S2.prototype.registerBinding;
        S2.prototype.registerBinding = function(kind, path, bindingPath) {
          try {
            return orig.call(this, kind, path, bindingPath);
          } catch (err) {
            if (err.message?.includes("Duplicate declaration")) return;
            throw err;
          }
        };
        console.error("[scope-patch] Scope.registerBinding patched (direct import)");
      }
    } catch(_) {}
  }
} catch (patchErr) {
  console.error("[scope-patch] Patch basarisiz:", patchErr.message);
}

// =====================================================================
// PHASE 1: SCOPE-AWARE TRAVERSE
// =====================================================================
// Duplicate'ler temizlendi + Babel scope patched.
// noScope: true KALDIRILDI.

class VariableInfo {
  constructor(name, scopeId) {
    this.name = name;
    this.scopeId = scopeId;
    this.declaration = null;
    this.declarationLine = null;
    this.references = 0;
    this.evidence = [];
    this.propertiesAccessed = new Set();
    this.methodsCalled = new Set();
    this.passedToFunctions = [];
    this.assignedFrom = null;
    this.assignedFromChain = [];
    this.usedInReturn = false;
    this.usedInCondition = false;
    this.typeofChecks = new Set();
    this.instanceofChecks = new Set();
    this.suggestedName = null;
    this.confidence = 0;
    this.requireSource = null;
    this.constructorSource = null;
    this.globalFunctionReturn = null;
    this.isCallback = false;
    this.isEventHandler = false;
    this.expressPosition = -1;
    this.arrayMethodParam = null;
    this.reactHook = null;
    this.destructuredFrom = null;
    this.spreadFrom = null;
    this.bindingNode = null;
  }

  addEvidence(type, value, confidence) {
    this.evidence.push({ type, value, confidence });
    this.confidence += confidence;
  }
}

const variables = new Map();

function getScopeId(path) {
  try {
    const scope = path.scope;
    if (scope && scope.block) {
      const block = scope.block;
      if (block.loc && block.loc.start) {
        const funcName =
          block.id?.name ||
          (block.type === "Program" ? "program" : block.type);
        return `${funcName}@${block.loc.start.line}:${block.loc.start.column}`;
      }
      if (scope.uid !== undefined) return `scope_${scope.uid}`;
    }
  } catch (_) {}

  let current = path;
  while (current) {
    const node = current.node;
    if (
      node &&
      (node.type === "FunctionDeclaration" ||
        node.type === "FunctionExpression" ||
        node.type === "ArrowFunctionExpression" ||
        node.type === "Program" ||
        node.type === "ClassMethod" ||
        node.type === "ObjectMethod")
    ) {
      if (node.loc?.start) {
        const name = node.id?.name || node.type;
        return `${name}@${node.loc.start.line}:${node.loc.start.column}`;
      }
    }
    current = current.parentPath;
  }
  return "global";
}

function getOrCreate(name, path) {
  const scopeId = getScopeId(path);
  const key = `${scopeId}::${name}`;
  if (!variables.has(key)) {
    variables.set(key, new VariableInfo(name, scopeId));
  }
  return variables.get(key);
}

function getMemberExprKey(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const obj = getMemberExprKey(node.object);
    const prop = node.computed ? null : node.property?.name;
    if (obj && prop) return `${obj}.${prop}`;
  }
  return null;
}

function getCalleeKey(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") return getMemberExprKey(node);
  return null;
}

// Hata toleransli visitor wrapper
function safe(fn) {
  return function (path) {
    try {
      fn.call(this, path);
    } catch (err) {
      if (!err.message?.includes("Duplicate declaration")) {
        errors.push(`Visitor hatasi: ${err.message?.slice(0, 100)}`);
      }
    }
  };
}

function safeVisitors(visitors) {
  const wrapped = {};
  for (const [key, fn] of Object.entries(visitors)) {
    wrapped[key] = safe(fn);
  }
  return wrapped;
}

// =====================================================================
// SCOPE-AWARE TRAVERSE
// =====================================================================

let scopeTraverseSuccess = false;
let identifiersProcessed = 0;

try {
  traverse(ast, safeVisitors({
    // --- Degisken tanimlari ---
    VariableDeclarator(path) {
      const id = path.node.id;
      const init = path.node.init;
      const declKind = path.parent.kind;

      if (id.type === "Identifier") {
        const info = getOrCreate(id.name, path);
        info.declaration = declKind;
        info.declarationLine = id.loc?.start?.line;
        info.bindingNode = id;

        if (init) {
          analyzeAssignment(info, init, path);
        }
      }

      // Destructuring: const {a, b} = obj
      if (id.type === "ObjectPattern" && init) {
        for (const prop of id.properties) {
          if (prop.type === "ObjectProperty" && prop.value?.type === "Identifier") {
            const info = getOrCreate(prop.value.name, path);
            info.declaration = declKind;
            info.declarationLine = prop.loc?.start?.line;
            info.destructuredFrom = init.type === "Identifier" ? init.name : null;

            if (prop.key?.type === "Identifier" && prop.key.name !== prop.value.name) {
              info.addEvidence("destructured_property", prop.key.name, 0.3);
              if (prop.key.name.length > 2) {
                info.suggestedName = prop.key.name;
              }
            }
          }
        }
      }

      // Array destructuring: const [a, b] = arr
      if (id.type === "ArrayPattern" && init) {
        for (let i = 0; i < id.elements.length; i++) {
          const elem = id.elements[i];
          if (elem?.type === "Identifier") {
            const info = getOrCreate(elem.name, path);
            info.declaration = declKind;
            info.declarationLine = elem.loc?.start?.line;

            if (
              init.type === "CallExpression" &&
              init.callee.type === "Identifier"
            ) {
              const hookName = init.callee.name;
              if (REACT_HOOKS[hookName]?.returns) {
                const returns = REACT_HOOKS[hookName].returns;
                if (Array.isArray(returns) && returns[i]) {
                  info.addEvidence(
                    "react_hook_destructure",
                    `${hookName}[${i}]`,
                    REACT_HOOKS[hookName].confidence
                  );
                  info.suggestedName = returns[i];
                  info.reactHook = hookName;
                }
              }
            }
          }
        }
      }
    },

    // --- Fonksiyon parametreleri ---
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression"(path) {
      const params = path.node.params;
      const parent = path.parent;

      for (let i = 0; i < params.length; i++) {
        const param = params[i];
        if (param.type !== "Identifier") continue;
        if (param.name.length > 2) continue;

        const info = getOrCreate(param.name, path);
        info.declaration = "param";
        info.declarationLine = param.loc?.start?.line;

        // Express handler tespiti
        if (parent.type === "CallExpression" && parent.callee?.type === "MemberExpression") {
          const methodName =
            parent.callee.property?.name || parent.callee.property?.value || "";
          const httpMethods = [
            "get", "post", "put", "delete", "patch",
            "use", "all", "options", "head",
          ];
          if (httpMethods.includes(methodName)) {
            const isErrorHandler = params.length === 4;
            const key = isErrorHandler ? "express_handler_4" : "express_handler_3";
            const names = PARAM_POSITION_RULES[key];
            if (names && names[i]) {
              info.addEvidence("express_handler", `${methodName}:position_${i}`, 0.3);
              info.suggestedName = names[i];
              info.expressPosition = i;
            }
          }
        }

        // Array method callback tespiti
        if (parent.type === "CallExpression" && parent.callee?.type === "MemberExpression") {
          const methodName =
            parent.callee.property?.name || parent.callee.property?.value || "";
          const arrayMethods = {
            map: "array_map",
            filter: "array_filter",
            reduce: "array_reduce",
            forEach: "array_forEach",
            find: "array_find",
            findIndex: "array_find",
            some: "array_filter",
            every: "array_filter",
            flatMap: "array_map",
            sort: "array_sort",
          };
          if (arrayMethods[methodName]) {
            const key = `${arrayMethods[methodName]}_${params.length}`;
            const names = PARAM_POSITION_RULES[key];
            if (names && names[i]) {
              info.addEvidence("array_method_param", `${methodName}:position_${i}`, 0.25);
              info.suggestedName = names[i];
              info.arrayMethodParam = methodName;
            }
          }
        }

        // Genel callback pattern
        if (
          !info.suggestedName &&
          parent.type === "CallExpression" &&
          params.length >= 2
        ) {
          const key = `callback_${params.length}`;
          const names = PARAM_POSITION_RULES[key];
          if (names && names[i]) {
            info.addEvidence("callback_param", `position_${i}`, 0.15);
            if (!info.suggestedName) {
              info.suggestedName = names[i];
            }
          }
        }

        // Event handler callback
        if (
          parent.type === "CallExpression" &&
          parent.callee?.type === "MemberExpression" &&
          (parent.callee.property?.name === "on" ||
            parent.callee.property?.name === "once" ||
            parent.callee.property?.name === "addEventListener") &&
          parent.arguments?.[0]?.type === "StringLiteral"
        ) {
          const eventName = parent.arguments[0].value;
          if (parent.arguments[1] === path.node) {
            if (i === 0) {
              info.addEvidence("event_handler_param", eventName, 0.25);
              info.suggestedName = "event";
              info.isEventHandler = true;
            }
          }
        }
      }
    },

    // --- Kullanim yerleri (SCOPE-AWARE) ---
    Identifier(path) {
      const name = path.node.name;
      if (name.length > 3) return;

      if (
        path.parent.type === "MemberExpression" &&
        path.parent.property === path.node &&
        !path.parent.computed
      ) {
        return;
      }
      if (
        path.parent.type === "ObjectProperty" &&
        path.parent.key === path.node &&
        !path.parent.computed
      ) {
        return;
      }
      if (path.parent.type === "LabeledStatement" || path.parent.type === "BreakStatement" || path.parent.type === "ContinueStatement") {
        return;
      }

      const info = getOrCreate(name, path);
      info.references++;
      identifiersProcessed++;
    },

    // --- Member expression ---
    MemberExpression(path) {
      const obj = path.node.object;
      const prop = path.node.property;

      if (obj.type === "Identifier" && obj.name.length <= 3) {
        const info = getOrCreate(obj.name, path);

        if (!path.node.computed && prop.type === "Identifier") {
          info.propertiesAccessed.add(prop.name);

          if (PROPERTY_HINTS[prop.name]) {
            const hint = PROPERTY_HINTS[prop.name];
            info.addEvidence("property_access", prop.name, hint.confidence);
          }

          if (
            path.parent.type === "CallExpression" &&
            path.parent.callee === path.node
          ) {
            info.methodsCalled.add(prop.name);
          }
        }
      }
    },

    // --- Call expression ---
    CallExpression(path) {
      const node = path.node;
      const callee = node.callee;

      if (callee.type === "MemberExpression" || callee.type === "Identifier") {
        const calleeKey = getCalleeKey(callee);

        for (let i = 0; i < node.arguments.length; i++) {
          const arg = node.arguments[i];
          if (arg.type !== "Identifier" || arg.name.length > 3) continue;

          const info = getOrCreate(arg.name, path);
          info.passedToFunctions.push({
            functionName: calleeKey || "unknown",
            position: i,
          });

          if (calleeKey) {
            const lastPart = calleeKey.split(".").pop();
            if (FUNCTION_PARAM_NAMES[lastPart]) {
              const paramNames = FUNCTION_PARAM_NAMES[lastPart];
              if (paramNames && Array.isArray(paramNames) && paramNames[i]) {
                info.addEvidence(
                  "passed_to_function",
                  `${calleeKey}:position_${i}`,
                  0.2
                );
                if (!info.suggestedName) {
                  info.suggestedName = paramNames[i];
                }
              }
            }
          }
        }
      }

      // Event handler: x.on('click', handler)
      if (
        callee.type === "MemberExpression" &&
        !callee.computed &&
        callee.property?.type === "Identifier" &&
        (callee.property.name === "on" ||
          callee.property.name === "once" ||
          callee.property.name === "addEventListener") &&
        node.arguments.length >= 2 &&
        node.arguments[0].type === "StringLiteral"
      ) {
        const handler = node.arguments[1];
        if (handler.type === "Identifier" && handler.name.length <= 3) {
          const info = getOrCreate(handler.name, path);
          const eventName = node.arguments[0].value;
          info.addEvidence("event_handler", eventName, 0.3);
          const safeEventName = eventName
            .replace(/[^a-zA-Z0-9]/g, ' ')
            .split(/\s+/)
            .filter(Boolean)
            .map((w) => capitalize(w))
            .join('');
          info.suggestedName = `on${safeEventName}`;
          info.isEventHandler = true;
        }
      }

      // Promise: x.then(y), x.catch(z)
      if (
        callee.type === "MemberExpression" &&
        !callee.computed &&
        callee.property?.type === "Identifier"
      ) {
        if (callee.property.name === "then" && node.arguments.length >= 1) {
          const resolver = node.arguments[0];
          if (resolver.type === "Identifier" && resolver.name.length <= 3) {
            const info = getOrCreate(resolver.name, path);
            info.addEvidence("promise_then", "resolver", 0.2);
            if (!info.suggestedName) info.suggestedName = "onResolve";
          }
          if (node.arguments.length >= 2) {
            const rejector = node.arguments[1];
            if (rejector.type === "Identifier" && rejector.name.length <= 3) {
              const info = getOrCreate(rejector.name, path);
              info.addEvidence("promise_then_reject", "rejector", 0.2);
              if (!info.suggestedName) info.suggestedName = "onReject";
            }
          }
        }
        if (callee.property.name === "catch" && node.arguments.length >= 1) {
          const handler = node.arguments[0];
          if (handler.type === "Identifier" && handler.name.length <= 3) {
            const info = getOrCreate(handler.name, path);
            info.addEvidence("promise_catch", "handler", 0.2);
            if (!info.suggestedName) info.suggestedName = "onError";
          }
        }
      }
    },

    // --- typeof ---
    UnaryExpression(path) {
      if (path.node.operator === "typeof" && path.node.argument?.type === "Identifier") {
        const name = path.node.argument.name;
        if (name.length <= 3) {
          if (
            path.parent.type === "BinaryExpression" &&
            (path.parent.operator === "===" || path.parent.operator === "==")
          ) {
            const other =
              path.parent.left === path.node
                ? path.parent.right
                : path.parent.left;
            if (other.type === "StringLiteral" && TYPE_CHECKS[other.value]) {
              const info = getOrCreate(name, path);
              info.typeofChecks.add(other.value);
              info.addEvidence("typeof_check", other.value, TYPE_CHECKS[other.value].confidence);
            }
          }
        }
      }

      if (
        path.node.operator === "!" &&
        path.node.argument?.type === "Identifier" &&
        path.node.argument.name.length <= 3
      ) {
        const info = getOrCreate(path.node.argument.name, path);
        info.addEvidence("negation", "boolean_hint", 0.1);
      }
    },

    // --- instanceof ---
    BinaryExpression(path) {
      if (path.node.operator === "instanceof") {
        const left = path.node.left;
        const right = path.node.right;
        if (left.type === "Identifier" && left.name.length <= 3 && right.type === "Identifier") {
          const info = getOrCreate(left.name, path);
          info.instanceofChecks.add(right.name);
          if (INSTANCEOF_NAMES[right.name]) {
            info.addEvidence(
              "instanceof_check",
              right.name,
              INSTANCEOF_NAMES[right.name].confidence
            );
            if (!info.suggestedName) {
              info.suggestedName = INSTANCEOF_NAMES[right.name].name;
            }
          }
        }
      }

      if (
        ["<", ">", "<=", ">="].includes(path.node.operator) &&
        path.node.left?.type === "Identifier" &&
        path.node.left.name.length <= 3 &&
        path.node.right?.type === "NumericLiteral"
      ) {
        const info = getOrCreate(path.node.left.name, path);
        info.addEvidence("numeric_comparison", `${path.node.operator}${path.node.right.value}`, 0.1);
      }
    },

    // --- Return ---
    ReturnStatement(path) {
      if (
        path.node.argument?.type === "Identifier" &&
        path.node.argument.name.length <= 3
      ) {
        const info = getOrCreate(path.node.argument.name, path);
        info.usedInReturn = true;
        info.addEvidence("return_value", "returned", 0.05);
      }
    },

    // --- Condition ---
    IfStatement(path) {
      if (path.node.test?.type === "Identifier" && path.node.test.name.length <= 3) {
        const info = getOrCreate(path.node.test.name, path);
        info.usedInCondition = true;
        info.addEvidence("condition_check", "if_test", 0.05);
      }
    },

    ConditionalExpression(path) {
      if (path.node.test?.type === "Identifier" && path.node.test.name.length <= 3) {
        const info = getOrCreate(path.node.test.name, path);
        info.usedInCondition = true;
        info.addEvidence("condition_check", "ternary_test", 0.05);
      }
    },

    // --- Assignment ---
    AssignmentExpression(path) {
      if (path.node.left?.type === "Identifier" && path.node.left.name.length <= 3) {
        const info = getOrCreate(path.node.left.name, path);
        analyzeAssignment(info, path.node.right, path);
      }
    },

    // --- For ---
    ForStatement(path) {
      if (
        path.node.init?.type === "VariableDeclaration" &&
        path.node.init.declarations.length === 1
      ) {
        const decl = path.node.init.declarations[0];
        if (decl.id?.type === "Identifier" && decl.id.name.length <= 2) {
          const info = getOrCreate(decl.id.name, path);
          info.addEvidence("for_loop_var", "loop_counter", 0.2);
          if (!info.suggestedName) {
            const indexNames = { i: "index", j: "innerIndex", k: "depthIndex" };
            info.suggestedName = indexNames[decl.id.name] || "loopIndex";
          }
        }
      }
    },

    ForInStatement(path) {
      if (path.node.left?.type === "VariableDeclaration") {
        const decl = path.node.left.declarations[0];
        if (decl?.id?.type === "Identifier" && decl.id.name.length <= 2) {
          const info = getOrCreate(decl.id.name, path);
          info.addEvidence("for_in_var", "property_key", 0.2);
          if (!info.suggestedName) info.suggestedName = "propertyKey";
        }
      }
    },

    ForOfStatement(path) {
      if (path.node.left?.type === "VariableDeclaration") {
        const decl = path.node.left.declarations[0];
        if (decl?.id?.type === "Identifier" && decl.id.name.length <= 2) {
          const info = getOrCreate(decl.id.name, path);
          info.addEvidence("for_of_var", "iterable_item", 0.15);
          if (!info.suggestedName) info.suggestedName = "item";
        }
      }
    },

    // --- Catch ---
    CatchClause(path) {
      const param = path.node.param;
      if (param?.type === "Identifier" && param.name.length <= 3) {
        const info = getOrCreate(param.name, path);
        info.declaration = "catch";
        info.addEvidence("catch_param", "error", 0.5);
        info.suggestedName = "caughtError";
      }
    },

    // --- Import ---
    ImportDeclaration(path) {
      const importSource = path.node.source.value;
      for (const specifier of path.node.specifiers) {
        if (specifier.local?.type === "Identifier" && specifier.local.name.length <= 3) {
          const info = getOrCreate(specifier.local.name, path);
          info.declaration = "import";
          info.requireSource = importSource;

          if (REQUIRE_NAMES[importSource]) {
            info.addEvidence("import_source", importSource, 0.5);
            info.suggestedName = REQUIRE_NAMES[importSource];
          }

          if (specifier.type === "ImportSpecifier" && specifier.imported?.name) {
            if (specifier.imported.name.length > 2) {
              info.addEvidence("import_named", specifier.imported.name, 0.3);
              info.suggestedName = specifier.imported.name;
            }
          }
        }
      }
    },
  }));

  scopeTraverseSuccess = true;
  console.error(`[scope-traverse] BASARILI - ${identifiersProcessed} identifier islendi, ${variables.size} unique variable`);

} catch (err) {
  console.error(`[scope-traverse] BASARISIZ: ${err.message}`);
  errors.push(`Scope traverse hatasi: ${err.message}`);

  // Fallback: noScope traverse
  console.error(`[fallback] noScope traverse'a donuluyor...`);
  try {
    traverse(ast, { noScope: true, ...safeVisitors({
      VariableDeclarator(path) {
        const id = path.node.id;
        const init = path.node.init;
        const declKind = path.parent.kind;
        if (id.type === "Identifier") {
          const info = getOrCreate(id.name, path);
          info.declaration = declKind;
          info.declarationLine = id.loc?.start?.line;
          if (init) analyzeAssignment(info, init, path);
        }
      },
      Identifier(path) {
        const name = path.node.name;
        if (name.length > 3) return;
        if (path.parent.type === "MemberExpression" && path.parent.property === path.node && !path.parent.computed) return;
        if (path.parent.type === "ObjectProperty" && path.parent.key === path.node && !path.parent.computed) return;
        if (path.parent.type === "LabeledStatement" || path.parent.type === "BreakStatement" || path.parent.type === "ContinueStatement") return;
        const info = getOrCreate(name, path);
        info.references++;
        identifiersProcessed++;
      },
      MemberExpression(path) {
        const obj = path.node.object;
        const prop = path.node.property;
        if (obj.type === "Identifier" && obj.name.length <= 3) {
          const info = getOrCreate(obj.name, path);
          if (!path.node.computed && prop.type === "Identifier") {
            info.propertiesAccessed.add(prop.name);
            if (PROPERTY_HINTS[prop.name]) {
              info.addEvidence("property_access", prop.name, PROPERTY_HINTS[prop.name].confidence);
            }
            if (path.parent.type === "CallExpression" && path.parent.callee === path.node) {
              info.methodsCalled.add(prop.name);
            }
          }
        }
      },
      CallExpression(path) {
        const node = path.node;
        const callee = node.callee;
        if (callee.type === "MemberExpression" || callee.type === "Identifier") {
          const calleeKey = getCalleeKey(callee);
          for (let i = 0; i < node.arguments.length; i++) {
            const arg = node.arguments[i];
            if (arg.type !== "Identifier" || arg.name.length > 3) continue;
            const info = getOrCreate(arg.name, path);
            info.passedToFunctions.push({ functionName: calleeKey || "unknown", position: i });
          }
        }
      },
      AssignmentExpression(path) {
        if (path.node.left?.type === "Identifier" && path.node.left.name.length <= 3) {
          const info = getOrCreate(path.node.left.name, path);
          analyzeAssignment(info, path.node.right, path);
        }
      },
      CatchClause(path) {
        const param = path.node.param;
        if (param?.type === "Identifier" && param.name.length <= 3) {
          const info = getOrCreate(param.name, path);
          info.declaration = "catch";
          info.addEvidence("catch_param", "error", 0.5);
          info.suggestedName = "caughtError";
        }
      },
    })});
    console.error(`[fallback] noScope traverse tamamlandi - ${identifiersProcessed} identifier`);
  } catch (err2) {
    errors.push(`Fallback traverse hatasi: ${err2.message}`);
  }
}

// =====================================================================
// Atama analizi (data flow tracking)
// =====================================================================

function analyzeAssignment(info, initNode, path, depth = 0) {
  if (!initNode || depth > 3) return;

  // require('module')
  if (
    initNode.type === "CallExpression" &&
    initNode.callee?.type === "Identifier" &&
    initNode.callee.name === "require" &&
    initNode.arguments.length >= 1 &&
    initNode.arguments[0].type === "StringLiteral"
  ) {
    const moduleName = initNode.arguments[0].value;
    info.requireSource = moduleName;
    info.assignedFrom = `require('${moduleName}')`;
    info.assignedFromChain.push(`require('${moduleName}')`);

    if (REQUIRE_NAMES[moduleName]) {
      info.addEvidence("require_source", moduleName, 0.5);
      info.suggestedName = REQUIRE_NAMES[moduleName];
    } else {
      const parts = moduleName.split("/");
      const lastPart = parts[parts.length - 1]
        .replace(/[^a-zA-Z0-9]/g, "")
        .replace(/^[0-9]/, "_$&");
      if (lastPart && lastPart.length > 1) {
        info.addEvidence("require_unknown", moduleName, 0.15);
        info.suggestedName = camelCase(lastPart) + "Module";
      }
    }
    return;
  }

  // new Constructor()
  if (initNode.type === "NewExpression" && initNode.callee?.type === "Identifier") {
    const ctorName = initNode.callee.name;
    info.constructorSource = ctorName;
    info.assignedFrom = `new ${ctorName}()`;
    info.assignedFromChain.push(`new ${ctorName}()`);

    if (CONSTRUCTOR_NAMES[ctorName]) {
      info.addEvidence("constructor", ctorName, 0.4);
      if (!info.suggestedName) {
        info.suggestedName = CONSTRUCTOR_NAMES[ctorName];
      }
    } else if (ctorName.length > 2) {
      info.addEvidence("constructor_unknown", ctorName, 0.15);
      if (!info.suggestedName) {
        info.suggestedName = ctorName.charAt(0).toLowerCase() + ctorName.slice(1) + "Instance";
      }
    }
    return;
  }

  // Global fonksiyon cagrisi
  if (initNode.type === "CallExpression") {
    const calleeKey = getCalleeKey(initNode.callee);
    if (calleeKey && GLOBAL_FUNCTION_RETURNS[calleeKey]) {
      info.globalFunctionReturn = calleeKey;
      info.assignedFrom = `${calleeKey}()`;
      info.assignedFromChain.push(`${calleeKey}()`);
      info.addEvidence("global_function_return", calleeKey, 0.25);
      if (!info.suggestedName) {
        info.suggestedName = GLOBAL_FUNCTION_RETURNS[calleeKey];
      }
      return;
    }

    if (initNode.callee?.type === "MemberExpression") {
      const methodName = initNode.callee.property?.name;
      if (methodName) {
        info.assignedFrom = `*.${methodName}()`;
        info.assignedFromChain.push(`*.${methodName}()`);

        const allMethodReturns = {
          readFileSync: "fileContent", readFile: "fileContent",
          readdir: "directoryEntries", readdirSync: "directoryEntries",
          stat: "fileStats", statSync: "fileStats",
          lstat: "fileLinkStats", lstatSync: "fileLinkStats",
          realpath: "realPath", realpathSync: "realPath",
          existsSync: "fileExists",
          createReadStream: "readStream", createWriteStream: "writeStream",
          join: "joinedPath", resolve: "resolvedPath",
          dirname: "directoryName", basename: "fileName",
          extname: "fileExtension", parse: "parsedPath",
          relative: "relativePath", normalize: "normalizedPath",
          isAbsolute: "isAbsolutePath",
          split: "splitParts", trim: "trimmedText",
          replace: "replacedText", replaceAll: "replacedText",
          slice: "slicedText", substring: "substringText",
          toLowerCase: "lowerText", toUpperCase: "upperText",
          match: "matchResult", toString: "stringValue",
          concat: "concatenated", padStart: "paddedText", padEnd: "paddedText",
          map: "mappedItems", filter: "filteredItems",
          reduce: "reducedValue", find: "foundItem",
          findIndex: "foundIndex", flat: "flattenedArray",
          flatMap: "flatMappedItems", sort: "sortedItems",
          reverse: "reversedItems", splice: "splicedItems",
          entries: "entryIterator", keys: "keyIterator",
          values: "valueIterator", from: "convertedArray",
        };

        if (allMethodReturns[methodName]) {
          info.addEvidence("method_return", methodName, 0.2);
          if (!info.suggestedName) {
            info.suggestedName = allMethodReturns[methodName];
          }
        }
      }
    }

    if (initNode.callee?.type === "Identifier") {
      const hookName = initNode.callee.name;
      if (REACT_HOOKS[hookName] && !Array.isArray(REACT_HOOKS[hookName].returns)) {
        info.addEvidence("react_hook", hookName, REACT_HOOKS[hookName].confidence);
        if (!info.suggestedName && typeof REACT_HOOKS[hookName].returns === "string") {
          info.suggestedName = REACT_HOOKS[hookName].returns;
        }
      }
    }

    return;
  }

  if (initNode.type === "ArrayExpression") {
    info.addEvidence("array_literal", "array", 0.15);
    if (!info.suggestedName) info.suggestedName = "items";
    return;
  }

  if (initNode.type === "ObjectExpression") {
    info.addEvidence("object_literal", "object", 0.1);
    const propNames = initNode.properties
      .filter((p) => p.key?.type === "Identifier")
      .map((p) => p.key.name);

    if (propNames.some((n) => ["host", "port", "hostname", "protocol"].includes(n))) {
      info.addEvidence("object_shape_config", "server_config", 0.2);
      if (!info.suggestedName) info.suggestedName = "serverConfig";
    } else if (propNames.some((n) => ["username", "password", "email"].includes(n))) {
      info.addEvidence("object_shape_credentials", "credentials", 0.2);
      if (!info.suggestedName) info.suggestedName = "credentials";
    } else if (propNames.some((n) => ["width", "height", "x", "y"].includes(n))) {
      info.addEvidence("object_shape_dimensions", "dimensions", 0.2);
      if (!info.suggestedName) info.suggestedName = "dimensions";
    } else if (propNames.some((n) => ["name", "version", "description"].includes(n))) {
      info.addEvidence("object_shape_metadata", "metadata", 0.15);
      if (!info.suggestedName) info.suggestedName = "metadata";
    }
    return;
  }

  if (initNode.type === "StringLiteral") {
    info.addEvidence("string_literal", "string", 0.1);
    const val = initNode.value;
    if (val.startsWith("http://") || val.startsWith("https://")) {
      if (!info.suggestedName) info.suggestedName = "urlString";
    } else if (val.startsWith("/") || val.includes("\\")) {
      if (!info.suggestedName) info.suggestedName = "pathString";
    }
    return;
  }

  if (initNode.type === "NumericLiteral") {
    info.addEvidence("numeric_literal", "number", 0.1);
    return;
  }

  if (initNode.type === "BooleanLiteral") {
    info.addEvidence("boolean_literal", "boolean", 0.15);
    if (!info.suggestedName) info.suggestedName = "flag";
    return;
  }

  if (initNode.type === "NullLiteral") {
    info.addEvidence("null_literal", "nullable", 0.05);
    return;
  }

  if (initNode.type === "TemplateLiteral") {
    info.addEvidence("template_literal", "string", 0.15);
    if (!info.suggestedName) info.suggestedName = "formattedText";
    return;
  }

  if (initNode.type === "RegExpLiteral") {
    info.addEvidence("regexp_literal", "regex", 0.25);
    if (!info.suggestedName) info.suggestedName = "pattern";
    return;
  }

  if (initNode.type === "SpreadElement") {
    info.assignedFrom = `...spread`;
    info.addEvidence("spread_operation", "spread", 0.1);
    return;
  }

  if (initNode.type === "Identifier" && depth < 3) {
    info.assignedFrom = initNode.name;
    info.assignedFromChain.push(initNode.name);
    return;
  }

  if (initNode.type === "MemberExpression") {
    const key = getMemberExprKey(initNode);
    if (key) {
      info.assignedFrom = key;
      info.assignedFromChain.push(key);
      if (key === "process.env") {
        info.addEvidence("process_env", "environment", 0.25);
        if (!info.suggestedName) info.suggestedName = "envVars";
      }
      if (key === "process.argv") {
        info.addEvidence("process_argv", "arguments", 0.25);
        if (!info.suggestedName) info.suggestedName = "commandArgs";
      }
      if (key === "module.exports") {
        info.addEvidence("module_exports", "exports", 0.2);
        if (!info.suggestedName) info.suggestedName = "moduleExports";
      }
    }
    return;
  }

  if (initNode.type === "AwaitExpression") {
    analyzeAssignment(info, initNode.argument, path, depth + 1);
    return;
  }

  if (
    initNode.type === "ArrowFunctionExpression" ||
    initNode.type === "FunctionExpression"
  ) {
    info.addEvidence("function_value", "callback", 0.1);
    if (!info.suggestedName) info.suggestedName = "handler";
    return;
  }

  if (
    initNode.type === "LogicalExpression" &&
    (initNode.operator === "||" || initNode.operator === "??")
  ) {
    analyzeAssignment(info, initNode.left, path, depth + 1);
    return;
  }

  if (initNode.type === "ConditionalExpression") {
    analyzeAssignment(info, initNode.consequent, path, depth + 1);
    return;
  }
}

// =====================================================================
// PASS 2: Isim cikarimi ve confidence hesaplama
// =====================================================================

function resolveVariableName(info) {
  if (info.suggestedName && info.confidence >= 0.3) {
    return info.suggestedName;
  }

  if (info.propertiesAccessed.size > 0) {
    const typeScores = {};
    for (const prop of info.propertiesAccessed) {
      if (PROPERTY_HINTS[prop]) {
        const hint = PROPERTY_HINTS[prop];
        typeScores[hint.type] = (typeScores[hint.type] || 0) + hint.confidence;
      }
    }

    const bestType = Object.entries(typeScores).sort((a, b) => b[1] - a[1])[0];
    if (bestType && bestType[1] > 0.3) {
      const typeNameMap = {
        array: "items", array_or_string: null, string: "text",
        promise: "pendingPromise", event_emitter: "emitter",
        stream: "dataStream", writable: "writer", readable: "reader",
        response: "response", request: "request", request_response: null,
        dom_element: "element", map_set: "collection", map_or_object: null,
        set: "uniqueSet", config: "config", options: "options",
        error: "error", error_or_message: null, error_or_status: null,
        closable: "handle", class: null, function: "handler",
        iterator: "iterator", iterable: "iterable",
      };

      if (!info.suggestedName && typeNameMap[bestType[0]]) {
        info.suggestedName = typeNameMap[bestType[0]];
        info.addEvidence("property_type_inference", bestType[0], 0.15);
      }
    }
  }

  if (info.typeofChecks.size > 0 && !info.suggestedName) {
    const typeCheck = [...info.typeofChecks][0];
    if (TYPE_CHECKS[typeCheck]) {
      info.suggestedName = info.name + TYPE_CHECKS[typeCheck].suffix;
    }
  }

  if (info.instanceofChecks.size > 0 && !info.suggestedName) {
    const instCheck = [...info.instanceofChecks][0];
    if (INSTANCEOF_NAMES[instCheck]) {
      info.suggestedName = INSTANCEOF_NAMES[instCheck].name;
    }
  }

  if (!info.suggestedName && info.passedToFunctions.length > 0) {
    for (const usage of info.passedToFunctions) {
      const lastPart = usage.functionName.split(".").pop();
      if (FUNCTION_PARAM_NAMES[lastPart]) {
        const paramNames = FUNCTION_PARAM_NAMES[lastPart];
        if (paramNames && Array.isArray(paramNames) && paramNames[usage.position]) {
          info.suggestedName = paramNames[usage.position];
          info.addEvidence("function_param_name", `${usage.functionName}:${usage.position}`, 0.15);
          break;
        }
      }
    }
  }

  if (!info.suggestedName && info.methodsCalled.size > 0) {
    const methodArray = [...info.methodsCalled];
    if (methodArray.some((m) => ["send", "json", "status", "render", "redirect"].includes(m))) {
      info.suggestedName = "response";
    } else if (
      methodArray.some((m) => ["get", "post", "put", "delete", "patch"].includes(m)) &&
      !methodArray.some((m) => ["push", "pop", "map", "filter"].includes(m))
    ) {
      info.suggestedName = "httpClient";
    }
  }

  if (!info.suggestedName && info.name.length === 1) {
    const letterDefaults = {
      a: "arg", b: "buffer", c: "count", d: "data",
      e: "element", f: "fn", g: "group", h: "handler",
      i: "index", j: "innerIndex", k: "key", l: "length",
      m: "moduleRef", n: "num", o: "obj", p: "param",
      q: "query", r: "result", s: "str", t: "temp",
      u: "user", v: "value", w: "writer", x: "posX",
      y: "posY", z: "posZ", _: "unused", $: "jQueryRef",
    };
    info.suggestedName =
      letterDefaults[info.name.toLowerCase()] || `var_${info.name}`;
    info.addEvidence("single_letter_fallback", info.name, 0.05);
  }

  return info.suggestedName;
}

// =====================================================================
// PASS 3: Resolve + cakisma kontrolu
// =====================================================================

for (const [key, info] of variables) {
  resolveVariableName(info);
}

const scopeNameUsage = new Map();

for (const [key, info] of variables) {
  if (!info.suggestedName) continue;
  if (info.name === info.suggestedName) continue;
  if (info.name.length > 3) continue;

  const scopeId = info.scopeId;
  if (!scopeNameUsage.has(scopeId)) {
    scopeNameUsage.set(scopeId, new Set());
  }

  const usedInScope = scopeNameUsage.get(scopeId);
  let finalName = info.suggestedName;
  let suffix = 2;

  while (usedInScope.has(finalName)) {
    finalName = `${info.suggestedName}${suffix}`;
    suffix++;
  }

  usedInScope.add(finalName);
  info.suggestedName = finalName;
}

// =====================================================================
// CIKTI OLUSTUR (SCOPE-AWARE FORMAT)
// =====================================================================

const outputVariables = {};
let totalVars = 0;
let highConfidence = 0;
let mediumConfidence = 0;
let lowConfidence = 0;
let unnamed = 0;

for (const [key, info] of variables) {
  totalVars++;

  if (info.name.length > 3) continue;
  if (!info.suggestedName || info.suggestedName === info.name) {
    unnamed++;
    continue;
  }

  const conf = Math.min(info.confidence, 1.0);
  if (conf >= 0.5) highConfidence++;
  else if (conf >= 0.2) mediumConfidence++;
  else lowConfidence++;

  outputVariables[key] = {
    original_name: info.name,
    scope: info.scopeId,
    declaration: info.declaration,
    line: info.declarationLine,
    references: info.references,
    suggested_name: info.suggestedName,
    confidence: Math.round(conf * 100) / 100,
    evidence: info.evidence.map((e) => ({
      type: e.type,
      value: e.value,
      confidence: Math.round(e.confidence * 100) / 100,
    })),
    data_flow: {
      assigned_from: info.assignedFrom,
      chain: info.assignedFromChain,
      properties_accessed: [...info.propertiesAccessed],
      methods_called: [...info.methodsCalled],
      passed_to: info.passedToFunctions.slice(0, 10),
      typeof_checks: [...info.typeofChecks],
      instanceof_checks: [...info.instanceofChecks],
      require_source: info.requireSource,
      constructor_source: info.constructorSource,
      global_function_return: info.globalFunctionReturn,
      used_in_return: info.usedInReturn,
      used_in_condition: info.usedInCondition,
    },
  };
}

// Geriye uyumlu flat variables (apply-names.mjs icin)
const bestNameForVar = new Map();
const scopeRenames = [];

for (const [key, info] of variables) {
  if (info.name.length > 3) continue;
  if (!info.suggestedName || info.suggestedName === info.name) continue;

  scopeRenames.push({
    originalName: info.name,
    newName: info.suggestedName,
    scopeId: info.scopeId,
    line: info.declarationLine,
    confidence: Math.min(info.confidence, 1.0),
  });

  const existing = bestNameForVar.get(info.name);
  if (!existing || info.confidence > existing.confidence) {
    bestNameForVar.set(info.name, {
      suggestedName: info.suggestedName,
      confidence: info.confidence,
    });
  }
}

const flatVariables = {};
for (const [name, best] of bestNameForVar) {
  flatVariables[name] = {
    scope: "best_match",
    declaration: null,
    line: null,
    references: 0,
    suggested_name: best.suggestedName,
    confidence: Math.round(Math.min(best.confidence, 1.0) * 100) / 100,
    evidence: [],
    data_flow: {},
  };
}

const result = {
  success: true,
  scope_aware: scopeTraverseSuccess,
  duplicates_fixed: duplicatesFixed,
  variables: flatVariables,
  scope_variables: outputVariables,
  scope_renames: scopeRenames,
  stats: {
    total_variables: totalVars,
    short_variables: Object.keys(outputVariables).length + unnamed,
    unique_scoped_entries: Object.keys(outputVariables).length,
    named_high_confidence: highConfidence,
    named_medium_confidence: mediumConfidence,
    named_low_confidence: lowConfidence,
    unnamed: unnamed,
    total_named: highConfidence + mediumConfidence + lowConfidence,
    scope_aware: scopeTraverseSuccess,
    duplicates_fixed: duplicatesFixed,
    identifiers_processed: identifiersProcessed,
    rule_categories: {
      A_require_import: Object.keys(REQUIRE_NAMES).length,
      B_param_position: Object.keys(PARAM_POSITION_RULES).length,
      C_property_hints: Object.keys(PROPERTY_HINTS).length,
      D_type_checks: Object.keys(TYPE_CHECKS).length + Object.keys(INSTANCEOF_NAMES).length,
      E_constructors: Object.keys(CONSTRUCTOR_NAMES).length + Object.keys(GLOBAL_FUNCTION_RETURNS).length,
      F_function_params: Object.keys(FUNCTION_PARAM_NAMES).length,
      G_react_hooks: Object.keys(REACT_HOOKS).length + Object.keys(REACT_ELEMENT_PARAMS).length,
    },
  },
  errors,
};

try {
  writeFileSync(outputPath, JSON.stringify(result, null, 2), "utf-8");
} catch (err) {
  errors.push(`Cikti dosyasi yazilamadi: ${err.message}`);
}

process.stdout.write(JSON.stringify(result) + "\n");

// =====================================================================
// HELPERS
// =====================================================================

function capitalize(str) {
  if (!str) return "";
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function camelCase(str) {
  if (!str) return "";
  return str
    .replace(/[-_\s]+(.)?/g, (_, c) => (c ? c.toUpperCase() : ""))
    .replace(/^[A-Z]/, (c) => c.toLowerCase());
}
