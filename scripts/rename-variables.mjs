#!/usr/bin/env node
/**
 * rename-variables.mjs -- Babel AST ile akilli variable renaming
 *
 * Tek harfli veya anlamsiz degisken isimlerini baglamsal analiz ile
 * anlamli isimlere donusturur.
 *
 * Kullanim:
 *   node rename-variables.mjs <input-file> <output-file> [--context <json-file>]
 *
 * Cikti (stdout JSON):
 *   {
 *     "success": true,
 *     "renamed": 42,
 *     "mappings": {"e": "request", "t": "response", ...},
 *     "output": "/path/to/output.js"
 *   }
 *
 * Renaming stratejileri:
 *   1. require('X') -> modul adi bazli (require('fs') -> fileSystem)
 *   2. Parametre pozisyonu: (e, t, n) -> express callback ise (req, res, next)
 *   3. Kullanim analizi: x.length -> array/string, x.push -> array
 *   4. React pattern: React.createElement(x, y, z) -> (component, props, children)
 *   5. Event handler: x.on('y', z) -> z = yHandler
 *   6. Promise: x.then(y) -> y = onResolve
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve, basename, extname } from "node:path";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import _generate from "@babel/generator";

const traverse = _traverse.default || _traverse;
const generate = _generate.default || _generate;

// --- CLI ---
const args = process.argv.slice(2);
const positional = args.filter((a) => !a.startsWith("--"));
const contextIdx = args.indexOf("--context");

if (positional.length < 2) {
  const result = {
    success: false,
    renamed: 0,
    mappings: {},
    errors: ["Kullanim: node rename-variables.mjs <input-file> <output-file> [--context <json-file>]"],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const inputPath = resolve(positional[0]);
const outputPath = resolve(positional[1]);

// Opsiyonel context (statik analiz sonuclari)
let externalContext = {};
if (contextIdx !== -1 && args[contextIdx + 1]) {
  try {
    externalContext = JSON.parse(readFileSync(resolve(args[contextIdx + 1]), "utf-8"));
  } catch (_) {
    // Context okunamazsa devam et
  }
}

// --- Kaynak oku ---
let source;
try {
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  const result = {
    success: false,
    renamed: 0,
    mappings: {},
    errors: [`Dosya okunamadi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

// --- Bilinen modul isimleri ---
const MODULE_NAME_MAP = {
  fs: "fileSystem",
  path: "pathUtils",
  os: "operatingSystem",
  http: "httpModule",
  https: "httpsModule",
  url: "urlModule",
  crypto: "cryptoModule",
  events: "eventEmitter",
  stream: "streamModule",
  util: "utilModule",
  child_process: "childProcess",
  cluster: "clusterModule",
  net: "netModule",
  dns: "dnsModule",
  tls: "tlsModule",
  zlib: "zlibModule",
  readline: "readlineModule",
  querystring: "queryStringModule",
  express: "app",
  react: "React",
  "react-dom": "ReactDOM",
  axios: "httpClient",
  lodash: "lodashUtils",
  _: "lodashUtils",
  moment: "momentDate",
  chalk: "colorOutput",
  commander: "cliProgram",
  yargs: "cliArgs",
  mongoose: "mongooseDb",
  sequelize: "sequelizeOrm",
  "socket.io": "socketIO",
  cors: "corsMiddleware",
  helmet: "helmetSecurity",
  morgan: "morganLogger",
  winston: "winstonLogger",
  dotenv: "dotenvConfig",
  joi: "joiValidator",
  bcrypt: "bcryptHash",
  jsonwebtoken: "jwtToken",
  passport: "passportAuth",
  multer: "multerUpload",
  nodemailer: "nodeMailer",
  redis: "redisClient",
  pg: "postgresClient",
  mysql: "mysqlClient",
  "body-parser": "bodyParser",
  "cookie-parser": "cookieParser",
};

// Express callback pattern: (e, t, n) -> (req, res, next)
const EXPRESS_PARAMS = ["request", "response", "next"];
// Error middleware: (e, t, n, r) -> (error, req, res, next)
const EXPRESS_ERROR_PARAMS = ["error", "request", "response", "next"];

// --- Parse ---
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
      "dynamicImport",
      "optionalChaining",
      "nullishCoalescingOperator",
    ],
  });
} catch (err) {
  const result = {
    success: false,
    renamed: 0,
    mappings: {},
    errors: [`Parse hatasi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
}

// --- Analiz: degisken kullanim bilgisi topla ---
const varInfo = new Map(); // bindingId -> {usages: Set<string>, requireSource: string|null, ...}

// Ilk pass: bilgi topla
try {
  traverse(ast, {
    // require('X') pattern'i
    VariableDeclarator(path) {
      const init = path.node.init;
      if (!init) return;

      // const X = require('module')
      if (
        init.type === "CallExpression" &&
        init.callee.type === "Identifier" &&
        init.callee.name === "require" &&
        init.arguments.length === 1 &&
        init.arguments[0].type === "StringLiteral"
      ) {
        const id = path.node.id;
        if (id.type === "Identifier") {
          const binding = path.scope.getBinding(id.name);
          if (binding) {
            ensureVarInfo(id.name);
            varInfo.get(id.name).requireSource = init.arguments[0].value;
          }
        }
      }
    },

    // Fonksiyon parametreleri
    "FunctionDeclaration|FunctionExpression|ArrowFunctionExpression"(path) {
      const params = path.node.params;
      const body = path.node.body;

      // Express middleware tespiti: app.use, app.get, router.post, vb.
      const parent = path.parent;
      let isExpressHandler = false;
      let isErrorHandler = false;

      if (parent.type === "CallExpression") {
        const callee = parent.callee;
        if (callee.type === "MemberExpression" && callee.property) {
          const methodName = callee.property.name || callee.property.value || "";
          const httpMethods = ["get", "post", "put", "delete", "patch", "use", "all"];
          if (httpMethods.includes(methodName)) {
            isExpressHandler = true;
            isErrorHandler = params.length === 4;
          }
        }
      }

      // React.createElement pattern tespiti
      let isReactCreateElement = false;
      if (parent.type === "CallExpression" && parent.callee.type === "MemberExpression") {
        const obj = parent.callee.object;
        const prop = parent.callee.property;
        if (
          obj.type === "Identifier" &&
          obj.name === "React" &&
          prop.type === "Identifier" &&
          prop.name === "createElement"
        ) {
          isReactCreateElement = true;
        }
      }

      // Parametreleri isimlendir
      for (let i = 0; i < params.length; i++) {
        const param = params[i];
        if (param.type !== "Identifier") continue;
        if (param.name.length > 2) continue; // Zaten anlamli isim

        ensureVarInfo(param.name);
        const info = varInfo.get(param.name);

        if (isExpressHandler) {
          if (isErrorHandler) {
            info.suggestedName = EXPRESS_ERROR_PARAMS[i] || null;
          } else {
            info.suggestedName = EXPRESS_PARAMS[i] || null;
          }
          info.context = "express_handler";
        }

        if (isReactCreateElement) {
          const reactParamNames = ["component", "props", "children"];
          info.suggestedName = reactParamNames[i] || null;
          info.context = "react_createElement";
        }
      }

      // Parametre kullanim analizi
      for (const param of params) {
        if (param.type !== "Identifier") continue;
        analyzeUsages(path, param.name);
      }
    },

    // Event handler tespiti: x.on('event', handler)
    CallExpression(path) {
      const node = path.node;
      if (
        node.callee.type === "MemberExpression" &&
        node.callee.property.type === "Identifier" &&
        node.callee.property.name === "on" &&
        node.arguments.length >= 2 &&
        node.arguments[0].type === "StringLiteral"
      ) {
        const eventName = node.arguments[0].value;
        const handler = node.arguments[1];
        if (handler.type === "Identifier" && handler.name.length <= 2) {
          ensureVarInfo(handler.name);
          const info = varInfo.get(handler.name);
          info.suggestedName = `on${capitalize(eventName)}`;
          info.context = "event_handler";
        }
      }

      // Promise pattern: x.then(y) -> y = onResolve
      if (
        node.callee.type === "MemberExpression" &&
        node.callee.property.type === "Identifier" &&
        node.callee.property.name === "then" &&
        node.arguments.length >= 1
      ) {
        const resolver = node.arguments[0];
        if (resolver.type === "Identifier" && resolver.name.length <= 2) {
          ensureVarInfo(resolver.name);
          varInfo.get(resolver.name).suggestedName = "onResolve";
          varInfo.get(resolver.name).context = "promise_then";
        }
        if (node.arguments.length >= 2) {
          const rejector = node.arguments[1];
          if (rejector.type === "Identifier" && rejector.name.length <= 2) {
            ensureVarInfo(rejector.name);
            varInfo.get(rejector.name).suggestedName = "onReject";
            varInfo.get(rejector.name).context = "promise_then";
          }
        }
      }

      // .catch(handler) pattern
      if (
        node.callee.type === "MemberExpression" &&
        node.callee.property.type === "Identifier" &&
        node.callee.property.name === "catch" &&
        node.arguments.length >= 1
      ) {
        const handler = node.arguments[0];
        if (handler.type === "Identifier" && handler.name.length <= 2) {
          ensureVarInfo(handler.name);
          varInfo.get(handler.name).suggestedName = "onError";
          varInfo.get(handler.name).context = "promise_catch";
        }
      }
    },
  });
} catch (err) {
  errors.push(`Analiz traversal hatasi: ${err.message}`);
}

// --- Renaming kararlarini olustur ---
const mappings = {};
const usedNames = new Set();

for (const [originalName, info] of varInfo.entries()) {
  // Zaten anlamli isim (3+ karakter ve bazi ozel durumlar haric)
  if (originalName.length > 2 && !info.requireSource) continue;

  let newName = null;

  // 1. require() bazli isimlendirme
  if (info.requireSource) {
    const moduleName = info.requireSource;
    // Bilinen modul mu?
    if (MODULE_NAME_MAP[moduleName]) {
      newName = MODULE_NAME_MAP[moduleName];
    } else {
      // Bilinmeyen modul: modul adinin son parcasini kullan
      const parts = moduleName.split("/");
      const lastPart = parts[parts.length - 1]
        .replace(/[^a-zA-Z0-9]/g, "")
        .replace(/^[0-9]/, "_$&");
      if (lastPart) {
        newName = camelCase(lastPart) + "Module";
      }
    }
  }

  // 2. Onerilen isim (express, react, event handler, promise)
  if (!newName && info.suggestedName) {
    newName = info.suggestedName;
  }

  // 3. Kullanim bazli cikarim
  if (!newName && info.usages.size > 0) {
    newName = inferFromUsages(originalName, info.usages);
  }

  // 4. Genel fallback: tek harfli degiskenlere semantik isim
  if (!newName && originalName.length === 1) {
    const letterDefaults = {
      a: "arg",
      b: "buffer",
      c: "count",
      d: "data",
      e: "element",
      f: "fn",
      g: "group",
      h: "handler",
      i: "index",
      j: "innerIndex",
      k: "key",
      l: "length",
      m: "module",
      n: "num",
      o: "obj",
      p: "param",
      q: "query",
      r: "result",
      s: "str",
      t: "temp",
      u: "user",
      v: "value",
      w: "writer",
      x: "posX",
      y: "posY",
      z: "posZ",
    };
    newName = letterDefaults[originalName.toLowerCase()] || `var_${originalName}`;
  }

  if (newName && newName !== originalName) {
    // Cakisma kontrolu
    let finalName = newName;
    let suffix = 2;
    while (usedNames.has(finalName)) {
      finalName = `${newName}${suffix}`;
      suffix++;
    }
    usedNames.add(finalName);
    mappings[originalName] = finalName;
  }
}

// --- Ikinci pass: rename uygula ---
let renameCount = 0;

try {
  traverse(ast, {
    Identifier(path) {
      const name = path.node.name;
      if (!mappings[name]) return;

      // Sadece binding'e sahip identifier'lari rename et
      const binding = path.scope.getBinding(name);
      if (!binding) return;

      // Property erisimleri haric (obj.x'deki x'i degistirme)
      if (
        path.parent.type === "MemberExpression" &&
        path.parent.property === path.node &&
        !path.parent.computed
      ) {
        return;
      }

      // Object property key'leri haric
      if (
        path.parent.type === "ObjectProperty" &&
        path.parent.key === path.node &&
        !path.parent.computed
      ) {
        return;
      }

      path.node.name = mappings[name];
      renameCount++;
    },
  });
} catch (err) {
  errors.push(`Rename traversal hatasi: ${err.message}`);
}

// --- Cikti uret ---
try {
  const { code } = generate(ast, {
    comments: true,
    compact: false,
    concise: false,
    retainLines: true,
  });

  writeFileSync(outputPath, code, "utf-8");

  const result = {
    success: true,
    renamed: Object.keys(mappings).length,
    mappings,
    output: outputPath,
    errors,
  };
  process.stdout.write(JSON.stringify(result) + "\n");
} catch (err) {
  const result = {
    success: false,
    renamed: 0,
    mappings,
    errors: [...errors, `Code generation hatasi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
}

// --- Helpers ---

function ensureVarInfo(name) {
  if (!varInfo.has(name)) {
    varInfo.set(name, {
      usages: new Set(),
      requireSource: null,
      suggestedName: null,
      context: null,
    });
  }
}

function analyzeUsages(functionPath, paramName) {
  // Fonksiyon body'si icinde parametrenin nasil kullanildigini analiz et
  const body = functionPath.node.body;
  if (!body) return;

  ensureVarInfo(paramName);
  const info = varInfo.get(paramName);

  // Basit text-based analiz (AST traverse icinde kullaniyoruz zaten)
  try {
    functionPath.traverse({
      MemberExpression(innerPath) {
        if (
          innerPath.node.object.type === "Identifier" &&
          innerPath.node.object.name === paramName &&
          innerPath.node.property.type === "Identifier"
        ) {
          info.usages.add(innerPath.node.property.name);
        }
      },
    });
  } catch (_) {
    // Hata olursa sessizce devam
  }
}

function inferFromUsages(name, usages) {
  const usageSet = usages;

  // Array pattern
  if (usageSet.has("push") || usageSet.has("pop") || usageSet.has("forEach") ||
      usageSet.has("map") || usageSet.has("filter") || usageSet.has("reduce") ||
      usageSet.has("slice") || usageSet.has("splice") || usageSet.has("indexOf")) {
    return "items";
  }

  // String pattern
  if (usageSet.has("trim") || usageSet.has("split") || usageSet.has("replace") ||
      usageSet.has("match") || usageSet.has("toLowerCase") || usageSet.has("toUpperCase") ||
      usageSet.has("substring") || usageSet.has("charAt")) {
    return "text";
  }

  // Object/config pattern
  if (usageSet.has("hasOwnProperty") || usageSet.has("keys") || usageSet.has("values") ||
      usageSet.has("entries")) {
    return "options";
  }

  // HTTP request pattern
  if (usageSet.has("body") || usageSet.has("params") || usageSet.has("query") ||
      usageSet.has("headers") || usageSet.has("method") || usageSet.has("url")) {
    return "request";
  }

  // HTTP response pattern
  if (usageSet.has("status") || usageSet.has("send") || usageSet.has("json") ||
      usageSet.has("render") || usageSet.has("redirect") || usageSet.has("cookie")) {
    return "response";
  }

  // DOM element pattern
  if (usageSet.has("innerHTML") || usageSet.has("className") || usageSet.has("style") ||
      usageSet.has("appendChild") || usageSet.has("querySelector") ||
      usageSet.has("addEventListener")) {
    return "element";
  }

  // Error pattern
  if (usageSet.has("message") || usageSet.has("stack") || usageSet.has("code")) {
    return "error";
  }

  return null;
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function camelCase(str) {
  return str
    .replace(/[-_\s]+(.)?/g, (_, c) => (c ? c.toUpperCase() : ""))
    .replace(/^[A-Z]/, (c) => c.toLowerCase());
}
