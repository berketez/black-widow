# VS Code .d.ts ile Cursor Minified Kod Parametre Geri Kazanimi

**Tarih:** 2026-03-22
**Cursor Versiyon:** 2.6.19 (VS Code 1.105.1 base, build 2026-03-12)
**Analiz:** Architect Agent

---

## 1. MEVCUT KAYNAKLAR

### 1.1 vscode.d.ts (Ana Tip Tanimi)
- **Konum:** `/Applications/Cursor.app/Contents/Resources/app/out/vscode-dts/vscode.d.ts`
- **Boyut:** 732KB, 21,038 satir
- **Icerik:** VS Code Extension API'nin tam TypeScript tip tanimlari

```
Header notu:
"DO NOT MODIFY THIS FILE. FOR NOW, WE ARE PUTTING ALL CURSOR-SPECIFIC IN THE CURSOR PROPOSED API."
```

| Kategori | Sayi |
|----------|------|
| export function (namespace metotlari) | 156 |
| export interface | 300 |
| Interface property/metot tanimlari | 1,305 |
| Unique parametre isimleri | 310 |
| Unique member isimleri | 793 |
| **TOPLAM geri kazanilabilir isim** | **929** |

### 1.2 Namespace Yapisi (15 namespace)
```
tasks, env, commands, window, workspace, languages,
notebooks, scm, debug, extensions, authentication,
l10n, tests, chat, lm
```

### 1.3 Cursor Proposed API Dosyalari
Cursor build zamaninda 4 proposed API dosyasi kullaniyor ama **dagitima dahil ETMIYOR**:
- `vscode.proposed.cursor.d.ts` -- Ana Cursor API
- `vscode.proposed.cursorNoDeps.d.ts` -- Dependency-free Cursor API
- `vscode.proposed.cursorPublic.d.ts` -- Public Cursor API
- `vscode.proposed.cursorTracing.d.ts` -- Tracing/telemetry API

Bu dosyalarin URL'leri `extensionHostProcess.js`'te referans olarak var ama dosyalarin kendisi yok. Bu kritik bir kayip -- Cursor'in kendi API'sinin tip tanimlari elde edilemiyor.

---

## 2. CURSOR EXTENSION'LARI ANALIZI

### 2.1 Extension Listesi ve Boyutlari

| Extension | Boyut | VS Code API | Cursor API |
|-----------|-------|-------------|------------|
| cursor-agent-exec | 4.4MB | 13 | 61 unique |
| cursor-always-local | 4.1MB | 23 | 31 unique |
| cursor-retrieval | 3.8MB | 37 | 31 unique |
| cursor-resolver | 2.6MB (+ 6.9MB browser) | 2 | 8 unique |
| cursor-commits | 2.3MB | 10 | 8 unique |
| cursor-mcp | 1.6MB | 26 | 16 unique |
| cursor-shadow-workspace | 1.2MB | - | - |
| cursor-deeplink | 0.9MB | 38 | 2 unique |
| cursor-browser-automation | 0.3MB | - | - |
| cursor-polyfills-remote | 0.1MB | - | - |
| cursor-ndjson-ingest | 14KB | 19 | - |
| cursor-socket | 5KB | 1 | 2 unique |

### 2.2 VS Code Standart API Fonksiyon Cagrilari (Extension'larda)

Toplam: **169 cagri** (tum extension'lar), 27 unique fonksiyon

En cok kullanilan:
```
commands.registerCommand     - 8 extension'da
commands.executeCommand      - 7 extension'da
window.createOutputChannel   - 10 extension'da (hepsinde)
workspace.getConfiguration   - 5 extension'da
workspace.workspaceFolders   - 5 extension'da
extensions.getExtension      - 5 extension'da
window.showErrorMessage      - 5 extension'da
```

### 2.3 Cursor-Specific API Cagrilari

Toplam: **281 cagri**, 36 unique register fonksiyonu

VS Code .d.ts'de OLMAYAN Cursor register fonksiyonlari:
```
registerAgentExecProvider       registerAggregatingMetricsProvider
registerBackgroundShellProvider registerCodebaseSnapshot
registerConnectTransportProvider registerConnectionTokenProvider
registerControlledImplementation registerControlProvider
registerCursorRulesProvider     registerDiffingProvider
registerEditHistoryProvider     registerEverythingProvider
registerEverythingProviderAllLocal registerExtHostEventLogger
registerFileSyncActions         registerGitContextProvider
registerGitIgnoreProvider       registerGrepProvider
registerIndexProvider           registerMcpLeaseChangeListener
registerMcpProvider             registerMcpProviderToManager
registerMetricsProvider         registerPluginsProvider
registerShadowClientProvider    registerShadowServerProvider
registerStructuredLogProvider   registerSubagentsProvider
```

---

## 3. ESLESTIRME ANALIZI

### 3.1 Katman 1: VS Code .d.ts -> Minified Kod (DOGRUDAN)

**Nasil calisiyor:**
```javascript
// Minified (cursor-mcp):
o.commands.registerCommand("mcp.probeAllServers", () => {...})

// vscode.d.ts:
export function registerCommand(
    command: string,
    callback: (...args: any[]) => any,
    thisArg?: any
): Disposable;

// ESLESTIRME:
// "mcp.probeAllServers" = command parametresi
// () => {...}           = callback parametresi
```

**Verim:** 169 cagri x ortalama 2.5 parametre = ~400 parametre isleme geri kazanilir.

**Sorun:** Bu parametreler zaten cagri noktasinda literal veya tek harf. .d.ts sadece "bu tek harfin semantik anlami ne" sorusuna cevap verir. Minified kodun yapisini degistirmez.

### 3.2 Katman 2: Korunan (Minify Edilmeyen) Isimler

Webpack/Terser ile minify ETMEDIGI isimler:

| Tip | Ornek | Neden Korunur | Sayi |
|-----|-------|---------------|------|
| Object property | `this.factory`, `this.sessions` | Runtime reflection kirar | 12,000+ |
| Class isimleri | `VscodeAgentExecProvider` | Constructor.name kullanilabilir | 339 |
| String literal | `"mcp.probeAllServers"` | Semantik anlam | binlerce |
| API metot isimleri | `registerCommand` | External API cagrilari | tumu |
| Enum/const isimleri | `ThemeIcon` | API uyumlulugu | yuzlerce |

**Kritik Bulgu:** Constructor parametreleri bazen korunuyor:
```javascript
// Minified kodda ORIJINAL isimlerle:
VscodeAgentExecProvider = class {
    constructor(e, t, n, r, s, i) {
        this.factory = e,
        this.teamSettingsService = t,
        this.createTerminalExecutor = n,
        this.workspacePaths = r,
        this.loggerBackend = s,
        this.metricsBackend = i
    }
}
```
Burada `this.xxx = param` atamalari sayesinde minified `e,t,n,r,s,i` parametrelerinin semantik anlamlarini zaten ogrenebiliyoruz. .d.ts'e gerek yok.

### 3.3 Katman 3: Cursor Namespace API (Implementasyondan Cikarim)

extensionHostProcess.js'ten cikarilan Cursor API:

**43 unique metot + 23 getter property:**
```
REGISTER metotlari (14):
  registerAgentExecProvider(T)     registerMcpProvider(T)
  registerGrepProvider(T)          registerIndexProvider(T)
  registerDiffingProvider(T)       registerEditHistoryProvider(T)
  registerEverythingProvider(T)    registerEverythingProviderAllLocal(T)
  registerConnectionTokenProvider(T) registerShadowClientProvider(T)
  registerShadowServerProvider(T)  registerStructuredLogProvider(T)
  registerAggregatingMetricsProvider(T)  registerExtHostEventLogger(T)

EVENT handler'lari (17):
  onDidChangeCursorAuthToken      onDidChangeCursorCreds
  onDidChangePrivacyMode          onDidChangePrivacyModeEnum
  onDidChangeSnippetLearningEligibility  onDidChangeGates
  onDidChangeFileSyncClientEnabled onDidChangeIndexingGrepEnabled
  onDidChangeCppEnabled           onDidChangeCppConfig
  onDidChangeMembershipType       onDidChangeThirdPartyExtensibilityEnabled
  onDidChangeUseLegacyTerminalTool onDidChangeCursorIgnoredFiles
  onDidRegisterMcpProvider        onDidUnregisterMcpProvider
  onDidRequestRepoIndex

GET metotlari (cursor-agent-exec'ten, 20+):
  getAuthId           getCursorAuthToken
  getDynamicConfigValue  getEffectiveUserPlugins
  getManagedSkills    getMcpSnapshotPushEnabled
  getPathEncryptionKey  getRepoInfo
  getTeamAdminSettings  getTeamRepos
  getThirdPartyExtensibilityEnabled  getUseLegacyTerminalTool
  getGrepProvider     getConfiguredHooks
  getHookExecutor     checkFeatureGate
  ...
```

### 3.4 Katman 4: Geri Kazanilamayan

**Local variable isimleri** (tum fonksiyon iclerindeki):
```javascript
// Orijinal (varsayimsal):
async function createAgentSession(config, workspacePath, options) {
    const terminal = await createTerminal(config.name);
    const executor = new TerminalExecutor(terminal, options);
    return executor.start();
}

// Minified (gercek):
async function p(e, t, n) {
    const r = await o(e.name);
    const s = new l(r, n);
    return s.start();
}
```

Bu tip local variable isimlerini geri kazanmak icin .d.ts yetersiz. VS Code 1.105.1 kaynak kodu gerekli.

---

## 4. VS CODE KAYNAK KODU ESLESTIRMESI (ALTERNATIF YAKLASIM)

### 4.1 Neden Daha Guclu?

Cursor'in `out/vs/` dizini (70MB) dogrudan VS Code 1.105.1'den derleniyor. VS Code tamamen MIT lisansli ve acik kaynak.

```
github.com/microsoft/vscode @ tag 1.105.1
src/vs/workbench/  -->  Cursor out/vs/workbench/ (65MB)
src/vs/platform/   -->  Cursor out/vs/platform/ (1.7MB)
src/vs/editor/     -->  Cursor out/vs/editor/ (528KB)
src/vs/code/       -->  Cursor out/vs/code/ (2.7MB)
```

**Yaklasim:**
1. VS Code 1.105.1 kaynak kodunu indir
2. Ayni build konfigurasyonu ile derle (minify OLMADAN)
3. Minified ciktiyi unminified ciiktiyla fonksiyon fonksiyon eslesir (AST diff)
4. Tum local variable/parametre isimleri geri kazanilir

**Verim:** ~70MB VS Code kodunun TAMAMININ parametre isimleri geri kazanilir.

### 4.2 Cursor-Specific Kod (Eslestirilemez)

Cursor'in kendi eklentileri VS Code kaynak kodunda yok:
- `out/vs/workbench/contrib/aichat/` -- Cursor AI chat
- `out/vs/workbench/contrib/aiSettings/` -- Cursor AI settings
- `out/vs/workbench/services/ai/` -- AI servisleri
- Cursor extension'lari (18MB)

Bu kisimlar icin kaynak kod yok. Sadece korunan isimler (property, class, string) kullanilabilir.

---

## 5. SONUC VE ONERILER

### 5.1 .d.ts Yaklasiminin Degerlendirmesi

| Kriter | Puan |
|--------|------|
| Extension API cagrilari icin | ISINIR (%15 kapsama) |
| Property isimleri icin | GEREKSIZ (zaten korunmus) |
| Local variable isimleri icin | YETERSIZ (baglanti kurulamaz) |
| Cursor kendi API'si icin | YOK (.d.ts dagitimda mevcut degil) |

**.d.ts tek basina yeterli DEGIL.** Parametre isimlerini verir ama minified koddaki tek harflere baglanamaz (hangi `e` hangi `command`'a karsilik geliyor?).

### 5.2 Onerilen Strateji (4 Katmanli)

```
KATMAN 1 - Bedava (Zaten Var)
  Property isimleri (this.xxx)     : 12,000+ isim
  Class isimleri                    : 339 isim
  API metot isimleri                : 900+ isim (VS Code + Cursor)
  String literal'lar                : binlerce
  --> TOPLAM: ~15,000+ korunan isim

KATMAN 2 - Dusuk Efor (.d.ts eslestirme)
  VS Code API cagri parametreleri   : ~400 parametre
  Interface property tipleri        : tip bilgisi
  --> Ek kazanim: ~400 parametre semantik anlam

KATMAN 3 - Orta Efor (VS Code kaynak kodu eslestirme)
  out/vs/ dizini tum fonksiyonlar   : on binlerce parametre
  VS Code 1.105.1 kaynak kodu ile AST-based eslestirme
  --> Ek kazanim: 70MB kodun tum parametre isimleri

KATMAN 4 - Yuksek Efor (Cursor-specific ters muhendislik)
  Cursor extension'lari             : 18MB
  Cursor workbench eklentileri      : bilinmiyor
  Runtime analiz, dinamik izleme gerekir
  --> Ek kazanim: Cursor'a ozgu tum parametreler
```

### 5.3 Pragmatik Oneri

**Simdiki is icin (black-widow projesinin mevcut amaci):**

Katman 1 (bedava) + Katman 2 (dusuk efor) yeterli. Cursor extension'larinin API cagrilarini anlamak icin:

1. vscode.d.ts'i referans olarak kullan
2. Property isimleri zaten korunan isimler
3. VS Code kaynak kodu eslestirmesi sadece out/vs/ icindeki VS Code kodunu anlamak icin gerekli
4. Cursor'in kendi extension kodu icin zaten yeterli ipucu var (class isimleri, property isimleri, string literal'lar)

**Tam deobfuscation icin (gelecek):**
VS Code 1.105.1 kaynak kodunu klonla, AST-based eslestirme araci yaz. Bu tek basina 70MB'lik out/vs/ dizininin tamamini orijinal isimleriyle geri kazandirir.
