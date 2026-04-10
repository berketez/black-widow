#!/usr/bin/env node
/**
 * extract-inline-regions.mjs -- Anthropic inline kod bolgelerini beautified JS'den cikar
 *
 * Claude Code CLI'nin 9MB+ bundle'inda Anthropic'in kendi kodu (tool'lar, MCP,
 * permissions, API client vb.) webpack modulu olarak DEGIL, inline olarak gomulu.
 * Bu script o bolgeleri anchor string'leriyle bulur ve ayri dosyalara cikarir.
 *
 * Algoritma:
 *   1. Beautified JS'yi satir satir oku
 *   2. Her anchor pattern'i ara
 *   3. Bulunan satirdan yukari/asagi giderek brace matching ile fonksiyon/blok sinirlarini bul
 *   4. Her bolgeyi ayri dosyaya yaz
 *   5. Bolgeler arasi cross-reference'lari tespit et
 *
 * Kullanim:
 *   node extract-inline-regions.mjs <beautified-js> <output-dir>
 *
 * Cikti (stdout JSON):
 *   { regions_found, total_lines_extracted, regions: [...], cross_references: [...] }
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, join, basename } from "node:path";

// ============================================================================
// ANCHOR TANIMLARI
// ============================================================================

const ANCHORS = {
  "tool-definitions": {
    patterns: [
      /\bBashTool\b/,
      /\bReadTool\b/,
      /\bWriteTool\b/,
      /\bEditTool\b/,
      /\bGlobTool\b/,
      /\bGrepTool\b/,
      /\bWebFetchTool\b/,
      /\bWebSearchTool\b/,
      /\bNotebookEditTool\b/,
      /\bTodoWriteTool\b/,
      /\bAgentTool\b/,
      /\bMultiEditTool\b/,
      /\bFileReadTool\b/,
      /\bListFilesTool\b/,
    ],
    extractMode: "surrounding_function",
    description: "Tool tanım ve implementasyonları",
  },
  "mcp-server": {
    patterns: [
      /\bMcpServer\b/,
      /\bmcpServers\b/,
      /\bstartMcpServer\b/,
      /\bMCP_TRANSPORT\b/,
      /\bmcp__/,
      /\bmcpClient\b/,
    ],
    extractMode: "surrounding_function",
    description: "MCP (Model Context Protocol) server implementasyonu",
  },
  "permission-system": {
    patterns: [
      /\bPermissionMode\b/,
      /\ballowedTools\b/,
      /\baskPermission\b/,
      /\bPERMISSION_/,
      /\bpermissionRules\b/,
      /\bcheckPermission\b/,
    ],
    extractMode: "surrounding_function",
    description: "Permission / izin yonetim sistemi",
  },
  "api-client": {
    patterns: [
      /api\.anthropic\.com/,
      /messages\.create\b/,
      /\bMessageStream\b/,
      /\bcontent_block\b/,
      /\bBASE_API_URL\b/,
      /\bAPI_KEY_URL\b/,
    ],
    extractMode: "surrounding_function",
    description: "Anthropic API client ve endpoint'leri",
  },
  "model-selection": {
    patterns: [
      /claude-sonnet-4/,
      /claude-opus-4/,
      /claude-haiku/,
      /\bgetModelId\b/,
      /\bmodelSelection\b/,
      /firstParty.*bedrock.*vertex/,
    ],
    extractMode: "surrounding_function",
    description: "Model secimi ve provider (firstParty/bedrock/vertex) eslesmesi",
  },
  "system-prompt": {
    patterns: [
      /\bsystemPrompt\b/i,
      /\bSYSTEM_PROMPT\b/,
      /You are Claude/,
      /\bsystem_prompt\b/,
      /\bgetSystemPrompt\b/,
    ],
    extractMode: "surrounding_block",
    description: "System prompt olusturma ve yonetimi",
  },
  "config-reader": {
    patterns: [
      /CLAUDE\.md/,
      /ULTRACLAUDE\.md/,
      /\bsettings\.json\b/,
      /\.claude\//,
      /\bglobalConfig\b/,
      /\bprojectConfig\b/,
    ],
    extractMode: "surrounding_function",
    description: "Konfigurasyon dosyasi okuma (CLAUDE.md, settings.json)",
  },
  "cli-commands": {
    patterns: [
      /\.command\s*\(/,
      /\.action\s*\(/,
      /process\.argv/,
      /\bparseAsync\b/,
      /\bCommander\b/,
    ],
    extractMode: "surrounding_function",
    description: "CLI komut tanimlari ve arguman parsing",
  },
  "hooks-system": {
    patterns: [
      /\bPreToolUse\b/,
      /\bPostToolUse\b/,
      /\bSessionStart\b/,
      /\bSessionEnd\b/,
      /\bUserPromptSubmit\b/,
      /\bhook.*event\b/i,
    ],
    extractMode: "surrounding_function",
    description: "Hook sistemi (PreToolUse, PostToolUse, SessionStart vb.)",
  },
  "streaming": {
    patterns: [
      /\bcontent_block_delta\b/,
      /\bmessage_delta\b/,
      /\bmessage_start\b/,
      /\bcontent_block_start\b/,
      /\bmessage_stop\b/,
    ],
    extractMode: "surrounding_function",
    description: "Streaming event handler'lari",
  },
  "oauth-auth": {
    patterns: [
      /\boauth\b/i,
      /\baccess_token\b/,
      /\brefresh_token\b/,
      /\bauthorization_code\b/,
      /\bOAuthClientAuth\b/,
    ],
    extractMode: "surrounding_function",
    description: "OAuth / authentication akisi",
  },
  "telemetry": {
    patterns: [
      /Sentry\.init\b/,
      /\bcaptureException\b/,
      /\btelemetry\b/i,
      /\bStatsigClient\b/,
      /\bmetrics\b/i,
    ],
    extractMode: "surrounding_function",
    description: "Telemetri, Sentry hata raporlama, metriler",
  },
};

// ============================================================================
// CLI ARGUMANLARI
// ============================================================================

const args = process.argv.slice(2);

if (args.length < 2) {
  const result = {
    success: false,
    regions_found: 0,
    total_lines_extracted: 0,
    regions: [],
    errors: ["Kullanim: node extract-inline-regions.mjs <beautified-js> <output-dir>"],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputDir = resolve(args[1]);

// ============================================================================
// DOSYAYI OKU
// ============================================================================

let lines;
try {
  const source = readFileSync(inputPath, "utf-8");
  lines = source.split("\n");
} catch (err) {
  const result = {
    success: false,
    regions_found: 0,
    total_lines_extracted: 0,
    regions: [],
    errors: [`Dosya okunamadi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

// Cikti dizini
try {
  mkdirSync(outputDir, { recursive: true });
} catch (err) {
  // dizin zaten varsa sorun yok
}

console.error(`[extract-inline] ${lines.length} satir okundu: ${basename(inputPath)}`);

// ============================================================================
// YARDIMCI FONKSIYONLAR
// ============================================================================

/**
 * Verilen satir indeksinden yukari giderek fonksiyon/blok baslangicini bul.
 * Brace matching kullanarak { } dengesi izler.
 *
 * "surrounding_function" modu: En yakin fonksiyon/class/const declaration baslangicina git.
 * "surrounding_block" modu: Daha genis -- 200 satir yukari/asagi.
 */
function findBlockStart(lineIdx, mode) {
  const contextLines = mode === "surrounding_block" ? 300 : 150;
  let start = Math.max(0, lineIdx - contextLines);

  // Yukari git, boş satır veya ust-duzey declaration bul
  let braceCount = 0;
  let foundStart = lineIdx;

  for (let i = lineIdx; i >= start; i--) {
    const line = lines[i];

    // Brace sayimi (satirda)
    for (const ch of line) {
      if (ch === "}") braceCount++;
      if (ch === "{") braceCount--;
    }

    // Ust-duzey baslangic isaretleri
    if (braceCount <= 0) {
      // function, class, const, let, var, export declaration
      if (/^\s*(function |class |const |let |var |export |async function |module\.)/.test(line)) {
        foundStart = i;
        break;
      }
      // Bos satir = potansiyel blok siniri (sadece brace 0 ise)
      if (braceCount === 0 && line.trim() === "" && i < lineIdx - 2) {
        foundStart = i + 1;
        break;
      }
    }
  }

  return foundStart;
}

/**
 * Verilen satir indeksinden asagi giderek blok sonunu bul.
 * Brace matching.
 */
function findBlockEnd(lineIdx, mode) {
  const contextLines = mode === "surrounding_block" ? 300 : 150;
  let end = Math.min(lines.length - 1, lineIdx + contextLines);

  let braceCount = 0;
  let foundEnd = lineIdx;

  for (let i = lineIdx; i <= end; i++) {
    const line = lines[i];

    for (const ch of line) {
      if (ch === "{") braceCount++;
      if (ch === "}") braceCount--;
    }

    foundEnd = i;

    // Brace dengesi kapandiysa ve asagi yeterlince gittik
    if (braceCount <= 0 && i > lineIdx + 3) {
      break;
    }
  }

  return foundEnd;
}

/**
 * Bir region'in satirlarini cikart.
 * Oncesi/sonrasi icin biraz context ekle.
 */
function extractRegion(startLine, endLine) {
  // 5 satir oncesi/sonrasi context
  const ctxStart = Math.max(0, startLine - 5);
  const ctxEnd = Math.min(lines.length - 1, endLine + 5);
  return lines.slice(ctxStart, ctxEnd + 1);
}

/**
 * Iki region'un overlap edip etmedigini kontrol et.
 */
function regionsOverlap(a, b) {
  return a.startLine <= b.endLine && b.startLine <= a.endLine;
}

/**
 * Overlapping region'lari birlestir.
 */
function mergeOverlappingRegions(regions) {
  if (regions.length === 0) return [];

  // startLine'a gore sirala
  regions.sort((a, b) => a.startLine - b.startLine);

  const merged = [regions[0]];

  for (let i = 1; i < regions.length; i++) {
    const prev = merged[merged.length - 1];
    const curr = regions[i];

    if (curr.startLine <= prev.endLine + 20) {
      // Birlestir -- gap 20 satirdan azsa
      prev.endLine = Math.max(prev.endLine, curr.endLine);
      prev.anchorHits.push(...curr.anchorHits);
      prev.patternMatches.push(...curr.patternMatches);
    } else {
      merged.push(curr);
    }
  }

  return merged;
}

// ============================================================================
// ANA ISLEM: Her anchor icin bolgeleri bul
// ============================================================================

const allRegions = {}; // anchorName -> [{startLine, endLine, anchorHits, patternMatches}]
const anchorStats = {};

for (const [anchorName, anchorDef] of Object.entries(ANCHORS)) {
  console.error(`[extract-inline] Araniyor: ${anchorName} (${anchorDef.patterns.length} pattern)`);

  const rawRegions = [];
  const matchedLines = new Set();

  // Her satiri tara
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    for (const pattern of anchorDef.patterns) {
      if (pattern.test(line) && !matchedLines.has(i)) {
        matchedLines.add(i);

        // Blok sinirlarini bul
        const blockStart = findBlockStart(i, anchorDef.extractMode);
        const blockEnd = findBlockEnd(i, anchorDef.extractMode);

        rawRegions.push({
          startLine: blockStart,
          endLine: blockEnd,
          anchorHits: [i],
          patternMatches: [{ line: i + 1, pattern: pattern.source, text: line.trim().substring(0, 120) }],
        });

        break; // Ayni satir icin tek anchor yeterli
      }
    }
  }

  // Overlap'leri birlestir
  const mergedRegions = mergeOverlappingRegions(rawRegions);

  allRegions[anchorName] = mergedRegions;
  anchorStats[anchorName] = {
    raw_hits: rawRegions.length,
    merged_regions: mergedRegions.length,
    total_lines: mergedRegions.reduce((sum, r) => sum + (r.endLine - r.startLine + 1), 0),
  };

  console.error(
    `  -> ${rawRegions.length} hit, ${mergedRegions.length} region, ` +
    `${anchorStats[anchorName].total_lines} satir`
  );
}

// ============================================================================
// CROSS-REFERENCE TESPITI
// ============================================================================

/**
 * Farkli anchor'larin ayni satirlari kapsayip kapsamadigini kontrol et.
 */
const crossRefs = [];

const anchorNames = Object.keys(allRegions);
for (let i = 0; i < anchorNames.length; i++) {
  for (let j = i + 1; j < anchorNames.length; j++) {
    const a = anchorNames[i];
    const b = anchorNames[j];

    for (const regionA of allRegions[a]) {
      for (const regionB of allRegions[b]) {
        if (regionsOverlap(regionA, regionB)) {
          crossRefs.push({
            anchor_a: a,
            anchor_b: b,
            overlap_start: Math.max(regionA.startLine, regionB.startLine) + 1,
            overlap_end: Math.min(regionA.endLine, regionB.endLine) + 1,
          });
        }
      }
    }
  }
}

// ============================================================================
// DOSYALARA YAZ
// ============================================================================

const outputRegions = [];
let totalLinesExtracted = 0;

for (const [anchorName, regions] of Object.entries(allRegions)) {
  if (regions.length === 0) continue;

  // Her region icin dosya yaz
  for (let idx = 0; idx < regions.length; idx++) {
    const region = regions[idx];
    const suffix = regions.length > 1 ? `_${idx + 1}` : "";
    const fileName = `${anchorName}${suffix}.js`;
    const filePath = join(outputDir, fileName);

    const regionLines = extractRegion(region.startLine, region.endLine);
    const lineCount = region.endLine - region.startLine + 1;
    totalLinesExtracted += lineCount;

    // Dosya header'i ekle
    const header = [
      `// ============================================================================`,
      `// EXTRACTED REGION: ${anchorName}${suffix ? ` (part ${idx + 1}/${regions.length})` : ""}`,
      `// Source: ${basename(inputPath)}`,
      `// Lines: ${region.startLine + 1} - ${region.endLine + 1} (${lineCount} lines)`,
      `// Description: ${ANCHORS[anchorName].description}`,
      `// Anchor hits: ${region.anchorHits.map(h => h + 1).join(", ")}`,
      `// ============================================================================`,
      ``,
    ];

    const content = [...header, ...regionLines].join("\n");

    try {
      writeFileSync(filePath, content, "utf-8");
    } catch (err) {
      console.error(`[extract-inline] HATA: ${filePath}: ${err.message}`);
    }

    outputRegions.push({
      anchor: anchorName,
      file: fileName,
      start_line: region.startLine + 1,
      end_line: region.endLine + 1,
      line_count: lineCount,
      anchor_hits: region.anchorHits.map(h => h + 1),
      pattern_matches: region.patternMatches.length,
      first_patterns: region.patternMatches.slice(0, 5).map(p => ({
        line: p.line,
        pattern: p.pattern,
        text: p.text,
      })),
    });
  }
}

// ============================================================================
// INDEX DOSYASI OLUSTUR
// ============================================================================

const indexContent = [
  `# Extracted Inline Regions`,
  ``,
  `Source: \`${basename(inputPath)}\``,
  `Total lines: ${lines.length}`,
  `Extracted regions: ${outputRegions.length}`,
  `Total lines extracted: ${totalLinesExtracted}`,
  `Coverage: ${((totalLinesExtracted / lines.length) * 100).toFixed(1)}%`,
  ``,
  `## Regions`,
  ``,
  `| # | Anchor | File | Lines | Range | Hits |`,
  `|---|--------|------|-------|-------|------|`,
];

outputRegions.forEach((r, i) => {
  indexContent.push(
    `| ${i + 1} | ${r.anchor} | ${r.file} | ${r.line_count} | ${r.start_line}-${r.end_line} | ${r.anchor_hits.length} |`
  );
});

if (crossRefs.length > 0) {
  indexContent.push(``);
  indexContent.push(`## Cross-References`);
  indexContent.push(``);
  indexContent.push(`| Anchor A | Anchor B | Overlap |`);
  indexContent.push(`|----------|----------|---------|`);
  for (const cr of crossRefs) {
    indexContent.push(`| ${cr.anchor_a} | ${cr.anchor_b} | L${cr.overlap_start}-${cr.overlap_end} |`);
  }
}

indexContent.push(``);
indexContent.push(`## Stats per Anchor`);
indexContent.push(``);
indexContent.push(`| Anchor | Raw Hits | Merged Regions | Total Lines |`);
indexContent.push(`|--------|----------|----------------|-------------|`);
for (const [name, stats] of Object.entries(anchorStats)) {
  indexContent.push(`| ${name} | ${stats.raw_hits} | ${stats.merged_regions} | ${stats.total_lines} |`);
}

writeFileSync(join(outputDir, "INDEX.md"), indexContent.join("\n"), "utf-8");

// ============================================================================
// MANIFEST JSON
// ============================================================================

const manifest = {
  source: basename(inputPath),
  source_lines: lines.length,
  regions: outputRegions,
  cross_references: crossRefs,
  anchor_stats: anchorStats,
};

writeFileSync(join(outputDir, "manifest.json"), JSON.stringify(manifest, null, 2), "utf-8");

// ============================================================================
// STDOUT SONUC
// ============================================================================

const result = {
  success: true,
  regions_found: outputRegions.length,
  total_lines_extracted: totalLinesExtracted,
  coverage_percent: +((totalLinesExtracted / lines.length) * 100).toFixed(1),
  regions: outputRegions,
  cross_references: crossRefs.length,
  anchor_stats: anchorStats,
};

process.stdout.write(JSON.stringify(result) + "\n");
