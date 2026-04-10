#!/usr/bin/env node
/**
 * beautify.mjs — js-beautify wrapper
 *
 * Minified/obfuscated JS dosyasini alir, beautified ciktisini dosyaya yazar.
 * Sonucu JSON olarak stdout'a raporlar.
 *
 * Kullanim:
 *   node beautify.mjs <input-file> <output-file>
 *
 * Cikti: JSON { success, input, output, stats: { input_lines, output_lines, input_size, output_size } }
 */

import { readFileSync, writeFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import jsBeautify from "js-beautify";
const { js_beautify } = jsBeautify;

const args = process.argv.slice(2);

if (args.length < 2) {
  const result = {
    success: false,
    errors: ["Kullanim: node beautify.mjs <input-file> <output-file>"],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const inputPath = resolve(args[0]);
const outputPath = resolve(args[1]);

// Girdiyi oku
let source;
let inputSize;
try {
  inputSize = statSync(inputPath).size;
  source = readFileSync(inputPath, "utf-8");
} catch (err) {
  const result = {
    success: false,
    errors: [`Girdi okunamadi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const inputLines = source.split("\n").length;

// Beautify
let beautified;
try {
  beautified = js_beautify(source, {
    indent_size: 2,
    indent_char: " ",
    max_preserve_newlines: 2,
    preserve_newlines: true,
    keep_array_indentation: false,
    break_chained_methods: true,
    indent_scripts: "normal",
    brace_style: "collapse,preserve-inline",
    space_before_conditional: true,
    unescape_strings: false,
    jslint_happy: false,
    end_with_newline: true,
    wrap_line_length: 120,
    e4x: false,
    comma_first: false,
    operator_position: "before-newline",
  });
} catch (err) {
  const result = {
    success: false,
    errors: [`Beautify hatasi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

// Ciktiyi yaz
try {
  writeFileSync(outputPath, beautified, "utf-8");
} catch (err) {
  const result = {
    success: false,
    errors: [`Cikti yazilamadi: ${err.message}`],
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(1);
}

const outputLines = beautified.split("\n").length;
const outputSize = Buffer.byteLength(beautified, "utf-8");

const result = {
  success: true,
  input: inputPath,
  output: outputPath,
  stats: {
    input_lines: inputLines,
    output_lines: outputLines,
    input_size: inputSize,
    output_size: outputSize,
    expansion_ratio: +(outputLines / inputLines).toFixed(2),
  },
};

process.stdout.write(JSON.stringify(result) + "\n");
