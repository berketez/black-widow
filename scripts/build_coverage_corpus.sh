#!/usr/bin/env bash
# build_coverage_corpus.sh — Kapsam ölçümü için ÇEŞİTLİ (format×mimari×dil) küçük
# binary corpus'u üretir. Amaç: karadul motorunun nerede çalışıp nerede çöktüğünü
# ölçmek (doğruluk değil, KAPSAM). Çıktı repo DIŞINDA (~/karadul_coverage/corpus),
# repo'yu şişirmez. Ground-truth için her self-build'in hem sembollü hem stripped'i.
#
# Toolchain gereksinimi (yoksa o hücre ATLANIR, manifest'e "skipped:no-toolchain"):
#   clang/clang++ (C/C++), rustc (Rust), swiftc (Swift), javac (JVM). go/mingw/dotnet YOK.
set -u

OUT="${KARADUL_COVERAGE_DIR:-$HOME/karadul_coverage}"
CORPUS="$OUT/corpus"
SRC="$OUT/src"
MANIFEST="$OUT/corpus_manifest.jsonl"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$CORPUS" "$SRC"
: > "$MANIFEST"

# manifest satırı ekle (jsonl): path, format, arch, lang, symbols, gt_path
row() {  # row <path> <format> <arch> <lang> <symbols> <gt_path>
  python3 - "$@" <<'PY' >> "$MANIFEST"
import json, sys
p, fmt, arch, lang, sym, gt = sys.argv[1:7]
print(json.dumps({"path": p, "format": fmt, "arch": arch, "lang": lang,
                  "symbols": sym, "gt_path": gt or None}))
PY
}

have() { command -v "$1" >/dev/null 2>&1; }
note() { echo "[corpus] $*"; }

# ---- kaynak programlar (küçük, inline'lanamaz birkaç fonksiyon) ----
cat > "$SRC/prog.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) int add(int a,int b){return a+b;}
__attribute__((noinline)) int mul(int a,int b){return a*b;}
__attribute__((noinline)) long fib(int n){return n<2?n:fib(n-1)+fib(n-2);}
__attribute__((noinline)) void greet(const char*w){printf("hi %s: %ld\n",w,fib(10));}
int main(int c,char**v){greet(c>1?v[1]:"world");return add(mul(3,4),5);}
EOF

cat > "$SRC/prog.cpp" <<'EOF'
#include <cstdio>
#include <string>
#include <vector>
struct Shape { virtual double area() const = 0; virtual ~Shape(){} };
struct Circle : Shape { double r; Circle(double x):r(x){} double area() const override {return 3.14159*r*r;} };
struct Rect : Shape { double w,h; Rect(double a,double b):w(a),h(b){} double area() const override {return w*h;} };
__attribute__((noinline)) double total(const std::vector<Shape*>& s){double t=0;for(auto*p:s)t+=p->area();return t;}
int main(){std::vector<Shape*> s{new Circle(2),new Rect(3,4)};printf("%.2f\n",total(s));for(auto*p:s)delete p;return 0;}
EOF

cat > "$SRC/prog.rs" <<'EOF'
#[inline(never)]
fn add(a: i64, b: i64) -> i64 { a + b }
#[inline(never)]
fn fib(n: u64) -> u64 { if n < 2 { n } else { fib(n-1) + fib(n-2) } }
fn main() {
    let s: i64 = (1..=10).map(|x| add(x, x*x)).sum();
    println!("{} {}", s, fib(12));
}
EOF

cat > "$SRC/Prog.swift" <<'EOF'
func add(_ a: Int, _ b: Int) -> Int { return a + b }
func fib(_ n: Int) -> Int { return n < 2 ? n : fib(n-1) + fib(n-2) }
let s = (1...10).map { add($0, $0*$0) }.reduce(0, +)
print("\(s) \(fib(12))")
EOF

cat > "$SRC/Prog.java" <<'EOF'
public class Prog {
  static int add(int a,int b){return a+b;}
  static long fib(int n){return n<2?n:fib(n-1)+fib(n-2);}
  public static void main(String[] a){
    int s=0; for(int i=1;i<=10;i++) s+=add(i,i*i);
    System.out.println(s+" "+fib(12));
  }
}
EOF

# ---- C: Mach-O arm64 + x86_64 (sembollü + stripped) ----
if have clang; then
  for arch in arm64 x86_64; do
    dbg="$CORPUS/c_macho_${arch}_debug"; strp="$CORPUS/c_macho_${arch}_stripped"
    if clang -arch "$arch" -O0 -fno-inline -g -o "$dbg" "$SRC/prog.c" 2>/dev/null; then
      cp "$dbg" "$strp"; strip "$strp" 2>/dev/null; rm -rf "$dbg.dSYM"
      row "$strp" macho "$arch" c stripped "$dbg"
      note "C Mach-O $arch OK"
    else note "C Mach-O $arch BUILD FAIL"; fi
  done
else note "clang YOK — C atlandı"; fi

# ---- C++: Mach-O arm64 (RTTI/mangling — cpp_rtti/demangler kapsamı) ----
if have clang++; then
  dbg="$CORPUS/cpp_macho_arm64_debug"; strp="$CORPUS/cpp_macho_arm64_stripped"
  if clang++ -arch arm64 -O0 -fno-inline -g -o "$dbg" "$SRC/prog.cpp" 2>/dev/null; then
    cp "$dbg" "$strp"; strip "$strp" 2>/dev/null; rm -rf "$dbg.dSYM"
    row "$strp" macho arm64 cpp stripped "$dbg"; note "C++ Mach-O arm64 OK"
  else note "C++ BUILD FAIL"; fi
else note "clang++ YOK — C++ atlandı"; fi

# ---- Rust: Mach-O arm64 ----
if have rustc; then
  dbg="$CORPUS/rust_macho_arm64_debug"; strp="$CORPUS/rust_macho_arm64_stripped"
  if rustc -C opt-level=0 -C debuginfo=2 -o "$dbg" "$SRC/prog.rs" 2>/dev/null; then
    cp "$dbg" "$strp"; strip "$strp" 2>/dev/null; rm -rf "$dbg.dSYM"
    row "$strp" macho arm64 rust stripped "$dbg"; note "Rust Mach-O arm64 OK"
  else note "Rust BUILD FAIL"; fi
else note "rustc YOK — Rust atlandı"; fi

# ---- Swift: Mach-O arm64 ----
if have swiftc; then
  dbg="$CORPUS/swift_macho_arm64_debug"; strp="$CORPUS/swift_macho_arm64_stripped"
  if swiftc -Onone -g -o "$dbg" "$SRC/Prog.swift" 2>/dev/null; then
    cp "$dbg" "$strp"; strip "$strp" 2>/dev/null; rm -rf "$dbg.dSYM"
    row "$strp" macho arm64 swift stripped "$dbg"; note "Swift Mach-O arm64 OK"
  else note "Swift BUILD FAIL"; fi
else note "swiftc YOK — Swift atlandı"; fi

# ---- Java: JVM bytecode (jar) ----
if have javac; then
  jdir="$OUT/jvm"; mkdir -p "$jdir"
  if javac -g -d "$jdir" "$SRC/Prog.java" 2>/dev/null; then
    ( cd "$jdir" && echo "Main-Class: Prog" > mf.txt && jar cfm "$CORPUS/prog.jar" mf.txt Prog.class 2>/dev/null )
    [ -f "$CORPUS/prog.jar" ] && { row "$CORPUS/prog.jar" jvm jvm java symbols ""; note "JVM jar OK"; }
  else note "javac BUILD FAIL"; fi
else note "javac YOK — JVM atlandı"; fi

# ---- ELF aarch64: mevcut coreutils fixture'larından 3 örnek (referans, kopya değil) ----
for b in cat echo basename; do
  f="$REPO/tests/fixtures/coreutils/binaries/stripped/$b"
  [ -f "$f" ] && { row "$f" elf aarch64 c stripped ""; note "ELF aarch64 $b (ref)"; }
done

# ---- Gerçek sistem binary'leri (GT yok, sağlamlık-only): çeşitli boyut/dil ----
for sysb in /usr/bin/true /usr/bin/uname /bin/echo; do
  [ -f "$sysb" ] && { a=$(file -b "$sysb" | grep -o 'arm64\|x86_64\|universal' | head -1)
    row "$sysb" macho "${a:-unknown}" system stripped ""; note "sistem $sysb ($a)"; }
done

note "----"
note "corpus: $CORPUS"
note "manifest: $MANIFEST ($(wc -l < "$MANIFEST" | tr -d ' ') satır)"
echo
echo "=== BOŞLUKLAR (toolchain yok, bu turda üretilemedi) ==="
have go   || echo "  - Go (GT'li): 'go' YOK. Gerçek Go binary'si Homebrew'dan sağlamlık-only alınabilir."
have x86_64-w64-mingw32-gcc || echo "  - Windows PE: mingw-w64 YOK."
have dotnet || echo "  - .NET: 'dotnet' YOK."