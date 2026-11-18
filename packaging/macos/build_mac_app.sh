#!/usr/bin/env bash
# Black Widow.app kurucu (macOS arm64) -- HRMA reçetesinden uyarlandı.
#   (varsayılan) CORE : stub + relocatable python + karadul + ui + pywebview.
#                       Çift-tıkla AÇILIR (TCC yok, her şey bundle içinde). Analiz
#                       için Ghidra gerekir (bu modda yok) ama uygulama açılır.
#   --full            : + Ghidra + JDK (yerel Homebrew) + signatures.lmdb -> analiz çalışır.
#   --protect         : motoru RE'ye karşı sertleştir (Nuitka .so + kaynak sıyırma).
#   --check           : yalnız ön denetim (yollar, arşiv özeti, Ghidra sabitlemesi,
#                       pycdc, kaynak kopyası); derleme YOK, derleme dizinine yazma YOK.
#
# Ortam değişkenleri:
#   KARADUL_BUILD_DIR   çıktı kökü (uygulama + Nuitka ortamı). iCloud altında olamaz.
#   KARADUL_PBS         relocatable Python arşivi (python-build-standalone).
#   KARADUL_PBS_SHA256  o arşivin beklenen özeti (başka arşiv verilirse ikisi birlikte).
#   KARADUL_PYCDC_DIR   pycdc + pycdas ikililerinin dizini (varsayılan: <depo>/vendor/pycdc).
#   GHIDRA_INSTALL_DIR  --full için Ghidra kurulumu (sürümü sabitlenenle AYNI olmalı).
#   KARADUL_SIG_LMDB_SRC --full'de gömülecek imza veritabanı dizini (varsayılan: veri
#                       kökündeki <depo>/signatures.lmdb; bağ olabilir). Şema 2 olmalı:
#                       eski şema (~/.karadul/signatures.lmdb) gömülmez (K-5).
#   KARADUL_CODESIGN_ID imza kimliği (yoksa ad-hoc).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

FULL=0; PROTECT=0; CHECK=0
for _a in "$@"; do case "$_a" in
  --full) FULL=1;;
  --protect) PROTECT=1;;   # motoru RE'ye karşı sertleştir (Nuitka .so + kaynak sıyırma)
  --check) CHECK=1;;
  # Yanlış yazılan bayrak (ör. --ful) sessizce CORE derlemeye düşmesin.
  *) echo "!! bilinmeyen argüman: $_a (geçerli: --full --protect --check)" >&2; exit 2;;
esac; done
[ "${KARADUL_PROTECT:-}" = "1" ] && PROTECT=1

# .app ASLA iCloud senkronlu bir dizinde üretilmez (repo Desktop'ta ve "Desktop &
# Documents" senkronu açık): FileProvider bundle'a com.apple.FinderInfo iliştirir,
# xattr -c silmesine izin VERMEZ, codesign da "resource fork, Finder information,
# or similar detritus not allowed" ile reddeder -> imzasız/bozuk app.
# ~/Library iCloud kapsamı dışında. Repo dist/ yalnızca DMG çıktısı için kullanılır.
DIST="${KARADUL_BUILD_DIR:-$HOME/Library/BlackWidowBuild}"
case "$DIST" in /*) ;; *) DIST="$PWD/$DIST";; esac      # göreli yol -> mutlak
while [ "$DIST" != "/" ] && [ "${DIST%/}" != "$DIST" ]; do DIST="${DIST%/}"; done
APP="$DIST/Black Widow.app"

# --- iCloud bekçisi ---------------------------------------------------------
# Yukarıdaki tuzak yalnız yorumdaydı; KARADUL_BUILD_DIR=~/Desktop/... verilince
# betik dakikalarca derleyip en sonda codesign'da ölüyordu. Artık baştan reddeder.
# Hem yazıldığı hâliyle hem fiziksel (symlink çözülmüş) yol denetlenir; dizin
# henüz yoksa en yakın var olan atası çözülür. Karşılaştırma küçük harfle (APFS
# büyük/küçük harf ayırmaz: ~/desktop da Masaüstü'dür).
_fiziksel() {
  local p="$1" kalan=""
  while [ ! -d "$p" ]; do kalan="/$(basename "$p")$kalan"; p="$(dirname "$p")"; done
  echo "$(cd -P "$p" && pwd -P)$kalan"
}
_kucuk() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
_icloud_altinda() {
  local aday kok y k
  for aday in "$1" "$(_fiziksel "$1")"; do
    y="$(_kucuk "$aday")"
    case "$y" in *"/mobile documents"|*"/mobile documents/"*) return 0;; esac
    for kok in "$HOME/Desktop" "$HOME/Documents" \
               "$(_fiziksel "$HOME/Desktop")" "$(_fiziksel "$HOME/Documents")"; do
      k="$(_kucuk "$kok")"
      case "$y" in "$k"|"$k"/*) return 0;; esac
    done
  done
  return 1
}
if _icloud_altinda "$DIST"; then
  echo "!! derleme dizini iCloud ile eşitlenen bir kökün altında (Desktop / Documents /" >&2
  echo "   Mobile Documents): $DIST" >&2
  echo "   codesign orada bozulur. KARADUL_BUILD_DIR'i ~/Library altına ver." >&2
  exit 1
fi
# TUZAK: Ghidra'nın ClassJar.ignoreJar() yolunda "caches" / "ExternalLibraries" /
# "flatrepo" geçen TÜM jar'ları 3rd-party sayıp atlar -> extension point bulunamaz
# -> "Unable to locate extension points!" ile başlamaz. Yani bundle ~/Library/Caches
# altında üretilirse analiz sessizce ölür. Bu yüzden build dizini asla "caches"
# içeremez (kurulum hedefi /Applications zaten temiz).
case "$(_kucuk "$DIST")" in
  *caches*|*externallibraries*|*flatrepo*)
    echo "!! build dizini 'caches/ExternalLibraries/flatrepo' içeremez (Ghidra jar'ları"
    echo "   atlar, analiz çalışmaz): $DIST"; exit 1;;
esac

RES="$APP/Contents/Resources"; MACOS="$APP/Contents/MacOS"
# Relocatable Python (python-build-standalone, CPython 3.12.13). Arşiv özetle
# sabitlenir: yol doğru ama içerik farklıysa (başka sürüm, yarım indirme) dur.
# Başka bir arşivle derlemek için KARADUL_PBS ve KARADUL_PBS_SHA256 BİRLİKTE verilir.
PBS="${KARADUL_PBS:-$HOME/HRMA/packaging/runtime/pbs-mac.tar.gz}"
PBS_SHA256="${KARADUL_PBS_SHA256:-12d6700f7e8f222639f0ee5bbd173082c3041aeb65af8f9828e4216bc8047de6}"
JDK_SRC="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk"
# K-5 (P15b): imza veritabanı veri kökünden (karadul.config.resolve_sig_lmdb_path ile
# aynı konum: <depo>/signatures.lmdb). Eskiden ~/.karadul/signatures.lmdb (şema 1)
# kopyalanıyordu; yeni veritabanı kendiliğinden gömülmüyordu.
LMDB_SRC="${KARADUL_SIG_LMDB_SRC:-$REPO/signatures.lmdb}"
NUITKA_VENV="$DIST/nuitka-venv"   # motor koruma derleyicisi (bundle DIŞI, ship edilmez)
# pycdc/pycdas: scripts/setup_pycdc.sh bunları <depo>/vendor/pycdc altına kurar.
# vendor/ git-ignore'da -> worktree'de yoktur; başka yerden vermek için KARADUL_PYCDC_DIR.
PYCDC_SRC="${KARADUL_PYCDC_DIR:-$REPO/vendor/pycdc}"

# Tek geçici kök, tek temizlik (kaynak kopyası + mühür testi aynı yerde).
TMP_KOK="$(mktemp -d)"; trap 'rm -rf "$TMP_KOK"' EXIT

echo "[0/9] ön denetim (hiçbir şey silinmeden ÖNCE; eskiden pbs yoksa önce .app siliniyordu)"
echo "    derleme dizini: $DIST"

# --- çalışma zamanı arşivi ---
[ -f "$PBS" ] || { echo "!! pbs yok: $PBS (KARADUL_PBS ile ver)"; exit 1; }
_PBS_OLCULEN="$(shasum -a 256 "$PBS" | awk '{print $1}')"
if [ "$_PBS_OLCULEN" != "$PBS_SHA256" ]; then
  echo "!! pbs özeti uyuşmuyor: $PBS"
  echo "   beklenen: $PBS_SHA256"
  echo "   ölçülen : $_PBS_OLCULEN"
  echo "   (bilerek başka arşiv veriyorsan KARADUL_PBS_SHA256 ile özetini de ver)"
  exit 1
fi
echo "    pbs: $PBS (sha256 doğru)"

# --- kaynak kopyası ---------------------------------------------------------
# Kurulum depodan DEĞİL, geçici bir kopyadan yapılır. Eskiden `pip install "$REPO"`:
#   (1) depoya build/ ve karadul.egg-info yazıyordu (derleme kaynak ağacı kirletiyordu),
#   (2) depoda duran BAYAT build/lib'i wheel'e taşıyordu (setuptools build_py eski
#       dosyayı silmez): iCloud kopyası "stages 2.py" gibi artıklar pakete giriyordu.
# Kopyaya yalnız git'in İZLEDİĞİ dosyalar girer, içerik çalışma ağacından alınır:
# commit'lenmemiş değişiklik pakete girer (o yüzden commit "-dirty" ile işaretlenir),
# izlenmeyen dosya GİRMEZ (aşağıda uyarılır). ui/ da aynı kopyadan alınır ->
# karadul ile ui aynı andaki aynı kaynaktan gelir.
KAYNAK_YOLLAR=(pyproject.toml MANIFEST.in README.md LICENSE karadul ui)
SRC="$TMP_KOK/src"; mkdir -p "$SRC"
BI_COMMIT=""
if git -C "$REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  ( cd "$REPO" && git ls-files -z -- "${KAYNAK_YOLLAR[@]}" \
      | while IFS= read -r -d '' _f; do
          # İzlenen ama çalışma ağacında silinmiş dosya: atla (tar hata vermesin).
          if [ -f "$_f" ] || [ -L "$_f" ]; then printf '%s\0' "$_f"; fi
        done \
      | COPYFILE_DISABLE=1 tar -cf - --null -T - ) | tar -xf - -C "$SRC"
  BI_COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || true)"
  if [ -n "$BI_COMMIT" ] && [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
    BI_COMMIT="$BI_COMMIT-dirty"
    echo "    !! UYARI: çalışma ağacında commit'lenmemiş değişiklik var -> commit: $BI_COMMIT"
  fi
  _IZLENMEYEN="$(git -C "$REPO" ls-files -o --exclude-standard -- karadul ui)"
  if [ -n "$_IZLENMEYEN" ]; then
    echo "    !! UYARI: karadul/ ve ui/ altında izlenmeyen dosya var; pakete GİRMEZ"
    echo "       (gerekliyse önce 'git add'):"
    printf '%s\n' "$_IZLENMEYEN" | sed -n '1,20s/^/         /p'
  fi
else
  # git deposu değil (ör. kaynak arşivinden): izlenen/izlenmeyen ayrımı yapılamaz.
  # Yalnız bilinen artıklar ayıklanır; depo kökündeki build/ zaten listede değil.
  echo "    !! UYARI: git deposu değil -> commit: null; kaynak süzülmeden kopyalanıyor"
  _VAR=()
  for _f in "${KAYNAK_YOLLAR[@]}"; do
    if [ -e "$REPO/$_f" ]; then _VAR+=("$_f"); fi
  done
  ( cd "$REPO" && COPYFILE_DISABLE=1 tar -cf - --exclude '__pycache__' --exclude '*.pyc' \
      --exclude '.DS_Store' --exclude '_runs' --exclude '*.egg-info' "${_VAR[@]}" ) \
    | tar -xf - -C "$SRC"
fi
[ -f "$SRC/pyproject.toml" ] && [ -d "$SRC/karadul" ] && [ -f "$SRC/ui/server.py" ] \
  || { echo "!! kaynak kopyası eksik (pyproject.toml / karadul / ui/server.py): $SRC"; exit 1; }
echo "    kaynak kopyası: $(find "$SRC" -type f | wc -l | tr -d ' ') dosya, commit: ${BI_COMMIT:-yok}"

# --- Ghidra sabitlemesi -----------------------------------------------------
# Ghidra dizini ve sürümü TEK kaynaktan: karadul/config.py (GHIDRA_PINNED_*).
# Eskiden: env > "$DIST/ghidra_*_PUBLIC" içinde en yenisi > iCloud altındaki
# ghidra_12.0_DEV. KARADUL_BUILD_DIR başka yere verilince (ya da yeni bir
# ghidra_*_PUBLIC indirilince) --full sabitlenenden FARKLI bir Ghidra'yı sessizce
# paketliyordu. Artık: GHIDRA_INSTALL_DIR ya da sabitlenen dizin; sürüm
# sabitlenenle aynı değilse dur. Başka konuma düşme YOK.
_pin() {
  sed -n "s/^GHIDRA_PINNED_$1 *= *\"\(.*\)\" *\$/\1/p" "$SRC/karadul/config.py" | sed -n '1p'
}
GH_PIN_VER="$(_pin VERSION)"; GH_PIN_DIR_HAM="$(_pin DIR)"
GH_PIN_DIR="${GH_PIN_DIR_HAM/#\~/$HOME}"
if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
  GH="$GHIDRA_INSTALL_DIR"; GH_NEREDEN="GHIDRA_INSTALL_DIR"
else
  GH="$GH_PIN_DIR"; GH_NEREDEN="karadul/config.py GHIDRA_PINNED_DIR"
fi
_ghidra_surum() {
  grep -m1 '^application.version=' "$1/Ghidra/application.properties" 2>/dev/null \
    | cut -d= -f2 | tr -d '[:space:]' || true
}
if [ $FULL = 1 ]; then
  [ -n "$GH_PIN_VER" ] && [ -n "$GH_PIN_DIR_HAM" ] \
    || { echo "!! karadul/config.py'den GHIDRA_PINNED_VERSION / GHIDRA_PINNED_DIR okunamadı"; exit 1; }
  [ -d "$GH" ] || { echo "!! Ghidra yok: $GH ($GH_NEREDEN)"; exit 1; }
  _GH_SURUM="$(_ghidra_surum "$GH")"
  if [ "$_GH_SURUM" != "$GH_PIN_VER" ]; then
    echo "!! Ghidra sürümü sabitlenenle aynı değil -> paketlenmedi"
    echo "   kaynak   : $GH ($GH_NEREDEN)"
    echo "   sürüm    : ${_GH_SURUM:-okunamadı}"
    echo "   sabitlenen: $GH_PIN_VER (karadul/config.py GHIDRA_PINNED_VERSION)"
    exit 1
  fi
  echo "    Ghidra: $GH ($GH_NEREDEN), sürüm $_GH_SURUM = sabitlenen"
  [ -d "$JDK_SRC" ] || { echo "!! JDK yok: $JDK_SRC"; exit 1; }
else
  echo "    Ghidra: paketlenmiyor (CORE); sabitlenen ${GH_PIN_VER:-okunamadı} @ ${GH_PIN_DIR_HAM:-okunamadı}"
fi

# --- imza veritabanı (K-5) --------------------------------------------------
# Künye kunye.json'dan (plutil JSON okur; python gerekmez). Okunamayan alan boş
# kalır, uydurulmaz. Eski şema (künyesiz ya da schema_version != 2) --full'de
# gömülmez: ürün sessizce eski kitaplık iddialarıyla çıkmasın.
SIG_REAL=""; SIG_SCHEMA=""; SIG_BUILD_ID=""; SIG_SOURCE_HASH=""; SIG_SYMBOLS=""
_kunye() { /usr/bin/plutil -extract "$1" raw -o - "$SIG_REAL/kunye.json" 2>/dev/null || true; }
if [ -f "$LMDB_SRC/data.mdb" ]; then
  SIG_REAL="$(cd -P "$LMDB_SRC" && pwd -P)"
  SIG_SCHEMA="$(_kunye schema_version)"; SIG_BUILD_ID="$(_kunye build_id)"
  SIG_SOURCE_HASH="$(_kunye source_hash)"; SIG_SYMBOLS="$(_kunye symbols)"
  if [ "$SIG_SCHEMA" = "2" ]; then
    echo "    imza veritabanı: $SIG_REAL (şema 2, $SIG_BUILD_ID, ${SIG_SYMBOLS:-?} ad)"
  elif [ $FULL = 1 ]; then
    echo "!! imza veritabanı eski şema (${SIG_SCHEMA:-künyesiz}): $SIG_REAL -> gömülmez"
    echo "   Şema 2 veritabanını <depo>/signatures.lmdb'ye bağla ya da KARADUL_SIG_LMDB_SRC ile ver."
    exit 1
  else
    echo "    !! UYARI: imza veritabanı eski şema (${SIG_SCHEMA:-künyesiz}): $SIG_REAL (CORE: gömülmez)"
  fi
elif [ $FULL = 1 ]; then
  echo "    !! UYARI: imza veritabanı yok: $LMDB_SRC -> app imza DB'siz gidecek (isimlendirme zayıflar)"
else
  echo "    imza veritabanı: paketlenmiyor (CORE); kaynak $LMDB_SRC $([ -e "$LMDB_SRC" ] || echo '(yok)')"
fi

# --- pycdc ---
PYCDC_VAR=1
for _t in pycdc pycdas; do [ -x "$PYCDC_SRC/$_t" ] || PYCDC_VAR=0; done
if [ $PYCDC_VAR = 1 ]; then
  echo "    pycdc: $PYCDC_SRC (pycdc + pycdas)"
elif [ $FULL = 1 ]; then
  echo "!! pycdc/pycdas yok: $PYCDC_SRC"
  echo "   --full paketi .pyc decompile aracı olmadan çıkmaz. Kur: scripts/setup_pycdc.sh"
  echo "   (ya da KARADUL_PYCDC_DIR ile ikililerin dizinini ver)"
  exit 1
else
  echo "    !! UYARI: pycdc/pycdas yok ($PYCDC_SRC) -> paket pycdc'SİZ çıkıyor;"
  echo "       Python ikililerinde .pyc decompile disassembly'ye düşer (scripts/setup_pycdc.sh)."
fi

if [ $CHECK = 1 ]; then
  echo "ÖN DENETİM TAMAM ($([ $FULL = 1 ] && echo FULL || echo CORE)): derleme yapılmadı, $DIST altına yazılmadı."
  exit 0
fi
mkdir -p "$DIST"

echo "[1/9] iskelet + arm64 stub (bash değil -> mimari/çift-tık sorunu yok)"
rm -rf "$APP"; mkdir -p "$MACOS" "$RES"
cp "$HERE/app/Info.plist" "$APP/Contents/Info.plist"
# Sürüm tek kaynaktan (pyproject.toml); plist elle tutulunca kayıyordu.
# CFBundleVersion sayısal olmak zorunda -> "1.20.0-pre" -> "1.20.0".
# tomllib 3.11+ ister; PATH'teki python3 daha eskiyse SESSİZCE boş dönüyordu
# (sürüm yazılmaz, kimse fark etmez) -> tomllib yoksa grep'e düş.
VER="$(python3 -c "import tomllib;print(tomllib.load(open('$SRC/pyproject.toml','rb'))['project']['version'])" 2>/dev/null || true)"
[ -n "$VER" ] || VER="$(grep -m1 '^version *= *"' "$SRC/pyproject.toml" 2>/dev/null | cut -d'"' -f2 || true)"
if [ -n "$VER" ]; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${VER%%-*}" \
                          -c "Set :CFBundleShortVersionString $VER" \
                          -c "Set :CFBundleGetInfoString $VER, © 2026 Berke Tezgöçen" \
                          "$APP/Contents/Info.plist" >/dev/null
  echo "    sürüm: $VER"
else
  echo "    !! UYARI: pyproject sürümü okunamadı -> plist'teki yedek sürüm kalıyor"
fi
cp "$HERE/app/bw_launch.sh" "$MACOS/bw_launch.sh"; chmod +x "$MACOS/bw_launch.sh"
clang -arch arm64 -O2 -o "$MACOS/BlackWidow" "$HERE/app/bw_stub.c"
cp "$HERE/icon/Karadul.icns" "$RES/Karadul.icns"
# Bileşen/lisans özeti. Cocoa bunu KENDİLİĞİNDEN bulamaz: süreç .app olarak
# değil, bw_launch.sh içinde düz script olarak başladığı için
# NSBundle.mainBundle() = .../Resources/python/bin -> pathForResource("Credits")
# None döner (ölçüldü). Standart Cocoa "Hakkında" paneli zaten hiç açılmıyor:
# app_window.py o menü maddesini web modalına bağlıyor. Bu yüzden dosyayı
# app_window.py:_act_credits "Yardım > Bileşenler ve Lisanslar…" maddesinden
# YOLDAN (Resources/Credits.html) açar. Buradaki kopya onun beklediği yerdir.
cp "$HERE/app/Credits.html" "$RES/Credits.html"

echo "[2/9] relocatable Python (pbs cache, indirme yok)"
tar xzf "$PBS" -C "$RES"                 # 'python/' kökünü açar
PY="$RES/python/bin/python3.12"
[ -x "$PY" ] || { echo "!! arşivde python/bin/python3.12 yok: $PBS"; exit 1; }
echo "    $("$PY" --version)"
# Bu betikteki HER "$PY" -c / -m / - çağrısı -I (yalıtık kip) ile yapılır. -I olmadan
# sys.path'in başına ÇALIŞMA DİZİNİ girer: betik depo kökünden koşturulunca
# `import karadul` paketteki kurulumu değil DEPODAKİ karadul/'u yükler. Ölçüldü
# (2026-11-10): "karadul + pywebview OK" satırı paketi değil depoyu sınıyordu ve
# depodaki karadul/ altına __pycache__ yazıyordu. -I ayrıca PYTHONPATH'i ve
# kullanıcı site-packages'ını (~/Library/Python/3.12) kapatır: pip orada kurulu bir
# bağımlılığı "zaten var" sayıp pakete KOYMAMAZLIK edemez.

echo "[3/9] karadul + deps (pip -> bundle python site-packages)"
# Yavaş/kesintili ağa dayanıklılık: uzun timeout + çok deneme, ilerleme çubuğu kapalı (log şişmesin).
PIP_NET=(--retries 10 --timeout 120 --progress-bar off)
"$PY" -I -m pip install --no-input --disable-pip-version-check -q "${PIP_NET[@]}" --upgrade pip 2>/dev/null || true
# Tamamı tırnak içinde: köşeli parantez bash'te karakter sınıfı, tırnaksız
# bırakılırsa pathname expansion pip argümanını bozabilir.
# Kaynak: $SRC (geçici kopya), $REPO DEĞİL -> build/ ve egg-info geçici dizinde
# kalır, depoya yazılmaz, depodaki bayat build/lib wheel'e girmez.
"$PY" -I -m pip install --no-input --disable-pip-version-check "${PIP_NET[@]}" "$SRC[ghidra,perf,computation,app]"
SP="$RES/python/lib/python3.12/site-packages"
# Yüklenen karadul GERÇEKTEN paketteki mi? (yalnız "import oldu" demek yetmez)
"$PY" -I -c "
import sys, karadul, webview
from pathlib import Path
kok = Path(sys.argv[1]).resolve()
yer = Path(karadul.__file__).resolve()
if kok not in yer.parents:
    sys.exit(f'!! karadul paketten yüklenmedi: {yer}')
print('    karadul + pywebview OK (paketten yüklendi)')" "$SP"
[ -d "$SP/webview/js" ] || { echo "!! webview/js eksik (pencere çöker)"; exit 1; }
# Betiğin config.py'den sed ile okuduğu sabitleme, paketin GERÇEKTE import ettiği
# değerle aynı mı? (config.py'deki atama biçimi değişirse sed sessizce yanlış okur.)
if [ -n "$GH_PIN_VER" ] || [ $FULL = 1 ]; then
  if "$PY" -I -c "
import sys
from karadul.config import GHIDRA_PINNED_DIR as d, GHIDRA_PINNED_VERSION as v
sys.exit(0 if (v, d) == (sys.argv[1], sys.argv[2]) else 1)" "$GH_PIN_VER" "$GH_PIN_DIR_HAM"; then
    echo "    Ghidra sabitlemesi paketle aynı: $GH_PIN_VER @ $GH_PIN_DIR_HAM"
  elif [ $FULL = 1 ]; then
    echo "!! betiğin okuduğu Ghidra sabitlemesi paketteki karadul.config ile uyuşmuyor"; exit 1
  else
    echo "    !! UYARI: betiğin okuduğu Ghidra sabitlemesi paketteki karadul.config ile uyuşmuyor"
  fi
fi

# pycdc + pycdas: kod bunları Path(python_binary.py).parents[2]/vendor/pycdc
# yolunda arar; depoda bu <depo>/vendor/pycdc, PAKETTE site-packages/vendor/pycdc.
# pip onları taşımaz (vendor/ paket değil, üstelik git-ignore'da) -> elle kopyala.
# codesign'DAN ÖNCE (mührün içinde olmalı).
if [ $PYCDC_VAR = 1 ]; then
  mkdir -p "$SP/vendor/pycdc"
  cp "$PYCDC_SRC/pycdc" "$PYCDC_SRC/pycdas" "$SP/vendor/pycdc/"
  chmod 755 "$SP/vendor/pycdc/pycdc" "$SP/vendor/pycdc/pycdas"
  # Kopyalamak yetmez: paketin KENDİ kodu o dizini görüyor mu?
  "$PY" -I -c "
import sys
from pathlib import Path
from karadul.analyzers.python_binary import _vendor_tool_paths
from karadul.analyzers.pyc_decompiler import pycdc_available
ek = _vendor_tool_paths()
beklenen = str(Path(sys.argv[1]).resolve())
ok = bool(ek) and str(Path(ek[0]).resolve()) == beklenen and pycdc_available(ek)
sys.exit(0 if ok else 1)" "$SP/vendor/pycdc" \
    || { echo "!! pycdc pakete kopyalandı ama karadul onu bulamıyor ($SP/vendor/pycdc)"; exit 1; }
  echo "    pycdc + pycdas pakette, karadul buluyor (site-packages/vendor/pycdc)"
fi

echo "[4/9] ui/"
# _runs = runtime analiz çıktısı (UI oturumları), .DS_Store = Finder artığı: ikisi de
# BUNDLE'A GİRMEMELİ. _runs iCloud'da cloud-only olunca rsync mmap timeout ile ölüyordu
# (build [4/9]'da patlıyordu). Kaynak değiller -> hariç tut. (Kaynak artık izlenen
# dosyaların kopyası; hariç tutmalar git'siz kopyalama yolu için duruyor.)
rm -rf "$RES/ui"; /usr/bin/rsync -a --exclude='__pycache__' --exclude='_runs' --exclude='.DS_Store' "$SRC/ui/" "$RES/ui/"

if [ $FULL = 1 ]; then
  echo "[5/9] Ghidra (yerel kopya)"
  echo "    kaynak: $GH ($GH_NEREDEN)"
  echo "    sürüm : $(_ghidra_surum "$GH")"
  cp -R "$GH" "$RES/ghidra"
  echo "[6/9] JDK 21 (yerel Homebrew, indirme yok)"
  [ -d "$RES/jdk" ] || cp -R "$JDK_SRC" "$RES/jdk"
  echo "[7/9] signatures.lmdb (~3GB, şema 2; kaynak ön denetimde)"
  # Sessiz yutma YOK: yarım kopyalanmış DB ile "DONE" demek, app'i kötü
  # isimlendirmeyle ship etmek demek. Kaynak yoksa app yine kurulur ama uyarır.
  # Kaynak bağ olabilir: çözülmüş fiziksel dizin kopyalanır (cp -R bağı bağ olarak
  # kopyalardı -> pakette kırık bağ).
  if [ -n "$SIG_REAL" ]; then
    cp -R "$SIG_REAL" "$RES/signatures.lmdb" || { echo "!! signatures.lmdb kopyalanamadı"; exit 1; }
    [ "$(stat -f %z "$RES/signatures.lmdb/data.mdb")" = "$(stat -f %z "$SIG_REAL/data.mdb")" ] \
      || { echo "!! signatures.lmdb/data.mdb boyutu kaynakla aynı değil (yarım kopya)"; exit 1; }
    echo "    kopyalandı ($(du -sh "$RES/signatures.lmdb" | cut -f1)) <- $SIG_REAL"
  else
    echo "    !! UYARI: $LMDB_SRC yok -> app imza DB'siz gidiyor (isimlendirme zayıflar)"
  fi
else
  echo "[5-7/9] ATLANDI (CORE build; analiz için: build_mac_app.sh --full)"
fi

echo "[8/9] build-info.json (Hakkında paneli / GET /api/about bunu okur)"
# codesign'DAN ÖNCE yazılmalı: imzadan SONRA Resources'a dosya eklemek mührü kırar
# -> macOS "damaged" der. (Aynı tuzağın .pyc hâli için [9/9] notuna bak.)
# server.py bunu PROJECT_ROOT/build-info.json yolundan okur; bundle'da
# PROJECT_ROOT = Contents/Resources. Dosya yoksa server dev fallback'ine düşer.
# BI_COMMIT [0/9]'da, kaynak kopyası alınırken okundu (çalışma ağacı kirliyse
# "-dirty" ekli): commit ile paketlenen kaynak aynı ana ait.
[ -n "$BI_COMMIT" ] || echo "    !! UYARI: git commit okunamadı (repo git değil?) -> commit: null"
BI_GHIDRA=""
if [ $FULL = 1 ]; then
  # Kaynak ağaçtan ($GH) değil, GERÇEKTEN PAKETLENEN kopyadan oku: ikisi ayrışırsa
  # build-info yalan söylemesin.
  BI_GHIDRA="$(_ghidra_surum "$RES/ghidra")"
  [ -n "$BI_GHIDRA" ] || echo "    !! UYARI: Ghidra sürümü okunamadı -> ghidra_version: null"
fi
# K-5: gömülen imza veritabanının kaynağı ve künyesi (gömülmediyse null).
BI_SIG_EMBEDDED=0
if [ $FULL = 1 ] && [ -n "$SIG_REAL" ] && [ -f "$RES/signatures.lmdb/data.mdb" ]; then BI_SIG_EMBEDDED=1; fi
# Bundle python'ı kullan (3.12 garanti); ortamdaki python3'ün sürümüne bağlanma.
"$PY" -I - "$RES/build-info.json" "$VER" "$BI_COMMIT" \
        "$([ $FULL = 1 ] && echo full || echo core)" "$BI_GHIDRA" \
        "$BI_SIG_EMBEDDED" "$SIG_REAL" "$SIG_SCHEMA" "$SIG_BUILD_ID" "$SIG_SOURCE_HASH" \
        "$SIG_SYMBOLS" <<'PYEOF'
import datetime, json, sys
out, ver, commit, flavor, ghidra = sys.argv[1:6]
sig_embedded, sig_src, sig_schema, sig_build, sig_hash, sig_symbols = sys.argv[6:12]
# Okunamayan alan UYDURULMAZ -> null. (Sözleşme: /api/about alanları null olabilir.)
json.dump({
    "version": ver or None,
    "commit": commit or None,
    "built_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "flavor": flavor,
    "ghidra_version": ghidra or None,
    "signature_db": {
        "source": sig_src or None,
        "schema_version": int(sig_schema) if sig_schema.isdigit() else None,
        "build_id": sig_build or None,
        "source_hash": sig_hash or None,
        "symbols": int(sig_symbols) if sig_symbols.isdigit() else None,
    } if sig_embedded == "1" else None,
}, open(out, "w"), indent=2, ensure_ascii=False)
PYEOF
echo "    $(tr -d '\n ' < "$RES/build-info.json")"

if [ $PROTECT = 1 ]; then
  echo "[koruma-1] motor sertleştirme: Nuitka .so derleme (RE'ye karşı)"
  # karadul mantık modüllerini native arm64 .so'ya derle -> decompile için Ghidra +
  # ciddi RE emeği gerekir (aracın kendi zorluk seviyesi). --python-flag=no_docstrings
  # algoritma-anlatan docstring/yorumları siler. Derlenen modülün .py'si silinir.
  # ABI: .so 'undefined dynamic_lookup' ile derlenir, belirli libpython'a hard-link
  # ETMEZ -> bundle'ın 3.12'sine yüklenir (POC 2026-07-18 ölçümle kanıtlı).
  # Derleyici bundle'a GİRMEZ: ayrı venv ($DIST altında), ship edilmez.
  # Bu adım compileall'DAN ÖNCE: compileall yalnız KALAN .py'yi .pyc'ler.
  # m6: venv'i yeniden kullan AMA gerçekten çalışıyorsa. Bundle python yükseltilirse
  # (base değişir) venv bayatlar/kırılır -> nuitka --version ile fiilen doğrula, aksi
  # halde sıfırdan kur. (Salt 'bin/python var mı' kontrolü kırık venv'i yakalamaz.)
  if ! { [ -x "$NUITKA_VENV/bin/python" ] && "$NUITKA_VENV/bin/python" -m nuitka --version >/dev/null 2>&1; }; then
    echo "    nuitka venv (yeniden) kuruluyor (bundle python'dan -> birebir ABI eşleşmesi)"
    rm -rf "$NUITKA_VENV"
    "$PY" -m venv "$NUITKA_VENV"
    "$NUITKA_VENV/bin/pip" install --no-input --disable-pip-version-check -q \
        "${PIP_NET[@]}" nuitka || { echo "!! nuitka kurulamadı"; exit 1; }
  fi
  "$NUITKA_VENV/bin/python" "$HERE/protect_modules.py" \
      --package "$SP/karadul" --phase compile \
      --nuitka-python "$NUITKA_VENV/bin/python" \
    || { echo "!! koruma derlemesi başarısız"; exit 1; }
fi

echo "[9/10] bytecode (imza mührünün ön koşulu)"
# stdlib DAHİL derle: eksik .pyc kalırsa Python onları ÇALIŞMA ZAMANINDA bundle'a
# yazar -> imza mührü kırılır -> macOS "damaged" der. (bw_launch.sh ayrıca
# PYTHONDONTWRITEBYTECODE=1 ile ikinci emniyet kemerini takar.)
#
# --invalidation-mode unchecked-hash: varsayılan .pyc başlığı KAYNAK MTIME'ı gömer;
# mtime kayarsa (rsync/cp/checkout) Python .pyc'yi bayat sayıp YENİDEN YAZAR ve mührü
# kırar. unchecked-hash mtime'a hiç bakmaz -> bayatlama diye bir şey kalmaz.
#
# -f ŞART: compileall, .pyc'si GÜNCEL görünen dosyayı atlar. pip kurarken her
# modülü zaman damgalı (timestamp) .pyc ile derliyor, yukarıdaki "$PY -c import"
# satırları da öyle yazıyor -> -f olmadan site-packages'ın tamamı ve stdlib'in
# bir kısmı timestamp kipinde KALIYORDU; "unchecked-hash" yalnız kâğıt üstündeydi.
# Kök python/'un TAMAMI (yalnız lib/python3.12 değil): pip bazı paketlerin .py
# betiklerini bin/'e de koyup derliyor (ölçüldü: bin/__pycache__/bottle.cpython-312.pyc
# timestamp kipinde kalıyordu). site-packages ayrıca verilmez: python/'un altında,
# özyinelemeyle zaten derlenir (-f ile iki kez verilirse iki kez derlenir).
#
# `|| true` KALDIRILDI (2026-07-16): hata yutuluyordu. compileall yarım kalırsa eksik
# .pyc'ler runtime'da yazılır ve app kendi mührünü kırar; ölçüldü -> ~/Applications'daki
# kurulu kopyada build sonrası 1328 .pyc yazılmış ve codesign "a sealed resource is
# missing or invalid" veriyordu. Sessiz yutma = imzasız app ship etmek.
"$PY" -I -m compileall -q -f -j 0 --invalidation-mode unchecked-hash \
      "$RES/python" "$RES/ui" \
  || { echo "!! compileall BAŞARISIZ -> eksik .pyc runtime'da yazılıp mührü kırar"; exit 1; }
# Ölç, varsayma: derlenen köklerdeki HER .pyc unchecked-hash mi? (.pyc başlığı:
# 4 bayt magic + 4 bayt bayrak; 0 = timestamp, 1 = unchecked-hash, 3 = checked-hash.)
# Yalnız compileall'a verilen kökler sayılır; --full'deki Ghidra/JDK'nın kendi
# .pyc'leri bu kapının konusu değil.
"$PY" -I -B - "$RES/python" "$RES/ui" <<'PYEOF' \
  || { echo "!! unchecked-hash OLMAYAN .pyc var -> çalışma zamanında yeniden yazılıp mührü kırabilir"; exit 1; }
import os, sys
ad = {0: "timestamp", 1: "unchecked-hash", 3: "checked-hash"}
say, kotu = {}, []
for kok in sys.argv[1:]:
    for d, _, fs in os.walk(kok):
        for f in fs:
            if not f.endswith(".pyc"):
                continue
            p = os.path.join(d, f)
            with open(p, "rb") as h:
                b = h.read(8)
            kip = int.from_bytes(b[4:8], "little") if len(b) == 8 else -1
            say[kip] = say.get(kip, 0) + 1
            if kip != 1:
                kotu.append(p)
print("    .pyc kipleri: " + (", ".join(f"{ad.get(k, k)}={v}" for k, v in sorted(say.items())) or "hiç .pyc yok"))
for p in kotu[:10]:
    print("      !! " + p)
sys.exit(1 if kotu or not say else 0)
PYEOF

if [ $PROTECT = 1 ]; then
  echo "[koruma-2] kaynak sıyırma: kalan karadul .py -> sourceless .pyc (yan yana)"
  # compileall'DAN SONRA olmalı: her .py'nin .pyc'si artık var. Strip fazı
  # __pycache__/X.cpython-VER.pyc'yi yan-yana X.pyc'ye TAŞIR, sonra .py'yi siler.
  # Taşıma ŞART: Python __pycache__'teki .pyc'yi ancak yanında .py varsa kullanır;
  # .py silinip .pyc __pycache__'te kalırsa paket NAMESPACE'e düşer, __init__ kodu
  # hiç çalışmaz (ölçüldü: karadul.__version__/Config kaybolur). Sourceless yan-yana
  # .pyc doğrudan yüklenir + runtime'da yeniden yazılmaz -> mühür sağlam. __init__'ler
  # (düşük IP re-export tutkalı) .pyc-only olur: kaynak "metin editörü" -> "3.12
  # decompiler" (olgunlaşmamış) bariyerine çıkar. .so modüller ne .py ne .pyc bırakır.
  "$NUITKA_VENV/bin/python" "$HERE/protect_modules.py" \
      --package "$SP/karadul" --phase strip \
    || { echo "!! kaynak sıyırma başarısız"; exit 1; }
fi

# Homebrew JDK / Ghidra kopyaları salt-okunur gelir; codesign yazamaz -> u+w şart.
chmod -R u+w "$APP"
# codesign "resource fork, Finder information, or similar detritus" ile reddeder:
# xattr (com.apple.provenance vb.) + AppleDouble/.DS_Store artıkları temizlenmeli.
xattr -cr "$APP" 2>/dev/null || true
find "$APP" \( -name '._*' -o -name '.DS_Store' \) -delete 2>/dev/null || true
# --deep: bundle içinde nested Mach-O var (python, Ghidra native, JDK).
# arm64'te imzasız bundle Gatekeeper'a "damaged" görünür -> ad-hoc imza şart.
# Kimlik: Developer ID varsa onunla imzala (Gatekeeper sessizce açar), yoksa ad-hoc.
# KARADUL_CODESIGN_ID ile zorlanabilir; boşsa makinedeki ilk Developer ID aranır.
SIGN_ID="${KARADUL_CODESIGN_ID:-}"
if [ -z "$SIGN_ID" ]; then
  SIGN_ID="$(security find-identity -v -p codesigning 2>/dev/null \
             | grep -m1 'Developer ID Application' | sed -n 's/.*"\(.*\)".*/\1/p' || true)"
fi
if [ -n "$SIGN_ID" ]; then
  # --options runtime: notarization Hardened Runtime ZORUNLU kılar.
  codesign --force --deep --timestamp --options runtime -s "$SIGN_ID" "$APP" \
    || { echo "!! codesign BAŞARISIZ ($SIGN_ID)"; exit 1; }
  echo "    imza: Developer ID -> $SIGN_ID"
else
  codesign --force --deep -s - "$APP" || { echo "!! codesign BAŞARISIZ"; exit 1; }
  echo "    imza: ad-hoc (Developer ID yok -> Gatekeeper başka makinede 'Yine de Aç' ister)"
fi
codesign --verify --deep --strict "$APP" || { echo "!! imza doğrulanamadı"; exit 1; }

echo "[10/10] ÇALIŞTIRMA SONRASI mühür testi (imza ancak bunu geçerse imzadır)"
# NEDEN: "build sonunda codesign --verify geçti" YETMEZ. App çalışırken bundle'a
# yazarsa (stdlib .pyc, Ghidra/JVM artığı) mühür ÇALIŞTIKTAN SONRA kırılır ve
# kullanıcının makinesinde "damaged" olur -- build makinesinde asla görülmez.
# 2026-07-16'da elle ölçüldü: temiz build 25 sn koşturuldu -> 0 dosya değişti,
# imza sağlam kaldı. Bu adım o testin otomatik hâli; regresyon sessizce geri gelmesin.
_SEAL_TMP="$TMP_KOK/muhur"; mkdir -p "$_SEAL_TMP"     # temizlik: baştaki EXIT trap'i
(
  KARADUL_DATA_DIR="$_SEAL_TMP/data"; export KARADUL_DATA_DIR; mkdir -p "$KARADUL_DATA_DIR"
  # Pencere AÇMA (Cocoa event loop build'i bloklar): server tek başına da stdlib'in
  # büyük kısmını import eder -- .pyc yazımı olacaksa burada olur.
  KARADUL_PORT=0 "$PY" "$RES/ui/server.py" >"$_SEAL_TMP/seal.log" 2>&1 &
  _sp=$!
  sleep 8
  kill -TERM $_sp 2>/dev/null || true; wait $_sp 2>/dev/null || true
) || true
if codesign --verify --deep --strict "$APP" 2>"$_SEAL_TMP/verify.err"; then
  echo "    mühür çalıştırma sonrası da SAĞLAM"
else
  echo "!! MÜHÜR ÇALIŞTIRINCA KIRILDI -- bu app başka makinede 'damaged' der:"
  sed -n '1,15p' "$_SEAL_TMP/verify.err"
  echo "   (bundle'a yazan bir şey var; en olası sebep eksik .pyc)"
  exit 1
fi

echo "DONE ($([ $FULL = 1 ] && echo FULL || echo CORE)): $(du -sh "$APP" 2>/dev/null | cut -f1) -> $APP"
