#!/bin/zsh
# Kalem 5: planların "bugün var" dediği sembol ve dosyalar gerçekten yerinde mi (dosyaya özgü grep).
# Komut (depo kökünden): zsh scripts/arge/karsi/sembol_denet.sh > $V/sembol_denet.txt
chk(){ f="$1"; shift; if [ ! -e "$f" ]; then echo "DOSYA YOK: $f"; return; fi; for s in "$@"; do n=$(grep -c -- "$s" "$f"); [ "$n" = "0" ] && echo "YOK: $f :: $s" || echo "var($n): $f :: $s"; done; }
S=karadul/pipeline/steps
chk $S/_feedback_naming_bindiff.py "def _config_source" "def _refdb_source" "transfer_names_with_confidence" "bindiff_confidence_map" "bindiff_names" "update_unprotected"
chk $S/_feedback_naming_refdiff.py "def _match_against_db" "refdiff_naming" "\.matches"
chk $S/_feedback_naming_candidates.py "def _add_bindiff" "def _add_refdiff" "K4_CHANNEL_FLAGS" "def add_k4_channels" "def _add_resolved" "_is_unnamed" "GhidraFunctionIndex" "0\.95" "def _add_go_demangler" "is_go_symbol"
chk $S/_feedback_naming_merger.py "config_flag(br, flag) for src, flag in K4_CHANNEL_FLAGS.items()" "add_k4_channels" "name_merger"
chk karadul/core/naming_labels.py "MEASURED_PRE_NAME_PRECISION" "0\.706"
chk karadul/reconstruction/tarif/baglama.py "def wilson"
chk karadul/config.py "class BinaryReconstructionConfig" "reference_binary" "enable_dwarf_naming" "allow_reference_download" "large_binary_timeout_multiplier" "class Timeouts" "enable_ks1_anchors" "pcode_selective_ops"
chk karadul/analyzers/dwarf_extractor.py "class DwarfExtractor" "def extract_functions"
chk karadul/analyzers/bindiff.py "class BinaryDiffer" "size_params" "cfg_fingerprint" "string_refs" "call_pattern"
chk karadul/reconstruction/reference_differ.py "class ReferenceDiffer" "def match_direct" "cfg_similarity" "string_fingerprint" "class FunctionMatch" "class VersionDetector"
chk karadul/reconstruction/c_namer.py "def _strategy_string_context" "def _extract_keywords_from_string" "def _sanitize_c_name" "_string_refs_by_func"
chk karadul/analyzers/go_binary.py "def _extract_gopclntab" "class GoBinaryAnalyzer"
chk karadul/analyzers/cpp_rtti.py "class CppRttiAnalyzer" "_ZTI"
chk karadul/ghidra/headless.py "def _run_auto_analysis"
chk karadul/stages.py "def _recover_main_from_entry" "_LIBC_START_MAIN_RE" "def _execute_app_bundle" "def _seed_recovery_pre_names"
for f in tests/test_p12a_on_ad_guveni.py tests/test_bindiff.py tests/test_reference_differ.py scripts/mutation_probe.py karadul/reconstruction/reference_populator.py karadul/core/target.py karadul/analyzers/dotnet_binary.py karadul/analyzers/binary_intelligence.py scripts/measurement/masum_kapi_esik.json karadul/analyzers/app_bundle.py karadul/reconstruction/tarif/alt_kanal.py scripts/measurement/alt_kanal.py tests/test_tip_degisimi_metin_sadakati.py karadul/reconstruction/go_reconstructor.py; do [ -e $f ] && echo "dosya var: $f" || echo "DOSYA YOK: $f"; done
