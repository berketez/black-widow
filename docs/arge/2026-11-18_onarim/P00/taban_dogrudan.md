# Masum ikili kapısı — dogrudan kip

- Zaman: 2026-11-18T09:39:12+03:00 → 2026-11-18T09:39:37+03:00 (25.2 sn)
- Ağaç: `/Users/apple/Black_Widow/.claude/worktrees/agent-aa796f040812276d2` @ `e9d2d08ab5` (karadul 1.23.1; `/Users/apple/Black_Widow/.claude/worktrees/agent-aa796f040812276d2/karadul/__init__.py`); kirli: 0 dosya
- Kapı: **GEÇTİ** (çıkış 0)

## Katman × set: yanlış iddia

| Katman | Set | İkili | Durum | İddia | Yanlış | Doğru bilinen | Yanlışlı ikili | Eşik |
|---|---|---|---|---|---|---|---|---|
| bi | gelistirme | 119 | calisti 119 | 2267 | 2102 | 165 | 119 | 2102 (icinde) |
| bi | macos | 48 | calisti 48 | 809 | 701 | 108 | 48 | 701 (icinde) |
| bi | pe | 21 | calisti 20, uygulanmaz 1 | 203 | 203 | 0 | 20 | 203 (icinde) |
| bi | pozitif | 6 | calisti 6 | 154 | 0 | 0 | 0 | — |
| antidebug | gelistirme | 119 | calisti 119 | 23 | 23 | 0 | 16 | 23 (icinde) |
| antidebug | macos | 48 | calisti 48 | 22 | 22 | 0 | 18 | 22 (icinde) |
| antidebug | pe | 21 | calisti 21 | 76 | 76 | 0 | 21 | 76 (icinde) |
| antidebug | pozitif | 6 | calisti 6 | 9 | 0 | 0 | 0 | — |
| packer | gelistirme | 119 | calisti 119 | 0 | 0 | 0 | 0 | 0 (icinde) |
| packer | macos | 48 | calisti 48 | 0 | 0 | 0 | 0 | 0 (icinde) |
| packer | pe | 21 | calisti 21 | 19 | 19 | 0 | 18 | 19 (icinde) |
| packer | pozitif | 6 | calisti 6 | 5 | 0 | 0 | 0 | — |
| yara | gelistirme | 119 | calisti 119 | 81 | 70 | 11 | 31 | 70 (icinde) |
| yara | macos | 48 | calisti 48 | 132 | 127 | 5 | 48 | 127 (icinde) |
| yara | pe | 21 | calisti 21 | 92 | 71 | 21 | 20 | 71 (icinde) |
| yara | pozitif | 6 | calisti 6 | 21 | 0 | 0 | 0 | — |
| capa | gelistirme | 119 | calismadi 119 | 0 | 0 | 0 | 0 | 0 (icinde) |
| capa | macos | 48 | calismadi 48 | 0 | 0 | 0 | 0 | 0 (icinde) |
| capa | pe | 21 | calismadi 21 | 0 | 0 | 0 | 0 | 0 (icinde) |
| capa | pozitif | 6 | calismadi 6 | 0 | 0 | 0 | 0 | — |

## En sık etiketler (ikili sayısı değil, iddia sayısı; bir ikilide etiket bir kez)

- **bi / gelistirme**: `algoritma:OpenGL` 119, `altsistem:Bluetooth` 119, `altsistem:Encryption` 119, `altsistem:Memory Management` 119, `guvenlik:Stack Protection` 119, `altsistem:File System Operations` 118, `altsistem:Terminal Emulator` 118, `altsistem:HTTP Client` 115
- **bi / macos**: `altsistem:Process Management` 48, `altsistem:Encryption` 46, `altsistem:Memory Management` 40, `guvenlik:Stack Protection` 40, `altsistem:File System Operations` 32, `altsistem:Bluetooth` 28, `altsistem:Localization` 24, `altsistem:Digital Signatures` 23
- **bi / pe**: `altsistem:Bluetooth` 18, `protokol:NTP` 17, `altsistem:HTTP Client` 16, `altsistem:Memory Management` 16, `altsistem:Encryption` 14, `altsistem:Process Management` 13, `altsistem:Clipboard` 10, `altsistem:Swift Runtime` 9
  - neden (1 ikili): uygulanmaz: hedef türü dotnet_assembly (ürün MachOAnalyzer'ı çağırmaz)
- **bi / pozitif**: `altsistem:Encryption` 4, `altsistem:HTTP Client` 4, `altsistem:Memory Management` 4, `algoritma:OpenGL` 3, `altsistem:Process Management` 3, `guvenlik:Stack Protection` 3, `algoritma:3DES` 2, `algoritma:AES` 2
- **antidebug / gelistirme**: `teknik:RDTSC_Timing` 14, `teknik:prctl_set_dumpable` 4, `teknik:INT3_Cluster` 2, `teknik:Linux_ProcMaps` 2, `teknik:sysctl_kinfo_proc` 1
- **antidebug / macos**: `teknik:RDTSC_Timing` 15, `teknik:sysctl_kinfo_proc` 6, `teknik:INT3_Cluster` 1
- **antidebug / pe**: `teknik:INT3_Cluster` 19, `teknik:QueryPerformanceCounter` 17, `teknik:IsDebuggerPresent` 15, `teknik:GetTickCount` 9, `teknik:PEB_GS60_x64` 6, `teknik:OutputDebugString` 3, `teknik:CreateToolhelp32Snapshot` 2, `teknik:Process32First` 2
- **antidebug / pozitif**: `teknik:RDTSC_Timing` 5, `teknik:INT3_Cluster` 1, `teknik:ptrace_pt_deny_attach` 1, `teknik:ptrace_traceme` 1, `teknik:sysctl_kinfo_proc` 1
- **packer / pe**: `paketleyici:FSG` 18, `paketleyici:NSIS` 1
- **packer / pozitif**: `paketleyici:UPX` 3, `paketleyici:FSG` 2
- **yara / gelistirme**: `kural:AntiDebug_Timing` 23, `kural:Stack_String_Construction` 19, `kural:MPRESS_Packed` 13, `kural:Zlib_Library` 10, `kural:OpenSSL_Library` 5, `kural:AntiDebug_SysctlCheck` 4, `kural:Delphi_Compiler` 2, `kural:GCC_Compiler` 2
- **yara / macos**: `kural:RSA_Public_Key_Constants` 48, `kural:Stack_String_Construction` 30, `kural:MPRESS_Packed` 16, `kural:Zlib_Library` 11, `kural:AntiDebug_Timing` 9, `kural:AntiDebug_SysctlCheck` 8, `kural:Clang_Compiler` 2, `kural:AntiDebug_Ptrace` 1
- **yara / pe**: `kural:MSVC_Compiler` 21, `kural:AntiDebug_Timing` 18, `kural:AntiDebug_ExceptionTricks` 17, `kural:AntiDebug_IsDebuggerPresent` 15, `kural:Stack_String_Construction` 12, `kural:MPRESS_Packed` 3, `kural:Zlib_Library` 3, `kural:AntiDebug_ProcessEnum` 2
- **yara / pozitif**: `kural:UPX_Packed` 4, `kural:Stack_String_Construction` 3, `kural:Zlib_Library` 3, `kural:MPRESS_Packed` 2, `kural:MSVC_Compiler` 2, `kural:OpenSSL_Library` 2, `kural:AntiDebug_SysctlCheck` 1, `kural:AntiDebug_Timing` 1
- **capa / gelistirme**: —
  - neden (119 ikili): CAPA extractor hatasi (format desteklenmiyor olabilir): unexpected backend: auto
- **capa / macos**: —
  - neden (48 ikili): CAPA extractor hatasi (format desteklenmiyor olabilir): unexpected backend: auto
- **capa / pe**: —
  - neden (21 ikili): CAPA extractor hatasi (format desteklenmiyor olabilir): unexpected backend: auto
- **capa / pozitif**: —
  - neden (6 ikili): CAPA extractor hatasi (format desteklenmiyor olabilir): unexpected backend: auto

## İzlenen yanlış etiketler (rapordaki bulgular; ikili sayısı)

| Ad | Katman | Set | Etiket | İkili / ölçülen | Rapordaki |
|---|---|---|---|---|---|
| bluetooth | bi | gelistirme | `^altsistem:Bluetooth$` | 119 / 119 | IMZA-01: 119/119 (gelistirme) |
| bluetooth | bi | macos | `^altsistem:Bluetooth$` | 28 / 48 | IMZA-01: 119/119 (gelistirme) |
| bluetooth | bi | pe | `^altsistem:Bluetooth$` | 18 / 21 | IMZA-01: 119/119 (gelistirme) |
| encryption | bi | gelistirme | `^altsistem:Encryption$` | 108 / 108 | IMZA-01: 119/119; burada kriptosuz alt küme |
| encryption | bi | macos | `^altsistem:Encryption$` | 14 / 15 | IMZA-01: 119/119; burada kriptosuz alt küme |
| opengl | bi | gelistirme | `^algoritma:OpenGL$` | 119 / 119 | IMZA-01: 119/119 |
| opengl | bi | macos | `^algoritma:OpenGL$` | 14 / 48 | IMZA-01: 119/119 |
| opengl | bi | pe | `^algoritma:OpenGL$` | 7 / 21 | IMZA-01: 119/119 |
| sha256_yardim_metni | bi | gelistirme | `^algoritma:SHA-256$` | 104 / 106 | IMZA-01: 107 (gelistirme, tümü); burada coreutils |
| kernel_riskli | bi | gelistirme | `^guvenlik:(SIP \(System Integrity\)|Kernel Extension)$` | 5 / 119 | IMZA-01: SIP 5, Kernel Extension 3 |
| kernel_riskli | bi | macos | `^guvenlik:(SIP \(System Integrity\)|Kernel Extension)$` | 2 / 48 | IMZA-01: SIP 5, Kernel Extension 3 |
| kernel_riskli | bi | pe | `^guvenlik:(SIP \(System Integrity\)|Kernel Extension)$` | 0 / 21 | IMZA-01: SIP 5, Kernel Extension 3 |
| ipsec | bi | gelistirme | `^protokol:IPsec$` | 46 / 119 | IMZA-01: 46 |
| ipsec | bi | macos | `^protokol:IPsec$` | 12 / 48 | IMZA-01: 46 |
| ipsec | bi | pe | `^protokol:IPsec$` | 1 / 21 | IMZA-01: 46 |
| rdtsc | antidebug | gelistirme | `^teknik:RDTSC_Timing$` | 14 / 119 | IMZA-02: 14 (gelistirme, AArch64) |
| rdtsc | antidebug | macos | `^teknik:RDTSC_Timing$` | 15 / 48 | IMZA-02: 14 (gelistirme, AArch64) |
| rdtsc | antidebug | pe | `^teknik:RDTSC_Timing$` | 2 / 21 | IMZA-02: 14 (gelistirme, AArch64) |
| sysctl_tek_ithal | antidebug | gelistirme | `^teknik:sysctl_kinfo_proc$` | 1 / 119 | IMZA-02: mac/htop, top, sysctl, vim |
| sysctl_tek_ithal | antidebug | macos | `^teknik:sysctl_kinfo_proc$` | 6 / 48 | IMZA-02: mac/htop, top, sysctl, vim |
| sysctl_tek_ithal | antidebug | pe | `^teknik:sysctl_kinfo_proc$` | 0 / 21 | IMZA-02: mac/htop, top, sysctl, vim |
| pe_crt_ithal | antidebug | pe | `^teknik:(IsDebuggerPresent|QueryPerformanceCounter|GetTickCount|INT3_Cluster)$` | 21 / 21 | IMZA-03 |
| fsg | packer | gelistirme | `^paketleyici:FSG$` | 0 / 119 | IMZA-04 |
| fsg | packer | macos | `^paketleyici:FSG$` | 0 / 48 | IMZA-04 |
| fsg | packer | pe | `^paketleyici:FSG$` | 18 / 21 | IMZA-04 |
| imza11_fsg | packer | pe | `^paketleyici:FSG$` | 10 / 11 | IMZA-04: 10/11 (makensisw.exe yerine makensis.exe) |
| mpress | yara | gelistirme | `^kural:MPRESS_Packed$` | 13 / 119 | IMZA-05: 13 (gelistirme) |
| mpress | yara | macos | `^kural:MPRESS_Packed$` | 16 / 48 | IMZA-05: 13 (gelistirme) |
| mpress | yara | pe | `^kural:MPRESS_Packed$` | 3 / 21 | IMZA-05: 13 (gelistirme) |
| aspack | yara | gelistirme | `^kural:ASPack_Packed$` | 1 / 119 | IMZA-05: 1 (tree) |
| aspack | yara | macos | `^kural:ASPack_Packed$` | 0 / 48 | IMZA-05: 1 (tree) |
| aspack | yara | pe | `^kural:ASPack_Packed$` | 0 / 21 | IMZA-05: 1 (tree) |
| delphi | yara | gelistirme | `^kural:Delphi_Compiler$` | 2 / 119 | IMZA-05: 2 (redis) |
| delphi | yara | macos | `^kural:Delphi_Compiler$` | 1 / 48 | IMZA-05: 2 (redis) |
| delphi | yara | pe | `^kural:Delphi_Compiler$` | 1 / 21 | IMZA-05: 2 (redis) |
| yara_antidebug | yara | gelistirme | `^kural:AntiDebug_` | 24 / 119 | IMZA-05: Timing 23, SysctlCheck 4 |
| yara_antidebug | yara | macos | `^kural:AntiDebug_` | 16 / 48 | IMZA-05: Timing 23, SysctlCheck 4 |
| yara_antidebug | yara | pe | `^kural:AntiDebug_` | 18 / 21 | IMZA-05: Timing 23, SysctlCheck 4 |
| stack_string | yara | gelistirme | `^kural:Stack_String_Construction$` | 19 / 119 | IMZA-05: 19 |
| stack_string | yara | macos | `^kural:Stack_String_Construction$` | 30 / 48 | IMZA-05: 19 |
| stack_string | yara | pe | `^kural:Stack_String_Construction$` | 12 / 21 | IMZA-05: 19 |
| rsa_oid_imza | yara | macos | `^kural:RSA_Public_Key_Constants$` | 48 / 48 | IMZA-05: Apple kod imzası sertifikasındaki OID |

## Rapora yansıyan düzeyler

- antidebug_rapor_seviyesi / gelistirme: INFO 8, MED 8
- antidebug_rapor_seviyesi / macos: MED 12, INFO 6
- antidebug_rapor_seviyesi / pe: HIGH 14, MED 1, INFO 6
- antidebug_rapor_seviyesi / pozitif: HIGH 1, MED 2, INFO 2
- bi_kernel_riskli_guvenlik / gelistirme: guvenlik:SIP (System Integrity) 5, guvenlik:Kernel Extension 3
- bi_kernel_riskli_guvenlik / macos: guvenlik:SIP (System Integrity) 1, guvenlik:Endpoint Security API 2, guvenlik:Kernel Extension 1
- bi_kernel_riskli_guvenlik / pozitif: guvenlik:SIP (System Integrity) 2
- packer_sarif_duzeyi / pe: note 18, error 1
- packer_sarif_duzeyi / pozitif: error 3, note 2

## Gerçek pozitifler

| Set | İkili | Katman | Beklenen | Zorunlu | Sonuç |
|---|---|---|---|---|---|
| pozitif | `upx_pe_t32` | packer | `^paketleyici:UPX$` | evet | var paketleyici:UPX |
| pozitif | `upx_pe_t32` | yara | `^kural:UPX_Packed$` | evet | var kural:UPX_Packed |
| pozitif | `upx_pe_t64` | packer | `^paketleyici:UPX$` | evet | var paketleyici:UPX |
| pozitif | `upx_pe_t64` | yara | `^kural:UPX_Packed$` | evet | var kural:UPX_Packed |
| pozitif | `upx_elf_true` | packer | `^paketleyici:UPX$` | evet | var paketleyici:UPX |
| pozitif | `upx_elf_true` | yara | `^kural:UPX_Packed$` | evet | var kural:UPX_Packed |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:RDTSC_Timing$` | evet | var teknik:RDTSC_Timing |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:ptrace_pt_deny_attach$` | evet | var teknik:ptrace_pt_deny_attach |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:sysctl_kinfo_proc$` | evet | var teknik:sysctl_kinfo_proc |
| pozitif | `antidebug_x86_64` | yara | `^kural:AntiDebug_SysctlCheck$` | evet | var kural:AntiDebug_SysctlCheck |
| pozitif | `antidebug_x86_64` | yara | `^kural:AntiDebug_(Ptrace|Timing)$` | hayır | yok  |
| pozitif | `antidebug_x86_64` | bi | `^guvenlik:Anti-Debugging$` | evet | var guvenlik:Anti-Debugging |
| pozitif | `libcrypto` | bi | `^algoritma:AES$` | evet | var algoritma:AES |
| pozitif | `libcrypto` | bi | `^algoritma:RSA$` | evet | var algoritma:RSA |
| pozitif | `libcrypto` | bi | `^algoritma:SHA-256$` | evet | var algoritma:SHA-256 |
| pozitif | `libcrypto` | yara | `^kural:OpenSSL_Library$` | evet | var kural:OpenSSL_Library |
| pozitif | `libcrypto` | yara | `^kural:(AES_SBox|SHA256_Init_Constants|SHA256_Round_Constants)$` | hayır | yok  |
| pozitif | `openssl_cli` | bi | `^algoritma:AES$` | evet | var algoritma:AES |
| pozitif | `openssl_cli` | bi | `^algoritma:RSA$` | evet | var algoritma:RSA |
| pozitif | `openssl_cli` | yara | `^kural:OpenSSL_Library$` | evet | var kural:OpenSSL_Library |
| gelistirme | `debian/openssl/openssl` | bi | `^algoritma:AES$` | evet | var algoritma:AES |
| gelistirme | `debian/openssl/openssl` | bi | `^algoritma:RSA$` | evet | var algoritma:RSA |
| gelistirme | `debian/openssl/openssl` | yara | `^kural:OpenSSL_Library$` | evet | var kural:OpenSSL_Library |
| macos | `/usr/bin/ssh` | bi | `^algoritma:(Ed25519|ChaCha20-Poly1305)$` | evet | var algoritma:ChaCha20-Poly1305, algoritma:Ed25519 |
| pe | `/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib/w32.exe` | capa | `^yetenek:` | hayır | yok  |
