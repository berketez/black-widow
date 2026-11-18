# Masum ikili kapısı — cikti kip

- Zaman: 2026-11-18T09:49:31+03:00 → 2026-11-18T09:50:46+03:00 (75.3 sn)
- Ağaç: `/Users/apple/Black_Widow/.claude/worktrees/agent-aa796f040812276d2` @ `27e2e1a900` (karadul 1.23.1; `/Users/apple/Black_Widow/.claude/worktrees/agent-aa796f040812276d2/karadul/__init__.py`); kirli: 2 dosya
- Koşu: `/Users/apple/karadul_olcum/runs/urun-yeni2-f30ac9a` (119 ikili; koşunun ağacı `f30ac9a1d2`, karadul 1.22.1)
  - **Dikkat:** koşuyu üreten commit ölçülen ağaçtan farklı; bileşim şablon listesi ölçülen ağaçtan okunur.
- Kapı: **GEÇTİ** (çıkış 0)

## Katman × set: yanlış iddia

| Katman | Set | İkili | Durum | İddia | Yanlış | Doğru bilinen | Yanlışlı ikili | Adet (yanlış) | Eşik |
|---|---|---|---|---|---|---|---|---|---|
| bilesim | gelistirme | 119 | calisti 119 | 451 | 451 | 0 | 119 | 451 (451) | 82 ≤ 82 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 369 |
| algoritma_kod | gelistirme | 119 | calisti 119 | 66 | 66 | 0 | 18 | 171 (171) | 29 ≤ 29 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 37 |
| algoritma_json | gelistirme | 119 | calisti 119 | 109 | 109 | 0 | 37 | 392 (392) | 45 ≤ 45 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 64 |
| security_etiketi | gelistirme | 119 | calisti 119 | 47 | 47 | 0 | 18 | 4327 (4327) | 22 ≤ 22 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 25 |
| sarif | gelistirme | 119 | calisti 119 | 81 | 81 | 0 | 31 | 81 (81) | 37 ≤ 37 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 44 |
| blok_yorumu | gelistirme | 119 | calisti 119 | 112 | 112 | 0 | 111 | 376 (376) | 9 ≤ 10 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 103 |
| types_h | gelistirme | 119 | calisti 118, yapit_yok 1 | 117 | 117 | 0 | 117 | 7183 (7183) | 13 ≤ 14 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 104 |
| intel | gelistirme | 119 | calisti 119 | 2130 | 1965 | 165 | 119 | 2130 (1965) | 344 ≤ 353 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 1621 |
| antidebug_cikti | gelistirme | 119 | calisti 119 | 23 | 23 | 0 | 16 | 23 (23) | 7 ≤ 7 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 16 |
| packer_cikti | gelistirme | 119 | calisti 119 | 0 | 0 | 0 | 0 | 0 (0) | 0 ≤ 0 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 0 |
| yara_cikti | gelistirme | 119 | bilinmiyor 88, calisti 31 | 81 | 70 | 11 | 31 | 81 (70) | 31 ≤ 31 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 39 |
| bilesim_yeniden | gelistirme | 119 | calisti 119 | 451 | 451 | 0 | 119 | 451 (451) | 82 ≤ 82 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 369 |
| algoritma_yeniden | gelistirme | 119 | calisti 119 | 109 | 109 | 0 | 37 | 392 (392) | 45 ≤ 45 (icinde; 14 ikili); eşiksiz 105 ikilide yanlış 64 |

## En sık etiketler (ikili sayısı değil, iddia sayısı; bir ikilide etiket bir kez)

- **bilesim / gelistirme**: `sablon:Matrix Solve Pipeline` 119, `sablon:Rocket / Trajectory Simulation Loop` 119, `sablon:Transient CFD Time-Stepping` 119, `sablon:VPN Tunnel Setup Pipeline` 16, `sablon:Compress-then-Encrypt Pipeline` 11, `sablon:Cryptographic Key Derivation Pipeline` 9, `sablon:Key Derivation Pipeline` 9, `sablon:Hash-then-Sign Pipeline` 6
- **algoritma_kod / gelistirme**: `algoritma:Galois field operations (ECC, AES-GF)` 13, `algoritma:TLS context` 5, `algoritma:TLS handshake (client)` 5, `algoritma:LZ-family compression (LZ77, LZW, zlib)` 4, `algoritma:TLS encrypted read` 4, `algoritma:TLS encrypted write` 4, `algoritma:Base64 encoding/decoding` 3, `algoritma:TLS handshake (server)` 3
- **algoritma_json / gelistirme**: `algoritma:Galois field operations (ECC, AES-GF)` 32, `algoritma:Base64 encoding/decoding` 5, `algoritma:Password-based key derivation (PBKDF2, scrypt)` 5, `algoritma:TLS context` 5, `algoritma:TLS encrypted read` 5, `algoritma:TLS encrypted write` 5, `algoritma:TLS handshake (client)` 5, `algoritma:TLS session` 5
- **security_etiketi / gelistirme**: `security:Handles cryptographic operations` 12, `security:Handles sensitive key material` 10, `security:Handles authentication/credentials` 6, `security:Handles certificates/TLS` 6, `security:Code injection/hooking mechanism` 5, `security:Handles privilege/sandbox operations` 4, `security:Receives sensitive parameters` 4
- **sarif / gelistirme**: `KRDL003:AntiDebug_Timing` 23, `KRDL003:Stack_String_Construction` 19, `KRDL003:MPRESS_Packed` 13, `KRDL003:Zlib_Library` 10, `KRDL003:OpenSSL_Library` 5, `KRDL003:AntiDebug_SysctlCheck` 4, `KRDL003:Delphi_Compiler` 2, `KRDL003:GCC_Compiler` 2
- **blok_yorumu / gelistirme**: `blok:Row-major matrix access` 111, `blok:Iteration loop` 1
- **types_h / gelistirme**: `yapi:recovered_struct` 117
  - neden (1 ikili): out/src/include/types.h yok
- **intel / gelistirme**: `algoritma:OpenGL` 119, `altsistem:Bluetooth` 119, `altsistem:Encryption` 119, `altsistem:Memory Management` 119, `guvenlik:Stack Protection` 119, `altsistem:File System Operations` 118, `altsistem:Terminal Emulator` 117, `altsistem:HTTP Client` 115
- **antidebug_cikti / gelistirme**: `teknik:RDTSC_Timing` 14, `teknik:prctl_set_dumpable` 4, `teknik:INT3_Cluster` 2, `teknik:Linux_ProcMaps` 2, `teknik:sysctl_kinfo_proc` 1
- **yara_cikti / gelistirme**: `kural:AntiDebug_Timing` 23, `kural:Stack_String_Construction` 19, `kural:MPRESS_Packed` 13, `kural:Zlib_Library` 10, `kural:OpenSSL_Library` 5, `kural:AntiDebug_SysctlCheck` 4, `kural:Delphi_Compiler` 2, `kural:GCC_Compiler` 2
  - neden (88 ikili): yara_backend yok: tarandı mı bilinmiyor
- **bilesim_yeniden / gelistirme**: `sablon:Matrix Solve Pipeline` 119, `sablon:Rocket / Trajectory Simulation Loop` 119, `sablon:Transient CFD Time-Stepping` 119, `sablon:VPN Tunnel Setup Pipeline` 16, `sablon:Compress-then-Encrypt Pipeline` 11, `sablon:Cryptographic Key Derivation Pipeline` 9, `sablon:Key Derivation Pipeline` 9, `sablon:Hash-then-Sign Pipeline` 6
- **algoritma_yeniden / gelistirme**: `algoritma:Galois field operations (ECC, AES-GF)` 32, `algoritma:Base64 encoding/decoding` 5, `algoritma:Password-based key derivation (PBKDF2, scrypt)` 5, `algoritma:TLS context` 5, `algoritma:TLS encrypted read` 5, `algoritma:TLS encrypted write` 5, `algoritma:TLS handshake (client)` 5, `algoritma:TLS session` 5

## İzlenen yanlış etiketler (rapordaki bulgular; ikili sayısı)

| Ad | Katman | Set | Etiket | İkili / ölçülen | Adet | Rapordaki |
|---|---|---|---|---|---|---|
| bluetooth | intel | gelistirme | `^altsistem:Bluetooth$` | 119 / 119 | 119 | IMZA-01: 119/119 (gelistirme) |
| encryption | intel | gelistirme | `^altsistem:Encryption$` | 108 / 108 | 108 | IMZA-01: 119/119; burada kriptosuz alt küme |
| opengl | intel | gelistirme | `^algoritma:OpenGL$` | 119 / 119 | 119 | IMZA-01: 119/119 |
| sha256_yardim_metni | intel | gelistirme | `^algoritma:SHA-256$` | 104 / 106 | 104 | IMZA-01: 107 (gelistirme, tümü); burada coreutils |
| kernel_riskli | intel | gelistirme | `^guvenlik:(SIP \(System Integrity\)|Kernel Extension)$` | 5 / 119 | 8 | IMZA-01: SIP 5, Kernel Extension 3 |
| ipsec | intel | gelistirme | `^protokol:IPsec$` | 46 / 119 | 46 | IMZA-01: 46 |
| rdtsc | antidebug_cikti | gelistirme | `^teknik:RDTSC_Timing$` | 14 / 119 | 14 | IMZA-02: 14 (gelistirme, AArch64) |
| sysctl_tek_ithal | antidebug_cikti | gelistirme | `^teknik:sysctl_kinfo_proc$` | 1 / 119 | 1 | IMZA-02: mac/htop, top, sysctl, vim |
| fsg | packer_cikti | gelistirme | `^paketleyici:FSG$` | 0 / 119 | 0 | IMZA-04 |
| mpress | yara_cikti | gelistirme | `^kural:MPRESS_Packed$` | 13 / 119 | 13 | IMZA-05: 13 (gelistirme) |
| aspack | yara_cikti | gelistirme | `^kural:ASPack_Packed$` | 1 / 119 | 1 | IMZA-05: 1 (tree) |
| delphi | yara_cikti | gelistirme | `^kural:Delphi_Compiler$` | 2 / 119 | 2 | IMZA-05: 2 (redis) |
| yara_antidebug | yara_cikti | gelistirme | `^kural:AntiDebug_` | 24 / 119 | 27 | IMZA-05: Timing 23, SysctlCheck 4 |
| stack_string | yara_cikti | gelistirme | `^kural:Stack_String_Construction$` | 19 / 119 | 19 | IMZA-05: 19 |
| cfd | bilesim | gelistirme | `CFD` | 119 / 119 | 123 | MUH-03/ARAYUZ-01: 119/119 (Transient CFD) |
| cfd | bilesim_yeniden | gelistirme | `CFD` | 119 / 119 | 123 | MUH-03/ARAYUZ-01: 119/119 (Transient CFD) |
| roket | bilesim | gelistirme | `^sablon:Rocket` | 119 / 119 | 119 | MUH-03: 119/119 |
| roket | bilesim_yeniden | gelistirme | `^sablon:Rocket` | 119 / 119 | 119 | MUH-03: 119/119 |
| matris | bilesim | gelistirme | `^sablon:Matrix Solve` | 119 / 119 | 119 | MUH-03: 119/119 |
| matris | bilesim_yeniden | gelistirme | `^sablon:Matrix Solve` | 119 / 119 | 119 | MUH-03: 119/119 |
| vpn | bilesim | gelistirme | `^sablon:VPN Tunnel` | 16 / 119 | 16 | ARAYUZ-01: 16 ikili |
| vpn | bilesim_yeniden | gelistirme | `^sablon:VPN Tunnel` | 16 / 119 | 16 | ARAYUZ-01: 16 ikili |
| ses | bilesim | gelistirme | `^sablon:Audio Codec` | 4 / 119 | 4 | MUH-03: 4 |
| ses | bilesim_yeniden | gelistirme | `^sablon:Audio Codec` | 4 / 119 | 4 | MUH-03: 4 |
| galois_kod | algoritma_kod | gelistirme | `^algoritma:Galois field` | 13 / 119 | 69 | MEK HEAD 14: htop 8, sqlite3 10, redis-cli 2, iki tmux 2'şer |
| galois_json | algoritma_json | gelistirme | `^algoritma:Galois field` | 32 / 119 | 172 | TIP-09: 162 etiket, 30 ikili (1.22.1) |
| galois_json | algoritma_yeniden | gelistirme | `^algoritma:Galois field` | 32 / 119 | 172 | TIP-09: 162 etiket, 30 ikili (1.22.1) |
| pbkdf2_json | algoritma_json | gelistirme | `^algoritma:Password-based key derivation` | 5 / 119 | 6 | TIP-09: 6 etiket |
| pbkdf2_json | algoritma_yeniden | gelistirme | `^algoritma:Password-based key derivation` | 5 / 119 | 6 | TIP-09: 6 etiket |
| security_kanca | security_etiketi | gelistirme | `^security:Code injection/hooking` | 5 / 119 | 15 | TIP-08: 9 |
| security_kimlik | security_etiketi | gelistirme | `^security:Handles authentication/credentials` | 6 / 119 | 70 | TIP-08: 70 |
| security_anahtar | security_etiketi | gelistirme | `^security:Handles sensitive key material` | 10 / 119 | 894 | TIP-08: 869 |
| row_major | blok_yorumu | gelistirme | `^blok:Row-major matrix access$` | 111 / 119 | 370 | MUH-07: 370 yorum (1.22.1, 119 ikili) |
| recovered_struct | types_h | gelistirme | `^yapi:recovered_struct$` | 117 / 119 | 7183 | TIP-07: 5 585 yapı, 116 ikili (1.22.1); MEK HEAD 14: 4 109 |
| sarif_paket_uyarisi | sarif | gelistirme | `^KRDL003:(MPRESS|ASPack|UPX|VMProtect|Themida|PECompact|Enigma)` | 14 / 119 | 14 | ARAYUZ-17 / IMZA-05: SARIF warning |
| sarif_antidebug_uyarisi | sarif | gelistirme | `^KRDL003:AntiDebug_` | 24 / 119 | 27 | MEK HEAD tablosu |

## Gerçek pozitifler

| Set | İkili | Katman | Beklenen | Zorunlu | Sonuç |
|---|---|---|---|---|---|
| pozitif | `upx_pe_t32` | packer | `^paketleyici:UPX$` | evet | olculmedi  |
| pozitif | `upx_pe_t32` | yara | `^kural:UPX_Packed$` | evet | olculmedi  |
| pozitif | `upx_pe_t64` | packer | `^paketleyici:UPX$` | evet | olculmedi  |
| pozitif | `upx_pe_t64` | yara | `^kural:UPX_Packed$` | evet | olculmedi  |
| pozitif | `upx_elf_true` | packer | `^paketleyici:UPX$` | evet | olculmedi  |
| pozitif | `upx_elf_true` | yara | `^kural:UPX_Packed$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:RDTSC_Timing$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:ptrace_pt_deny_attach$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | antidebug | `^teknik:sysctl_kinfo_proc$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | yara | `^kural:AntiDebug_SysctlCheck$` | evet | olculmedi  |
| pozitif | `antidebug_x86_64` | yara | `^kural:AntiDebug_(Ptrace|Timing)$` | hayır | olculmedi  |
| pozitif | `antidebug_x86_64` | bi | `^guvenlik:Anti-Debugging$` | evet | olculmedi  |
| pozitif | `libcrypto` | bi | `^algoritma:AES$` | evet | olculmedi  |
| pozitif | `libcrypto` | bi | `^algoritma:RSA$` | evet | olculmedi  |
| pozitif | `libcrypto` | bi | `^algoritma:SHA-256$` | evet | olculmedi  |
| pozitif | `libcrypto` | yara | `^kural:OpenSSL_Library$` | evet | olculmedi  |
| pozitif | `libcrypto` | yara | `^kural:(AES_SBox|SHA256_Init_Constants|SHA256_Round_Constants)$` | hayır | olculmedi  |
| pozitif | `openssl_cli` | bi | `^algoritma:AES$` | evet | olculmedi  |
| pozitif | `openssl_cli` | bi | `^algoritma:RSA$` | evet | olculmedi  |
| pozitif | `openssl_cli` | yara | `^kural:OpenSSL_Library$` | evet | olculmedi  |
| gelistirme | `debian/openssl/openssl` | bi | `^algoritma:AES$` | evet | var algoritma:AES |
| gelistirme | `debian/openssl/openssl` | bi | `^algoritma:RSA$` | evet | var algoritma:RSA |
| gelistirme | `debian/openssl/openssl` | yara | `^kural:OpenSSL_Library$` | evet | var kural:OpenSSL_Library |
| macos | `/usr/bin/ssh` | bi | `^algoritma:(Ed25519|ChaCha20-Poly1305)$` | evet | olculmedi  |
| pe | `/opt/anaconda3/lib/python3.12/site-packages/pip/_vendor/distlib/w32.exe` | capa | `^yetenek:` | hayır | olculmedi  |
