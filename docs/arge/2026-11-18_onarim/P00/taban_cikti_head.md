# Masum ikili kapısı — cikti kip

- Zaman: 2026-11-18T09:48:56+03:00 → 2026-11-18T09:49:22+03:00 (25.6 sn)
- Ağaç: `/Users/apple/Black_Widow/.claude/worktrees/agent-aa796f040812276d2` @ `27e2e1a900` (karadul 1.23.1; `/Users/apple/Black_Widow/.claude/worktrees/agent-aa796f040812276d2/karadul/__init__.py`); kirli: 2 dosya
- Koşu: `/Users/apple/karadul_olcum/runs/genel-tarama-2026-11-18` (14 ikili; koşunun ağacı `e9d2d08ab5`, karadul 1.23.1)
  - **Dikkat:** koşuyu üreten commit ölçülen ağaçtan farklı; bileşim şablon listesi ölçülen ağaçtan okunur.
- Kapı: **GEÇTİ** (çıkış 0)

## Katman × set: yanlış iddia

| Katman | Set | İkili | Durum | İddia | Yanlış | Doğru bilinen | Yanlışlı ikili | Adet (yanlış) | Eşik |
|---|---|---|---|---|---|---|---|---|---|
| bilesim | gelistirme | 14 | calisti 14 | 82 | 82 | 0 | 14 | 82 (82) | 82 ≤ 82 (icinde; 14 ikili) |
| algoritma_kod | gelistirme | 14 | calisti 14 | 29 | 29 | 0 | 7 | 46 (46) | 29 ≤ 29 (icinde; 14 ikili) |
| algoritma_json | gelistirme | 14 | calisti 14 | 45 | 45 | 0 | 9 | 142 (142) | 45 ≤ 45 (icinde; 14 ikili) |
| security_etiketi | gelistirme | 14 | calisti 14 | 22 | 22 | 0 | 7 | 3209 (3209) | 22 ≤ 22 (icinde; 14 ikili) |
| sarif | gelistirme | 14 | calisti 14 | 37 | 37 | 0 | 12 | 37 (37) | 37 ≤ 37 (icinde; 14 ikili) |
| blok_yorumu | gelistirme | 14 | calisti 14 | 10 | 10 | 0 | 9 | 101 (101) | 10 ≤ 10 (icinde; 14 ikili) |
| types_h | gelistirme | 14 | calisti 14 | 14 | 14 | 0 | 14 | 4109 (4109) | 14 ≤ 14 (icinde; 14 ikili) |
| intel | gelistirme | 14 | calisti 14 | 396 | 353 | 43 | 14 | 396 (353) | 353 ≤ 353 (icinde; 14 ikili) |
| antidebug_cikti | gelistirme | 14 | calisti 14 | 7 | 7 | 0 | 6 | 7 (7) | 7 ≤ 7 (icinde; 14 ikili) |
| packer_cikti | gelistirme | 14 | calisti 14 | 0 | 0 | 0 | 0 | 0 (0) | 0 ≤ 0 (icinde; 14 ikili) |
| yara_cikti | gelistirme | 14 | bilinmiyor 2, calisti 12 | 37 | 31 | 6 | 12 | 37 (31) | 31 ≤ 31 (icinde; 14 ikili) |
| bilesim_yeniden | gelistirme | 14 | calisti 14 | 82 | 82 | 0 | 14 | 82 (82) | 82 ≤ 82 (icinde; 14 ikili) |
| algoritma_yeniden | gelistirme | 14 | calisti 14 | 45 | 45 | 0 | 9 | 142 (142) | 45 ≤ 45 (icinde; 14 ikili) |

## En sık etiketler (ikili sayısı değil, iddia sayısı; bir ikilide etiket bir kez)

- **bilesim / gelistirme**: `sablon:Matrix Solve Pipeline` 14, `sablon:Rocket / Trajectory Simulation Loop` 14, `sablon:Transient CFD Time-Stepping` 14, `sablon:Compress-then-Encrypt Pipeline` 8, `sablon:Cryptographic Key Derivation Pipeline` 5, `sablon:VPN Tunnel Setup Pipeline` 5, `sablon:Hash-then-Sign Pipeline` 3, `sablon:Key Derivation Pipeline` 3
- **algoritma_kod / gelistirme**: `algoritma:Galois field operations (ECC, AES-GF)` 5, `algoritma:Base64 encoding/decoding` 2, `algoritma:LZ-family compression (LZ77, LZW, zlib)` 2, `algoritma:TLS context` 2, `algoritma:TLS handshake (client)` 2, `algoritma:Block cipher mode of operation (CBC, CTR, GCM)` 1, `algoritma:CSPRNG (OpenSSL)` 1, `algoritma:Elliptic curve operations (ECDSA, ECDH)` 1
- **algoritma_json / gelistirme**: `algoritma:Galois field operations (ECC, AES-GF)` 9, `algoritma:Base64 encoding/decoding` 2, `algoritma:LZ-family compression (LZ77, LZW, zlib)` 2, `algoritma:Password-based key derivation (PBKDF2, scrypt)` 2, `algoritma:TLS context` 2, `algoritma:TLS encrypted read` 2, `algoritma:TLS encrypted write` 2, `algoritma:TLS handshake (client)` 2
- **security_etiketi / gelistirme**: `security:Handles sensitive key material` 7, `security:Code injection/hooking mechanism` 3, `security:Handles authentication/credentials` 3, `security:Handles certificates/TLS` 3, `security:Handles cryptographic operations` 3, `security:Receives sensitive parameters` 2, `security:Handles privilege/sandbox operations` 1
- **sarif / gelistirme**: `KRDL003:Stack_String_Construction` 11, `KRDL003:MPRESS_Packed` 8, `KRDL003:AntiDebug_Timing` 6, `KRDL003:Zlib_Library` 6, `KRDL003:OpenSSL_Library` 2, `KRDL003:Zstd_Library` 2, `KRDL003:ASPack_Packed` 1, `KRDL003:AntiDebug_SysctlCheck` 1
- **blok_yorumu / gelistirme**: `blok:Row-major matrix access` 9, `blok:Iteration loop` 1
- **types_h / gelistirme**: `yapi:recovered_struct` 14
- **intel / gelistirme**: `algoritma:OpenGL` 14, `altsistem:Bluetooth` 14, `altsistem:Encryption` 14, `altsistem:File System Operations` 14, `altsistem:Memory Management` 14, `altsistem:Terminal Emulator` 14, `guvenlik:Stack Protection` 14, `protokol:IPsec` 12
- **antidebug_cikti / gelistirme**: `teknik:RDTSC_Timing` 5, `teknik:prctl_set_dumpable` 1, `teknik:sysctl_kinfo_proc` 1
- **yara_cikti / gelistirme**: `kural:Stack_String_Construction` 11, `kural:MPRESS_Packed` 8, `kural:AntiDebug_Timing` 6, `kural:Zlib_Library` 6, `kural:OpenSSL_Library` 2, `kural:Zstd_Library` 2, `kural:ASPack_Packed` 1, `kural:AntiDebug_SysctlCheck` 1
  - neden (2 ikili): yara_backend yok: tarandı mı bilinmiyor
- **bilesim_yeniden / gelistirme**: `sablon:Matrix Solve Pipeline` 14, `sablon:Rocket / Trajectory Simulation Loop` 14, `sablon:Transient CFD Time-Stepping` 14, `sablon:Compress-then-Encrypt Pipeline` 8, `sablon:Cryptographic Key Derivation Pipeline` 5, `sablon:VPN Tunnel Setup Pipeline` 5, `sablon:Hash-then-Sign Pipeline` 3, `sablon:Key Derivation Pipeline` 3
- **algoritma_yeniden / gelistirme**: `algoritma:Galois field operations (ECC, AES-GF)` 9, `algoritma:Base64 encoding/decoding` 2, `algoritma:LZ-family compression (LZ77, LZW, zlib)` 2, `algoritma:Password-based key derivation (PBKDF2, scrypt)` 2, `algoritma:TLS context` 2, `algoritma:TLS encrypted read` 2, `algoritma:TLS encrypted write` 2, `algoritma:TLS handshake (client)` 2

## İzlenen yanlış etiketler (rapordaki bulgular; ikili sayısı)

| Ad | Katman | Set | Etiket | İkili / ölçülen | Adet | Rapordaki |
|---|---|---|---|---|---|---|
| bluetooth | intel | gelistirme | `^altsistem:Bluetooth$` | 14 / 14 | 14 | IMZA-01: 119/119 (gelistirme) |
| encryption | intel | gelistirme | `^altsistem:Encryption$` | 6 / 6 | 6 | IMZA-01: 119/119; burada kriptosuz alt küme |
| opengl | intel | gelistirme | `^algoritma:OpenGL$` | 14 / 14 | 14 | IMZA-01: 119/119 |
| sha256_yardim_metni | intel | gelistirme | `^algoritma:SHA-256$` | 4 / 4 | 4 | IMZA-01: 107 (gelistirme, tümü); burada coreutils |
| kernel_riskli | intel | gelistirme | `^guvenlik:(SIP \(System Integrity\)|Kernel Extension)$` | 2 / 14 | 3 | IMZA-01: SIP 5, Kernel Extension 3 |
| ipsec | intel | gelistirme | `^protokol:IPsec$` | 12 / 14 | 12 | IMZA-01: 46 |
| rdtsc | antidebug_cikti | gelistirme | `^teknik:RDTSC_Timing$` | 5 / 14 | 5 | IMZA-02: 14 (gelistirme, AArch64) |
| sysctl_tek_ithal | antidebug_cikti | gelistirme | `^teknik:sysctl_kinfo_proc$` | 1 / 14 | 1 | IMZA-02: mac/htop, top, sysctl, vim |
| fsg | packer_cikti | gelistirme | `^paketleyici:FSG$` | 0 / 14 | 0 | IMZA-04 |
| mpress | yara_cikti | gelistirme | `^kural:MPRESS_Packed$` | 8 / 14 | 8 | IMZA-05: 13 (gelistirme) |
| aspack | yara_cikti | gelistirme | `^kural:ASPack_Packed$` | 1 / 14 | 1 | IMZA-05: 1 (tree) |
| delphi | yara_cikti | gelistirme | `^kural:Delphi_Compiler$` | 0 / 14 | 0 | IMZA-05: 2 (redis) |
| yara_antidebug | yara_cikti | gelistirme | `^kural:AntiDebug_` | 7 / 14 | 7 | IMZA-05: Timing 23, SysctlCheck 4 |
| stack_string | yara_cikti | gelistirme | `^kural:Stack_String_Construction$` | 11 / 14 | 11 | IMZA-05: 19 |
| cfd | bilesim | gelistirme | `CFD` | 14 / 14 | 16 | MUH-03/ARAYUZ-01: 119/119 (Transient CFD) |
| cfd | bilesim_yeniden | gelistirme | `CFD` | 14 / 14 | 16 | MUH-03/ARAYUZ-01: 119/119 (Transient CFD) |
| roket | bilesim | gelistirme | `^sablon:Rocket` | 14 / 14 | 14 | MUH-03: 119/119 |
| roket | bilesim_yeniden | gelistirme | `^sablon:Rocket` | 14 / 14 | 14 | MUH-03: 119/119 |
| matris | bilesim | gelistirme | `^sablon:Matrix Solve` | 14 / 14 | 14 | MUH-03: 119/119 |
| matris | bilesim_yeniden | gelistirme | `^sablon:Matrix Solve` | 14 / 14 | 14 | MUH-03: 119/119 |
| vpn | bilesim | gelistirme | `^sablon:VPN Tunnel` | 5 / 14 | 5 | ARAYUZ-01: 16 ikili |
| vpn | bilesim_yeniden | gelistirme | `^sablon:VPN Tunnel` | 5 / 14 | 5 | ARAYUZ-01: 16 ikili |
| ses | bilesim | gelistirme | `^sablon:Audio Codec` | 2 / 14 | 2 | MUH-03: 4 |
| ses | bilesim_yeniden | gelistirme | `^sablon:Audio Codec` | 2 / 14 | 2 | MUH-03: 4 |
| galois_kod | algoritma_kod | gelistirme | `^algoritma:Galois field` | 5 / 14 | 12 | MEK HEAD 14: htop 8, sqlite3 10, redis-cli 2, iki tmux 2'şer |
| galois_json | algoritma_json | gelistirme | `^algoritma:Galois field` | 9 / 14 | 39 | TIP-09: 162 etiket, 30 ikili (1.22.1) |
| galois_json | algoritma_yeniden | gelistirme | `^algoritma:Galois field` | 9 / 14 | 39 | TIP-09: 162 etiket, 30 ikili (1.22.1) |
| pbkdf2_json | algoritma_json | gelistirme | `^algoritma:Password-based key derivation` | 2 / 14 | 3 | TIP-09: 6 etiket |
| pbkdf2_json | algoritma_yeniden | gelistirme | `^algoritma:Password-based key derivation` | 2 / 14 | 3 | TIP-09: 6 etiket |
| security_kanca | security_etiketi | gelistirme | `^security:Code injection/hooking` | 3 / 14 | 11 | TIP-08: 9 |
| security_kimlik | security_etiketi | gelistirme | `^security:Handles authentication/credentials` | 3 / 14 | 21 | TIP-08: 70 |
| security_anahtar | security_etiketi | gelistirme | `^security:Handles sensitive key material` | 7 / 14 | 618 | TIP-08: 869 |
| row_major | blok_yorumu | gelistirme | `^blok:Row-major matrix access$` | 9 / 14 | 95 | MUH-07: 370 yorum (1.22.1, 119 ikili) |
| recovered_struct | types_h | gelistirme | `^yapi:recovered_struct$` | 14 / 14 | 4109 | TIP-07: 5 585 yapı, 116 ikili (1.22.1); MEK HEAD 14: 4 109 |
| sarif_paket_uyarisi | sarif | gelistirme | `^KRDL003:(MPRESS|ASPack|UPX|VMProtect|Themida|PECompact|Enigma)` | 9 / 14 | 9 | ARAYUZ-17 / IMZA-05: SARIF warning |
| sarif_antidebug_uyarisi | sarif | gelistirme | `^KRDL003:AntiDebug_` | 7 / 14 | 7 | MEK HEAD tablosu |

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
