// ==== _sw_dense @ 100000548

undefined4 _sw_dense(int param_1)

{
  undefined4 local_4;
  
  if (param_1 == 0) {
    local_4 = 0xb;
  }
  else if (param_1 == 1) {
    local_4 = 0x1b;
  }
  else if (param_1 == 2) {
    local_4 = 0x23;
  }
  else if (param_1 == 3) {
    local_4 = 0x31;
  }
  else if (param_1 == 4) {
    local_4 = 0x34;
  }
  else if (param_1 == 5) {
    local_4 = 0x44;
  }
  else if (param_1 == 6) {
    local_4 = 0x47;
  }
  else if (param_1 == 7) {
    local_4 = 0x59;
  }
  else {
    local_4 = 0xffffffff;
  }
  return local_4;
}


// ==== _sw_sparse @ 100000648

undefined4 _sw_sparse(int param_1)

{
  undefined4 local_4;
  
  if (param_1 == 3) {
    local_4 = 1;
  }
  else if (param_1 == 100) {
    local_4 = 2;
  }
  else if (param_1 == 1000) {
    local_4 = 3;
  }
  else if (param_1 == 5000) {
    local_4 = 4;
  }
  else if (param_1 == 20000) {
    local_4 = 5;
  }
  else if (param_1 == 0x12fd1) {
    local_4 = 6;
  }
  else if (param_1 == 0x1e240) {
    local_4 = 7;
  }
  else {
    local_4 = 0;
  }
  return local_4;
}


// ==== _sw_bittest @ 100000744

undefined4 _sw_bittest(int param_1)

{
  undefined4 local_4;
  
  if ((((param_1 - 9U < 5) || (param_1 == 0x20)) || (param_1 == 0x2c)) || (param_1 == 0x3b)) {
    local_4 = 1;
  }
  else {
    local_4 = 0;
  }
  return local_4;
}


// ==== _udiv7 @ 1000007b4

uint _udiv7(uint param_1)

{
  return param_1 / 7;
}


// ==== _sdiv7 @ 1000007d0

int _sdiv7(int param_1)

{
  return param_1 / 7;
}


// ==== _umod10 @ 1000007ec

uint _umod10(uint param_1)

{
  return param_1 % 10;
}


// ==== _sdiv16 @ 100000810

int _sdiv16(int param_1)

{
  return param_1 / 0x10;
}


// ==== _udiv1000_64 @ 10000082c

ulong _udiv1000_64(ulong param_1)

{
  return param_1 / 1000;
}


// ==== _sel_max @ 100000848

int _sel_max(int param_1,int param_2)

{
  int local_c;
  
  local_c = param_2;
  if (param_2 < param_1) {
    local_c = param_1;
  }
  return local_c;
}


// ==== _sel_abs @ 10000088c

int _sel_abs(int param_1)

{
  int local_8;
  
  local_8 = param_1;
  if (param_1 < 0) {
    local_8 = -param_1;
  }
  return local_8;
}


// ==== _sel_clamp @ 1000008cc

int _sel_clamp(int param_1,int param_2,int param_3)

{
  int local_14;
  int local_10;
  
  local_10 = param_2;
  if (param_2 <= param_1) {
    local_14 = param_1;
    if (param_3 < param_1) {
      local_14 = param_3;
    }
    local_10 = local_14;
  }
  return local_10;
}


// ==== _popcount_loop @ 100000940

int _popcount_loop(uint param_1)

{
  undefined4 local_8;
  undefined4 local_4;
  
  local_8 = 0;
  for (local_4 = param_1; local_4 != 0; local_4 = local_4 & local_4 - 1) {
    local_8 = local_8 + 1;
  }
  return local_8;
}


// ==== _bswap32_manual @ 10000098c

uint _bswap32_manual(uint param_1)

{
  return param_1 >> 8 & 0xff00 | param_1 >> 0x18 | (param_1 & 0xff00) << 8 | param_1 << 0x18;
}


// ==== _rotl32 @ 1000009c8

uint _rotl32(uint param_1,uint param_2)

{
  return param_1 << (ulong)(param_2 & 0x1f) | param_1 >> (ulong)(0x20 - param_2 & 0x1f);
}


// ==== _is_pow2 @ 100000a08

bool _is_pow2(uint param_1)

{
  return param_1 != 0 && (param_1 & param_1 - 1) == 0;
}


// ==== _copy16 @ 100000a50

void _copy16(undefined8 param_1,undefined8 param_2)

{
  ___memcpy_chk(param_1,param_2,0x10,0xffffffffffffffff);
  return;
}


// ==== _zero64 @ 100000a84

void _zero64(undefined8 param_1)

{
  ___memset_chk(param_1,0,0x40,0xffffffffffffffff);
  return;
}


// ==== _zero_n @ 100000ab4

void _zero_n(undefined8 param_1,undefined8 param_2)

{
  ___memset_chk(param_1,0,param_2,0xffffffffffffffff);
  return;
}


// ==== _strlen_const @ 100000ae8

undefined8 _strlen_const(void)

{
  return 7;
}


// ==== _strcmp_const @ 100000af0

bool _strcmp_const(char *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp(param_1,"GET");
  return iVar1 == 0;
}


// ==== _strncmp_const @ 100000b24

bool _strncmp_const(char *param_1)

{
  int iVar1;
  
  iVar1 = _strncmp(param_1,"HTTP/1.",7);
  return iVar1 == 0;
}


// ==== _loop_zero @ 100000b5c

void _loop_zero(long param_1,int param_2)

{
  undefined4 local_10;
  
  for (local_10 = 0; local_10 < param_2; local_10 = local_10 + 1) {
    *(undefined4 *)(param_1 + (long)local_10 * 4) = 0;
  }
  return;
}


// ==== _loop_copy @ 100000bb0

void _loop_copy(long param_1,long param_2,int param_3)

{
  undefined4 local_18;
  
  for (local_18 = 0; local_18 < param_3; local_18 = local_18 + 1) {
    *(undefined1 *)(param_1 + local_18) = *(undefined1 *)(param_2 + local_18);
  }
  return;
}


// ==== _loop_strlen @ 100000c18

long _loop_strlen(char *param_1)

{
  char *local_10;
  
  for (local_10 = param_1; *local_10 != '\0'; local_10 = local_10 + 1) {
  }
  return (long)local_10 - (long)param_1;
}


// ==== _make_big @ 100000c60

void _make_big(long param_1,long param_2)

{
  undefined4 local_c;
  
  for (local_c = 0; local_c < 8; local_c = local_c + 1) {
    *(long *)(param_1 + (long)local_c * 8) = param_2 + local_c;
  }
  return;
}


// ==== _use_big @ 100000cb8

long _use_big(undefined8 param_1)

{
  undefined1 auStack_58 [24];
  long local_40;
  long local_20;
  undefined8 local_18;
  
  local_18 = param_1;
  _make_big(auStack_58,param_1);
  return local_40 + local_20;
}


// ==== _make_small @ 100000cec

undefined8 _make_small(int param_1)

{
  return CONCAT44(param_1 * 3,param_1);
}


// ==== _sum_va @ 100000d18

int _sum_va(int param_1)

{
  int iVar1;
  int local_18;
  int local_14;
  
  local_14 = 0;
  for (local_18 = 0; local_18 < param_1; local_18 = local_18 + 1) {
    iVar1 = *(int *)register0x00000008;
    register0x00000008 = (BADSPACEBASE *)((long)register0x00000008 + 8);
    local_14 = local_14 + iVar1;
  }
  return local_14;
}


// ==== _ssp_copy @ 100000d90

int _ssp_copy(undefined8 param_1)

{
  size_t sVar1;
  char acStack_58 [3];
  char local_55;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004020;
  ___strcpy_chk(acStack_58,param_1,0x40);
  sVar1 = _strlen(acStack_58);
  if (*(long *)PTR____stack_chk_guard_100004020 - local_18 != 0) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail(*(long *)PTR____stack_chk_guard_100004020 - local_18);
  }
  return (int)sVar1 + (int)local_55;
}


// ==== _fortify_memcpy @ 100000e0c

void _fortify_memcpy(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined1 auStack_38 [32];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004020;
  ___memcpy_chk(auStack_38,param_2,param_3);
  ___memcpy_chk(param_1,auStack_38,0x20,0xffffffffffffffff);
  if (*(long *)PTR____stack_chk_guard_100004020 - local_18 != 0) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail(*(long *)PTR____stack_chk_guard_100004020 - local_18);
  }
  return;
}


// ==== _fortify_snprintf @ 100000e90

void _fortify_snprintf(undefined8 param_1,undefined8 param_2)

{
  ___snprintf_chk(param_1,param_2,0,0xffffffffffffffff,"deger=%d");
  return;
}


// ==== _read_file_head @ 100000edc

undefined4 _read_file_head(char *param_1,undefined8 param_2,size_t param_3)

{
  int iVar1;
  int *piVar2;
  void *pvVar3;
  ssize_t sVar4;
  FILE *pFVar5;
  undefined4 local_34;
  undefined4 local_14;
  
  local_34 = 0xffffffff;
  iVar1 = _open(param_1,0x1000000);
  if (iVar1 < 0) {
    pFVar5 = *(FILE **)PTR____stderrp_100004050;
    piVar2 = ___error();
    _strerror(*piVar2);
    _fprintf(pFVar5,"open %s: %s\n");
    local_14 = 0xffffffff;
  }
  else {
    pvVar3 = _malloc(param_3);
    if (pvVar3 != (void *)0x0) {
      sVar4 = _read(iVar1,pvVar3,param_3);
      if (sVar4 < 0) {
        piVar2 = ___error();
        *piVar2 = 5;
      }
      else {
        ___memcpy_chk(param_2,pvVar3,sVar4,0xffffffffffffffff);
        local_34 = (undefined4)sVar4;
      }
      _free(pvVar3);
    }
    _close(iVar1);
    local_14 = local_34;
  }
  return local_14;
}


// ==== _tail_target @ 100001008

int _tail_target(int param_1)

{
  return param_1 * 3 + 1;
}


// ==== _tail_caller @ 100001028

void _tail_caller(int param_1)

{
  _tail_target(param_1 + 1);
  return;
}


// ==== _tail_ext @ 100001050

int _tail_ext(long param_1)

{
  int iVar1;
  
  iVar1 = _atoi((char *)(param_1 + 1));
  return iVar1;
}


// ==== _vadd @ 100001078

void _vadd(long param_1,long param_2,long param_3,int param_4)

{
  undefined4 local_20;
  
  for (local_20 = 0; local_20 < param_4; local_20 = local_20 + 1) {
    *(int *)(param_1 + (long)local_20 * 4) =
         *(int *)(param_2 + (long)local_20 * 4) + *(int *)(param_3 + (long)local_20 * 4);
  }
  return;
}


// ==== _vsum @ 1000010ec

int _vsum(long param_1,int param_2)

{
  undefined4 local_14;
  undefined4 local_10;
  
  local_10 = 0;
  for (local_14 = 0; local_14 < param_2; local_14 = local_14 + 1) {
    local_10 = local_10 + *(int *)(param_1 + (long)local_14 * 4);
  }
  return local_10;
}


// ==== _vdot @ 100001150

float _vdot(long param_1,long param_2,int param_3)

{
  undefined4 local_1c;
  undefined4 local_18;
  
  local_18 = 0.0;
  for (local_1c = 0; local_1c < param_3; local_1c = local_1c + 1) {
    local_18 = local_18 +
               *(float *)(param_2 + (long)local_1c * 4) * *(float *)(param_1 + (long)local_1c * 4);
  }
  return local_18;
}


// ==== _md5_init @ 1000011c8

void _md5_init(undefined4 *param_1)

{
  *param_1 = 0x67452301;
  param_1[1] = 0xefcdab89;
  param_1[2] = 0x98badcfe;
  param_1[3] = 0x10325476;
  return;
}


// ==== _crc32_make_table @ 100001218

void _crc32_make_table(void)

{
  uint local_10;
  int local_c;
  uint local_8;
  uint local_4;
  
  for (local_4 = 0; local_4 < 0x100; local_4 = local_4 + 1) {
    local_8 = local_4;
    for (local_c = 0; local_c < 8; local_c = local_c + 1) {
      if ((local_8 & 1) == 0) {
        local_10 = local_8 >> 1;
      }
      else {
        local_10 = local_8 >> 1 ^ 0xedb88320;
      }
      local_8 = local_10;
    }
    *(uint *)(&_crc_table + (ulong)local_4 * 4) = local_8;
  }
  return;
}


// ==== _crc32_buf @ 1000012d8

uint _crc32_buf(byte *param_1,long param_2)

{
  uint local_14;
  long local_10;
  byte *local_8;
  
  local_14 = 0xffffffff;
  local_10 = param_2;
  local_8 = param_1;
  while (local_10 != 0) {
    local_14 = *(uint *)(&_crc_table + (ulong)((local_14 ^ *local_8) & 0xff) * 4) ^ local_14 >> 8;
    local_10 = local_10 + -1;
    local_8 = local_8 + 1;
  }
  return ~local_14;
}


// ==== _tea_encrypt @ 10000134c

void _tea_encrypt(uint *param_1,int *param_2)

{
  int local_24;
  int local_1c;
  uint local_18;
  uint local_14;
  
  local_14 = *param_1;
  local_18 = param_1[1];
  local_1c = 0;
  for (local_24 = 0; local_24 < 0x20; local_24 = local_24 + 1) {
    local_1c = local_1c + -0x61c88647;
    local_14 = local_14 +
               (*param_2 + local_18 * 0x10 ^ local_18 + local_1c ^ param_2[1] + (local_18 >> 5));
    local_18 = local_18 +
               (param_2[2] + local_14 * 0x10 ^ local_14 + local_1c ^ param_2[3] + (local_14 >> 5));
  }
  *param_1 = local_14;
  param_1[1] = local_18;
  return;
}


// ==== entry @ 10000145c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 entry(int param_1,long param_2)

{
  char *pcVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  long lVar6;
  size_t sVar7;
  int extraout_var;
  ulong uVar8;
  float fVar9;
  char *local_6b8;
  char *local_638;
  uint local_62c;
  undefined1 auStack_620 [12];
  int local_614;
  uint local_610 [4];
  long local_600;
  uint local_5f4;
  char *local_5f0;
  uint local_5e4;
  long local_5e0;
  int local_5d8;
  undefined4 local_5d4;
  undefined8 local_5d0;
  undefined8 uStack_5c8;
  uint local_5c0;
  undefined4 local_5bc;
  uint local_5b8;
  undefined4 local_5b4;
  float afStack_5a8 [64];
  float afStack_4a8 [64];
  int aiStack_3a8 [64];
  uint auStack_2a8 [64];
  undefined1 auStack_1a8 [256];
  undefined1 auStack_a8 [128];
  long local_28;
  
  local_28 = *(long *)PTR____stack_chk_guard_100004020;
  local_5d4 = 0;
  local_5e0 = param_2;
  local_5d8 = param_1;
  if (param_1 < 2) {
    local_62c = 3;
  }
  else {
    local_62c = _atoi(*(char **)(param_2 + 8));
  }
  local_5e4 = local_62c;
  if (local_5d8 < 3) {
    local_638 = "GET";
  }
  else {
    local_638 = *(char **)(local_5e0 + 0x10);
  }
  local_5f0 = local_638;
  for (local_5f4 = 0; (int)local_5f4 < 0x40; local_5f4 = local_5f4 + 1) {
    auStack_2a8[(int)local_5f4] = local_5f4 ^ local_62c;
    aiStack_3a8[(int)local_5f4] = local_5f4 + local_62c;
    afStack_4a8[(int)local_5f4] = (float)(int)local_5f4;
    afStack_5a8[(int)local_5f4] = (float)(int)local_62c;
  }
  local_600 = 0;
  iVar2 = _sw_dense(local_5f4 - 0x40,local_62c);
  iVar3 = _sw_sparse(local_5e4);
  iVar4 = _sw_bittest(local_5e4);
  local_600 = local_600 + (iVar2 + iVar3 + iVar4);
  iVar2 = _udiv7(local_5e4);
  iVar3 = _sdiv7(local_5e4);
  iVar4 = _umod10(local_5e4);
  iVar5 = _sdiv16(local_5e4);
  lVar6 = _udiv1000_64((long)(int)local_5e4);
  local_600 = local_600 + (ulong)(uint)(iVar2 + iVar3 + iVar4 + iVar5) + lVar6;
  iVar2 = _sel_max(local_5e4,5);
  iVar3 = _sel_abs(local_5e4);
  iVar4 = _sel_clamp(local_5e4,0,9);
  iVar5 = _popcount_loop(local_5e4);
  local_600 = local_600 + (iVar2 + iVar3 + iVar4 + iVar5);
  iVar2 = _bswap32_manual(local_5e4);
  iVar3 = _rotl32(local_5e4,local_5e4);
  iVar4 = _is_pow2(local_5e4);
  local_600 = local_600 + (ulong)(uint)(iVar2 + iVar3 + iVar4);
  local_610[0] = local_5e4;
  local_610[1] = 1;
  local_610[2] = 2;
  local_610[3] = 3;
  _copy16(auStack_620,local_610);
  local_600 = local_600 + local_614;
  _zero64();
  _zero_n(auStack_a8,local_5e4 & 0x3f);
  lVar6 = _strlen_const();
  iVar2 = _strcmp_const(local_5f0);
  iVar3 = _strncmp_const(local_5f0);
  local_600 = local_600 + lVar6 + iVar2 + (long)iVar3;
  _loop_zero(auStack_1a8,local_5e4 & 0x3f);
  pcVar1 = local_5f0;
  sVar7 = _strlen(local_5f0);
  _loop_copy(auStack_a8,pcVar1,sVar7);
  lVar6 = _loop_strlen(local_5f0);
  local_600 = local_600 + lVar6;
  lVar6 = _use_big((long)(int)local_5e4);
  _make_small(local_5e4);
  iVar2 = _sum_va(3);
  local_600 = local_600 + lVar6 + extraout_var + (long)iVar2;
  iVar2 = _ssp_copy(local_5f0);
  pcVar1 = local_5f0;
  local_600 = local_600 + iVar2;
  sVar7 = _strlen(local_5f0);
  _fortify_memcpy(auStack_a8,pcVar1,sVar7 & 0x1f);
  iVar2 = _fortify_snprintf(auStack_a8,0x80,local_5e4);
  local_600 = local_600 + iVar2;
  if (local_5d8 < 4) {
    local_6b8 = "/etc/hosts";
  }
  else {
    local_6b8 = *(char **)(local_5e0 + 0x18);
  }
  iVar2 = _read_file_head(local_6b8,auStack_a8,0x80);
  local_600 = local_600 + iVar2;
  iVar2 = _tail_caller(local_5e4);
  iVar3 = _tail_ext(local_5f0);
  local_600 = local_600 + (iVar2 + iVar3);
  _vadd(auStack_1a8,auStack_2a8,aiStack_3a8);
  iVar2 = _vsum(auStack_1a8,0x40);
  fVar9 = (float)_vdot(afStack_4a8,afStack_5a8,0x40);
  local_600 = local_600 + (long)fVar9 + (long)iVar2;
  _md5_init(&local_5b8);
  _crc32_make_table();
  pcVar1 = local_5f0;
  sVar7 = _strlen(local_5f0);
  uVar8 = _crc32_buf(pcVar1,sVar7);
  local_600 = local_600 + (uVar8 & 0xffffffff);
  local_5c0 = local_5b8;
  local_5bc = local_5b4;
  uStack_5c8 = _UNK_100001b28;
  local_5d0 = _DAT_100001b20;
  _tea_encrypt(&local_5c0,&local_5d0);
  local_600 = local_600 + (ulong)local_5c0;
  iVar2 = _printf("%ld\n");
  if (*(long *)PTR____stack_chk_guard_100004020 - local_28 != 0) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail(*(long *)PTR____stack_chk_guard_100004020 - local_28,iVar2);
  }
  return 0;
}


