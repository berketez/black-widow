// ==== _sw_dense @ 100000560

undefined4 _sw_dense(undefined4 param_1)

{
  undefined4 local_c;
  
  switch(param_1) {
  case 0:
    local_c = 0xb;
    break;
  case 1:
    local_c = 0x1b;
    break;
  case 2:
    local_c = 0x23;
    break;
  case 3:
    local_c = 0x31;
    break;
  case 4:
    local_c = 0x34;
    break;
  case 5:
    local_c = 0x44;
    break;
  case 6:
    local_c = 0x47;
    break;
  case 7:
    local_c = 0x59;
    break;
  default:
    local_c = 0xffffffff;
  }
  return local_c;
}


// ==== _sw_sparse @ 100000600

undefined4 _sw_sparse(int param_1)

{
  undefined4 local_c;
  
  if (param_1 == 3) {
    local_c = 1;
  }
  else if (param_1 == 100) {
    local_c = 2;
  }
  else if (param_1 == 1000) {
    local_c = 3;
  }
  else if (param_1 == 5000) {
    local_c = 4;
  }
  else if (param_1 == 20000) {
    local_c = 5;
  }
  else if (param_1 == 0x12fd1) {
    local_c = 6;
  }
  else if (param_1 == 0x1e240) {
    local_c = 7;
  }
  else {
    local_c = 0;
  }
  return local_c;
}


// ==== _sw_bittest @ 1000006b0

undefined4 _sw_bittest(int param_1)

{
  undefined4 local_c;
  
  if ((((param_1 - 9U < 5) || (param_1 == 0x20)) || (param_1 == 0x2c)) || (param_1 == 0x3b)) {
    local_c = 1;
  }
  else {
    local_c = 0;
  }
  return local_c;
}


// ==== _udiv7 @ 100000700

undefined1  [16] _udiv7(uint param_1)

{
  undefined1 auVar1 [16];
  
  auVar1._8_8_ = (ulong)param_1 % 7;
  auVar1._0_8_ = (ulong)param_1 / 7;
  return auVar1;
}


// ==== _sdiv7 @ 100000720

undefined1  [16] _sdiv7(int param_1)

{
  undefined1 auVar1 [16];
  
  auVar1._0_8_ = (long)param_1 / 7 & 0xffffffff;
  auVar1._8_8_ = (long)param_1 % 7 & 0xffffffff;
  return auVar1;
}


// ==== _umod10 @ 100000740

ulong _umod10(uint param_1)

{
  return (ulong)param_1 % 10;
}


// ==== _sdiv16 @ 100000760

undefined1  [16] _sdiv16(int param_1)

{
  undefined1 auVar1 [16];
  
  auVar1._0_8_ = (long)param_1 / 0x10 & 0xffffffff;
  auVar1._8_8_ = (long)param_1 % 0x10 & 0xffffffff;
  return auVar1;
}


// ==== _udiv1000_64 @ 100000780

ulong _udiv1000_64(ulong param_1)

{
  return param_1 / 1000;
}


// ==== _sel_max @ 1000007a0

int _sel_max(int param_1,int param_2)

{
  int local_14;
  
  local_14 = param_2;
  if (param_2 < param_1) {
    local_14 = param_1;
  }
  return local_14;
}


// ==== _sel_abs @ 1000007d0

int _sel_abs(int param_1)

{
  int local_10;
  
  local_10 = param_1;
  if (param_1 < 0) {
    local_10 = -param_1;
  }
  return local_10;
}


// ==== _sel_clamp @ 100000800

int _sel_clamp(int param_1,int param_2,int param_3)

{
  int local_1c;
  int local_18;
  
  local_18 = param_2;
  if (param_2 <= param_1) {
    local_1c = param_1;
    if (param_3 < param_1) {
      local_1c = param_3;
    }
    local_18 = local_1c;
  }
  return local_18;
}


// ==== _popcount_loop @ 100000840

int _popcount_loop(uint param_1)

{
  undefined4 local_10;
  undefined4 local_c;
  
  local_10 = 0;
  for (local_c = param_1; local_c != 0; local_c = local_c - 1 & local_c) {
    local_10 = local_10 + 1;
  }
  return local_10;
}


// ==== _bswap32_manual @ 100000870

uint _bswap32_manual(uint param_1)

{
  return param_1 >> 0x18 | param_1 >> 8 & 0xff00 | (param_1 & 0xff00) << 8 | param_1 << 0x18;
}


// ==== _rotl32 @ 1000008b0

uint _rotl32(uint param_1,byte param_2)

{
  return param_1 << (param_2 & 0x1f) | param_1 >> (0x20 - param_2 & 0x1f);
}


// ==== _is_pow2 @ 1000008e0

byte _is_pow2(uint param_1)

{
  undefined1 local_d;
  
  local_d = 0;
  if (param_1 != 0) {
    local_d = (param_1 & param_1 - 1) != 0 ^ 0xff;
  }
  return local_d & 1;
}


// ==== _copy16 @ 100000920

void _copy16(undefined8 param_1,undefined8 param_2)

{
  ___memcpy_chk(param_1,param_2,0x10,0xffffffffffffffff);
  return;
}


// ==== _zero64 @ 100000950

void _zero64(undefined8 param_1)

{
  ___memset_chk(param_1,0,0x40,0xffffffffffffffff);
  return;
}


// ==== _zero_n @ 100000980

void _zero_n(undefined8 param_1,undefined8 param_2)

{
  ___memset_chk(param_1,0,param_2,0xffffffffffffffff);
  return;
}


// ==== _strlen_const @ 1000009b0

undefined8 _strlen_const(void)

{
  return 7;
}


// ==== _strcmp_const @ 1000009c0

bool _strcmp_const(char *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp(param_1,"GET");
  return iVar1 == 0;
}


// ==== _strncmp_const @ 1000009f0

bool _strncmp_const(char *param_1)

{
  int iVar1;
  
  iVar1 = _strncmp(param_1,"HTTP/1.",7);
  return iVar1 == 0;
}


// ==== _loop_zero @ 100000a30

void _loop_zero(long param_1,int param_2)

{
  undefined4 local_18;
  
  for (local_18 = 0; local_18 < param_2; local_18 = local_18 + 1) {
    *(undefined4 *)(param_1 + (long)local_18 * 4) = 0;
  }
  return;
}


// ==== _loop_copy @ 100000a70

void _loop_copy(long param_1,long param_2,int param_3)

{
  undefined4 local_20;
  
  for (local_20 = 0; local_20 < param_3; local_20 = local_20 + 1) {
    *(undefined1 *)(param_1 + local_20) = *(undefined1 *)(param_2 + local_20);
  }
  return;
}


// ==== _loop_strlen @ 100000ac0

long _loop_strlen(char *param_1)

{
  char *local_18;
  
  for (local_18 = param_1; *local_18 != '\0'; local_18 = local_18 + 1) {
  }
  return (long)local_18 - (long)param_1;
}


// ==== _make_big @ 100000b00

long _make_big(long param_1,long param_2)

{
  undefined4 local_14;
  
  for (local_14 = 0; local_14 < 8; local_14 = local_14 + 1) {
    *(long *)(param_1 + (long)local_14 * 8) = param_2 + local_14;
  }
  return param_1;
}


// ==== _use_big @ 100000b50

long _use_big(undefined8 param_1)

{
  undefined1 local_50 [24];
  long local_38;
  long local_18;
  undefined8 local_10;
  
  local_10 = param_1;
  _make_big(local_50,param_1);
  return local_38 + local_18;
}


// ==== _make_small @ 100000b80

undefined8 _make_small(int param_1)

{
  return CONCAT44(param_1 * 3,param_1);
}


// ==== _sum_va @ 100000ba0

/* WARNING: Restarted to delay deadcode elimination for space: stack */

int _sum_va(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
           undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
           undefined8 param_10,undefined8 param_11,undefined8 param_12,undefined8 param_13,
           undefined8 param_14)

{
  char in_AL;
  int *local_100;
  int local_e8 [2];
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_a8;
  undefined8 local_98;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  int local_34;
  int local_30;
  int local_2c;
  uint local_28;
  undefined4 local_24;
  int *local_20;
  int *local_18;
  long local_10;
  
  if (in_AL != '\0') {
    local_b8 = param_1;
    local_a8 = param_2;
    local_98 = param_3;
    local_88 = param_4;
    local_78 = param_5;
    local_68 = param_6;
    local_58 = param_7;
    local_48 = param_8;
  }
  local_10 = *(long *)PTR____stack_chk_guard_100002020;
  local_18 = local_e8;
  local_20 = (int *)&stack0x00000008;
  local_24 = 0x30;
  local_28 = 8;
  local_30 = 0;
  for (local_34 = 0; local_34 < param_9; local_34 = local_34 + 1) {
    if (local_28 < 0x29) {
      local_100 = (int *)((long)local_18 + (long)(int)local_28);
      local_28 = local_28 + 8;
    }
    else {
      local_100 = local_20;
      local_20 = local_20 + 2;
    }
    local_30 = *local_100 + local_30;
  }
  if (*(long *)PTR____stack_chk_guard_100002020 == local_10) {
    return local_30;
  }
  local_e0 = param_10;
  local_d8 = param_11;
  local_d0 = param_12;
  local_c8 = param_13;
  local_c0 = param_14;
  local_2c = param_9;
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


// ==== _ssp_copy @ 100000cf0

int _ssp_copy(undefined8 param_1)

{
  size_t sVar1;
  char local_58 [3];
  char local_55;
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_100002020;
  ___strcpy_chk(local_58,param_1,0x40);
  sVar1 = _strlen(local_58);
  if (*(long *)PTR____stack_chk_guard_100002020 == local_10) {
    return (int)sVar1 + (int)local_55;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


// ==== _fortify_memcpy @ 100000d50

void _fortify_memcpy(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined1 local_38 [40];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_100002020;
  ___memcpy_chk(local_38,param_2,param_3,0x20);
  ___memcpy_chk(param_1,local_38,0x20,0xffffffffffffffff);
  if (*(long *)PTR____stack_chk_guard_100002020 == local_10) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


// ==== _fortify_snprintf @ 100000dc0

void _fortify_snprintf(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  ___snprintf_chk(param_1,param_2,0,0xffffffffffffffff,"deger=%d",param_3);
  return;
}


// ==== _read_file_head @ 100000e00

undefined4 _read_file_head(char *param_1,undefined8 param_2,size_t param_3)

{
  FILE *pFVar1;
  int iVar2;
  int *piVar3;
  char *pcVar4;
  void *pvVar5;
  ssize_t sVar6;
  undefined4 local_2c;
  undefined4 local_c;
  
  local_2c = 0xffffffff;
  iVar2 = _open(param_1,0x1000000);
  if (iVar2 < 0) {
    pFVar1 = *(FILE **)PTR____stderrp_100002050;
    piVar3 = ___error();
    pcVar4 = _strerror(*piVar3);
    _fprintf(pFVar1,"open %s: %s\n",param_1,pcVar4);
    local_c = 0xffffffff;
  }
  else {
    pvVar5 = _malloc(param_3);
    if (pvVar5 != (void *)0x0) {
      sVar6 = _read(iVar2,pvVar5,param_3);
      if (sVar6 < 0) {
        piVar3 = ___error();
        *piVar3 = 5;
      }
      else {
        ___memcpy_chk(param_2,pvVar5,sVar6,0xffffffffffffffff);
        local_2c = (undefined4)sVar6;
      }
      _free(pvVar5);
    }
    _close(iVar2);
    local_c = local_2c;
  }
  return local_c;
}


// ==== _tail_target @ 100000f00

int _tail_target(int param_1)

{
  return param_1 * 3 + 1;
}


// ==== _tail_caller @ 100000f10

void _tail_caller(int param_1)

{
  _tail_target(param_1 + 1);
  return;
}


// ==== _tail_ext @ 100000f30

void _tail_ext(long param_1)

{
  _atoi((char *)(param_1 + 1));
  return;
}


// ==== _vadd @ 100000f50

void _vadd(long param_1,long param_2,long param_3,int param_4)

{
  undefined4 local_28;
  
  for (local_28 = 0; local_28 < param_4; local_28 = local_28 + 1) {
    *(int *)(param_1 + (long)local_28 * 4) =
         *(int *)(param_2 + (long)local_28 * 4) + *(int *)(param_3 + (long)local_28 * 4);
  }
  return;
}


// ==== _vsum @ 100000fa0

int _vsum(long param_1,int param_2)

{
  undefined4 local_1c;
  undefined4 local_18;
  
  local_18 = 0;
  for (local_1c = 0; local_1c < param_2; local_1c = local_1c + 1) {
    local_18 = *(int *)(param_1 + (long)local_1c * 4) + local_18;
  }
  return local_18;
}


// ==== _vdot @ 100000ff0

float _vdot(long param_1,long param_2,int param_3)

{
  undefined4 local_24;
  undefined4 local_20;
  
  local_20 = 0.0;
  for (local_24 = 0; local_24 < param_3; local_24 = local_24 + 1) {
    local_20 = *(float *)(param_1 + (long)local_24 * 4) * *(float *)(param_2 + (long)local_24 * 4) +
               local_20;
  }
  return local_20;
}


// ==== _md5_init @ 100001060

void _md5_init(undefined4 *param_1)

{
  *param_1 = 0x67452301;
  param_1[1] = 0xefcdab89;
  param_1[2] = 0x98badcfe;
  param_1[3] = 0x10325476;
  return;
}


// ==== _crc32_make_table @ 1000010a0

void _crc32_make_table(void)

{
  uint local_18;
  int local_14;
  uint local_10;
  uint local_c;
  
  for (local_c = 0; local_c < 0x100; local_c = local_c + 1) {
    local_10 = local_c;
    for (local_14 = 0; local_14 < 8; local_14 = local_14 + 1) {
      if ((local_10 & 1) == 0) {
        local_18 = local_10 >> 1;
      }
      else {
        local_18 = local_10 >> 1 ^ 0xedb88320;
      }
      local_10 = local_18;
    }
    *(uint *)(&_crc_table + (ulong)local_c * 4) = local_10;
  }
  return;
}


// ==== _crc32_buf @ 100001120

uint _crc32_buf(byte *param_1,long param_2)

{
  uint local_1c;
  long local_18;
  byte *local_10;
  
  local_1c = 0xffffffff;
  local_18 = param_2;
  local_10 = param_1;
  while (local_18 != 0) {
    local_1c = *(uint *)(&_crc_table + (ulong)((local_1c ^ *local_10) & 0xff) * 4) ^ local_1c >> 8;
    local_18 = local_18 + -1;
    local_10 = local_10 + 1;
  }
  return local_1c ^ 0xffffffff;
}


// ==== _tea_encrypt @ 100001190

void _tea_encrypt(uint *param_1,int *param_2)

{
  int local_2c;
  int local_24;
  uint local_20;
  uint local_1c;
  
  local_1c = *param_1;
  local_20 = param_1[1];
  local_24 = 0;
  for (local_2c = 0; local_2c < 0x20; local_2c = local_2c + 1) {
    local_24 = local_24 + -0x61c88647;
    local_1c = (local_20 * 0x10 + *param_2 ^ local_20 + local_24 ^ (local_20 >> 5) + param_2[1]) +
               local_1c;
    local_20 = (local_1c * 0x10 + param_2[2] ^ local_1c + local_24 ^ (local_1c >> 5) + param_2[3]) +
               local_20;
  }
  *param_1 = local_1c;
  param_1[1] = local_20;
  return;
}


// ==== entry @ 100001250

undefined8 entry(int param_1,long param_2)

{
  char *pcVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  long lVar7;
  size_t sVar8;
  int extraout_var;
  float fVar9;
  char *local_6b0;
  char *local_630;
  uint local_624;
  undefined1 local_618 [12];
  int local_60c;
  uint local_608 [4];
  long local_5f8;
  uint local_5ec;
  char *local_5e8;
  uint local_5dc;
  long local_5d8;
  int local_5d0;
  undefined4 local_5cc;
  undefined8 local_5c8;
  undefined8 local_5c0;
  uint local_5b0;
  undefined4 local_5ac;
  uint local_5a8;
  undefined4 local_5a4;
  float local_598 [64];
  float local_498 [64];
  int local_398 [64];
  uint local_298 [64];
  undefined1 local_198 [256];
  undefined1 local_98 [136];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_100002020;
  local_5cc = 0;
  local_5d8 = param_2;
  local_5d0 = param_1;
  if (param_1 < 2) {
    local_624 = 3;
  }
  else {
    local_624 = _atoi(*(char **)(param_2 + 8));
  }
  local_5dc = local_624;
  if (local_5d0 < 3) {
    local_630 = "GET";
  }
  else {
    local_630 = *(char **)(local_5d8 + 0x10);
  }
  local_5e8 = local_630;
  for (local_5ec = 0; (int)local_5ec < 0x40; local_5ec = local_5ec + 1) {
    local_298[(int)local_5ec] = local_5ec ^ local_624;
    local_398[(int)local_5ec] = local_5ec + local_624;
    local_498[(int)local_5ec] = (float)(int)local_5ec;
    local_598[(int)local_5ec] = (float)(int)local_624;
  }
  local_5f8 = 0;
  iVar2 = _sw_dense(local_624);
  iVar3 = _sw_sparse(local_5dc);
  iVar4 = _sw_bittest(local_5dc);
  local_5f8 = (iVar2 + iVar3 + iVar4) + local_5f8;
  iVar2 = _udiv7(local_5dc);
  iVar3 = _sdiv7(local_5dc);
  iVar4 = _umod10(local_5dc);
  iVar5 = _sdiv16(local_5dc);
  lVar7 = _udiv1000_64((long)(int)local_5dc);
  local_5f8 = (ulong)(uint)(iVar2 + iVar3 + iVar4 + iVar5) + lVar7 + local_5f8;
  iVar2 = _sel_max(local_5dc,5);
  iVar3 = _sel_abs(local_5dc);
  iVar4 = _sel_clamp(local_5dc,0,9);
  iVar5 = _popcount_loop(local_5dc);
  local_5f8 = (iVar2 + iVar3 + iVar4 + iVar5) + local_5f8;
  iVar2 = _bswap32_manual(local_5dc);
  iVar3 = _rotl32(local_5dc,local_5dc);
  iVar4 = _is_pow2(local_5dc);
  local_5f8 = (ulong)(uint)(iVar2 + iVar3 + iVar4) + local_5f8;
  local_608[0] = local_5dc;
  local_608[1] = 1;
  local_608[2] = 2;
  local_608[3] = 3;
  _copy16(local_618,local_608);
  local_5f8 = local_60c + local_5f8;
  _zero64(local_98);
  _zero_n(local_98,local_5dc & 0x3f);
  lVar7 = _strlen_const();
  iVar2 = _strcmp_const(local_5e8);
  iVar3 = _strncmp_const(local_5e8);
  local_5f8 = lVar7 + iVar2 + (long)iVar3 + local_5f8;
  _loop_zero(local_198,local_5dc & 0x3f);
  pcVar1 = local_5e8;
  sVar8 = _strlen(local_5e8);
  _loop_copy(local_98,pcVar1,sVar8 & 0xffffffff);
  lVar7 = _loop_strlen(local_5e8);
  local_5f8 = lVar7 + local_5f8;
  lVar7 = _use_big((long)(int)local_5dc);
  _make_small(local_5dc);
  iVar2 = _sum_va(3,local_5dc,local_5dc + 1,local_5dc + 2);
  local_5f8 = lVar7 + extraout_var + (long)iVar2 + local_5f8;
  iVar2 = _ssp_copy(local_5e8);
  pcVar1 = local_5e8;
  local_5f8 = iVar2 + local_5f8;
  sVar8 = _strlen(local_5e8);
  _fortify_memcpy(local_98,pcVar1,sVar8 & 0x1f);
  iVar2 = _fortify_snprintf(local_98,0x80,local_5dc);
  local_5f8 = iVar2 + local_5f8;
  if (local_5d0 < 4) {
    local_6b0 = "/etc/hosts";
  }
  else {
    local_6b0 = *(char **)(local_5d8 + 0x18);
  }
  iVar2 = _read_file_head(local_6b0,local_98,0x80);
  local_5f8 = iVar2 + local_5f8;
  iVar2 = _tail_caller(local_5dc);
  iVar3 = _tail_ext(local_5e8);
  local_5f8 = (iVar2 + iVar3) + local_5f8;
  _vadd(local_198,local_298,local_398,0x40);
  iVar2 = _vsum(local_198,0x40);
  fVar9 = (float)_vdot(local_498,local_598,0x40);
  local_5f8 = (long)iVar2 + (long)fVar9 + local_5f8;
  _md5_init(&local_5a8);
  _crc32_make_table();
  pcVar1 = local_5e8;
  sVar8 = _strlen(local_5e8);
  uVar6 = _crc32_buf(pcVar1,sVar8);
  local_5f8 = (ulong)uVar6 + local_5f8;
  local_5b0 = local_5a8;
  local_5ac = local_5a4;
  local_5c8 = DAT_1000019f0;
  local_5c0 = DAT_1000019f8;
  _tea_encrypt(&local_5b0,&local_5c8);
  local_5f8 = (ulong)local_5b0 + local_5f8;
  _printf("%ld\n",local_5f8);
  if (*(long *)PTR____stack_chk_guard_100002020 == local_10) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


