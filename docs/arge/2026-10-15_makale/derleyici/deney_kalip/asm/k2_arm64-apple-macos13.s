
bin/k2_arm64-apple-macos13.o:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000000000000 <ltmp0>:
       0:      	cmp	w0, #0x2
       4:      	b.le	0x28 <ltmp0+0x28>
       8:      	cmp	w0, #0x4
       c:      	b.gt	0x44 <ltmp0+0x44>
      10:      	cmp	w0, #0x3
      14:      	b.eq	0x6c <ltmp0+0x6c>
      18:      	cmp	w0, #0x4
      1c:      	b.ne	0x64 <ltmp0+0x64>
      20:      	eor	w0, w1, #0x3
      24:      	b	0x24 <ltmp0+0x24>
		0000000000000024:  ARM64_RELOC_BRANCH26	_f4
      28:      	cbz	w0, 0x5c <ltmp0+0x5c>
      2c:      	cmp	w0, #0x1
      30:      	b.eq	0x7c <ltmp0+0x7c>
      34:      	cmp	w0, #0x2
      38:      	b.ne	0x64 <ltmp0+0x64>
      3c:      	lsl	w0, w1, #1
      40:      	b	0x40 <ltmp0+0x40>
		0000000000000040:  ARM64_RELOC_BRANCH26	_f2
      44:      	cmp	w0, #0x5
      48:      	b.eq	0x74 <ltmp0+0x74>
      4c:      	cmp	w0, #0x6
      50:      	b.ne	0x64 <ltmp0+0x64>
      54:      	asr	w0, w1, #1
      58:      	b	0x58 <ltmp0+0x58>
		0000000000000058:  ARM64_RELOC_BRANCH26	_f6
      5c:      	mov	x0, x1
      60:      	b	0x60 <ltmp0+0x60>
		0000000000000060:  ARM64_RELOC_BRANCH26	_f0
      64:      	mov	w0, #-0x1               ; =-1
      68:      	ret
      6c:      	sub	w0, w1, #0x7
      70:      	b	0x70 <ltmp0+0x70>
		0000000000000070:  ARM64_RELOC_BRANCH26	_f3
      74:      	mov	x0, x1
      78:      	b	0x78 <ltmp0+0x78>
		0000000000000078:  ARM64_RELOC_BRANCH26	_f5
      7c:      	add	w0, w1, #0x1
      80:      	b	0x80 <ltmp0+0x80>
		0000000000000080:  ARM64_RELOC_BRANCH26	_f1

0000000000000084 <_canary>:
      84:      	sub	sp, sp, #0x60
      88:      	stp	x29, x30, [sp, #0x50]
      8c:      	add	x29, sp, #0x50
      90:      	mov	x1, x0
      94:      	adrp	x8, 0x0 <ltmp0>
		0000000000000094:  ARM64_RELOC_GOT_LOAD_PAGE21	___stack_chk_guard
      98:      	ldr	x8, [x8]
		0000000000000098:  ARM64_RELOC_GOT_LOAD_PAGEOFF12	___stack_chk_guard
      9c:      	ldr	x8, [x8]
      a0:      	stur	x8, [x29, #-0x8]
      a4:      	add	x0, sp, #0x8
      a8:      	bl	0xa8 <_canary+0x24>
		00000000000000a8:  ARM64_RELOC_BRANCH26	_strcpy
      ac:      	add	x0, sp, #0x8
      b0:      	bl	0xb0 <_canary+0x2c>
		00000000000000b0:  ARM64_RELOC_BRANCH26	_strlen
      b4:      	ldur	x8, [x29, #-0x8]
      b8:      	adrp	x9, 0x0 <ltmp0>
		00000000000000b8:  ARM64_RELOC_GOT_LOAD_PAGE21	___stack_chk_guard
      bc:      	ldr	x9, [x9]
		00000000000000bc:  ARM64_RELOC_GOT_LOAD_PAGEOFF12	___stack_chk_guard
      c0:      	ldr	x9, [x9]
      c4:      	cmp	x9, x8
      c8:      	b.ne	0xd8 <_canary+0x54>
      cc:      	ldp	x29, x30, [sp, #0x50]
      d0:      	add	sp, sp, #0x60
      d4:      	ret
      d8:      	bl	0xd8 <_canary+0x54>
		00000000000000d8:  ARM64_RELOC_BRANCH26	___stack_chk_fail

00000000000000dc <_seterr>:
      dc:      	stp	x20, x19, [sp, #-0x20]!
      e0:      	stp	x29, x30, [sp, #0x10]
      e4:      	add	x29, sp, #0x10
      e8:      	mov	x19, x0
      ec:      	bl	0xec <_seterr+0x10>
		00000000000000ec:  ARM64_RELOC_BRANCH26	___errno_location
      f0:      	str	w19, [x0]
      f4:      	mov	w0, #-0x1               ; =-1
      f8:      	ldp	x29, x30, [sp, #0x10]
      fc:      	ldp	x20, x19, [sp], #0x20
     100:      	ret
