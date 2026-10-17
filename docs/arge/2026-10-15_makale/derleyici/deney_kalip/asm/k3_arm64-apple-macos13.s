
bin/k3_arm64-apple-macos13.o:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000000000000 <ltmp0>:
       0:      	cmp	w0, #0x3
       4:      	b.gt	0x24 <ltmp0+0x24>
       8:      	cmp	w0, #0x1
       c:      	b.gt	0x44 <ltmp0+0x44>
      10:      	cbz	w0, 0x74 <ltmp0+0x74>
      14:      	cmp	w0, #0x1
      18:      	b.ne	0x94 <ltmp0+0x94>
      1c:      	mov	x0, x1
      20:      	b	0x20 <ltmp0+0x20>
		0000000000000020:  ARM64_RELOC_BRANCH26	_g8_1
      24:      	cmp	w0, #0x5
      28:      	b.gt	0x5c <ltmp0+0x5c>
      2c:      	cmp	w0, #0x4
      30:      	b.eq	0x7c <ltmp0+0x7c>
      34:      	cmp	w0, #0x5
      38:      	b.ne	0x94 <ltmp0+0x94>
      3c:      	mov	x0, x1
      40:      	b	0x40 <ltmp0+0x40>
		0000000000000040:  ARM64_RELOC_BRANCH26	_g8_5
      44:      	cmp	w0, #0x2
      48:      	b.eq	0x84 <ltmp0+0x84>
      4c:      	cmp	w0, #0x3
      50:      	b.ne	0x94 <ltmp0+0x94>
      54:      	mov	x0, x1
      58:      	b	0x58 <ltmp0+0x58>
		0000000000000058:  ARM64_RELOC_BRANCH26	_g8_3
      5c:      	cmp	w0, #0x6
      60:      	b.eq	0x8c <ltmp0+0x8c>
      64:      	cmp	w0, #0x7
      68:      	b.ne	0x94 <ltmp0+0x94>
      6c:      	mov	x0, x1
      70:      	b	0x70 <ltmp0+0x70>
		0000000000000070:  ARM64_RELOC_BRANCH26	_g8_7
      74:      	mov	x0, x1
      78:      	b	0x78 <ltmp0+0x78>
		0000000000000078:  ARM64_RELOC_BRANCH26	_g8_0
      7c:      	mov	x0, x1
      80:      	b	0x80 <ltmp0+0x80>
		0000000000000080:  ARM64_RELOC_BRANCH26	_g8_4
      84:      	mov	x0, x1
      88:      	b	0x88 <ltmp0+0x88>
		0000000000000088:  ARM64_RELOC_BRANCH26	_g8_2
      8c:      	mov	x0, x1
      90:      	b	0x90 <ltmp0+0x90>
		0000000000000090:  ARM64_RELOC_BRANCH26	_g8_6
      94:      	mov	w0, #-0x1               ; =-1
      98:      	ret

000000000000009c <_dispatch12>:
      9c:      	cmp	w0, #0xb
      a0:      	b.hi	0x120 <_dispatch12+0x84>
      a4:      	mov	w8, w0
      a8:      	adrp	x9, 0x0 <ltmp0>
		00000000000000a8:  ARM64_RELOC_PAGE21	lJTI1_0
      ac:      	add	x9, x9, #0x0
		00000000000000ac:  ARM64_RELOC_PAGEOFF12	lJTI1_0
      b0:      	adr	x10, 0xc0 <_dispatch12+0x24>
      b4:      	ldrb	w11, [x9, x8]
      b8:      	add	x10, x10, x11, lsl #2
      bc:      	br	x10
      c0:      	mov	x0, x1
      c4:      	b	0xc4 <_dispatch12+0x28>
		00000000000000c4:  ARM64_RELOC_BRANCH26	_g12_0
      c8:      	mov	x0, x1
      cc:      	b	0xcc <_dispatch12+0x30>
		00000000000000cc:  ARM64_RELOC_BRANCH26	_g12_11
      d0:      	mov	x0, x1
      d4:      	b	0xd4 <_dispatch12+0x38>
		00000000000000d4:  ARM64_RELOC_BRANCH26	_g12_4
      d8:      	mov	x0, x1
      dc:      	b	0xdc <_dispatch12+0x40>
		00000000000000dc:  ARM64_RELOC_BRANCH26	_g12_9
      e0:      	mov	x0, x1
      e4:      	b	0xe4 <_dispatch12+0x48>
		00000000000000e4:  ARM64_RELOC_BRANCH26	_g12_2
      e8:      	mov	x0, x1
      ec:      	b	0xec <_dispatch12+0x50>
		00000000000000ec:  ARM64_RELOC_BRANCH26	_g12_3
      f0:      	mov	x0, x1
      f4:      	b	0xf4 <_dispatch12+0x58>
		00000000000000f4:  ARM64_RELOC_BRANCH26	_g12_7
      f8:      	mov	x0, x1
      fc:      	b	0xfc <_dispatch12+0x60>
		00000000000000fc:  ARM64_RELOC_BRANCH26	_g12_1
     100:      	mov	x0, x1
     104:      	b	0x104 <_dispatch12+0x68>
		0000000000000104:  ARM64_RELOC_BRANCH26	_g12_5
     108:      	mov	x0, x1
     10c:      	b	0x10c <_dispatch12+0x70>
		000000000000010c:  ARM64_RELOC_BRANCH26	_g12_6
     110:      	mov	x0, x1
     114:      	b	0x114 <_dispatch12+0x78>
		0000000000000114:  ARM64_RELOC_BRANCH26	_g12_10
     118:      	mov	x0, x1
     11c:      	b	0x11c <_dispatch12+0x80>
		000000000000011c:  ARM64_RELOC_BRANCH26	_g12_8
     120:      	mov	w0, #-0x1               ; =-1
     124:      	ret

0000000000000128 <_dispatch16>:
     128:      	cmp	w0, #0xf
     12c:      	b.hi	0x1cc <_dispatch16+0xa4>
     130:      	mov	w8, w0
     134:      	adrp	x9, 0x0 <ltmp0>
		0000000000000134:  ARM64_RELOC_PAGE21	lJTI2_0
     138:      	add	x9, x9, #0x0
		0000000000000138:  ARM64_RELOC_PAGEOFF12	lJTI2_0
     13c:      	adr	x10, 0x14c <_dispatch16+0x24>
     140:      	ldrb	w11, [x9, x8]
     144:      	add	x10, x10, x11, lsl #2
     148:      	br	x10
     14c:      	mov	x0, x1
     150:      	b	0x150 <_dispatch16+0x28>
		0000000000000150:  ARM64_RELOC_BRANCH26	_g16_0
     154:      	mov	x0, x1
     158:      	b	0x158 <_dispatch16+0x30>
		0000000000000158:  ARM64_RELOC_BRANCH26	_g16_14
     15c:      	mov	x0, x1
     160:      	b	0x160 <_dispatch16+0x38>
		0000000000000160:  ARM64_RELOC_BRANCH26	_g16_11
     164:      	mov	x0, x1
     168:      	b	0x168 <_dispatch16+0x40>
		0000000000000168:  ARM64_RELOC_BRANCH26	_g16_4
     16c:      	mov	x0, x1
     170:      	b	0x170 <_dispatch16+0x48>
		0000000000000170:  ARM64_RELOC_BRANCH26	_g16_12
     174:      	mov	x0, x1
     178:      	b	0x178 <_dispatch16+0x50>
		0000000000000178:  ARM64_RELOC_BRANCH26	_g16_9
     17c:      	mov	x0, x1
     180:      	b	0x180 <_dispatch16+0x58>
		0000000000000180:  ARM64_RELOC_BRANCH26	_g16_2
     184:      	mov	x0, x1
     188:      	b	0x188 <_dispatch16+0x60>
		0000000000000188:  ARM64_RELOC_BRANCH26	_g16_15
     18c:      	mov	x0, x1
     190:      	b	0x190 <_dispatch16+0x68>
		0000000000000190:  ARM64_RELOC_BRANCH26	_g16_3
     194:      	mov	x0, x1
     198:      	b	0x198 <_dispatch16+0x70>
		0000000000000198:  ARM64_RELOC_BRANCH26	_g16_7
     19c:      	mov	x0, x1
     1a0:      	b	0x1a0 <_dispatch16+0x78>
		00000000000001a0:  ARM64_RELOC_BRANCH26	_g16_1
     1a4:      	mov	x0, x1
     1a8:      	b	0x1a8 <_dispatch16+0x80>
		00000000000001a8:  ARM64_RELOC_BRANCH26	_g16_5
     1ac:      	mov	x0, x1
     1b0:      	b	0x1b0 <_dispatch16+0x88>
		00000000000001b0:  ARM64_RELOC_BRANCH26	_g16_13
     1b4:      	mov	x0, x1
     1b8:      	b	0x1b8 <_dispatch16+0x90>
		00000000000001b8:  ARM64_RELOC_BRANCH26	_g16_6
     1bc:      	mov	x0, x1
     1c0:      	b	0x1c0 <_dispatch16+0x98>
		00000000000001c0:  ARM64_RELOC_BRANCH26	_g16_10
     1c4:      	mov	x0, x1
     1c8:      	b	0x1c8 <_dispatch16+0xa0>
		00000000000001c8:  ARM64_RELOC_BRANCH26	_g16_8
     1cc:      	mov	w0, #-0x1               ; =-1
     1d0:      	ret
