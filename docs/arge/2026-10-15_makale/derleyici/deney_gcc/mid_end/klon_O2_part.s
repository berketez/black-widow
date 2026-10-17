	.arch armv8.5-a
	.build_version macos,  26, 0
	.text
	.align	2
	.p2align 5,,15
	.globl _ikiz_a
_ikiz_a:
LFB7:
	lsl	x1, x0, 3
	sub	x0, x1, x0
	add	x0, x0, 13
	ret
LFE7:
	.align	2
	.p2align 5,,15
	.globl _ikiz_b
_ikiz_b:
LFB8:
	lsl	x1, x0, 3
	sub	x0, x1, x0
	add	x0, x0, 13
	ret
LFE8:
	.align	2
	.p2align 5,,15
_ikiz_c:
LFB9:
	add	x0, x0, x0, lsl 2
	add	x0, x0, 11
	ret
LFE9:
	.cstring
	.align	3
l.str.0:
	.ascii "hata %s\12\0"
	.text
	.align	2
	.p2align 5,,15
_bol:
LFB6:
	sub	sp, sp, #64
LCFI0:
	stp	x29, x30, [sp, 16]
LCFI1:
	add	x29, sp, 16
LCFI2:
	stp	x19, x20, [sp, 32]
LCFI3:
	cbz	x0, L6
	stp	x21, x22, [x29, 32]
LCFI4:
	mov	x22, x0
	ldrsb	w1, [x0]
	cbz	w1, L18
	mov	x21, 43241
	mov	x20, x0
	movk	x21, 0x17c0, lsl 16
	mov	x19, 0
	movk	x21, 0x3f57, lsl 32
	movk	x21, 0xa8e8, lsl 48
	b	L8
	.p2align 2,,3
L7:
	ldrsb	w1, [x20, 1]!
	cbz	w1, L20
L8:
	lsl	x2, x19, 5
	sub	x19, x2, x19
	add	x19, x19, w1, sxtw
	smulh	x1, x19, x21
	add	x1, x19, x1
	asr	x1, x1, 6
	sub	x1, x1, x19, asr 63
	add	x2, x1, x1, lsl 1
	add	x1, x1, x2, lsl 5
	sub	x1, x19, x1
	cmp	x1, 3
	bne	L7
	mov	x0, x20
	bl	_dis_cagri
	ldrsb	w1, [x20, 1]!
	cbnz	w1, L8
L20:
	cmp	x19, 42
	beq	L21
	mov	x0, x19
	ldp	x21, x22, [x29, 32]
LCFI5:
	ldp	x29, x30, [sp, 16]
	ldp	x19, x20, [sp, 32]
	add	sp, sp, 64
LCFI6:
	ret
	.p2align 2,,3
L18:
LCFI7:
	ldp	x21, x22, [x29, 32]
LCFI8:
L6:
	mov	x19, 0
	mov	x0, x19
	ldp	x29, x30, [sp, 16]
	ldp	x19, x20, [sp, 32]
	add	sp, sp, 64
LCFI9:
	ret
L21:
LCFI10:
	adrp	x0, ___stderrp@GOTPAGE
	ldr	x0, [x0, ___stderrp@GOTPAGEOFF]
	adrp	x1, l.str.0@PAGE
	add	x1, x1, l.str.0@PAGEOFF;
	str	x22, [sp]
	ldr	x0, [x0]
	bl	_fprintf
	bl	_abort
LFE6:
	.align	2
	.p2align 5,,15
_olcekle.constprop.0:
LFB13:
	add	x1, x0, x0, asr 1
	asr	x2, x0, 2
	add	x1, x1, x0
	add	x0, x2, x0, lsl 1
	add	x0, x0, x1
	ret
LFE13:
	.align	2
	.p2align 5,,15
_alan_oku.constprop.0.isra.0:
LFB15:
	mov	x1, 18725
	add	x2, x0, x0, lsl 1
	movk	x1, 0x2492, lsl 16
	movk	x1, 0x9249, lsl 32
	movk	x1, 0x4924, lsl 48
	smulh	x1, x0, x1
	asr	x1, x1, 1
	sub	x0, x1, x0, asr 63
	add	x0, x2, x0
	ret
LFE15:
	.align	2
	.p2align 5,,15
	.globl _kullan
_kullan:
LFB11:
	stp	x29, x30, [sp, -48]!
LCFI11:
	mov	x29, sp
LCFI12:
	mov	x4, x2
	stp	x19, x20, [sp, 16]
LCFI13:
	mov	x20, x0
	str	x21, [sp, 32]
LCFI14:
	mov	x21, x1
	bl	_olcekle.constprop.0
	mov	x3, x0
	add	x0, x20, 1
	bl	_olcekle.constprop.0
	add	x3, x3, x0
	ldr	x0, [x4, 8]
	bl	_alan_oku.constprop.0.isra.0
	add	x19, x3, x0
	mov	x0, x21
	bl	_bol
	add	x19, x19, x0
	add	x0, x21, 1
	bl	_bol
	add	x3, x19, x0
	mov	x0, x20
	bl	_ikiz_c
	add	x3, x3, x0
	add	x0, x20, 2
	bl	_ikiz_c
	ldr	x21, [sp, 32]
	add	x0, x3, x0
	ldp	x19, x20, [sp, 16]
	ldp	x29, x30, [sp], 48
LCFI15:
	ret
LFE11:
	.globl _adres_al2
	.data
	.align	3
_adres_al2:
	.quad	_ikiz_b
	.globl _adres_al
	.align	3
_adres_al:
	.quad	_ikiz_a
	.section __TEXT,__eh_frame,coalesced,no_toc+strip_static_syms+live_support
EH_frame1:
	.set L$set$0,LECIE1-LSCIE1
	.long L$set$0
LSCIE1:
	.long	0
	.byte	0x3
	.ascii "zR\0"
	.uleb128 0x1
	.sleb128 -8
	.uleb128 0x1e
	.uleb128 0x1
	.byte	0x10
	.byte	0xc
	.uleb128 0x1f
	.uleb128 0
	.align	3
LECIE1:
LSFDE1:
	.set L$set$1,LEFDE1-LASFDE1
	.long L$set$1
LASFDE1:
	.long	LASFDE1-EH_frame1
	.quad	LFB7-.
	.set L$set$2,LFE7-LFB7
	.quad L$set$2
	.uleb128 0
	.align	3
LEFDE1:
LSFDE3:
	.set L$set$3,LEFDE3-LASFDE3
	.long L$set$3
LASFDE3:
	.long	LASFDE3-EH_frame1
	.quad	LFB8-.
	.set L$set$4,LFE8-LFB8
	.quad L$set$4
	.uleb128 0
	.align	3
LEFDE3:
LSFDE5:
	.set L$set$5,LEFDE5-LASFDE5
	.long L$set$5
LASFDE5:
	.long	LASFDE5-EH_frame1
	.quad	LFB9-.
	.set L$set$6,LFE9-LFB9
	.quad L$set$6
	.uleb128 0
	.align	3
LEFDE5:
LSFDE7:
	.set L$set$7,LEFDE7-LASFDE7
	.long L$set$7
LASFDE7:
	.long	LASFDE7-EH_frame1
	.quad	LFB6-.
	.set L$set$8,LFE6-LFB6
	.quad L$set$8
	.uleb128 0
	.byte	0x4
	.set L$set$9,LCFI0-LFB6
	.long L$set$9
	.byte	0xe
	.uleb128 0x40
	.byte	0x4
	.set L$set$10,LCFI1-LCFI0
	.long L$set$10
	.byte	0x9d
	.uleb128 0x6
	.byte	0x9e
	.uleb128 0x5
	.byte	0x4
	.set L$set$11,LCFI2-LCFI1
	.long L$set$11
	.byte	0xc
	.uleb128 0x1d
	.uleb128 0x30
	.byte	0x4
	.set L$set$12,LCFI3-LCFI2
	.long L$set$12
	.byte	0x93
	.uleb128 0x4
	.byte	0x94
	.uleb128 0x3
	.byte	0x4
	.set L$set$13,LCFI4-LCFI3
	.long L$set$13
	.byte	0x96
	.uleb128 0x1
	.byte	0x95
	.uleb128 0x2
	.byte	0x4
	.set L$set$14,LCFI5-LCFI4
	.long L$set$14
	.byte	0xa
	.byte	0xd6
	.byte	0xd5
	.byte	0x4
	.set L$set$15,LCFI6-LCFI5
	.long L$set$15
	.byte	0xd3
	.byte	0xd4
	.byte	0xdd
	.byte	0xde
	.byte	0xc
	.uleb128 0x1f
	.uleb128 0
	.byte	0x4
	.set L$set$16,LCFI7-LCFI6
	.long L$set$16
	.byte	0xb
	.byte	0x4
	.set L$set$17,LCFI8-LCFI7
	.long L$set$17
	.byte	0xd6
	.byte	0xd5
	.byte	0x4
	.set L$set$18,LCFI9-LCFI8
	.long L$set$18
	.byte	0xd3
	.byte	0xd4
	.byte	0xdd
	.byte	0xde
	.byte	0xc
	.uleb128 0x1f
	.uleb128 0
	.byte	0x4
	.set L$set$19,LCFI10-LCFI9
	.long L$set$19
	.byte	0xc
	.uleb128 0x1d
	.uleb128 0x30
	.byte	0x93
	.uleb128 0x4
	.byte	0x94
	.uleb128 0x3
	.byte	0x95
	.uleb128 0x2
	.byte	0x96
	.uleb128 0x1
	.byte	0x9d
	.uleb128 0x6
	.byte	0x9e
	.uleb128 0x5
	.align	3
LEFDE7:
LSFDE9:
	.set L$set$20,LEFDE9-LASFDE9
	.long L$set$20
LASFDE9:
	.long	LASFDE9-EH_frame1
	.quad	LFB13-.
	.set L$set$21,LFE13-LFB13
	.quad L$set$21
	.uleb128 0
	.align	3
LEFDE9:
LSFDE11:
	.set L$set$22,LEFDE11-LASFDE11
	.long L$set$22
LASFDE11:
	.long	LASFDE11-EH_frame1
	.quad	LFB15-.
	.set L$set$23,LFE15-LFB15
	.quad L$set$23
	.uleb128 0
	.align	3
LEFDE11:
LSFDE13:
	.set L$set$24,LEFDE13-LASFDE13
	.long L$set$24
LASFDE13:
	.long	LASFDE13-EH_frame1
	.quad	LFB11-.
	.set L$set$25,LFE11-LFB11
	.quad L$set$25
	.uleb128 0
	.byte	0x4
	.set L$set$26,LCFI11-LFB11
	.long L$set$26
	.byte	0xe
	.uleb128 0x30
	.byte	0x9d
	.uleb128 0x6
	.byte	0x9e
	.uleb128 0x5
	.byte	0x4
	.set L$set$27,LCFI12-LCFI11
	.long L$set$27
	.byte	0xd
	.uleb128 0x1d
	.byte	0x4
	.set L$set$28,LCFI13-LCFI12
	.long L$set$28
	.byte	0x93
	.uleb128 0x4
	.byte	0x94
	.uleb128 0x3
	.byte	0x4
	.set L$set$29,LCFI14-LCFI13
	.long L$set$29
	.byte	0x95
	.uleb128 0x2
	.byte	0x4
	.set L$set$30,LCFI15-LCFI14
	.long L$set$30
	.byte	0xde
	.byte	0xdd
	.byte	0xd5
	.byte	0xd3
	.byte	0xd4
	.byte	0xc
	.uleb128 0x1f
	.uleb128 0
	.align	3
LEFDE13:
	.ident	"GCC: (Homebrew GCC 16.2.0) 16.2.0"
	.subsections_via_symbols
