
bin/k_arm64_O2:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000100000548 <_sw_dense>:
100000548:     	cmp	w0, #0x7
10000054c:     	b.hi	0x100000560 <_sw_dense+0x18>
100000550:     	adrp	x8, 0x100001000 <_main+0x74>
100000554:     	add	x8, x8, #0x8c8
100000558:     	ldr	w0, [x8, w0, uxtw #2]
10000055c:     	ret
100000560:     	mov	w0, #-0x1               ; =-1
100000564:     	ret

0000000100000568 <_sw_sparse>:
100000568:     	mov	w8, #0x1387             ; =4999
10000056c:     	cmp	w0, w8
100000570:     	b.le	0x1000005a4 <_sw_sparse+0x3c>
100000574:     	mov	w8, #0x2fd0             ; =12240
100000578:     	movk	w8, #0x1, lsl #16
10000057c:     	cmp	w0, w8
100000580:     	b.gt	0x1000005c4 <_sw_sparse+0x5c>
100000584:     	mov	w8, #0x1388             ; =5000
100000588:     	cmp	w0, w8
10000058c:     	b.eq	0x1000005fc <_sw_sparse+0x94>
100000590:     	mov	w8, #0x4e20             ; =20000
100000594:     	cmp	w0, w8
100000598:     	b.ne	0x1000005f4 <_sw_sparse+0x8c>
10000059c:     	mov	w0, #0x5                ; =5
1000005a0:     	ret
1000005a4:     	cmp	w0, #0x3
1000005a8:     	b.eq	0x1000005ec <_sw_sparse+0x84>
1000005ac:     	cmp	w0, #0x64
1000005b0:     	b.eq	0x10000060c <_sw_sparse+0xa4>
1000005b4:     	cmp	w0, #0x3e8
1000005b8:     	b.ne	0x1000005f4 <_sw_sparse+0x8c>
1000005bc:     	mov	w0, #0x3                ; =3
1000005c0:     	ret
1000005c4:     	mov	w8, #0x2fd1             ; =12241
1000005c8:     	movk	w8, #0x1, lsl #16
1000005cc:     	cmp	w0, w8
1000005d0:     	b.eq	0x100000604 <_sw_sparse+0x9c>
1000005d4:     	mov	w8, #0xe240             ; =57920
1000005d8:     	movk	w8, #0x1, lsl #16
1000005dc:     	cmp	w0, w8
1000005e0:     	b.ne	0x1000005f4 <_sw_sparse+0x8c>
1000005e4:     	mov	w0, #0x7                ; =7
1000005e8:     	ret
1000005ec:     	mov	w0, #0x1                ; =1
1000005f0:     	ret
1000005f4:     	mov	w0, #0x0                ; =0
1000005f8:     	ret
1000005fc:     	mov	w0, #0x4                ; =4
100000600:     	ret
100000604:     	mov	w0, #0x6                ; =6
100000608:     	ret
10000060c:     	mov	w0, #0x2                ; =2
100000610:     	ret

0000000100000614 <_sw_bittest>:
100000614:     	cmp	w0, #0x3b
100000618:     	b.hi	0x100000644 <_sw_bittest+0x30>
10000061c:     	mov	w8, w0
100000620:     	mov	w9, #0x1                ; =1
100000624:     	lsl	x8, x9, x8
100000628:     	mov	x9, #0x3e00             ; =15872
10000062c:     	movk	x9, #0x1001, lsl #32
100000630:     	movk	x9, #0x800, lsl #48
100000634:     	tst	x8, x9
100000638:     	b.eq	0x100000644 <_sw_bittest+0x30>
10000063c:     	mov	w0, #0x1                ; =1
100000640:     	ret
100000644:     	mov	w0, #0x0                ; =0
100000648:     	ret

000000010000064c <_udiv7>:
10000064c:     	mov	w8, #0x4925             ; =18725
100000650:     	movk	w8, #0x2492, lsl #16
100000654:     	umull	x8, w0, w8
100000658:     	lsr	x8, x8, #32
10000065c:     	sub	w9, w0, w8
100000660:     	add	w8, w8, w9, lsr #1
100000664:     	lsr	w0, w8, #2
100000668:     	ret

000000010000066c <_sdiv7>:
10000066c:     	mov	w8, #0x2493             ; =9363
100000670:     	movk	w8, #0x9249, lsl #16
100000674:     	smull	x8, w0, w8
100000678:     	lsr	x8, x8, #32
10000067c:     	add	w8, w8, w0
100000680:     	asr	w9, w8, #2
100000684:     	add	w0, w9, w8, lsr #31
100000688:     	ret

000000010000068c <_umod10>:
10000068c:     	mov	w8, #0xcccd             ; =52429
100000690:     	movk	w8, #0xcccc, lsl #16
100000694:     	umull	x8, w0, w8
100000698:     	lsr	x8, x8, #35
10000069c:     	mov	w9, #0xa                ; =10
1000006a0:     	msub	w0, w8, w9, w0
1000006a4:     	ret

00000001000006a8 <_sdiv16>:
1000006a8:     	add	w8, w0, #0xf
1000006ac:     	cmp	w0, #0x0
1000006b0:     	csel	w8, w8, w0, lt
1000006b4:     	asr	w0, w8, #4
1000006b8:     	ret

00000001000006bc <_udiv1000_64>:
1000006bc:     	lsr	x8, x0, #3
1000006c0:     	mov	x9, #0xf7cf             ; =63439
1000006c4:     	movk	x9, #0xe353, lsl #16
1000006c8:     	movk	x9, #0x9ba5, lsl #32
1000006cc:     	movk	x9, #0x20c4, lsl #48
1000006d0:     	umulh	x8, x8, x9
1000006d4:     	lsr	x0, x8, #4
1000006d8:     	ret

00000001000006dc <_sel_max>:
1000006dc:     	cmp	w0, w1
1000006e0:     	csel	w0, w0, w1, gt
1000006e4:     	ret

00000001000006e8 <_sel_abs>:
1000006e8:     	cmp	w0, #0x0
1000006ec:     	cneg	w0, w0, mi
1000006f0:     	ret

00000001000006f4 <_sel_clamp>:
1000006f4:     	cmp	w0, w2
1000006f8:     	csel	w8, w0, w2, lt
1000006fc:     	cmp	w0, w1
100000700:     	csel	w0, w1, w8, lt
100000704:     	ret

0000000100000708 <_popcount_loop>:
100000708:     	fmov	s0, w0
10000070c:     	cnt.8b	v0, v0
100000710:     	addv.8b	b0, v0
100000714:     	fmov	w0, s0
100000718:     	ret

000000010000071c <_bswap32_manual>:
10000071c:     	rev	w0, w0
100000720:     	ret

0000000100000724 <_rotl32>:
100000724:     	neg	w8, w1
100000728:     	ror	w0, w0, w8
10000072c:     	ret

0000000100000730 <_is_pow2>:
100000730:     	sub	w8, w0, #0x1
100000734:     	tst	w0, w8
100000738:     	cset	w8, eq
10000073c:     	cmp	w0, #0x0
100000740:     	csel	w0, wzr, w8, eq
100000744:     	ret

0000000100000748 <_copy16>:
100000748:     	ldr	q0, [x1]
10000074c:     	str	q0, [x0]
100000750:     	ret

0000000100000754 <_zero64>:
100000754:     	movi.2d	v0, #0000000000000000
100000758:     	stp	q0, q0, [x0, #0x20]
10000075c:     	stp	q0, q0, [x0]
100000760:     	ret

0000000100000764 <_zero_n>:
100000764:     	b	0x1000015c4 <_bzero@stub>

0000000100000768 <_strlen_const>:
100000768:     	mov	w0, #0x7                ; =7
10000076c:     	ret

0000000100000770 <_strcmp_const>:
100000770:     	stp	x29, x30, [sp, #-0x10]!
100000774:     	mov	x29, sp
100000778:     	adrp	x1, 0x100001000 <_main+0x74>
10000077c:     	add	x1, x1, #0x8e8
100000780:     	bl	0x10000163c <_strcmp@stub>
100000784:     	cmp	w0, #0x0
100000788:     	cset	w0, eq
10000078c:     	ldp	x29, x30, [sp], #0x10
100000790:     	ret

0000000100000794 <_strncmp_const>:
100000794:     	stp	x29, x30, [sp, #-0x10]!
100000798:     	mov	x29, sp
10000079c:     	adrp	x1, 0x100001000 <_main+0x74>
1000007a0:     	add	x1, x1, #0x8ec
1000007a4:     	mov	w2, #0x7                ; =7
1000007a8:     	bl	0x100001660 <_strncmp@stub>
1000007ac:     	cmp	w0, #0x0
1000007b0:     	cset	w0, eq
1000007b4:     	ldp	x29, x30, [sp], #0x10
1000007b8:     	ret

00000001000007bc <_loop_zero>:
1000007bc:     	cmp	w1, #0x1
1000007c0:     	b.lt	0x1000007cc <_loop_zero+0x10>
1000007c4:     	ubfiz	x1, x1, #2, #32
1000007c8:     	b	0x1000015c4 <_bzero@stub>
1000007cc:     	ret

00000001000007d0 <_loop_copy>:
1000007d0:     	cmp	w2, #0x1
1000007d4:     	b.lt	0x1000007e0 <_loop_copy+0x10>
1000007d8:     	mov	w2, w2
1000007dc:     	b	0x100001600 <_memcpy@stub>
1000007e0:     	ret

00000001000007e4 <_loop_strlen>:
1000007e4:     	b	0x100001654 <_strlen@stub>

00000001000007e8 <_make_big>:
1000007e8:     	str	x0, [x8]
1000007ec:     	dup.2d	v0, x0
1000007f0:     	adrp	x9, 0x100001000 <_main+0x74>
1000007f4:     	ldr	q1, [x9, #0x670]
1000007f8:     	add.2d	v1, v0, v1
1000007fc:     	stur	q1, [x8, #0x8]
100000800:     	adrp	x9, 0x100001000 <_main+0x74>
100000804:     	ldr	q1, [x9, #0x680]
100000808:     	add.2d	v1, v0, v1
10000080c:     	stur	q1, [x8, #0x18]
100000810:     	adrp	x9, 0x100001000 <_main+0x74>
100000814:     	ldr	q1, [x9, #0x690]
100000818:     	add.2d	v0, v0, v1
10000081c:     	stur	q0, [x8, #0x28]
100000820:     	add	x9, x0, #0x7
100000824:     	str	x9, [x8, #0x38]
100000828:     	ret

000000010000082c <_use_big>:
10000082c:     	sub	sp, sp, #0x50
100000830:     	stp	x29, x30, [sp, #0x40]
100000834:     	add	x29, sp, #0x40
100000838:     	mov	x8, sp
10000083c:     	bl	0x1000007e8 <_make_big>
100000840:     	ldr	x8, [sp, #0x18]
100000844:     	ldr	x9, [sp, #0x38]
100000848:     	add	x0, x9, x8
10000084c:     	ldp	x29, x30, [sp, #0x40]
100000850:     	add	sp, sp, #0x50
100000854:     	ret

0000000100000858 <_make_small>:
100000858:     	add	w8, w0, w0, lsl #1
10000085c:     	mov	w9, w0
100000860:     	orr	x0, x9, x8, lsl #32
100000864:     	ret

0000000100000868 <_sum_va>:
100000868:     	sub	sp, sp, #0x10
10000086c:     	add	x8, sp, #0x10
100000870:     	str	x8, [sp, #0x8]
100000874:     	cmp	w0, #0x1
100000878:     	b.lt	0x1000008a0 <_sum_va+0x38>
10000087c:     	mov	w8, #0x0                ; =0
100000880:     	ldr	x9, [sp, #0x8]
100000884:     	add	x10, x9, #0x8
100000888:     	str	x10, [sp, #0x8]
10000088c:     	ldr	w9, [x9]
100000890:     	add	w8, w9, w8
100000894:     	subs	w0, w0, #0x1
100000898:     	b.ne	0x100000880 <_sum_va+0x18>
10000089c:     	b	0x1000008a4 <_sum_va+0x3c>
1000008a0:     	mov	w8, #0x0                ; =0
1000008a4:     	mov	x0, x8
1000008a8:     	add	sp, sp, #0x10
1000008ac:     	ret

00000001000008b0 <_ssp_copy>:
1000008b0:     	sub	sp, sp, #0x60
1000008b4:     	stp	x29, x30, [sp, #0x50]
1000008b8:     	add	x29, sp, #0x50
1000008bc:     	mov	x1, x0
1000008c0:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
1000008c4:     	ldr	x8, [x8, #0x18]
1000008c8:     	ldr	x8, [x8]
1000008cc:     	stur	x8, [x29, #-0x8]
1000008d0:     	add	x0, sp, #0x8
1000008d4:     	mov	w2, #0x40               ; =64
1000008d8:     	bl	0x1000015ac <___strcpy_chk@stub>
1000008dc:     	add	x0, sp, #0x8
1000008e0:     	bl	0x100001654 <_strlen@stub>
1000008e4:     	ldrsb	w8, [sp, #0xb]
1000008e8:     	ldur	x9, [x29, #-0x8]
1000008ec:     	adrp	x10, 0x100004000 <_strncmp+0x100004000>
1000008f0:     	ldr	x10, [x10, #0x18]
1000008f4:     	ldr	x10, [x10]
1000008f8:     	cmp	x10, x9
1000008fc:     	b.ne	0x100000910 <_ssp_copy+0x60>
100000900:     	add	w0, w8, w0
100000904:     	ldp	x29, x30, [sp, #0x50]
100000908:     	add	sp, sp, #0x60
10000090c:     	ret
100000910:     	bl	0x1000015a0 <___stack_chk_fail@stub>

0000000100000914 <_fortify_memcpy>:
100000914:     	sub	sp, sp, #0x50
100000918:     	stp	x20, x19, [sp, #0x30]
10000091c:     	stp	x29, x30, [sp, #0x40]
100000920:     	add	x29, sp, #0x40
100000924:     	mov	x19, x0
100000928:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
10000092c:     	ldr	x8, [x8, #0x18]
100000930:     	ldr	x8, [x8]
100000934:     	stur	x8, [x29, #-0x18]
100000938:     	add	x0, sp, #0x8
10000093c:     	mov	w3, #0x20               ; =32
100000940:     	bl	0x100001594 <___memcpy_chk@stub>
100000944:     	ldur	q0, [sp, #0x8]
100000948:     	ldur	q1, [sp, #0x18]
10000094c:     	stp	q0, q1, [x19]
100000950:     	ldur	x8, [x29, #-0x18]
100000954:     	adrp	x9, 0x100004000 <_strncmp+0x100004000>
100000958:     	ldr	x9, [x9, #0x18]
10000095c:     	ldr	x9, [x9]
100000960:     	cmp	x9, x8
100000964:     	b.ne	0x100000978 <_fortify_memcpy+0x64>
100000968:     	ldp	x29, x30, [sp, #0x40]
10000096c:     	ldp	x20, x19, [sp, #0x30]
100000970:     	add	sp, sp, #0x50
100000974:     	ret
100000978:     	bl	0x1000015a0 <___stack_chk_fail@stub>

000000010000097c <_fortify_snprintf>:
10000097c:     	sub	sp, sp, #0x20
100000980:     	stp	x29, x30, [sp, #0x10]
100000984:     	add	x29, sp, #0x10
100000988:     	str	x2, [sp]
10000098c:     	adrp	x2, 0x100001000 <_main+0x74>
100000990:     	add	x2, x2, #0x8f4
100000994:     	bl	0x100001630 <_snprintf@stub>
100000998:     	ldp	x29, x30, [sp, #0x10]
10000099c:     	add	sp, sp, #0x20
1000009a0:     	ret

00000001000009a4 <_read_file_head>:
1000009a4:     	sub	sp, sp, #0x50
1000009a8:     	stp	x24, x23, [sp, #0x10]
1000009ac:     	stp	x22, x21, [sp, #0x20]
1000009b0:     	stp	x20, x19, [sp, #0x30]
1000009b4:     	stp	x29, x30, [sp, #0x40]
1000009b8:     	add	x29, sp, #0x40
1000009bc:     	mov	x23, x2
1000009c0:     	mov	x22, x1
1000009c4:     	mov	x20, x0
1000009c8:     	mov	w1, #0x1000000          ; =16777216
1000009cc:     	bl	0x10000160c <_open@stub>
1000009d0:     	tbnz	w0, #0x1f, 0x100000a14 <_read_file_head+0x70>
1000009d4:     	mov	x19, x0
1000009d8:     	mov	x0, x23
1000009dc:     	bl	0x1000015f4 <_malloc@stub>
1000009e0:     	cbz	x0, 0x100000a48 <_read_file_head+0xa4>
1000009e4:     	mov	x21, x0
1000009e8:     	mov	x0, x19
1000009ec:     	mov	x1, x21
1000009f0:     	mov	x2, x23
1000009f4:     	bl	0x100001624 <_read@stub>
1000009f8:     	tbnz	x0, #0x3f, 0x100000a50 <_read_file_head+0xac>
1000009fc:     	mov	x20, x0
100000a00:     	mov	x0, x22
100000a04:     	mov	x1, x21
100000a08:     	mov	x2, x20
100000a0c:     	bl	0x100001600 <_memcpy@stub>
100000a10:     	b	0x100000a60 <_read_file_head+0xbc>
100000a14:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000a18:     	ldr	x8, [x8, #0x20]
100000a1c:     	ldr	x19, [x8]
100000a20:     	bl	0x100001588 <___error@stub>
100000a24:     	ldr	w0, [x0]
100000a28:     	bl	0x100001648 <_strerror@stub>
100000a2c:     	stp	x20, x0, [sp]
100000a30:     	adrp	x1, 0x100001000 <_main+0x74>
100000a34:     	add	x1, x1, #0x8fd
100000a38:     	mov	x0, x19
100000a3c:     	bl	0x1000015dc <_fprintf@stub>
100000a40:     	mov	w20, #-0x1              ; =-1
100000a44:     	b	0x100000a70 <_read_file_head+0xcc>
100000a48:     	mov	w20, #-0x1              ; =-1
100000a4c:     	b	0x100000a68 <_read_file_head+0xc4>
100000a50:     	bl	0x100001588 <___error@stub>
100000a54:     	mov	w8, #0x5                ; =5
100000a58:     	str	w8, [x0]
100000a5c:     	mov	w20, #-0x1              ; =-1
100000a60:     	mov	x0, x21
100000a64:     	bl	0x1000015e8 <_free@stub>
100000a68:     	mov	x0, x19
100000a6c:     	bl	0x1000015d0 <_close@stub>
100000a70:     	mov	x0, x20
100000a74:     	ldp	x29, x30, [sp, #0x40]
100000a78:     	ldp	x20, x19, [sp, #0x30]
100000a7c:     	ldp	x22, x21, [sp, #0x20]
100000a80:     	ldp	x24, x23, [sp, #0x10]
100000a84:     	add	sp, sp, #0x50
100000a88:     	ret

0000000100000a8c <_tail_target>:
100000a8c:     	add	w8, w0, w0, lsl #1
100000a90:     	add	w0, w8, #0x1
100000a94:     	ret

0000000100000a98 <_tail_caller>:
100000a98:     	add	w0, w0, #0x1
100000a9c:     	b	0x100000a8c <_tail_target>

0000000100000aa0 <_tail_ext>:
100000aa0:     	add	x0, x0, #0x1
100000aa4:     	b	0x1000015b8 <_atoi@stub>

0000000100000aa8 <_vadd>:
100000aa8:     	cmp	w3, #0x1
100000aac:     	b.lt	0x100000b90 <_vadd+0xe8>
100000ab0:     	mov	w8, w3
100000ab4:     	cmp	w3, #0x3
100000ab8:     	b.hi	0x100000ac4 <_vadd+0x1c>
100000abc:     	mov	x9, #0x0                ; =0
100000ac0:     	b	0x100000b64 <_vadd+0xbc>
100000ac4:     	cmp	w3, #0x10
100000ac8:     	b.hs	0x100000ad4 <_vadd+0x2c>
100000acc:     	mov	x9, #0x0                ; =0
100000ad0:     	b	0x100000b28 <_vadd+0x80>
100000ad4:     	and	x9, x8, #0x7ffffff0
100000ad8:     	add	x10, x1, #0x20
100000adc:     	add	x11, x2, #0x20
100000ae0:     	add	x12, x0, #0x20
100000ae4:     	mov	x13, x9
100000ae8:     	ldp	q0, q1, [x10, #-0x20]
100000aec:     	ldp	q2, q3, [x10], #0x40
100000af0:     	ldp	q4, q5, [x11, #-0x20]
100000af4:     	ldp	q6, q7, [x11], #0x40
100000af8:     	add.4s	v0, v4, v0
100000afc:     	add.4s	v1, v5, v1
100000b00:     	add.4s	v2, v6, v2
100000b04:     	add.4s	v3, v7, v3
100000b08:     	stp	q0, q1, [x12, #-0x20]
100000b0c:     	stp	q2, q3, [x12], #0x40
100000b10:     	subs	x13, x13, #0x10
100000b14:     	b.ne	0x100000ae8 <_vadd+0x40>
100000b18:     	cmp	x9, x8
100000b1c:     	b.eq	0x100000b90 <_vadd+0xe8>
100000b20:     	tst	x8, #0xc
100000b24:     	b.eq	0x100000b64 <_vadd+0xbc>
100000b28:     	mov	x11, x9
100000b2c:     	and	x9, x8, #0x7ffffffc
100000b30:     	sub	x10, x11, x9
100000b34:     	lsl	x13, x11, #2
100000b38:     	add	x11, x0, x13
100000b3c:     	add	x12, x2, x13
100000b40:     	add	x13, x1, x13
100000b44:     	ldr	q0, [x13], #0x10
100000b48:     	ldr	q1, [x12], #0x10
100000b4c:     	add.4s	v0, v1, v0
100000b50:     	str	q0, [x11], #0x10
100000b54:     	adds	x10, x10, #0x4
100000b58:     	b.ne	0x100000b44 <_vadd+0x9c>
100000b5c:     	cmp	x9, x8
100000b60:     	b.eq	0x100000b90 <_vadd+0xe8>
100000b64:     	lsl	x12, x9, #2
100000b68:     	add	x10, x0, x12
100000b6c:     	add	x11, x2, x12
100000b70:     	add	x12, x1, x12
100000b74:     	sub	x8, x8, x9
100000b78:     	ldr	w9, [x12], #0x4
100000b7c:     	ldr	w13, [x11], #0x4
100000b80:     	add	w9, w13, w9
100000b84:     	str	w9, [x10], #0x4
100000b88:     	subs	x8, x8, #0x1
100000b8c:     	b.ne	0x100000b78 <_vadd+0xd0>
100000b90:     	ret

0000000100000b94 <_vsum>:
100000b94:     	cmp	w1, #0x1
100000b98:     	b.lt	0x100000bb4 <_vsum+0x20>
100000b9c:     	mov	w9, w1
100000ba0:     	cmp	w1, #0x3
100000ba4:     	b.hi	0x100000bc0 <_vsum+0x2c>
100000ba8:     	mov	x10, #0x0               ; =0
100000bac:     	mov	w8, #0x0                ; =0
100000bb0:     	b	0x100000c6c <_vsum+0xd8>
100000bb4:     	mov	w8, #0x0                ; =0
100000bb8:     	mov	x0, x8
100000bbc:     	ret
100000bc0:     	cmp	w1, #0x10
100000bc4:     	b.hs	0x100000bd4 <_vsum+0x40>
100000bc8:     	mov	x10, #0x0               ; =0
100000bcc:     	mov	w8, #0x0                ; =0
100000bd0:     	b	0x100000c34 <_vsum+0xa0>
100000bd4:     	and	x10, x9, #0x7ffffff0
100000bd8:     	add	x8, x0, #0x20
100000bdc:     	movi.2d	v0, #0000000000000000
100000be0:     	mov	x11, x10
100000be4:     	movi.2d	v1, #0000000000000000
100000be8:     	movi.2d	v2, #0000000000000000
100000bec:     	movi.2d	v3, #0000000000000000
100000bf0:     	ldp	q4, q5, [x8, #-0x20]
100000bf4:     	ldp	q6, q7, [x8], #0x40
100000bf8:     	add.4s	v0, v4, v0
100000bfc:     	add.4s	v1, v5, v1
100000c00:     	add.4s	v2, v6, v2
100000c04:     	add.4s	v3, v7, v3
100000c08:     	subs	x11, x11, #0x10
100000c0c:     	b.ne	0x100000bf0 <_vsum+0x5c>
100000c10:     	add.4s	v0, v1, v0
100000c14:     	add.4s	v0, v2, v0
100000c18:     	add.4s	v0, v3, v0
100000c1c:     	addv.4s	s0, v0
100000c20:     	fmov	w8, s0
100000c24:     	cmp	x10, x9
100000c28:     	b.eq	0x100000c84 <_vsum+0xf0>
100000c2c:     	tst	x9, #0xc
100000c30:     	b.eq	0x100000c6c <_vsum+0xd8>
100000c34:     	mov	x11, x10
100000c38:     	and	x10, x9, #0x7ffffffc
100000c3c:     	movi.2d	v0, #0000000000000000
100000c40:     	mov.s	v0[0], w8
100000c44:     	sub	x8, x11, x10
100000c48:     	add	x11, x0, x11, lsl #2
100000c4c:     	ldr	q1, [x11], #0x10
100000c50:     	add.4s	v0, v1, v0
100000c54:     	adds	x8, x8, #0x4
100000c58:     	b.ne	0x100000c4c <_vsum+0xb8>
100000c5c:     	addv.4s	s0, v0
100000c60:     	fmov	w8, s0
100000c64:     	cmp	x10, x9
100000c68:     	b.eq	0x100000c84 <_vsum+0xf0>
100000c6c:     	add	x11, x0, x10, lsl #2
100000c70:     	sub	x9, x9, x10
100000c74:     	ldr	w10, [x11], #0x4
100000c78:     	add	w8, w10, w8
100000c7c:     	subs	x9, x9, #0x1
100000c80:     	b.ne	0x100000c74 <_vsum+0xe0>
100000c84:     	mov	x0, x8
100000c88:     	ret

0000000100000c8c <_vdot>:
100000c8c:     	cmp	w2, #0x1
100000c90:     	b.lt	0x100000cac <_vdot+0x20>
100000c94:     	mov	w8, w2
100000c98:     	cmp	w2, #0x3
100000c9c:     	b.hi	0x100000cb4 <_vdot+0x28>
100000ca0:     	mov	x9, #0x0                ; =0
100000ca4:     	movi.2d	v0, #0000000000000000
100000ca8:     	b	0x100000dd4 <_vdot+0x148>
100000cac:     	movi.2d	v0, #0000000000000000
100000cb0:     	ret
100000cb4:     	cmp	w2, #0x10
100000cb8:     	b.hs	0x100000cc8 <_vdot+0x3c>
100000cbc:     	mov	x9, #0x0                ; =0
100000cc0:     	movi.2d	v0, #0000000000000000
100000cc4:     	b	0x100000d84 <_vdot+0xf8>
100000cc8:     	and	x9, x8, #0x7ffffff0
100000ccc:     	add	x10, x0, #0x20
100000cd0:     	add	x11, x1, #0x20
100000cd4:     	movi.2d	v0, #0000000000000000
100000cd8:     	mov	x12, x9
100000cdc:     	ldp	q1, q2, [x10, #-0x20]
100000ce0:     	ldp	q3, q4, [x10], #0x40
100000ce4:     	ldp	q5, q6, [x11, #-0x20]
100000ce8:     	ldp	q7, q16, [x11], #0x40
100000cec:     	fmul.4s	v1, v1, v5
100000cf0:     	mov	s5, v1[3]
100000cf4:     	mov	s17, v1[2]
100000cf8:     	mov	s18, v1[1]
100000cfc:     	fmul.4s	v2, v2, v6
100000d00:     	mov	s6, v2[3]
100000d04:     	mov	s19, v2[2]
100000d08:     	mov	s20, v2[1]
100000d0c:     	fmul.4s	v3, v3, v7
100000d10:     	mov	s7, v3[3]
100000d14:     	mov	s21, v3[2]
100000d18:     	mov	s22, v3[1]
100000d1c:     	fmul.4s	v4, v4, v16
100000d20:     	mov	s16, v4[3]
100000d24:     	mov	s23, v4[2]
100000d28:     	mov	s24, v4[1]
100000d2c:     	fadd	s0, s0, s1
100000d30:     	fadd	s0, s0, s18
100000d34:     	fadd	s0, s0, s17
100000d38:     	fadd	s0, s0, s5
100000d3c:     	fadd	s0, s0, s2
100000d40:     	fadd	s0, s0, s20
100000d44:     	fadd	s0, s0, s19
100000d48:     	fadd	s0, s0, s6
100000d4c:     	fadd	s0, s0, s3
100000d50:     	fadd	s0, s0, s22
100000d54:     	fadd	s0, s0, s21
100000d58:     	fadd	s0, s0, s7
100000d5c:     	fadd	s0, s0, s4
100000d60:     	fadd	s0, s0, s24
100000d64:     	fadd	s0, s0, s23
100000d68:     	fadd	s0, s0, s16
100000d6c:     	subs	x12, x12, #0x10
100000d70:     	b.ne	0x100000cdc <_vdot+0x50>
100000d74:     	cmp	x9, x8
100000d78:     	b.eq	0x100000df8 <_vdot+0x16c>
100000d7c:     	tst	x8, #0xc
100000d80:     	b.eq	0x100000dd4 <_vdot+0x148>
100000d84:     	mov	x11, x9
100000d88:     	and	x9, x8, #0x7ffffffc
100000d8c:     	sub	x10, x11, x9
100000d90:     	lsl	x12, x11, #2
100000d94:     	add	x11, x1, x12
100000d98:     	add	x12, x0, x12
100000d9c:     	ldr	q1, [x12], #0x10
100000da0:     	ldr	q2, [x11], #0x10
100000da4:     	fmul.4s	v1, v1, v2
100000da8:     	mov	s2, v1[3]
100000dac:     	mov	s3, v1[2]
100000db0:     	mov	s4, v1[1]
100000db4:     	fadd	s0, s0, s1
100000db8:     	fadd	s0, s0, s4
100000dbc:     	fadd	s0, s0, s3
100000dc0:     	fadd	s0, s0, s2
100000dc4:     	adds	x10, x10, #0x4
100000dc8:     	b.ne	0x100000d9c <_vdot+0x110>
100000dcc:     	cmp	x9, x8
100000dd0:     	b.eq	0x100000df8 <_vdot+0x16c>
100000dd4:     	lsl	x11, x9, #2
100000dd8:     	add	x10, x1, x11
100000ddc:     	add	x11, x0, x11
100000de0:     	sub	x8, x8, x9
100000de4:     	ldr	s1, [x11], #0x4
100000de8:     	ldr	s2, [x10], #0x4
100000dec:     	fmadd	s0, s1, s2, s0
100000df0:     	subs	x8, x8, #0x1
100000df4:     	b.ne	0x100000de4 <_vdot+0x158>
100000df8:     	ret

0000000100000dfc <_md5_init>:
100000dfc:     	adrp	x8, 0x100001000 <_main+0x74>
100000e00:     	ldr	q0, [x8, #0x6a0]
100000e04:     	str	q0, [x0]
100000e08:     	ret

0000000100000e0c <_crc32_make_table>:
100000e0c:     	mov	x8, #0x0                ; =0
100000e10:     	adrp	x9, 0x100001000 <_main+0x74>
100000e14:     	ldr	q0, [x9, #0x6b0]
100000e18:     	movi.4s	v1, #0x1
100000e1c:     	mov	w9, #0x8320             ; =33568
100000e20:     	movk	w9, #0xedb8, lsl #16
100000e24:     	dup.4s	v2, w9
100000e28:     	adrp	x9, 0x100008000 <_crc_table>
100000e2c:     	add	x9, x9, #0x0
100000e30:     	movi.4s	v3, #0x4
100000e34:     	and.16b	v4, v0, v1
100000e38:     	ushr.4s	v5, v0, #0x1
100000e3c:     	cmeq.4s	v4, v4, #0
100000e40:     	eor.16b	v6, v5, v2
100000e44:     	bsl.16b	v4, v5, v6
100000e48:     	and.16b	v5, v4, v1
100000e4c:     	cmeq.4s	v5, v5, #0
100000e50:     	ushr.4s	v4, v4, #0x1
100000e54:     	eor.16b	v6, v4, v2
100000e58:     	bif.16b	v4, v6, v5
100000e5c:     	and.16b	v5, v4, v1
100000e60:     	cmeq.4s	v5, v5, #0
100000e64:     	ushr.4s	v4, v4, #0x1
100000e68:     	eor.16b	v6, v4, v2
100000e6c:     	bif.16b	v4, v6, v5
100000e70:     	and.16b	v5, v4, v1
100000e74:     	cmeq.4s	v5, v5, #0
100000e78:     	ushr.4s	v4, v4, #0x1
100000e7c:     	eor.16b	v6, v4, v2
100000e80:     	bif.16b	v4, v6, v5
100000e84:     	and.16b	v5, v4, v1
100000e88:     	cmeq.4s	v5, v5, #0
100000e8c:     	ushr.4s	v4, v4, #0x1
100000e90:     	eor.16b	v6, v4, v2
100000e94:     	bif.16b	v4, v6, v5
100000e98:     	and.16b	v5, v4, v1
100000e9c:     	cmeq.4s	v5, v5, #0
100000ea0:     	ushr.4s	v4, v4, #0x1
100000ea4:     	eor.16b	v6, v4, v2
100000ea8:     	bif.16b	v4, v6, v5
100000eac:     	and.16b	v5, v4, v1
100000eb0:     	ushr.4s	v4, v4, #0x1
100000eb4:     	cmeq.4s	v5, v5, #0
100000eb8:     	eor.16b	v6, v4, v2
100000ebc:     	bif.16b	v4, v6, v5
100000ec0:     	and.16b	v5, v4, v1
100000ec4:     	cmeq.4s	v5, v5, #0
100000ec8:     	ushr.4s	v4, v4, #0x1
100000ecc:     	eor.16b	v6, v4, v2
100000ed0:     	bif.16b	v4, v6, v5
100000ed4:     	str	q4, [x9, x8]
100000ed8:     	add.4s	v0, v0, v3
100000edc:     	add	x8, x8, #0x10
100000ee0:     	cmp	x8, #0x400
100000ee4:     	b.ne	0x100000e34 <_crc32_make_table+0x28>
100000ee8:     	ret

0000000100000eec <_crc32_buf>:
100000eec:     	cbz	x1, 0x100000f20 <_crc32_buf+0x34>
100000ef0:     	mov	w8, #-0x1               ; =-1
100000ef4:     	adrp	x9, 0x100008000 <_crc_table>
100000ef8:     	add	x9, x9, #0x0
100000efc:     	ldrb	w10, [x0], #0x1
100000f00:     	eor	w10, w10, w8
100000f04:     	and	x10, x10, #0xff
100000f08:     	ldr	w10, [x9, x10, lsl #2]
100000f0c:     	eor	w8, w10, w8, lsr #8
100000f10:     	subs	x1, x1, #0x1
100000f14:     	b.ne	0x100000efc <_crc32_buf+0x10>
100000f18:     	mvn	w0, w8
100000f1c:     	ret
100000f20:     	mov	w0, #0x0                ; =0
100000f24:     	ret

0000000100000f28 <_tea_encrypt>:
100000f28:     	mov	w8, #0x79b9             ; =31161
100000f2c:     	movk	w8, #0x9e37, lsl #16
100000f30:     	ldp	w9, w10, [x0]
100000f34:     	ldp	w11, w12, [x1]
100000f38:     	mov	w13, #0x20              ; =32
100000f3c:     	mov	w14, #0x79b9            ; =31161
100000f40:     	movk	w14, #0x9e37, lsl #16
100000f44:     	ldp	w15, w16, [x1, #0x8]
100000f48:     	add	w17, w11, w10, lsl #4
100000f4c:     	add	w1, w10, w14
100000f50:     	eor	w17, w17, w1
100000f54:     	add	w1, w12, w10, lsr #5
100000f58:     	eor	w17, w17, w1
100000f5c:     	add	w9, w17, w9
100000f60:     	add	w17, w14, w9
100000f64:     	add	w1, w15, w9, lsl #4
100000f68:     	eor	w17, w1, w17
100000f6c:     	add	w1, w16, w9, lsr #5
100000f70:     	eor	w17, w17, w1
100000f74:     	add	w10, w17, w10
100000f78:     	add	w14, w14, w8
100000f7c:     	subs	w13, w13, #0x1
100000f80:     	b.ne	0x100000f48 <_tea_encrypt+0x20>
100000f84:     	stp	w9, w10, [x0]
100000f88:     	ret

0000000100000f8c <_main>:
100000f8c:     	stp	x28, x27, [sp, #-0x60]!
100000f90:     	stp	x26, x25, [sp, #0x10]
100000f94:     	stp	x24, x23, [sp, #0x20]
100000f98:     	stp	x22, x21, [sp, #0x30]
100000f9c:     	stp	x20, x19, [sp, #0x40]
100000fa0:     	stp	x29, x30, [sp, #0x50]
100000fa4:     	add	x29, sp, #0x50
100000fa8:     	sub	sp, sp, #0x650
100000fac:     	mov	x21, x1
100000fb0:     	mov	x22, x0
100000fb4:     	add	x24, sp, #0xb0
100000fb8:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000fbc:     	ldr	x8, [x8, #0x18]
100000fc0:     	ldr	x8, [x8]
100000fc4:     	stur	x8, [x29, #-0x68]
100000fc8:     	mov	w19, #0x3               ; =3
100000fcc:     	cmp	w0, #0x2
100000fd0:     	b.lt	0x100000ff4 <_main+0x68>
100000fd4:     	ldr	x0, [x21, #0x8]
100000fd8:     	bl	0x1000015b8 <_atoi@stub>
100000fdc:     	mov	x23, x0
100000fe0:     	cmp	w22, #0x2
100000fe4:     	b.ne	0x100001004 <_main+0x78>
100000fe8:     	adrp	x25, 0x100001000 <_main+0x74>
100000fec:     	add	x25, x25, #0x8e8
100000ff0:     	b	0x100001008 <_main+0x7c>
100000ff4:     	adrp	x25, 0x100001000 <_main+0x74>
100000ff8:     	add	x25, x25, #0x8e8
100000ffc:     	mov	w23, #0x3               ; =3
100001000:     	b	0x100001008 <_main+0x7c>
100001004:     	ldr	x25, [x21, #0x10]
100001008:     	scvtf	s0, w23
10000100c:     	dup.4s	v0, v0[0]
100001010:     	sxtw	x20, w23
100001014:     	dup.4s	v3, w23
100001018:     	adrp	x8, 0x100001000 <_main+0x74>
10000101c:     	ldr	q1, [x8, #0x6b0]
100001020:     	eor.16b	v2, v3, v1
100001024:     	adrp	x8, 0x100001000 <_main+0x74>
100001028:     	ldr	q4, [x8, #0x6c0]
10000102c:     	eor.16b	v5, v3, v4
100001030:     	adrp	x8, 0x100001000 <_main+0x74>
100001034:     	ldr	q6, [x8, #0x6d0]
100001038:     	eor.16b	v7, v3, v6
10000103c:     	adrp	x8, 0x100001000 <_main+0x74>
100001040:     	ldr	q16, [x8, #0x6e0]
100001044:     	eor.16b	v17, v3, v16
100001048:     	stp	q5, q7, [x24, #0x310]
10000104c:     	add.4s	v1, v3, v1
100001050:     	add.4s	v4, v3, v4
100001054:     	add.4s	v5, v3, v6
100001058:     	add.4s	v6, v3, v16
10000105c:     	stp	q4, q5, [x24, #0x210]
100001060:     	adrp	x8, 0x100001000 <_main+0x74>
100001064:     	ldr	q4, [x8, #0x700]
100001068:     	adrp	x8, 0x100001000 <_main+0x74>
10000106c:     	ldr	q5, [x8, #0x710]
100001070:     	stp	q4, q5, [x24, #0x110]
100001074:     	adrp	x8, 0x100001000 <_main+0x74>
100001078:     	ldr	q4, [x8, #0x720]
10000107c:     	adrp	x8, 0x100001000 <_main+0x74>
100001080:     	ldr	q5, [x8, #0x730]
100001084:     	eor.16b	v7, v3, v5
100001088:     	adrp	x8, 0x100001000 <_main+0x74>
10000108c:     	ldr	q16, [x8, #0x740]
100001090:     	eor.16b	v18, v3, v16
100001094:     	adrp	x8, 0x100001000 <_main+0x74>
100001098:     	ldr	q19, [x8, #0x750]
10000109c:     	eor.16b	v20, v3, v19
1000010a0:     	adrp	x8, 0x100001000 <_main+0x74>
1000010a4:     	ldr	q21, [x8, #0x760]
1000010a8:     	eor.16b	v22, v3, v21
1000010ac:     	stp	q17, q7, [x24, #0x330]
1000010b0:     	stp	q18, q20, [x24, #0x350]
1000010b4:     	add.4s	v5, v3, v5
1000010b8:     	add.4s	v7, v3, v16
1000010bc:     	add.4s	v16, v3, v19
1000010c0:     	add.4s	v17, v3, v21
1000010c4:     	stp	q6, q5, [x24, #0x230]
1000010c8:     	stp	q7, q16, [x24, #0x250]
1000010cc:     	adrp	x8, 0x100001000 <_main+0x74>
1000010d0:     	ldr	q5, [x8, #0x770]
1000010d4:     	stp	q4, q5, [x24, #0x130]
1000010d8:     	adrp	x8, 0x100001000 <_main+0x74>
1000010dc:     	ldr	q4, [x8, #0x780]
1000010e0:     	adrp	x8, 0x100001000 <_main+0x74>
1000010e4:     	ldr	q5, [x8, #0x790]
1000010e8:     	stp	q4, q5, [x24, #0x150]
1000010ec:     	adrp	x8, 0x100001000 <_main+0x74>
1000010f0:     	ldr	q4, [x8, #0x7a0]
1000010f4:     	adrp	x8, 0x100001000 <_main+0x74>
1000010f8:     	ldr	q5, [x8, #0x7b0]
1000010fc:     	eor.16b	v6, v3, v5
100001100:     	adrp	x8, 0x100001000 <_main+0x74>
100001104:     	ldr	q7, [x8, #0x7c0]
100001108:     	eor.16b	v16, v3, v7
10000110c:     	adrp	x8, 0x100001000 <_main+0x74>
100001110:     	ldr	q18, [x8, #0x7d0]
100001114:     	eor.16b	v19, v3, v18
100001118:     	adrp	x8, 0x100001000 <_main+0x74>
10000111c:     	ldr	q20, [x8, #0x7e0]
100001120:     	stp	q22, q6, [x24, #0x370]
100001124:     	eor.16b	v6, v3, v20
100001128:     	stp	q16, q19, [x24, #0x390]
10000112c:     	add.4s	v5, v3, v5
100001130:     	add.4s	v7, v3, v7
100001134:     	add.4s	v16, v3, v18
100001138:     	stp	q17, q5, [x24, #0x270]
10000113c:     	stp	q7, q16, [x24, #0x290]
100001140:     	adrp	x8, 0x100001000 <_main+0x74>
100001144:     	ldr	q5, [x8, #0x7f0]
100001148:     	stp	q4, q5, [x24, #0x170]
10000114c:     	adrp	x8, 0x100001000 <_main+0x74>
100001150:     	ldr	q4, [x8, #0x800]
100001154:     	adrp	x8, 0x100001000 <_main+0x74>
100001158:     	ldr	q5, [x8, #0x810]
10000115c:     	stp	q4, q5, [x24, #0x190]
100001160:     	adrp	x8, 0x100001000 <_main+0x74>
100001164:     	ldr	q4, [x8, #0x830]
100001168:     	eor.16b	v5, v3, v4
10000116c:     	adrp	x8, 0x100001000 <_main+0x74>
100001170:     	ldr	q7, [x8, #0x840]
100001174:     	eor.16b	v16, v3, v7
100001178:     	adrp	x8, 0x100001000 <_main+0x74>
10000117c:     	ldr	q17, [x8, #0x850]
100001180:     	eor.16b	v18, v3, v17
100001184:     	stp	q6, q5, [x24, #0x3b0]
100001188:     	adrp	x8, 0x100001000 <_main+0x74>
10000118c:     	ldr	q5, [x8, #0x860]
100001190:     	stp	q16, q18, [x24, #0x3d0]
100001194:     	eor.16b	v6, v3, v5
100001198:     	str	q6, [x24, #0x3f0]
10000119c:     	adrp	x8, 0x100001000 <_main+0x74>
1000011a0:     	ldr	q6, [x8, #0x6f0]
1000011a4:     	stp	q0, q0, [sp, #0xb0]
1000011a8:     	stp	q0, q0, [sp, #0xd0]
1000011ac:     	str	q0, [sp, #0xf0]
1000011b0:     	stp	q0, q0, [x24, #0x50]
1000011b4:     	add.4s	v16, v3, v20
1000011b8:     	add.4s	v4, v3, v4
1000011bc:     	add.4s	v7, v3, v7
1000011c0:     	add.4s	v17, v3, v17
1000011c4:     	add.4s	v3, v3, v5
1000011c8:     	adrp	x8, 0x100001000 <_main+0x74>
1000011cc:     	ldr	q5, [x8, #0x820]
1000011d0:     	stp	q0, q0, [x24, #0x70]
1000011d4:     	stp	q0, q0, [x24, #0x90]
1000011d8:     	stp	q16, q4, [x24, #0x2b0]
1000011dc:     	stp	q7, q17, [x24, #0x2d0]
1000011e0:     	stp	q3, q2, [x24, #0x2f0]
1000011e4:     	adrp	x8, 0x100001000 <_main+0x74>
1000011e8:     	ldr	q2, [x8, #0x870]
1000011ec:     	stp	q5, q2, [x24, #0x1b0]
1000011f0:     	adrp	x8, 0x100001000 <_main+0x74>
1000011f4:     	ldr	q2, [x8, #0x880]
1000011f8:     	adrp	x8, 0x100001000 <_main+0x74>
1000011fc:     	ldr	q3, [x8, #0x890]
100001200:     	stp	q2, q3, [x24, #0x1d0]
100001204:     	adrp	x8, 0x100001000 <_main+0x74>
100001208:     	ldr	q2, [x8, #0x8a0]
10000120c:     	stp	q2, q1, [x24, #0x1f0]
100001210:     	stp	q0, q0, [x24, #0xb0]
100001214:     	stp	q0, q0, [x24, #0xd0]
100001218:     	stp	q0, q6, [x24, #0xf0]
10000121c:     	str	w23, [sp, #0x88]
100001220:     	adrp	x8, 0x100001000 <_main+0x74>
100001224:     	ldr	d0, [x8, #0x8c0]
100001228:     	stur	d0, [sp, #0x8c]
10000122c:     	str	w19, [sp, #0x94]
100001230:     	add	x0, sp, #0x78
100001234:     	add	x1, sp, #0x88
100001238:     	bl	0x100000748 <_copy16>
10000123c:     	ldrsw	x8, [sp, #0x84]
100001240:     	str	x8, [sp, #0x68]
100001244:     	sub	x0, x29, #0xe8
100001248:     	bl	0x100000754 <_zero64>
10000124c:     	sub	x0, x29, #0xe8
100001250:     	and	x1, x20, #0x3f
100001254:     	bl	0x100000764 <_zero_n>
100001258:     	mov	x0, x25
10000125c:     	bl	0x100000770 <_strcmp_const>
100001260:     	str	w0, [sp, #0x50]
100001264:     	mov	x0, x25
100001268:     	bl	0x100000794 <_strncmp_const>
10000126c:     	str	w0, [sp, #0x3c]
100001270:     	add	x0, sp, #0x4b8
100001274:     	and	w1, w23, #0x3f
100001278:     	bl	0x1000007bc <_loop_zero>
10000127c:     	mov	x0, x25
100001280:     	bl	0x100001654 <_strlen@stub>
100001284:     	mov	x2, x0
100001288:     	sub	x0, x29, #0xe8
10000128c:     	mov	x1, x25
100001290:     	bl	0x1000007d0 <_loop_copy>
100001294:     	mov	x0, x25
100001298:     	bl	0x1000007e4 <_loop_strlen>
10000129c:     	str	x0, [sp, #0x60]
1000012a0:     	add	w8, w23, #0x1
1000012a4:     	add	w9, w23, #0x2
1000012a8:     	stp	x8, x9, [sp, #0x8]
1000012ac:     	str	x23, [sp]
1000012b0:     	mov	w0, #0x3                ; =3
1000012b4:     	bl	0x100000868 <_sum_va>
1000012b8:     	str	w0, [sp, #0x5c]
1000012bc:     	mov	x0, x25
1000012c0:     	bl	0x1000008b0 <_ssp_copy>
1000012c4:     	str	w0, [sp, #0x58]
1000012c8:     	mov	x0, x25
1000012cc:     	bl	0x100001654 <_strlen@stub>
1000012d0:     	mov	x8, x0
1000012d4:     	sub	x0, x29, #0xe8
1000012d8:     	and	x2, x8, #0x1f
1000012dc:     	mov	x1, x25
1000012e0:     	bl	0x100000914 <_fortify_memcpy>
1000012e4:     	sub	x0, x29, #0xe8
1000012e8:     	mov	w1, #0x80               ; =128
1000012ec:     	mov	x2, x23
1000012f0:     	bl	0x10000097c <_fortify_snprintf>
1000012f4:     	str	w0, [sp, #0x54]
1000012f8:     	cmp	w22, #0x4
1000012fc:     	str	x25, [sp, #0x70]
100001300:     	b.lt	0x10000130c <_main+0x380>
100001304:     	ldr	x8, [x21, #0x18]
100001308:     	b	0x100001314 <_main+0x388>
10000130c:     	adrp	x8, 0x100001000 <_main+0x74>
100001310:     	add	x8, x8, #0x90a
100001314:     	str	x8, [sp, #0x28]
100001318:     	mov	x0, x20
10000131c:     	bl	0x100000858 <_make_small>
100001320:     	str	x0, [sp, #0x48]
100001324:     	mov	x0, x20
100001328:     	bl	0x10000082c <_use_big>
10000132c:     	str	x0, [sp, #0x40]
100001330:     	mov	x0, x20
100001334:     	bl	0x100000730 <_is_pow2>
100001338:     	str	w0, [sp, #0x24]
10000133c:     	mov	x0, x20
100001340:     	mov	x1, x20
100001344:     	bl	0x100000724 <_rotl32>
100001348:     	str	w0, [sp, #0x20]
10000134c:     	mov	x0, x20
100001350:     	bl	0x10000071c <_bswap32_manual>
100001354:     	str	w0, [sp, #0x1c]
100001358:     	mov	x0, x20
10000135c:     	bl	0x100000708 <_popcount_loop>
100001360:     	str	w0, [sp, #0x18]
100001364:     	mov	x0, x20
100001368:     	mov	w1, #0x0                ; =0
10000136c:     	mov	w2, #0x9                ; =9
100001370:     	bl	0x1000006f4 <_sel_clamp>
100001374:     	mov	x22, x0
100001378:     	mov	x0, x20
10000137c:     	bl	0x1000006e8 <_sel_abs>
100001380:     	mov	x28, x0
100001384:     	mov	x0, x20
100001388:     	mov	w1, #0x5                ; =5
10000138c:     	bl	0x1000006dc <_sel_max>
100001390:     	mov	x24, x0
100001394:     	mov	x0, x20
100001398:     	bl	0x1000006bc <_udiv1000_64>
10000139c:     	str	x0, [sp, #0x30]
1000013a0:     	mov	x0, x20
1000013a4:     	bl	0x1000006a8 <_sdiv16>
1000013a8:     	mov	x25, x0
1000013ac:     	mov	x0, x20
1000013b0:     	bl	0x10000068c <_umod10>
1000013b4:     	mov	x26, x0
1000013b8:     	mov	x0, x20
1000013bc:     	bl	0x10000066c <_sdiv7>
1000013c0:     	mov	x23, x0
1000013c4:     	mov	x0, x20
1000013c8:     	bl	0x10000064c <_udiv7>
1000013cc:     	mov	x21, x0
1000013d0:     	mov	x0, x20
1000013d4:     	bl	0x100000614 <_sw_bittest>
1000013d8:     	mov	x27, x0
1000013dc:     	mov	x0, x20
1000013e0:     	bl	0x100000568 <_sw_sparse>
1000013e4:     	mov	x19, x0
1000013e8:     	mov	x0, x20
1000013ec:     	bl	0x100000548 <_sw_dense>
1000013f0:     	add	w8, w26, w25
1000013f4:     	add	w9, w23, w21
1000013f8:     	add	w21, w8, w9
1000013fc:     	add	w8, w19, w27
100001400:     	add	w25, w8, w0
100001404:     	ldr	w8, [sp, #0x18]
100001408:     	add	w8, w22, w8
10000140c:     	add	w9, w28, w24
100001410:     	add	w22, w8, w9
100001414:     	ldp	w9, w8, [sp, #0x20]
100001418:     	add	w8, w9, w8
10000141c:     	ldr	w9, [sp, #0x1c]
100001420:     	add	w24, w8, w9
100001424:     	ldr	w8, [sp, #0x50]
100001428:     	ldr	w9, [sp, #0x3c]
10000142c:     	add	w8, w8, w9
100001430:     	add	w26, w8, #0x7
100001434:     	sub	x1, x29, #0xe8
100001438:     	ldr	x0, [sp, #0x28]
10000143c:     	mov	w2, #0x80               ; =128
100001440:     	bl	0x1000009a4 <_read_file_head>
100001444:     	mov	x23, x0
100001448:     	mov	x0, x20
10000144c:     	bl	0x100000a98 <_tail_caller>
100001450:     	mov	x19, x0
100001454:     	ldr	x20, [sp, #0x70]
100001458:     	mov	x0, x20
10000145c:     	bl	0x100000aa0 <_tail_ext>
100001460:     	add	w27, w0, w19
100001464:     	add	x0, sp, #0x4b8
100001468:     	add	x1, sp, #0x3b0
10000146c:     	add	x2, sp, #0x2b0
100001470:     	mov	w3, #0x40               ; =64
100001474:     	bl	0x100000aa8 <_vadd>
100001478:     	add	x0, sp, #0x4b8
10000147c:     	mov	w1, #0x40               ; =64
100001480:     	bl	0x100000b94 <_vsum>
100001484:     	mov	x19, x0
100001488:     	add	x0, sp, #0x1b0
10000148c:     	add	x1, sp, #0xb0
100001490:     	mov	w2, #0x40               ; =64
100001494:     	bl	0x100000c8c <_vdot>
100001498:     	fcvtzs	x28, s0
10000149c:     	add	x0, sp, #0xa0
1000014a0:     	bl	0x100000dfc <_md5_init>
1000014a4:     	bl	0x100000e0c <_crc32_make_table>
1000014a8:     	mov	x0, x20
1000014ac:     	bl	0x100001654 <_strlen@stub>
1000014b0:     	mov	x1, x0
1000014b4:     	mov	x0, x20
1000014b8:     	bl	0x100000eec <_crc32_buf>
1000014bc:     	mov	x20, x0
1000014c0:     	ldr	d0, [sp, #0xa0]
1000014c4:     	str	d0, [sp, #0x98]
1000014c8:     	adrp	x1, 0x100001000 <_main+0x74>
1000014cc:     	add	x1, x1, #0x8b0
1000014d0:     	add	x0, sp, #0x98
1000014d4:     	bl	0x100000f28 <_tea_encrypt>
1000014d8:     	ldr	w8, [sp, #0x98]
1000014dc:     	ldp	x10, x9, [sp, #0x60]
1000014e0:     	add	x9, x9, x10
1000014e4:     	add	x9, x26, x9
1000014e8:     	ldp	w10, w11, [sp, #0x58]
1000014ec:     	add	x9, x9, w11, sxtw
1000014f0:     	add	x9, x9, w10, sxtw
1000014f4:     	ldr	w10, [sp, #0x54]
1000014f8:     	add	x9, x9, w10, sxtw
1000014fc:     	ldp	x10, x11, [sp, #0x40]
100001500:     	add	x9, x9, x11, asr #32
100001504:     	add	x10, x10, x24
100001508:     	ldr	x11, [sp, #0x30]
10000150c:     	add	x10, x10, x11
100001510:     	add	x9, x9, x10
100001514:     	add	x9, x9, w22, sxtw
100001518:     	add	x9, x9, x21
10000151c:     	add	x9, x9, w23, sxtw
100001520:     	add	x9, x9, w25, sxtw
100001524:     	add	x9, x9, w27, sxtw
100001528:     	add	x9, x9, w19, sxtw
10000152c:     	add	x9, x9, x28
100001530:     	add	x9, x9, w20, uxtw
100001534:     	add	x8, x9, x8
100001538:     	str	x8, [sp]
10000153c:     	adrp	x0, 0x100001000 <_main+0x74>
100001540:     	add	x0, x0, #0x915
100001544:     	bl	0x100001618 <_printf@stub>
100001548:     	ldur	x8, [x29, #-0x68]
10000154c:     	adrp	x9, 0x100004000 <_strncmp+0x100004000>
100001550:     	ldr	x9, [x9, #0x18]
100001554:     	ldr	x9, [x9]
100001558:     	cmp	x9, x8
10000155c:     	b.ne	0x100001584 <_main+0x5f8>
100001560:     	mov	w0, #0x0                ; =0
100001564:     	add	sp, sp, #0x650
100001568:     	ldp	x29, x30, [sp, #0x50]
10000156c:     	ldp	x20, x19, [sp, #0x40]
100001570:     	ldp	x22, x21, [sp, #0x30]
100001574:     	ldp	x24, x23, [sp, #0x20]
100001578:     	ldp	x26, x25, [sp, #0x10]
10000157c:     	ldp	x28, x27, [sp], #0x60
100001580:     	ret
100001584:     	bl	0x1000015a0 <___stack_chk_fail@stub>

Disassembly of section __TEXT,__stubs:

0000000100001588 <__stubs>:
100001588:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000158c:     	ldr	x16, [x16]
100001590:     	br	x16
100001594:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001598:     	ldr	x16, [x16, #0x8]
10000159c:     	br	x16
1000015a0:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015a4:     	ldr	x16, [x16, #0x10]
1000015a8:     	br	x16
1000015ac:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015b0:     	ldr	x16, [x16, #0x28]
1000015b4:     	br	x16
1000015b8:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015bc:     	ldr	x16, [x16, #0x30]
1000015c0:     	br	x16
1000015c4:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015c8:     	ldr	x16, [x16, #0x38]
1000015cc:     	br	x16
1000015d0:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015d4:     	ldr	x16, [x16, #0x40]
1000015d8:     	br	x16
1000015dc:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015e0:     	ldr	x16, [x16, #0x48]
1000015e4:     	br	x16
1000015e8:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015ec:     	ldr	x16, [x16, #0x50]
1000015f0:     	br	x16
1000015f4:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015f8:     	ldr	x16, [x16, #0x58]
1000015fc:     	br	x16
100001600:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001604:     	ldr	x16, [x16, #0x60]
100001608:     	br	x16
10000160c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001610:     	ldr	x16, [x16, #0x68]
100001614:     	br	x16
100001618:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000161c:     	ldr	x16, [x16, #0x70]
100001620:     	br	x16
100001624:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001628:     	ldr	x16, [x16, #0x78]
10000162c:     	br	x16
100001630:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001634:     	ldr	x16, [x16, #0x80]
100001638:     	br	x16
10000163c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001640:     	ldr	x16, [x16, #0x88]
100001644:     	br	x16
100001648:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000164c:     	ldr	x16, [x16, #0x90]
100001650:     	br	x16
100001654:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001658:     	ldr	x16, [x16, #0x98]
10000165c:     	br	x16
100001660:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001664:     	ldr	x16, [x16, #0xa0]
100001668:     	br	x16
