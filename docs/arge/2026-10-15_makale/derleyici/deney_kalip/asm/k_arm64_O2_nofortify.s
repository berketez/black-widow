
bin/k_arm64_O2_nofortify:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000100000548 <_sw_dense>:
100000548:     	cmp	w0, #0x7
10000054c:     	b.hi	0x100000560 <_sw_dense+0x18>
100000550:     	adrp	x8, 0x100001000 <_main+0x7c>
100000554:     	add	x8, x8, #0x868
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
100000764:     	b	0x10000155c <_strncmp+0x10000155c>

0000000100000768 <_strlen_const>:
100000768:     	mov	w0, #0x7                ; =7
10000076c:     	ret

0000000100000770 <_strcmp_const>:
100000770:     	stp	x29, x30, [sp, #-0x10]!
100000774:     	mov	x29, sp
100000778:     	adrp	x1, 0x100001000 <_main+0x7c>
10000077c:     	add	x1, x1, #0x888
100000780:     	bl	0x1000015d4 <_strncmp+0x1000015d4>
100000784:     	cmp	w0, #0x0
100000788:     	cset	w0, eq
10000078c:     	ldp	x29, x30, [sp], #0x10
100000790:     	ret

0000000100000794 <_strncmp_const>:
100000794:     	stp	x29, x30, [sp, #-0x10]!
100000798:     	mov	x29, sp
10000079c:     	adrp	x1, 0x100001000 <_main+0x7c>
1000007a0:     	add	x1, x1, #0x88c
1000007a4:     	mov	w2, #0x7                ; =7
1000007a8:     	bl	0x100001604 <_strncmp+0x100001604>
1000007ac:     	cmp	w0, #0x0
1000007b0:     	cset	w0, eq
1000007b4:     	ldp	x29, x30, [sp], #0x10
1000007b8:     	ret

00000001000007bc <_loop_zero>:
1000007bc:     	cmp	w1, #0x1
1000007c0:     	b.lt	0x1000007cc <_loop_zero+0x10>
1000007c4:     	ubfiz	x1, x1, #2, #32
1000007c8:     	b	0x10000155c <_strncmp+0x10000155c>
1000007cc:     	ret

00000001000007d0 <_loop_copy>:
1000007d0:     	cmp	w2, #0x1
1000007d4:     	b.lt	0x1000007e0 <_loop_copy+0x10>
1000007d8:     	mov	w2, w2
1000007dc:     	b	0x100001598 <_strncmp+0x100001598>
1000007e0:     	ret

00000001000007e4 <_loop_strlen>:
1000007e4:     	b	0x1000015f8 <_strncmp+0x1000015f8>

00000001000007e8 <_make_big>:
1000007e8:     	str	x0, [x8]
1000007ec:     	dup.2d	v0, x0
1000007f0:     	adrp	x9, 0x100001000 <_main+0x7c>
1000007f4:     	ldr	q1, [x9, #0x610]
1000007f8:     	add.2d	v1, v0, v1
1000007fc:     	stur	q1, [x8, #0x8]
100000800:     	adrp	x9, 0x100001000 <_main+0x7c>
100000804:     	ldr	q1, [x9, #0x620]
100000808:     	add.2d	v1, v0, v1
10000080c:     	stur	q1, [x8, #0x18]
100000810:     	adrp	x9, 0x100001000 <_main+0x7c>
100000814:     	ldr	q1, [x9, #0x630]
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
1000008c4:     	ldr	x8, [x8, #0x10]
1000008c8:     	ldr	x8, [x8]
1000008cc:     	stur	x8, [x29, #-0x8]
1000008d0:     	add	x0, sp, #0x8
1000008d4:     	bl	0x1000015e0 <_strncmp+0x1000015e0>
1000008d8:     	add	x0, sp, #0x8
1000008dc:     	bl	0x1000015f8 <_strncmp+0x1000015f8>
1000008e0:     	ldrsb	w8, [sp, #0xb]
1000008e4:     	ldur	x9, [x29, #-0x8]
1000008e8:     	adrp	x10, 0x100004000 <_strncmp+0x100004000>
1000008ec:     	ldr	x10, [x10, #0x10]
1000008f0:     	ldr	x10, [x10]
1000008f4:     	cmp	x10, x9
1000008f8:     	b.ne	0x10000090c <_ssp_copy+0x5c>
1000008fc:     	add	w0, w8, w0
100000900:     	ldp	x29, x30, [sp, #0x50]
100000904:     	add	sp, sp, #0x60
100000908:     	ret
10000090c:     	bl	0x100001544 <_strncmp+0x100001544>

0000000100000910 <_fortify_memcpy>:
100000910:     	sub	sp, sp, #0x50
100000914:     	stp	x20, x19, [sp, #0x30]
100000918:     	stp	x29, x30, [sp, #0x40]
10000091c:     	add	x29, sp, #0x40
100000920:     	mov	x19, x0
100000924:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000928:     	ldr	x8, [x8, #0x10]
10000092c:     	ldr	x8, [x8]
100000930:     	stur	x8, [x29, #-0x18]
100000934:     	add	x0, sp, #0x8
100000938:     	bl	0x100001598 <_strncmp+0x100001598>
10000093c:     	ldur	q0, [sp, #0x8]
100000940:     	ldur	q1, [sp, #0x18]
100000944:     	stp	q0, q1, [x19]
100000948:     	ldur	x8, [x29, #-0x18]
10000094c:     	adrp	x9, 0x100004000 <_strncmp+0x100004000>
100000950:     	ldr	x9, [x9, #0x10]
100000954:     	ldr	x9, [x9]
100000958:     	cmp	x9, x8
10000095c:     	b.ne	0x100000970 <_fortify_memcpy+0x60>
100000960:     	ldp	x29, x30, [sp, #0x40]
100000964:     	ldp	x20, x19, [sp, #0x30]
100000968:     	add	sp, sp, #0x50
10000096c:     	ret
100000970:     	bl	0x100001544 <_strncmp+0x100001544>

0000000100000974 <_fortify_snprintf>:
100000974:     	sub	sp, sp, #0x20
100000978:     	stp	x29, x30, [sp, #0x10]
10000097c:     	add	x29, sp, #0x10
100000980:     	str	x2, [sp]
100000984:     	adrp	x2, 0x100001000 <_main+0x7c>
100000988:     	add	x2, x2, #0x894
10000098c:     	bl	0x1000015c8 <_strncmp+0x1000015c8>
100000990:     	ldp	x29, x30, [sp, #0x10]
100000994:     	add	sp, sp, #0x20
100000998:     	ret

000000010000099c <_read_file_head>:
10000099c:     	sub	sp, sp, #0x50
1000009a0:     	stp	x24, x23, [sp, #0x10]
1000009a4:     	stp	x22, x21, [sp, #0x20]
1000009a8:     	stp	x20, x19, [sp, #0x30]
1000009ac:     	stp	x29, x30, [sp, #0x40]
1000009b0:     	add	x29, sp, #0x40
1000009b4:     	mov	x23, x2
1000009b8:     	mov	x22, x1
1000009bc:     	mov	x20, x0
1000009c0:     	mov	w1, #0x1000000          ; =16777216
1000009c4:     	bl	0x1000015a4 <_strncmp+0x1000015a4>
1000009c8:     	tbnz	w0, #0x1f, 0x100000a0c <_read_file_head+0x70>
1000009cc:     	mov	x19, x0
1000009d0:     	mov	x0, x23
1000009d4:     	bl	0x10000158c <_strncmp+0x10000158c>
1000009d8:     	cbz	x0, 0x100000a40 <_read_file_head+0xa4>
1000009dc:     	mov	x21, x0
1000009e0:     	mov	x0, x19
1000009e4:     	mov	x1, x21
1000009e8:     	mov	x2, x23
1000009ec:     	bl	0x1000015bc <_strncmp+0x1000015bc>
1000009f0:     	tbnz	x0, #0x3f, 0x100000a48 <_read_file_head+0xac>
1000009f4:     	mov	x20, x0
1000009f8:     	mov	x0, x22
1000009fc:     	mov	x1, x21
100000a00:     	mov	x2, x20
100000a04:     	bl	0x100001598 <_strncmp+0x100001598>
100000a08:     	b	0x100000a58 <_read_file_head+0xbc>
100000a0c:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000a10:     	ldr	x8, [x8, #0x18]
100000a14:     	ldr	x19, [x8]
100000a18:     	bl	0x100001538 <_strncmp+0x100001538>
100000a1c:     	ldr	w0, [x0]
100000a20:     	bl	0x1000015ec <_strncmp+0x1000015ec>
100000a24:     	stp	x20, x0, [sp]
100000a28:     	adrp	x1, 0x100001000 <_main+0x7c>
100000a2c:     	add	x1, x1, #0x89d
100000a30:     	mov	x0, x19
100000a34:     	bl	0x100001574 <_strncmp+0x100001574>
100000a38:     	mov	w20, #-0x1              ; =-1
100000a3c:     	b	0x100000a68 <_read_file_head+0xcc>
100000a40:     	mov	w20, #-0x1              ; =-1
100000a44:     	b	0x100000a60 <_read_file_head+0xc4>
100000a48:     	bl	0x100001538 <_strncmp+0x100001538>
100000a4c:     	mov	w8, #0x5                ; =5
100000a50:     	str	w8, [x0]
100000a54:     	mov	w20, #-0x1              ; =-1
100000a58:     	mov	x0, x21
100000a5c:     	bl	0x100001580 <_strncmp+0x100001580>
100000a60:     	mov	x0, x19
100000a64:     	bl	0x100001568 <_strncmp+0x100001568>
100000a68:     	mov	x0, x20
100000a6c:     	ldp	x29, x30, [sp, #0x40]
100000a70:     	ldp	x20, x19, [sp, #0x30]
100000a74:     	ldp	x22, x21, [sp, #0x20]
100000a78:     	ldp	x24, x23, [sp, #0x10]
100000a7c:     	add	sp, sp, #0x50
100000a80:     	ret

0000000100000a84 <_tail_target>:
100000a84:     	add	w8, w0, w0, lsl #1
100000a88:     	add	w0, w8, #0x1
100000a8c:     	ret

0000000100000a90 <_tail_caller>:
100000a90:     	add	w0, w0, #0x1
100000a94:     	b	0x100000a84 <_tail_target>

0000000100000a98 <_tail_ext>:
100000a98:     	add	x0, x0, #0x1
100000a9c:     	b	0x100001550 <_strncmp+0x100001550>

0000000100000aa0 <_vadd>:
100000aa0:     	cmp	w3, #0x1
100000aa4:     	b.lt	0x100000b88 <_vadd+0xe8>
100000aa8:     	mov	w8, w3
100000aac:     	cmp	w3, #0x3
100000ab0:     	b.hi	0x100000abc <_vadd+0x1c>
100000ab4:     	mov	x9, #0x0                ; =0
100000ab8:     	b	0x100000b5c <_vadd+0xbc>
100000abc:     	cmp	w3, #0x10
100000ac0:     	b.hs	0x100000acc <_vadd+0x2c>
100000ac4:     	mov	x9, #0x0                ; =0
100000ac8:     	b	0x100000b20 <_vadd+0x80>
100000acc:     	and	x9, x8, #0x7ffffff0
100000ad0:     	add	x10, x1, #0x20
100000ad4:     	add	x11, x2, #0x20
100000ad8:     	add	x12, x0, #0x20
100000adc:     	mov	x13, x9
100000ae0:     	ldp	q0, q1, [x10, #-0x20]
100000ae4:     	ldp	q2, q3, [x10], #0x40
100000ae8:     	ldp	q4, q5, [x11, #-0x20]
100000aec:     	ldp	q6, q7, [x11], #0x40
100000af0:     	add.4s	v0, v4, v0
100000af4:     	add.4s	v1, v5, v1
100000af8:     	add.4s	v2, v6, v2
100000afc:     	add.4s	v3, v7, v3
100000b00:     	stp	q0, q1, [x12, #-0x20]
100000b04:     	stp	q2, q3, [x12], #0x40
100000b08:     	subs	x13, x13, #0x10
100000b0c:     	b.ne	0x100000ae0 <_vadd+0x40>
100000b10:     	cmp	x9, x8
100000b14:     	b.eq	0x100000b88 <_vadd+0xe8>
100000b18:     	tst	x8, #0xc
100000b1c:     	b.eq	0x100000b5c <_vadd+0xbc>
100000b20:     	mov	x11, x9
100000b24:     	and	x9, x8, #0x7ffffffc
100000b28:     	sub	x10, x11, x9
100000b2c:     	lsl	x13, x11, #2
100000b30:     	add	x11, x0, x13
100000b34:     	add	x12, x2, x13
100000b38:     	add	x13, x1, x13
100000b3c:     	ldr	q0, [x13], #0x10
100000b40:     	ldr	q1, [x12], #0x10
100000b44:     	add.4s	v0, v1, v0
100000b48:     	str	q0, [x11], #0x10
100000b4c:     	adds	x10, x10, #0x4
100000b50:     	b.ne	0x100000b3c <_vadd+0x9c>
100000b54:     	cmp	x9, x8
100000b58:     	b.eq	0x100000b88 <_vadd+0xe8>
100000b5c:     	lsl	x12, x9, #2
100000b60:     	add	x10, x0, x12
100000b64:     	add	x11, x2, x12
100000b68:     	add	x12, x1, x12
100000b6c:     	sub	x8, x8, x9
100000b70:     	ldr	w9, [x12], #0x4
100000b74:     	ldr	w13, [x11], #0x4
100000b78:     	add	w9, w13, w9
100000b7c:     	str	w9, [x10], #0x4
100000b80:     	subs	x8, x8, #0x1
100000b84:     	b.ne	0x100000b70 <_vadd+0xd0>
100000b88:     	ret

0000000100000b8c <_vsum>:
100000b8c:     	cmp	w1, #0x1
100000b90:     	b.lt	0x100000bac <_vsum+0x20>
100000b94:     	mov	w9, w1
100000b98:     	cmp	w1, #0x3
100000b9c:     	b.hi	0x100000bb8 <_vsum+0x2c>
100000ba0:     	mov	x10, #0x0               ; =0
100000ba4:     	mov	w8, #0x0                ; =0
100000ba8:     	b	0x100000c64 <_vsum+0xd8>
100000bac:     	mov	w8, #0x0                ; =0
100000bb0:     	mov	x0, x8
100000bb4:     	ret
100000bb8:     	cmp	w1, #0x10
100000bbc:     	b.hs	0x100000bcc <_vsum+0x40>
100000bc0:     	mov	x10, #0x0               ; =0
100000bc4:     	mov	w8, #0x0                ; =0
100000bc8:     	b	0x100000c2c <_vsum+0xa0>
100000bcc:     	and	x10, x9, #0x7ffffff0
100000bd0:     	add	x8, x0, #0x20
100000bd4:     	movi.2d	v0, #0000000000000000
100000bd8:     	mov	x11, x10
100000bdc:     	movi.2d	v1, #0000000000000000
100000be0:     	movi.2d	v2, #0000000000000000
100000be4:     	movi.2d	v3, #0000000000000000
100000be8:     	ldp	q4, q5, [x8, #-0x20]
100000bec:     	ldp	q6, q7, [x8], #0x40
100000bf0:     	add.4s	v0, v4, v0
100000bf4:     	add.4s	v1, v5, v1
100000bf8:     	add.4s	v2, v6, v2
100000bfc:     	add.4s	v3, v7, v3
100000c00:     	subs	x11, x11, #0x10
100000c04:     	b.ne	0x100000be8 <_vsum+0x5c>
100000c08:     	add.4s	v0, v1, v0
100000c0c:     	add.4s	v0, v2, v0
100000c10:     	add.4s	v0, v3, v0
100000c14:     	addv.4s	s0, v0
100000c18:     	fmov	w8, s0
100000c1c:     	cmp	x10, x9
100000c20:     	b.eq	0x100000c7c <_vsum+0xf0>
100000c24:     	tst	x9, #0xc
100000c28:     	b.eq	0x100000c64 <_vsum+0xd8>
100000c2c:     	mov	x11, x10
100000c30:     	and	x10, x9, #0x7ffffffc
100000c34:     	movi.2d	v0, #0000000000000000
100000c38:     	mov.s	v0[0], w8
100000c3c:     	sub	x8, x11, x10
100000c40:     	add	x11, x0, x11, lsl #2
100000c44:     	ldr	q1, [x11], #0x10
100000c48:     	add.4s	v0, v1, v0
100000c4c:     	adds	x8, x8, #0x4
100000c50:     	b.ne	0x100000c44 <_vsum+0xb8>
100000c54:     	addv.4s	s0, v0
100000c58:     	fmov	w8, s0
100000c5c:     	cmp	x10, x9
100000c60:     	b.eq	0x100000c7c <_vsum+0xf0>
100000c64:     	add	x11, x0, x10, lsl #2
100000c68:     	sub	x9, x9, x10
100000c6c:     	ldr	w10, [x11], #0x4
100000c70:     	add	w8, w10, w8
100000c74:     	subs	x9, x9, #0x1
100000c78:     	b.ne	0x100000c6c <_vsum+0xe0>
100000c7c:     	mov	x0, x8
100000c80:     	ret

0000000100000c84 <_vdot>:
100000c84:     	cmp	w2, #0x1
100000c88:     	b.lt	0x100000ca4 <_vdot+0x20>
100000c8c:     	mov	w8, w2
100000c90:     	cmp	w2, #0x3
100000c94:     	b.hi	0x100000cac <_vdot+0x28>
100000c98:     	mov	x9, #0x0                ; =0
100000c9c:     	movi.2d	v0, #0000000000000000
100000ca0:     	b	0x100000dcc <_vdot+0x148>
100000ca4:     	movi.2d	v0, #0000000000000000
100000ca8:     	ret
100000cac:     	cmp	w2, #0x10
100000cb0:     	b.hs	0x100000cc0 <_vdot+0x3c>
100000cb4:     	mov	x9, #0x0                ; =0
100000cb8:     	movi.2d	v0, #0000000000000000
100000cbc:     	b	0x100000d7c <_vdot+0xf8>
100000cc0:     	and	x9, x8, #0x7ffffff0
100000cc4:     	add	x10, x0, #0x20
100000cc8:     	add	x11, x1, #0x20
100000ccc:     	movi.2d	v0, #0000000000000000
100000cd0:     	mov	x12, x9
100000cd4:     	ldp	q1, q2, [x10, #-0x20]
100000cd8:     	ldp	q3, q4, [x10], #0x40
100000cdc:     	ldp	q5, q6, [x11, #-0x20]
100000ce0:     	ldp	q7, q16, [x11], #0x40
100000ce4:     	fmul.4s	v1, v1, v5
100000ce8:     	mov	s5, v1[3]
100000cec:     	mov	s17, v1[2]
100000cf0:     	mov	s18, v1[1]
100000cf4:     	fmul.4s	v2, v2, v6
100000cf8:     	mov	s6, v2[3]
100000cfc:     	mov	s19, v2[2]
100000d00:     	mov	s20, v2[1]
100000d04:     	fmul.4s	v3, v3, v7
100000d08:     	mov	s7, v3[3]
100000d0c:     	mov	s21, v3[2]
100000d10:     	mov	s22, v3[1]
100000d14:     	fmul.4s	v4, v4, v16
100000d18:     	mov	s16, v4[3]
100000d1c:     	mov	s23, v4[2]
100000d20:     	mov	s24, v4[1]
100000d24:     	fadd	s0, s0, s1
100000d28:     	fadd	s0, s0, s18
100000d2c:     	fadd	s0, s0, s17
100000d30:     	fadd	s0, s0, s5
100000d34:     	fadd	s0, s0, s2
100000d38:     	fadd	s0, s0, s20
100000d3c:     	fadd	s0, s0, s19
100000d40:     	fadd	s0, s0, s6
100000d44:     	fadd	s0, s0, s3
100000d48:     	fadd	s0, s0, s22
100000d4c:     	fadd	s0, s0, s21
100000d50:     	fadd	s0, s0, s7
100000d54:     	fadd	s0, s0, s4
100000d58:     	fadd	s0, s0, s24
100000d5c:     	fadd	s0, s0, s23
100000d60:     	fadd	s0, s0, s16
100000d64:     	subs	x12, x12, #0x10
100000d68:     	b.ne	0x100000cd4 <_vdot+0x50>
100000d6c:     	cmp	x9, x8
100000d70:     	b.eq	0x100000df0 <_vdot+0x16c>
100000d74:     	tst	x8, #0xc
100000d78:     	b.eq	0x100000dcc <_vdot+0x148>
100000d7c:     	mov	x11, x9
100000d80:     	and	x9, x8, #0x7ffffffc
100000d84:     	sub	x10, x11, x9
100000d88:     	lsl	x12, x11, #2
100000d8c:     	add	x11, x1, x12
100000d90:     	add	x12, x0, x12
100000d94:     	ldr	q1, [x12], #0x10
100000d98:     	ldr	q2, [x11], #0x10
100000d9c:     	fmul.4s	v1, v1, v2
100000da0:     	mov	s2, v1[3]
100000da4:     	mov	s3, v1[2]
100000da8:     	mov	s4, v1[1]
100000dac:     	fadd	s0, s0, s1
100000db0:     	fadd	s0, s0, s4
100000db4:     	fadd	s0, s0, s3
100000db8:     	fadd	s0, s0, s2
100000dbc:     	adds	x10, x10, #0x4
100000dc0:     	b.ne	0x100000d94 <_vdot+0x110>
100000dc4:     	cmp	x9, x8
100000dc8:     	b.eq	0x100000df0 <_vdot+0x16c>
100000dcc:     	lsl	x11, x9, #2
100000dd0:     	add	x10, x1, x11
100000dd4:     	add	x11, x0, x11
100000dd8:     	sub	x8, x8, x9
100000ddc:     	ldr	s1, [x11], #0x4
100000de0:     	ldr	s2, [x10], #0x4
100000de4:     	fmadd	s0, s1, s2, s0
100000de8:     	subs	x8, x8, #0x1
100000dec:     	b.ne	0x100000ddc <_vdot+0x158>
100000df0:     	ret

0000000100000df4 <_md5_init>:
100000df4:     	adrp	x8, 0x100001000 <_main+0x7c>
100000df8:     	ldr	q0, [x8, #0x640]
100000dfc:     	str	q0, [x0]
100000e00:     	ret

0000000100000e04 <_crc32_make_table>:
100000e04:     	mov	x8, #0x0                ; =0
100000e08:     	adrp	x9, 0x100001000 <_main+0x7c>
100000e0c:     	ldr	q0, [x9, #0x650]
100000e10:     	movi.4s	v1, #0x1
100000e14:     	mov	w9, #0x8320             ; =33568
100000e18:     	movk	w9, #0xedb8, lsl #16
100000e1c:     	dup.4s	v2, w9
100000e20:     	adrp	x9, 0x100008000 <_crc_table>
100000e24:     	add	x9, x9, #0x0
100000e28:     	movi.4s	v3, #0x4
100000e2c:     	and.16b	v4, v0, v1
100000e30:     	ushr.4s	v5, v0, #0x1
100000e34:     	cmeq.4s	v4, v4, #0
100000e38:     	eor.16b	v6, v5, v2
100000e3c:     	bsl.16b	v4, v5, v6
100000e40:     	and.16b	v5, v4, v1
100000e44:     	cmeq.4s	v5, v5, #0
100000e48:     	ushr.4s	v4, v4, #0x1
100000e4c:     	eor.16b	v6, v4, v2
100000e50:     	bif.16b	v4, v6, v5
100000e54:     	and.16b	v5, v4, v1
100000e58:     	cmeq.4s	v5, v5, #0
100000e5c:     	ushr.4s	v4, v4, #0x1
100000e60:     	eor.16b	v6, v4, v2
100000e64:     	bif.16b	v4, v6, v5
100000e68:     	and.16b	v5, v4, v1
100000e6c:     	cmeq.4s	v5, v5, #0
100000e70:     	ushr.4s	v4, v4, #0x1
100000e74:     	eor.16b	v6, v4, v2
100000e78:     	bif.16b	v4, v6, v5
100000e7c:     	and.16b	v5, v4, v1
100000e80:     	cmeq.4s	v5, v5, #0
100000e84:     	ushr.4s	v4, v4, #0x1
100000e88:     	eor.16b	v6, v4, v2
100000e8c:     	bif.16b	v4, v6, v5
100000e90:     	and.16b	v5, v4, v1
100000e94:     	cmeq.4s	v5, v5, #0
100000e98:     	ushr.4s	v4, v4, #0x1
100000e9c:     	eor.16b	v6, v4, v2
100000ea0:     	bif.16b	v4, v6, v5
100000ea4:     	and.16b	v5, v4, v1
100000ea8:     	ushr.4s	v4, v4, #0x1
100000eac:     	cmeq.4s	v5, v5, #0
100000eb0:     	eor.16b	v6, v4, v2
100000eb4:     	bif.16b	v4, v6, v5
100000eb8:     	and.16b	v5, v4, v1
100000ebc:     	cmeq.4s	v5, v5, #0
100000ec0:     	ushr.4s	v4, v4, #0x1
100000ec4:     	eor.16b	v6, v4, v2
100000ec8:     	bif.16b	v4, v6, v5
100000ecc:     	str	q4, [x9, x8]
100000ed0:     	add.4s	v0, v0, v3
100000ed4:     	add	x8, x8, #0x10
100000ed8:     	cmp	x8, #0x400
100000edc:     	b.ne	0x100000e2c <_crc32_make_table+0x28>
100000ee0:     	ret

0000000100000ee4 <_crc32_buf>:
100000ee4:     	cbz	x1, 0x100000f18 <_crc32_buf+0x34>
100000ee8:     	mov	w8, #-0x1               ; =-1
100000eec:     	adrp	x9, 0x100008000 <_crc_table>
100000ef0:     	add	x9, x9, #0x0
100000ef4:     	ldrb	w10, [x0], #0x1
100000ef8:     	eor	w10, w10, w8
100000efc:     	and	x10, x10, #0xff
100000f00:     	ldr	w10, [x9, x10, lsl #2]
100000f04:     	eor	w8, w10, w8, lsr #8
100000f08:     	subs	x1, x1, #0x1
100000f0c:     	b.ne	0x100000ef4 <_crc32_buf+0x10>
100000f10:     	mvn	w0, w8
100000f14:     	ret
100000f18:     	mov	w0, #0x0                ; =0
100000f1c:     	ret

0000000100000f20 <_tea_encrypt>:
100000f20:     	mov	w8, #0x79b9             ; =31161
100000f24:     	movk	w8, #0x9e37, lsl #16
100000f28:     	ldp	w9, w10, [x0]
100000f2c:     	ldp	w11, w12, [x1]
100000f30:     	mov	w13, #0x20              ; =32
100000f34:     	mov	w14, #0x79b9            ; =31161
100000f38:     	movk	w14, #0x9e37, lsl #16
100000f3c:     	ldp	w15, w16, [x1, #0x8]
100000f40:     	add	w17, w11, w10, lsl #4
100000f44:     	add	w1, w10, w14
100000f48:     	eor	w17, w17, w1
100000f4c:     	add	w1, w12, w10, lsr #5
100000f50:     	eor	w17, w17, w1
100000f54:     	add	w9, w17, w9
100000f58:     	add	w17, w14, w9
100000f5c:     	add	w1, w15, w9, lsl #4
100000f60:     	eor	w17, w1, w17
100000f64:     	add	w1, w16, w9, lsr #5
100000f68:     	eor	w17, w17, w1
100000f6c:     	add	w10, w17, w10
100000f70:     	add	w14, w14, w8
100000f74:     	subs	w13, w13, #0x1
100000f78:     	b.ne	0x100000f40 <_tea_encrypt+0x20>
100000f7c:     	stp	w9, w10, [x0]
100000f80:     	ret

0000000100000f84 <_main>:
100000f84:     	stp	x28, x27, [sp, #-0x60]!
100000f88:     	stp	x26, x25, [sp, #0x10]
100000f8c:     	stp	x24, x23, [sp, #0x20]
100000f90:     	stp	x22, x21, [sp, #0x30]
100000f94:     	stp	x20, x19, [sp, #0x40]
100000f98:     	stp	x29, x30, [sp, #0x50]
100000f9c:     	add	x29, sp, #0x50
100000fa0:     	sub	sp, sp, #0x650
100000fa4:     	mov	x21, x1
100000fa8:     	mov	x22, x0
100000fac:     	add	x23, sp, #0xb0
100000fb0:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000fb4:     	ldr	x8, [x8, #0x10]
100000fb8:     	ldr	x8, [x8]
100000fbc:     	stur	x8, [x29, #-0x68]
100000fc0:     	mov	w19, #0x3               ; =3
100000fc4:     	cmp	w0, #0x2
100000fc8:     	b.lt	0x100000fec <_main+0x68>
100000fcc:     	ldr	x0, [x21, #0x8]
100000fd0:     	bl	0x100001550 <_strncmp+0x100001550>
100000fd4:     	mov	x20, x0
100000fd8:     	cmp	w22, #0x2
100000fdc:     	b.ne	0x100000ffc <_main+0x78>
100000fe0:     	adrp	x24, 0x100001000 <_main+0x7c>
100000fe4:     	add	x24, x24, #0x888
100000fe8:     	b	0x100001000 <_main+0x7c>
100000fec:     	adrp	x24, 0x100001000 <_main+0x7c>
100000ff0:     	add	x24, x24, #0x888
100000ff4:     	mov	w20, #0x3               ; =3
100000ff8:     	b	0x100001000 <_main+0x7c>
100000ffc:     	ldr	x24, [x21, #0x10]
100001000:     	scvtf	s0, w20
100001004:     	dup.4s	v0, v0[0]
100001008:     	dup.4s	v3, w20
10000100c:     	adrp	x8, 0x100001000 <_main+0x7c>
100001010:     	ldr	q1, [x8, #0x650]
100001014:     	eor.16b	v2, v3, v1
100001018:     	adrp	x8, 0x100001000 <_main+0x7c>
10000101c:     	ldr	q4, [x8, #0x660]
100001020:     	eor.16b	v5, v3, v4
100001024:     	adrp	x8, 0x100001000 <_main+0x7c>
100001028:     	ldr	q6, [x8, #0x670]
10000102c:     	eor.16b	v7, v3, v6
100001030:     	adrp	x8, 0x100001000 <_main+0x7c>
100001034:     	ldr	q16, [x8, #0x680]
100001038:     	eor.16b	v17, v3, v16
10000103c:     	stp	q5, q7, [x23, #0x310]
100001040:     	add.4s	v1, v3, v1
100001044:     	add.4s	v4, v3, v4
100001048:     	add.4s	v5, v3, v6
10000104c:     	add.4s	v6, v3, v16
100001050:     	stp	q4, q5, [x23, #0x210]
100001054:     	adrp	x8, 0x100001000 <_main+0x7c>
100001058:     	ldr	q4, [x8, #0x6a0]
10000105c:     	adrp	x8, 0x100001000 <_main+0x7c>
100001060:     	ldr	q5, [x8, #0x6b0]
100001064:     	stp	q4, q5, [x23, #0x110]
100001068:     	adrp	x8, 0x100001000 <_main+0x7c>
10000106c:     	ldr	q4, [x8, #0x6c0]
100001070:     	adrp	x8, 0x100001000 <_main+0x7c>
100001074:     	ldr	q5, [x8, #0x6d0]
100001078:     	eor.16b	v7, v3, v5
10000107c:     	adrp	x8, 0x100001000 <_main+0x7c>
100001080:     	ldr	q16, [x8, #0x6e0]
100001084:     	eor.16b	v18, v3, v16
100001088:     	adrp	x8, 0x100001000 <_main+0x7c>
10000108c:     	ldr	q19, [x8, #0x6f0]
100001090:     	eor.16b	v20, v3, v19
100001094:     	adrp	x8, 0x100001000 <_main+0x7c>
100001098:     	ldr	q21, [x8, #0x700]
10000109c:     	eor.16b	v22, v3, v21
1000010a0:     	stp	q17, q7, [x23, #0x330]
1000010a4:     	stp	q18, q20, [x23, #0x350]
1000010a8:     	add.4s	v5, v3, v5
1000010ac:     	add.4s	v7, v3, v16
1000010b0:     	add.4s	v16, v3, v19
1000010b4:     	add.4s	v17, v3, v21
1000010b8:     	stp	q6, q5, [x23, #0x230]
1000010bc:     	stp	q7, q16, [x23, #0x250]
1000010c0:     	adrp	x8, 0x100001000 <_main+0x7c>
1000010c4:     	ldr	q5, [x8, #0x710]
1000010c8:     	stp	q4, q5, [x23, #0x130]
1000010cc:     	adrp	x8, 0x100001000 <_main+0x7c>
1000010d0:     	ldr	q4, [x8, #0x720]
1000010d4:     	adrp	x8, 0x100001000 <_main+0x7c>
1000010d8:     	ldr	q5, [x8, #0x730]
1000010dc:     	stp	q4, q5, [x23, #0x150]
1000010e0:     	adrp	x8, 0x100001000 <_main+0x7c>
1000010e4:     	ldr	q4, [x8, #0x740]
1000010e8:     	adrp	x8, 0x100001000 <_main+0x7c>
1000010ec:     	ldr	q5, [x8, #0x750]
1000010f0:     	eor.16b	v6, v3, v5
1000010f4:     	adrp	x8, 0x100001000 <_main+0x7c>
1000010f8:     	ldr	q7, [x8, #0x760]
1000010fc:     	eor.16b	v16, v3, v7
100001100:     	adrp	x8, 0x100001000 <_main+0x7c>
100001104:     	ldr	q18, [x8, #0x770]
100001108:     	eor.16b	v19, v3, v18
10000110c:     	adrp	x8, 0x100001000 <_main+0x7c>
100001110:     	ldr	q20, [x8, #0x780]
100001114:     	stp	q22, q6, [x23, #0x370]
100001118:     	eor.16b	v6, v3, v20
10000111c:     	stp	q16, q19, [x23, #0x390]
100001120:     	add.4s	v5, v3, v5
100001124:     	add.4s	v7, v3, v7
100001128:     	add.4s	v16, v3, v18
10000112c:     	stp	q17, q5, [x23, #0x270]
100001130:     	stp	q7, q16, [x23, #0x290]
100001134:     	adrp	x8, 0x100001000 <_main+0x7c>
100001138:     	ldr	q5, [x8, #0x790]
10000113c:     	stp	q4, q5, [x23, #0x170]
100001140:     	adrp	x8, 0x100001000 <_main+0x7c>
100001144:     	ldr	q4, [x8, #0x7a0]
100001148:     	adrp	x8, 0x100001000 <_main+0x7c>
10000114c:     	ldr	q5, [x8, #0x7b0]
100001150:     	stp	q4, q5, [x23, #0x190]
100001154:     	adrp	x8, 0x100001000 <_main+0x7c>
100001158:     	ldr	q4, [x8, #0x7d0]
10000115c:     	eor.16b	v5, v3, v4
100001160:     	adrp	x8, 0x100001000 <_main+0x7c>
100001164:     	ldr	q7, [x8, #0x7e0]
100001168:     	eor.16b	v16, v3, v7
10000116c:     	adrp	x8, 0x100001000 <_main+0x7c>
100001170:     	ldr	q17, [x8, #0x7f0]
100001174:     	eor.16b	v18, v3, v17
100001178:     	stp	q6, q5, [x23, #0x3b0]
10000117c:     	adrp	x8, 0x100001000 <_main+0x7c>
100001180:     	ldr	q5, [x8, #0x800]
100001184:     	stp	q16, q18, [x23, #0x3d0]
100001188:     	eor.16b	v6, v3, v5
10000118c:     	str	q6, [x23, #0x3f0]
100001190:     	adrp	x8, 0x100001000 <_main+0x7c>
100001194:     	ldr	q6, [x8, #0x690]
100001198:     	stp	q0, q0, [sp, #0xb0]
10000119c:     	stp	q0, q0, [sp, #0xd0]
1000011a0:     	str	q0, [sp, #0xf0]
1000011a4:     	stp	q0, q0, [x23, #0x50]
1000011a8:     	add.4s	v16, v3, v20
1000011ac:     	add.4s	v4, v3, v4
1000011b0:     	add.4s	v7, v3, v7
1000011b4:     	add.4s	v17, v3, v17
1000011b8:     	add.4s	v3, v3, v5
1000011bc:     	adrp	x8, 0x100001000 <_main+0x7c>
1000011c0:     	ldr	q5, [x8, #0x7c0]
1000011c4:     	stp	q0, q0, [x23, #0x70]
1000011c8:     	stp	q0, q0, [x23, #0x90]
1000011cc:     	stp	q16, q4, [x23, #0x2b0]
1000011d0:     	stp	q7, q17, [x23, #0x2d0]
1000011d4:     	stp	q3, q2, [x23, #0x2f0]
1000011d8:     	adrp	x8, 0x100001000 <_main+0x7c>
1000011dc:     	ldr	q2, [x8, #0x810]
1000011e0:     	stp	q5, q2, [x23, #0x1b0]
1000011e4:     	adrp	x8, 0x100001000 <_main+0x7c>
1000011e8:     	ldr	q2, [x8, #0x820]
1000011ec:     	adrp	x8, 0x100001000 <_main+0x7c>
1000011f0:     	ldr	q3, [x8, #0x830]
1000011f4:     	stp	q2, q3, [x23, #0x1d0]
1000011f8:     	adrp	x8, 0x100001000 <_main+0x7c>
1000011fc:     	ldr	q2, [x8, #0x840]
100001200:     	stp	q2, q1, [x23, #0x1f0]
100001204:     	stp	q0, q0, [x23, #0xb0]
100001208:     	stp	q0, q0, [x23, #0xd0]
10000120c:     	stp	q0, q6, [x23, #0xf0]
100001210:     	str	w20, [sp, #0x88]
100001214:     	adrp	x8, 0x100001000 <_main+0x7c>
100001218:     	ldr	d0, [x8, #0x860]
10000121c:     	stur	d0, [sp, #0x8c]
100001220:     	str	w19, [sp, #0x94]
100001224:     	add	x0, sp, #0x78
100001228:     	add	x1, sp, #0x88
10000122c:     	bl	0x100000748 <_copy16>
100001230:     	ldrsw	x8, [sp, #0x84]
100001234:     	str	x8, [sp, #0x68]
100001238:     	mov	x0, x24
10000123c:     	bl	0x100000770 <_strcmp_const>
100001240:     	str	w0, [sp, #0x3c]
100001244:     	mov	x0, x24
100001248:     	bl	0x100000794 <_strncmp_const>
10000124c:     	str	w0, [sp, #0x38]
100001250:     	add	x0, sp, #0x4b8
100001254:     	and	w1, w20, #0x3f
100001258:     	bl	0x1000007bc <_loop_zero>
10000125c:     	mov	x0, x24
100001260:     	bl	0x1000007e4 <_loop_strlen>
100001264:     	str	x0, [sp, #0x60]
100001268:     	add	w8, w20, #0x1
10000126c:     	add	w9, w20, #0x2
100001270:     	stp	x8, x9, [sp, #0x8]
100001274:     	str	x20, [sp]
100001278:     	mov	w0, #0x3                ; =3
10000127c:     	bl	0x100000868 <_sum_va>
100001280:     	str	w0, [sp, #0x5c]
100001284:     	mov	x0, x24
100001288:     	bl	0x1000008b0 <_ssp_copy>
10000128c:     	str	w0, [sp, #0x58]
100001290:     	sub	x0, x29, #0xe8
100001294:     	mov	w1, #0x80               ; =128
100001298:     	mov	x2, x20
10000129c:     	bl	0x100000974 <_fortify_snprintf>
1000012a0:     	str	w0, [sp, #0x54]
1000012a4:     	cmp	w22, #0x4
1000012a8:     	str	x24, [sp, #0x70]
1000012ac:     	b.lt	0x1000012b8 <_main+0x334>
1000012b0:     	ldr	x8, [x21, #0x18]
1000012b4:     	b	0x1000012c0 <_main+0x33c>
1000012b8:     	adrp	x8, 0x100001000 <_main+0x7c>
1000012bc:     	add	x8, x8, #0x8aa
1000012c0:     	str	x8, [sp, #0x28]
1000012c4:     	mov	x8, x20
1000012c8:     	sxtw	x23, w8
1000012cc:     	mov	x0, x20
1000012d0:     	bl	0x100000858 <_make_small>
1000012d4:     	str	x0, [sp, #0x48]
1000012d8:     	mov	x0, x23
1000012dc:     	bl	0x10000082c <_use_big>
1000012e0:     	str	x0, [sp, #0x40]
1000012e4:     	mov	x0, x20
1000012e8:     	bl	0x100000730 <_is_pow2>
1000012ec:     	str	w0, [sp, #0x24]
1000012f0:     	mov	x0, x20
1000012f4:     	mov	x1, x20
1000012f8:     	bl	0x100000724 <_rotl32>
1000012fc:     	str	w0, [sp, #0x20]
100001300:     	mov	x0, x20
100001304:     	bl	0x10000071c <_bswap32_manual>
100001308:     	str	w0, [sp, #0x1c]
10000130c:     	mov	x0, x20
100001310:     	bl	0x100000708 <_popcount_loop>
100001314:     	str	w0, [sp, #0x18]
100001318:     	mov	x0, x20
10000131c:     	mov	w1, #0x0                ; =0
100001320:     	mov	w2, #0x9                ; =9
100001324:     	bl	0x1000006f4 <_sel_clamp>
100001328:     	mov	x27, x0
10000132c:     	mov	x0, x20
100001330:     	bl	0x1000006e8 <_sel_abs>
100001334:     	mov	x28, x0
100001338:     	mov	x0, x20
10000133c:     	mov	w1, #0x5                ; =5
100001340:     	bl	0x1000006dc <_sel_max>
100001344:     	mov	x24, x0
100001348:     	mov	x0, x23
10000134c:     	bl	0x1000006bc <_udiv1000_64>
100001350:     	str	x0, [sp, #0x30]
100001354:     	mov	x0, x20
100001358:     	bl	0x1000006a8 <_sdiv16>
10000135c:     	mov	x23, x0
100001360:     	mov	x0, x20
100001364:     	bl	0x10000068c <_umod10>
100001368:     	mov	x19, x0
10000136c:     	mov	x0, x20
100001370:     	bl	0x10000066c <_sdiv7>
100001374:     	mov	x25, x0
100001378:     	mov	x0, x20
10000137c:     	bl	0x10000064c <_udiv7>
100001380:     	mov	x26, x0
100001384:     	mov	x0, x20
100001388:     	bl	0x100000614 <_sw_bittest>
10000138c:     	mov	x21, x0
100001390:     	mov	x0, x20
100001394:     	bl	0x100000568 <_sw_sparse>
100001398:     	mov	x22, x0
10000139c:     	mov	x0, x20
1000013a0:     	bl	0x100000548 <_sw_dense>
1000013a4:     	add	w8, w19, w23
1000013a8:     	add	w9, w25, w26
1000013ac:     	add	w23, w8, w9
1000013b0:     	add	w8, w22, w21
1000013b4:     	add	w21, w8, w0
1000013b8:     	ldr	w8, [sp, #0x18]
1000013bc:     	add	w8, w27, w8
1000013c0:     	add	w9, w28, w24
1000013c4:     	add	w22, w8, w9
1000013c8:     	ldp	w9, w8, [sp, #0x20]
1000013cc:     	add	w8, w9, w8
1000013d0:     	ldr	w9, [sp, #0x1c]
1000013d4:     	add	w25, w8, w9
1000013d8:     	ldp	w9, w8, [sp, #0x38]
1000013dc:     	add	w8, w8, w9
1000013e0:     	add	w26, w8, #0x7
1000013e4:     	sub	x1, x29, #0xe8
1000013e8:     	ldr	x0, [sp, #0x28]
1000013ec:     	mov	w2, #0x80               ; =128
1000013f0:     	bl	0x10000099c <_read_file_head>
1000013f4:     	mov	x24, x0
1000013f8:     	mov	x0, x20
1000013fc:     	bl	0x100000a90 <_tail_caller>
100001400:     	mov	x19, x0
100001404:     	ldr	x20, [sp, #0x70]
100001408:     	mov	x0, x20
10000140c:     	bl	0x100000a98 <_tail_ext>
100001410:     	add	w27, w0, w19
100001414:     	add	x0, sp, #0x4b8
100001418:     	add	x1, sp, #0x3b0
10000141c:     	add	x2, sp, #0x2b0
100001420:     	mov	w3, #0x40               ; =64
100001424:     	bl	0x100000aa0 <_vadd>
100001428:     	add	x0, sp, #0x4b8
10000142c:     	mov	w1, #0x40               ; =64
100001430:     	bl	0x100000b8c <_vsum>
100001434:     	mov	x19, x0
100001438:     	add	x0, sp, #0x1b0
10000143c:     	add	x1, sp, #0xb0
100001440:     	mov	w2, #0x40               ; =64
100001444:     	bl	0x100000c84 <_vdot>
100001448:     	fcvtzs	x28, s0
10000144c:     	add	x0, sp, #0xa0
100001450:     	bl	0x100000df4 <_md5_init>
100001454:     	bl	0x100000e04 <_crc32_make_table>
100001458:     	mov	x0, x20
10000145c:     	bl	0x1000015f8 <_strncmp+0x1000015f8>
100001460:     	mov	x1, x0
100001464:     	mov	x0, x20
100001468:     	bl	0x100000ee4 <_crc32_buf>
10000146c:     	mov	x20, x0
100001470:     	ldr	d0, [sp, #0xa0]
100001474:     	str	d0, [sp, #0x98]
100001478:     	adrp	x1, 0x100001000 <_main+0x7c>
10000147c:     	add	x1, x1, #0x850
100001480:     	add	x0, sp, #0x98
100001484:     	bl	0x100000f20 <_tea_encrypt>
100001488:     	ldr	w8, [sp, #0x98]
10000148c:     	ldp	x10, x9, [sp, #0x60]
100001490:     	add	x9, x9, x10
100001494:     	add	x9, x26, x9
100001498:     	ldp	w10, w11, [sp, #0x58]
10000149c:     	add	x9, x9, w11, sxtw
1000014a0:     	add	x9, x9, w10, sxtw
1000014a4:     	ldr	w10, [sp, #0x54]
1000014a8:     	add	x9, x9, w10, sxtw
1000014ac:     	ldp	x10, x11, [sp, #0x40]
1000014b0:     	add	x9, x9, x11, asr #32
1000014b4:     	add	x10, x10, x25
1000014b8:     	ldr	x11, [sp, #0x30]
1000014bc:     	add	x10, x10, x11
1000014c0:     	add	x9, x9, x10
1000014c4:     	add	x9, x9, w22, sxtw
1000014c8:     	add	x9, x9, x23
1000014cc:     	add	x9, x9, w24, sxtw
1000014d0:     	add	x9, x9, w21, sxtw
1000014d4:     	add	x9, x9, w27, sxtw
1000014d8:     	add	x9, x9, w19, sxtw
1000014dc:     	add	x9, x9, x28
1000014e0:     	add	x9, x9, w20, uxtw
1000014e4:     	add	x8, x9, x8
1000014e8:     	str	x8, [sp]
1000014ec:     	adrp	x0, 0x100001000 <_main+0x7c>
1000014f0:     	add	x0, x0, #0x8b5
1000014f4:     	bl	0x1000015b0 <_strncmp+0x1000015b0>
1000014f8:     	ldur	x8, [x29, #-0x68]
1000014fc:     	adrp	x9, 0x100004000 <_strncmp+0x100004000>
100001500:     	ldr	x9, [x9, #0x10]
100001504:     	ldr	x9, [x9]
100001508:     	cmp	x9, x8
10000150c:     	b.ne	0x100001534 <_main+0x5b0>
100001510:     	mov	w0, #0x0                ; =0
100001514:     	add	sp, sp, #0x650
100001518:     	ldp	x29, x30, [sp, #0x50]
10000151c:     	ldp	x20, x19, [sp, #0x40]
100001520:     	ldp	x22, x21, [sp, #0x30]
100001524:     	ldp	x24, x23, [sp, #0x20]
100001528:     	ldp	x26, x25, [sp, #0x10]
10000152c:     	ldp	x28, x27, [sp], #0x60
100001530:     	ret
100001534:     	bl	0x100001544 <_strncmp+0x100001544>

Disassembly of section __TEXT,__stubs:

0000000100001538 <__stubs>:
100001538:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000153c:     	ldr	x16, [x16]
100001540:     	br	x16
100001544:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001548:     	ldr	x16, [x16, #0x8]
10000154c:     	br	x16
100001550:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001554:     	ldr	x16, [x16, #0x20]
100001558:     	br	x16
10000155c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001560:     	ldr	x16, [x16, #0x28]
100001564:     	br	x16
100001568:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000156c:     	ldr	x16, [x16, #0x30]
100001570:     	br	x16
100001574:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001578:     	ldr	x16, [x16, #0x38]
10000157c:     	br	x16
100001580:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001584:     	ldr	x16, [x16, #0x40]
100001588:     	br	x16
10000158c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001590:     	ldr	x16, [x16, #0x48]
100001594:     	br	x16
100001598:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000159c:     	ldr	x16, [x16, #0x50]
1000015a0:     	br	x16
1000015a4:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015a8:     	ldr	x16, [x16, #0x58]
1000015ac:     	br	x16
1000015b0:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015b4:     	ldr	x16, [x16, #0x60]
1000015b8:     	br	x16
1000015bc:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015c0:     	ldr	x16, [x16, #0x68]
1000015c4:     	br	x16
1000015c8:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015cc:     	ldr	x16, [x16, #0x70]
1000015d0:     	br	x16
1000015d4:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015d8:     	ldr	x16, [x16, #0x78]
1000015dc:     	br	x16
1000015e0:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015e4:     	ldr	x16, [x16, #0x80]
1000015e8:     	br	x16
1000015ec:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015f0:     	ldr	x16, [x16, #0x88]
1000015f4:     	br	x16
1000015f8:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015fc:     	ldr	x16, [x16, #0x90]
100001600:     	br	x16
100001604:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001608:     	ldr	x16, [x16, #0x98]
10000160c:     	br	x16
