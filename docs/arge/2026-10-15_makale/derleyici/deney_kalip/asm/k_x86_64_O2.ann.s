
bin/k_x86_64_O2:	file format mach-o 64-bit x86-64

Disassembly of section __TEXT,__text:

0000000100000560 <_sw_dense>:
100000560:     	pushq	%rbp
100000561:     	movq	%rsp, %rbp
100000564:     	movl	$0xffffffff, %eax       ## imm = 0xFFFFFFFF
100000569:     	cmpl	$0x7, %edi
10000056c:     	ja	0x10000057a <_sw_dense+0x1a>
10000056e:     	movl	%edi, %eax
100000570:     	leaq	0x15e9(%rip), %rcx      ## 0x100001b60 <_strncmp+0x100001b60>
100000577:     	movl	(%rcx,%rax,4), %eax
10000057a:     	popq	%rbp
10000057b:     	retq
10000057c:     	nopl	(%rax)

0000000100000580 <_sw_sparse>:
100000580:     	pushq	%rbp
100000581:     	movq	%rsp, %rbp
100000584:     	cmpl	$0x1387, %edi           ## imm = 0x1387
10000058a:     	jle	0x1000005ab <_sw_sparse+0x2b>
10000058c:     	cmpl	$0x12fd0, %edi          ## imm = 0x12FD0
100000592:     	jg	0x1000005c4 <_sw_sparse+0x44>
100000594:     	cmpl	$0x1388, %edi           ## imm = 0x1388
10000059a:     	je	0x1000005e6 <_sw_sparse+0x66>
10000059c:     	cmpl	$0x4e20, %edi           ## imm = 0x4E20
1000005a2:     	jne	0x1000005e2 <_sw_sparse+0x62>
1000005a4:     	movl	$0x5, %eax
1000005a9:     	popq	%rbp
1000005aa:     	retq
1000005ab:     	cmpl	$0x3, %edi
1000005ae:     	je	0x1000005db <_sw_sparse+0x5b>
1000005b0:     	cmpl	$0x64, %edi
1000005b3:     	je	0x1000005f4 <_sw_sparse+0x74>
1000005b5:     	cmpl	$0x3e8, %edi            ## imm = 0x3E8
1000005bb:     	jne	0x1000005e2 <_sw_sparse+0x62>
1000005bd:     	movl	$0x3, %eax
1000005c2:     	popq	%rbp
1000005c3:     	retq
1000005c4:     	cmpl	$0x12fd1, %edi          ## imm = 0x12FD1
1000005ca:     	je	0x1000005ed <_sw_sparse+0x6d>
1000005cc:     	cmpl	$0x1e240, %edi          ## imm = 0x1E240
1000005d2:     	jne	0x1000005e2 <_sw_sparse+0x62>
1000005d4:     	movl	$0x7, %eax
1000005d9:     	popq	%rbp
1000005da:     	retq
1000005db:     	movl	$0x1, %eax
1000005e0:     	popq	%rbp
1000005e1:     	retq
1000005e2:     	xorl	%eax, %eax
1000005e4:     	popq	%rbp
1000005e5:     	retq
1000005e6:     	movl	$0x4, %eax
1000005eb:     	popq	%rbp
1000005ec:     	retq
1000005ed:     	movl	$0x6, %eax
1000005f2:     	popq	%rbp
1000005f3:     	retq
1000005f4:     	movl	$0x2, %eax
1000005f9:     	popq	%rbp
1000005fa:     	retq
1000005fb:     	nopl	(%rax,%rax)

0000000100000600 <_sw_bittest>:
100000600:     	pushq	%rbp
100000601:     	movq	%rsp, %rbp
100000604:     	cmpl	$0x3b, %edi
100000607:     	ja	0x100000622 <_sw_bittest+0x22>
100000609:     	movl	$0x1, %eax
10000060e:     	movl	%edi, %ecx
100000610:     	movabsq	$0x800100100003e00, %rdx ## imm = 0x800100100003E00
10000061a:     	btq	%rcx, %rdx
10000061e:     	jae	0x100000622 <_sw_bittest+0x22>
100000620:     	popq	%rbp
100000621:     	retq
100000622:     	xorl	%eax, %eax
100000624:     	popq	%rbp
100000625:     	retq
100000626:     	nopw	%cs:(%rax,%rax)

0000000100000630 <_udiv7>:
100000630:     	pushq	%rbp
100000631:     	movq	%rsp, %rbp
100000634:     	movl	%edi, %eax
100000636:     	imulq	$0x24924925, %rax, %rax ## imm = 0x24924925
10000063d:     	shrq	$0x20, %rax
100000641:     	subl	%eax, %edi
100000643:     	shrl	%edi
100000645:     	addl	%edi, %eax
100000647:     	shrl	$0x2, %eax
10000064a:     	popq	%rbp
10000064b:     	retq
10000064c:     	nopl	(%rax)

0000000100000650 <_sdiv7>:
100000650:     	pushq	%rbp
100000651:     	movq	%rsp, %rbp
100000654:     	movslq	%edi, %rax
100000657:     	imulq	$-0x6db6db6d, %rax, %rcx ## imm = 0x92492493
10000065e:     	shrq	$0x20, %rcx
100000662:     	addl	%ecx, %eax
100000664:     	movl	%eax, %ecx
100000666:     	shrl	$0x1f, %ecx
100000669:     	sarl	$0x2, %eax
10000066c:     	addl	%ecx, %eax
10000066e:     	popq	%rbp
10000066f:     	retq

0000000100000670 <_umod10>:
100000670:     	pushq	%rbp
100000671:     	movq	%rsp, %rbp
100000674:     	movl	%edi, %eax
100000676:     	movl	%edi, %ecx
100000678:     	movl	$0xcccccccd, %edx       ## imm = 0xCCCCCCCD
10000067d:     	imulq	%rcx, %rdx
100000681:     	shrq	$0x23, %rdx
100000685:     	addl	%edx, %edx
100000687:     	leal	(%rdx,%rdx,4), %ecx
10000068a:     	subl	%ecx, %eax
10000068c:     	popq	%rbp
10000068d:     	retq
10000068e:     	nop

0000000100000690 <_sdiv16>:
100000690:     	pushq	%rbp
100000691:     	movq	%rsp, %rbp
100000694:     	leal	0xf(%rdi), %eax
100000697:     	testl	%edi, %edi
100000699:     	cmovnsl	%edi, %eax
10000069c:     	sarl	$0x4, %eax
10000069f:     	popq	%rbp
1000006a0:     	retq
1000006a1:     	nopw	%cs:(%rax,%rax)

00000001000006b0 <_udiv1000_64>:
1000006b0:     	pushq	%rbp
1000006b1:     	movq	%rsp, %rbp
1000006b4:     	movq	%rdi, %rax
1000006b7:     	shrq	$0x3, %rax
1000006bb:     	movabsq	$0x20c49ba5e353f7cf, %rcx ## imm = 0x20C49BA5E353F7CF
1000006c5:     	mulq	%rcx
1000006c8:     	movq	%rdx, %rax
1000006cb:     	shrq	$0x4, %rax
1000006cf:     	popq	%rbp
1000006d0:     	retq
1000006d1:     	nopw	%cs:(%rax,%rax)

00000001000006e0 <_sel_max>:
1000006e0:     	pushq	%rbp
1000006e1:     	movq	%rsp, %rbp
1000006e4:     	movl	%esi, %eax
1000006e6:     	cmpl	%esi, %edi
1000006e8:     	cmovgl	%edi, %eax
1000006eb:     	popq	%rbp
1000006ec:     	retq
1000006ed:     	nopl	(%rax)

00000001000006f0 <_sel_abs>:
1000006f0:     	pushq	%rbp
1000006f1:     	movq	%rsp, %rbp
1000006f4:     	movl	%edi, %eax
1000006f6:     	negl	%eax
1000006f8:     	cmovsl	%edi, %eax
1000006fb:     	popq	%rbp
1000006fc:     	retq
1000006fd:     	nopl	(%rax)

0000000100000700 <_sel_clamp>:
100000700:     	pushq	%rbp
100000701:     	movq	%rsp, %rbp
100000704:     	movl	%edx, %eax
100000706:     	cmpl	%edx, %edi
100000708:     	cmovll	%edi, %eax
10000070b:     	cmpl	%esi, %edi
10000070d:     	cmovll	%esi, %eax
100000710:     	popq	%rbp
100000711:     	retq
100000712:     	nopw	%cs:(%rax,%rax)

0000000100000720 <_popcount_loop>:
100000720:     	pushq	%rbp
100000721:     	movq	%rsp, %rbp
100000724:     	xorl	%eax, %eax
100000726:     	testl	%edi, %edi
100000728:     	je	0x10000073b <_popcount_loop+0x1b>
10000072a:     	nopw	(%rax,%rax)
100000730:     	leal	-0x1(%rdi), %ecx
100000733:     	incl	%eax
100000735:     	andl	%edi, %ecx
100000737:     	movl	%ecx, %edi
100000739:     	jne	0x100000730 <_popcount_loop+0x10>
10000073b:     	popq	%rbp
10000073c:     	retq
10000073d:     	nopl	(%rax)

0000000100000740 <_bswap32_manual>:
100000740:     	pushq	%rbp
100000741:     	movq	%rsp, %rbp
100000744:     	movl	%edi, %eax
100000746:     	bswapl	%eax
100000748:     	popq	%rbp
100000749:     	retq
10000074a:     	nopw	(%rax,%rax)

0000000100000750 <_rotl32>:
100000750:     	pushq	%rbp
100000751:     	movq	%rsp, %rbp
100000754:     	movl	%esi, %ecx
100000756:     	movl	%edi, %eax
100000758:     	roll	%cl, %eax
10000075a:     	popq	%rbp
10000075b:     	retq
10000075c:     	nopl	(%rax)

0000000100000760 <_is_pow2>:
100000760:     	pushq	%rbp
100000761:     	movq	%rsp, %rbp
100000764:     	testl	%edi, %edi
100000766:     	je	0x100000774 <_is_pow2+0x14>
100000768:     	leal	-0x1(%rdi), %ecx
10000076b:     	xorl	%eax, %eax
10000076d:     	testl	%ecx, %edi
10000076f:     	sete	%al
100000772:     	popq	%rbp
100000773:     	retq
100000774:     	xorl	%eax, %eax
100000776:     	popq	%rbp
100000777:     	retq
100000778:     	nopl	(%rax,%rax)

0000000100000780 <_copy16>:
100000780:     	pushq	%rbp
100000781:     	movq	%rsp, %rbp
100000784:     	movups	(%rsi), %xmm0
100000787:     	movups	%xmm0, (%rdi)
10000078a:     	popq	%rbp
10000078b:     	retq
10000078c:     	nopl	(%rax)

0000000100000790 <_zero64>:
100000790:     	pushq	%rbp
100000791:     	movq	%rsp, %rbp
100000794:     	xorps	%xmm0, %xmm0
100000797:     	movups	%xmm0, 0x30(%rdi)
10000079b:     	movups	%xmm0, 0x20(%rdi)
10000079f:     	movups	%xmm0, 0x10(%rdi)
1000007a3:     	movups	%xmm0, (%rdi)
1000007a6:     	popq	%rbp
1000007a7:     	retq
1000007a8:     	nopl	(%rax,%rax)

00000001000007b0 <_zero_n>:
1000007b0:     	pushq	%rbp
1000007b1:     	movq	%rsp, %rbp
1000007b4:     	popq	%rbp
1000007b5:     	jmp	0x10000187c <___bzero@stub>
1000007ba:     	nopw	(%rax,%rax)

00000001000007c0 <_strlen_const>:
1000007c0:     	pushq	%rbp
1000007c1:     	movq	%rsp, %rbp
1000007c4:     	movl	$0x7, %eax
1000007c9:     	popq	%rbp
1000007ca:     	retq
1000007cb:     	nopl	(%rax,%rax)

00000001000007d0 <_strcmp_const>:
1000007d0:     	pushq	%rbp
1000007d1:     	movq	%rsp, %rbp
1000007d4:     	leaq	0x13a5(%rip), %rsi      ## 0x100001b80 <_strncmp+0x100001b80>
1000007db:     	callq	0x1000018d6 <_strcmp@stub>
1000007e0:     	xorl	%ecx, %ecx
1000007e2:     	testl	%eax, %eax
1000007e4:     	sete	%cl
1000007e7:     	movl	%ecx, %eax
1000007e9:     	popq	%rbp
1000007ea:     	retq
1000007eb:     	nopl	(%rax,%rax)

00000001000007f0 <_strncmp_const>:
1000007f0:     	pushq	%rbp
1000007f1:     	movq	%rsp, %rbp
1000007f4:     	leaq	0x1389(%rip), %rsi      ## 0x100001b84 <_strncmp+0x100001b84>
1000007fb:     	movl	$0x7, %edx
100000800:     	callq	0x1000018e8 <_strncmp@stub>
100000805:     	xorl	%ecx, %ecx
100000807:     	testl	%eax, %eax
100000809:     	sete	%cl
10000080c:     	movl	%ecx, %eax
10000080e:     	popq	%rbp
10000080f:     	retq

0000000100000810 <_loop_zero>:
100000810:     	pushq	%rbp
100000811:     	movq	%rsp, %rbp
100000814:     	testl	%esi, %esi
100000816:     	jle	0x100000824 <_loop_zero+0x14>
100000818:     	movl	%esi, %esi
10000081a:     	shlq	$0x2, %rsi
10000081e:     	popq	%rbp
10000081f:     	jmp	0x10000187c <___bzero@stub>
100000824:     	popq	%rbp
100000825:     	retq
100000826:     	nopw	%cs:(%rax,%rax)

0000000100000830 <_loop_copy>:
100000830:     	pushq	%rbp
100000831:     	movq	%rsp, %rbp
100000834:     	testl	%edx, %edx
100000836:     	jle	0x100000840 <_loop_copy+0x10>
100000838:     	movl	%edx, %edx
10000083a:     	popq	%rbp
10000083b:     	jmp	0x1000018b8 <_memcpy@stub>
100000840:     	popq	%rbp
100000841:     	retq
100000842:     	nopw	%cs:(%rax,%rax)

0000000100000850 <_loop_strlen>:
100000850:     	pushq	%rbp
100000851:     	movq	%rsp, %rbp
100000854:     	popq	%rbp
100000855:     	jmp	0x1000018e2 <_strlen@stub>
10000085a:     	nopw	(%rax,%rax)

0000000100000860 <_make_big>:
100000860:     	pushq	%rbp
100000861:     	movq	%rsp, %rbp
100000864:     	movq	%rdi, %rax
100000867:     	movq	%rsi, (%rdi)
10000086a:     	movq	%rsi, %xmm0
10000086f:     	pshufd	$0x44, %xmm0, %xmm0     ## xmm0 = xmm0[0,1,0,1]
100000874:     	movdqa	0x1074(%rip), %xmm1     ## 0x1000018f0 <_strncmp+0x1000018f0>
10000087c:     	paddq	%xmm0, %xmm1
100000880:     	movdqa	0x1078(%rip), %xmm2     ## 0x100001900 <_strncmp+0x100001900>
100000888:     	paddq	%xmm0, %xmm2
10000088c:     	paddq	0x107c(%rip), %xmm0     ## 0x100001910 <_strncmp+0x100001910>
100000894:     	movdqu	%xmm0, 0x28(%rdi)
100000899:     	movdqu	%xmm2, 0x18(%rdi)
10000089e:     	movdqu	%xmm1, 0x8(%rdi)
1000008a3:     	addq	$0x7, %rsi
1000008a7:     	movq	%rsi, 0x38(%rdi)
1000008ab:     	popq	%rbp
1000008ac:     	retq
1000008ad:     	nopl	(%rax)

00000001000008b0 <_use_big>:
1000008b0:     	pushq	%rbp
1000008b1:     	movq	%rsp, %rbp
1000008b4:     	subq	$0x40, %rsp
1000008b8:     	movq	%rdi, %rsi
1000008bb:     	leaq	-0x40(%rbp), %rdi
1000008bf:     	callq	0x100000860 <_make_big>
1000008c4:     	movq	-0x8(%rbp), %rax
1000008c8:     	addq	-0x28(%rbp), %rax
1000008cc:     	addq	$0x40, %rsp
1000008d0:     	popq	%rbp
1000008d1:     	retq
1000008d2:     	nopw	%cs:(%rax,%rax)

00000001000008e0 <_make_small>:
1000008e0:     	pushq	%rbp
1000008e1:     	movq	%rsp, %rbp
1000008e4:     	leal	(%rdi,%rdi,2), %ecx
1000008e7:     	shlq	$0x20, %rcx
1000008eb:     	movl	%edi, %eax
1000008ed:     	orq	%rcx, %rax
1000008f0:     	popq	%rbp
1000008f1:     	retq
1000008f2:     	nopw	%cs:(%rax,%rax)

0000000100000900 <_sum_va>:
100000900:     	pushq	%rbp
100000901:     	movq	%rsp, %rbp
100000904:     	subq	$0xd0, %rsp
10000090b:     	movq	%rsi, -0xc8(%rbp)
100000912:     	movq	%rdx, -0xc0(%rbp)
100000919:     	movq	%rcx, -0xb8(%rbp)
100000920:     	movq	%r8, -0xb0(%rbp)
100000927:     	movq	%r9, -0xa8(%rbp)
10000092e:     	testb	%al, %al
100000930:     	je	0x100000958 <_sum_va+0x58>
100000932:     	movaps	%xmm0, -0xa0(%rbp)
100000939:     	movaps	%xmm1, -0x90(%rbp)
100000940:     	movaps	%xmm2, -0x80(%rbp)
100000944:     	movaps	%xmm3, -0x70(%rbp)
100000948:     	movaps	%xmm4, -0x60(%rbp)
10000094c:     	movaps	%xmm5, -0x50(%rbp)
100000950:     	movaps	%xmm6, -0x40(%rbp)
100000954:     	movaps	%xmm7, -0x30(%rbp)
100000958:     	movq	0x16c1(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
10000095f:     	movq	(%rax), %rax
100000962:     	movq	%rax, -0x8(%rbp)
100000966:     	leaq	-0xd0(%rbp), %rax
10000096d:     	movq	%rax, -0x10(%rbp)
100000971:     	leaq	0x10(%rbp), %rax
100000975:     	movq	%rax, -0x18(%rbp)
100000979:     	movabsq	$0x3000000008, %rax     ## imm = 0x3000000008
100000983:     	movq	%rax, -0x20(%rbp)
100000987:     	testl	%edi, %edi
100000989:     	jle	0x1000009bc <_sum_va+0xbc>
10000098b:     	movl	-0x20(%rbp), %edx
10000098e:     	movq	-0x10(%rbp), %rcx
100000992:     	movq	-0x18(%rbp), %rsi
100000996:     	cmpl	$0x1, %edi
100000999:     	jne	0x1000009c0 <_sum_va+0xc0>
10000099b:     	xorl	%eax, %eax
10000099d:     	testb	$0x1, %dil
1000009a1:     	je	0x100000a23 <_sum_va+0x123>
1000009a7:     	cmpl	$0x29, %edx
1000009aa:     	jae	0x100000a19 <_sum_va+0x119>
1000009ac:     	movl	%edx, %esi
1000009ae:     	addq	%rsi, %rcx
1000009b1:     	addl	$0x8, %edx
1000009b4:     	movl	%edx, -0x20(%rbp)
1000009b7:     	movq	%rcx, %rsi
1000009ba:     	jmp	0x100000a21 <_sum_va+0x121>
1000009bc:     	xorl	%eax, %eax
1000009be:     	jmp	0x100000a23 <_sum_va+0x123>
1000009c0:     	movl	%edi, %r8d
1000009c3:     	andl	$0x7ffffffe, %r8d       ## imm = 0x7FFFFFFE
1000009ca:     	xorl	%eax, %eax
1000009cc:     	jmp	0x1000009e8 <_sum_va+0xe8>
1000009ce:     	nop
1000009d0:     	movq	%r9, %rsi
1000009d3:     	movl	%edx, %r9d
1000009d6:     	addq	%rcx, %r9
1000009d9:     	addl	$0x8, %edx
1000009dc:     	movl	%edx, -0x20(%rbp)
1000009df:     	addl	(%r9), %eax
1000009e2:     	addl	$-0x2, %r8d
1000009e6:     	je	0x10000099d <_sum_va+0x9d>
1000009e8:     	cmpl	$0x28, %edx
1000009eb:     	ja	0x100000a00 <_sum_va+0x100>
1000009ed:     	movq	%rsi, %r9
1000009f0:     	movl	%edx, %esi
1000009f2:     	addq	%rcx, %rsi
1000009f5:     	addl	$0x8, %edx
1000009f8:     	movl	%edx, -0x20(%rbp)
1000009fb:     	jmp	0x100000a08 <_sum_va+0x108>
1000009fd:     	nopl	(%rax)
100000a00:     	leaq	0x8(%rsi), %r9
100000a04:     	movq	%r9, -0x18(%rbp)
100000a08:     	addl	(%rsi), %eax
100000a0a:     	cmpl	$0x29, %edx
100000a0d:     	jb	0x1000009d0 <_sum_va+0xd0>
100000a0f:     	leaq	0x8(%r9), %rsi
100000a13:     	movq	%rsi, -0x18(%rbp)
100000a17:     	jmp	0x1000009df <_sum_va+0xdf>
100000a19:     	leaq	0x8(%rsi), %rcx
100000a1d:     	movq	%rcx, -0x18(%rbp)
100000a21:     	addl	(%rsi), %eax
100000a23:     	movq	0x15f6(%rip), %rcx      ## 0x100002020 <_strncmp+0x100002020>
100000a2a:     	movq	(%rcx), %rcx
100000a2d:     	cmpq	-0x8(%rbp), %rcx
100000a31:     	jne	0x100000a3c <_sum_va+0x13c>
100000a33:     	addq	$0xd0, %rsp
100000a3a:     	popq	%rbp
100000a3b:     	retq
100000a3c:     	callq	0x10000188e <___stack_chk_fail@stub>
100000a41:     	nopw	%cs:(%rax,%rax)

0000000100000a50 <_ssp_copy>:
100000a50:     	pushq	%rbp
100000a51:     	movq	%rsp, %rbp
100000a54:     	pushq	%rbx
100000a55:     	subq	$0x48, %rsp
100000a59:     	movq	%rdi, %rsi
100000a5c:     	movq	0x15bd(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000a63:     	movq	(%rax), %rax
100000a66:     	movq	%rax, -0x10(%rbp)
100000a6a:     	leaq	-0x50(%rbp), %rbx
100000a6e:     	movl	$0x40, %edx
100000a73:     	movq	%rbx, %rdi
100000a76:     	callq	0x100001894 <___strcpy_chk@stub>
100000a7b:     	movq	%rbx, %rdi
100000a7e:     	callq	0x1000018e2 <_strlen@stub>
100000a83:     	movsbl	-0x4d(%rbp), %ecx
100000a87:     	movq	0x1592(%rip), %rdx      ## 0x100002020 <_strncmp+0x100002020>
100000a8e:     	movq	(%rdx), %rdx
100000a91:     	cmpq	-0x10(%rbp), %rdx
100000a95:     	jne	0x100000aa2 <_ssp_copy+0x52>
100000a97:     	addl	%eax, %ecx
100000a99:     	movl	%ecx, %eax
100000a9b:     	addq	$0x48, %rsp
100000a9f:     	popq	%rbx
100000aa0:     	popq	%rbp
100000aa1:     	retq
100000aa2:     	callq	0x10000188e <___stack_chk_fail@stub>
100000aa7:     	nopw	(%rax,%rax)

0000000100000ab0 <_fortify_memcpy>:
100000ab0:     	pushq	%rbp
100000ab1:     	movq	%rsp, %rbp
100000ab4:     	pushq	%rbx
100000ab5:     	subq	$0x28, %rsp
100000ab9:     	movq	%rdi, %rbx
100000abc:     	movq	0x155d(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000ac3:     	movq	(%rax), %rax
100000ac6:     	movq	%rax, -0x10(%rbp)
100000aca:     	leaq	-0x30(%rbp), %rdi
100000ace:     	movl	$0x20, %ecx
100000ad3:     	callq	0x100001888 <___memcpy_chk@stub>
100000ad8:     	movaps	-0x30(%rbp), %xmm0
100000adc:     	movaps	-0x20(%rbp), %xmm1
100000ae0:     	movups	%xmm0, (%rbx)
100000ae3:     	movups	%xmm1, 0x10(%rbx)
100000ae7:     	movq	0x1532(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000aee:     	movq	(%rax), %rax
100000af1:     	cmpq	-0x10(%rbp), %rax
100000af5:     	jne	0x100000afe <_fortify_memcpy+0x4e>
100000af7:     	addq	$0x28, %rsp
100000afb:     	popq	%rbx
100000afc:     	popq	%rbp
100000afd:     	retq
100000afe:     	callq	0x10000188e <___stack_chk_fail@stub>
100000b03:     	nopw	%cs:(%rax,%rax)

0000000100000b10 <_fortify_snprintf>:
100000b10:     	pushq	%rbp
100000b11:     	movq	%rsp, %rbp
100000b14:     	movl	%edx, %ecx
100000b16:     	leaq	0x106f(%rip), %rdx      ## 0x100001b8c <_strncmp+0x100001b8c>
100000b1d:     	xorl	%eax, %eax
100000b1f:     	popq	%rbp
100000b20:     	jmp	0x1000018d0 <_snprintf@stub>
100000b25:     	nopw	%cs:(%rax,%rax)

0000000100000b30 <_read_file_head>:
100000b30:     	pushq	%rbp
100000b31:     	movq	%rsp, %rbp
100000b34:     	pushq	%r15
100000b36:     	pushq	%r14
100000b38:     	pushq	%r13
100000b3a:     	pushq	%r12
100000b3c:     	pushq	%rbx
100000b3d:     	pushq	%rax
100000b3e:     	movq	%rdx, %r13
100000b41:     	movq	%rsi, %r15
100000b44:     	movq	%rdi, %r14
100000b47:     	movl	$0x1000000, %esi        ## imm = 0x1000000
100000b4c:     	xorl	%eax, %eax
100000b4e:     	callq	0x1000018be <_open@stub>
100000b53:     	testl	%eax, %eax
100000b55:     	js	0x100000b8e <_read_file_head+0x5e>
100000b57:     	movl	%eax, %ebx
100000b59:     	movq	%r13, %rdi
100000b5c:     	callq	0x1000018b2 <_malloc@stub>
100000b61:     	testq	%rax, %rax
100000b64:     	je	0x100000bc3 <_read_file_head+0x93>
100000b66:     	movq	%rax, %r12
100000b69:     	movl	%ebx, %edi
100000b6b:     	movq	%rax, %rsi
100000b6e:     	movq	%r13, %rdx
100000b71:     	callq	0x1000018ca <_read@stub>
100000b76:     	testq	%rax, %rax
100000b79:     	js	0x100000bcb <_read_file_head+0x9b>
100000b7b:     	movq	%rax, %r14
100000b7e:     	movq	%r15, %rdi
100000b81:     	movq	%r12, %rsi
100000b84:     	movq	%rax, %rdx
100000b87:     	callq	0x1000018b8 <_memcpy@stub>
100000b8c:     	jmp	0x100000bdc <_read_file_head+0xac>
100000b8e:     	movq	0x1493(%rip), %rax      ## 0x100002028 <_strncmp+0x100002028>
100000b95:     	movq	(%rax), %rbx
100000b98:     	callq	0x100001882 <___error@stub>
100000b9d:     	movl	(%rax), %edi
100000b9f:     	callq	0x1000018dc <_strerror@stub>
100000ba4:     	leaq	0xfea(%rip), %rsi       ## 0x100001b95 <_strncmp+0x100001b95>
100000bab:     	movq	%rbx, %rdi
100000bae:     	movq	%r14, %rdx
100000bb1:     	movq	%rax, %rcx
100000bb4:     	xorl	%eax, %eax
100000bb6:     	callq	0x1000018a6 <_fprintf@stub>
100000bbb:     	movl	$0xffffffff, %r14d      ## imm = 0xFFFFFFFF
100000bc1:     	jmp	0x100000beb <_read_file_head+0xbb>
100000bc3:     	movl	$0xffffffff, %r14d      ## imm = 0xFFFFFFFF
100000bc9:     	jmp	0x100000be4 <_read_file_head+0xb4>
100000bcb:     	callq	0x100001882 <___error@stub>
100000bd0:     	movl	$0x5, (%rax)
100000bd6:     	movl	$0xffffffff, %r14d      ## imm = 0xFFFFFFFF
100000bdc:     	movq	%r12, %rdi
100000bdf:     	callq	0x1000018ac <_free@stub>
100000be4:     	movl	%ebx, %edi
100000be6:     	callq	0x1000018a0 <_close@stub>
100000beb:     	movl	%r14d, %eax
100000bee:     	addq	$0x8, %rsp
100000bf2:     	popq	%rbx
100000bf3:     	popq	%r12
100000bf5:     	popq	%r13
100000bf7:     	popq	%r14
100000bf9:     	popq	%r15
100000bfb:     	popq	%rbp
100000bfc:     	retq
100000bfd:     	nopl	(%rax)

0000000100000c00 <_tail_target>:
100000c00:     	pushq	%rbp
100000c01:     	movq	%rsp, %rbp
100000c04:     	leal	(%rdi,%rdi,2), %eax
100000c07:     	incl	%eax
100000c09:     	popq	%rbp
100000c0a:     	retq
100000c0b:     	nopl	(%rax,%rax)

0000000100000c10 <_tail_caller>:
100000c10:     	pushq	%rbp
100000c11:     	movq	%rsp, %rbp
100000c14:     	incl	%edi
100000c16:     	popq	%rbp
100000c17:     	jmp	0x100000c00 <_tail_target>
100000c1c:     	nopl	(%rax)

0000000100000c20 <_tail_ext>:
100000c20:     	pushq	%rbp
100000c21:     	movq	%rsp, %rbp
100000c24:     	incq	%rdi
100000c27:     	popq	%rbp
100000c28:     	jmp	0x10000189a <_atoi@stub>
100000c2d:     	nopl	(%rax)

0000000100000c30 <_vadd>:
100000c30:     	pushq	%rbp
100000c31:     	movq	%rsp, %rbp
100000c34:     	testl	%ecx, %ecx
100000c36:     	jle	0x100000cb4 <_vadd+0x84>
100000c38:     	movl	%ecx, %eax
100000c3a:     	cmpl	$0x8, %ecx
100000c3d:     	jae	0x100000c43 <_vadd+0x13>
100000c3f:     	xorl	%ecx, %ecx
100000c41:     	jmp	0x100000ca0 <_vadd+0x70>
100000c43:     	movl	%eax, %ecx
100000c45:     	andl	$0x7ffffff8, %ecx       ## imm = 0x7FFFFFF8
100000c4b:     	movl	%eax, %r8d
100000c4e:     	shrl	$0x3, %r8d
100000c52:     	andl	$0xfffffff, %r8d        ## imm = 0xFFFFFFF
100000c59:     	shlq	$0x5, %r8
100000c5d:     	xorl	%r9d, %r9d
100000c60:     	movdqu	(%rsi,%r9), %xmm0
100000c66:     	movdqu	0x10(%rsi,%r9), %xmm1
100000c6d:     	movdqu	(%rdx,%r9), %xmm2
100000c73:     	paddd	%xmm0, %xmm2
100000c77:     	movdqu	0x10(%rdx,%r9), %xmm0
100000c7e:     	paddd	%xmm1, %xmm0
100000c82:     	movdqu	%xmm2, (%rdi,%r9)
100000c88:     	movdqu	%xmm0, 0x10(%rdi,%r9)
100000c8f:     	addq	$0x20, %r9
100000c93:     	cmpq	%r9, %r8
100000c96:     	jne	0x100000c60 <_vadd+0x30>
100000c98:     	cmpl	%eax, %ecx
100000c9a:     	je	0x100000cb4 <_vadd+0x84>
100000c9c:     	nopl	(%rax)
100000ca0:     	movl	(%rdx,%rcx,4), %r8d
100000ca4:     	addl	(%rsi,%rcx,4), %r8d
100000ca8:     	movl	%r8d, (%rdi,%rcx,4)
100000cac:     	incq	%rcx
100000caf:     	cmpq	%rcx, %rax
100000cb2:     	jne	0x100000ca0 <_vadd+0x70>
100000cb4:     	popq	%rbp
100000cb5:     	retq
100000cb6:     	nopw	%cs:(%rax,%rax)

0000000100000cc0 <_vsum>:
100000cc0:     	pushq	%rbp
100000cc1:     	movq	%rsp, %rbp
100000cc4:     	testl	%esi, %esi
100000cc6:     	jle	0x100000cd5 <_vsum+0x15>
100000cc8:     	movl	%esi, %ecx
100000cca:     	cmpl	$0x8, %esi
100000ccd:     	jae	0x100000cd9 <_vsum+0x19>
100000ccf:     	xorl	%edx, %edx
100000cd1:     	xorl	%eax, %eax
100000cd3:     	jmp	0x100000d40 <_vsum+0x80>
100000cd5:     	xorl	%eax, %eax
100000cd7:     	popq	%rbp
100000cd8:     	retq
100000cd9:     	movl	%ecx, %edx
100000cdb:     	andl	$0x7ffffff8, %edx       ## imm = 0x7FFFFFF8
100000ce1:     	movl	%ecx, %eax
100000ce3:     	shrl	$0x3, %eax
100000ce6:     	andl	$0xfffffff, %eax        ## imm = 0xFFFFFFF
100000ceb:     	shlq	$0x5, %rax
100000cef:     	pxor	%xmm0, %xmm0
100000cf3:     	xorl	%esi, %esi
100000cf5:     	pxor	%xmm1, %xmm1
100000cf9:     	nopl	(%rax)
100000d00:     	movdqu	(%rdi,%rsi), %xmm2
100000d05:     	paddd	%xmm2, %xmm0
100000d09:     	movdqu	0x10(%rdi,%rsi), %xmm2
100000d0f:     	paddd	%xmm2, %xmm1
100000d13:     	addq	$0x20, %rsi
100000d17:     	cmpq	%rsi, %rax
100000d1a:     	jne	0x100000d00 <_vsum+0x40>
100000d1c:     	paddd	%xmm0, %xmm1
100000d20:     	pshufd	$0xee, %xmm1, %xmm0     ## xmm0 = xmm1[2,3,2,3]
100000d25:     	paddd	%xmm1, %xmm0
100000d29:     	pshufd	$0x55, %xmm0, %xmm1     ## xmm1 = xmm0[1,1,1,1]
100000d2e:     	paddd	%xmm0, %xmm1
100000d32:     	movd	%xmm1, %eax
100000d36:     	cmpl	%ecx, %edx
100000d38:     	je	0x100000d4b <_vsum+0x8b>
100000d3a:     	nopw	(%rax,%rax)
100000d40:     	addl	(%rdi,%rdx,4), %eax
100000d43:     	incq	%rdx
100000d46:     	cmpq	%rdx, %rcx
100000d49:     	jne	0x100000d40 <_vsum+0x80>
100000d4b:     	popq	%rbp
100000d4c:     	retq
100000d4d:     	nopl	(%rax)

0000000100000d50 <_vdot>:
100000d50:     	pushq	%rbp
100000d51:     	movq	%rsp, %rbp
100000d54:     	testl	%edx, %edx
100000d56:     	jle	0x100000d6d <_vdot+0x1d>
100000d58:     	movl	%edx, %r8d
100000d5b:     	movl	%r8d, %eax
100000d5e:     	andl	$0x3, %eax
100000d61:     	cmpl	$0x4, %edx
100000d64:     	jae	0x100000d72 <_vdot+0x22>
100000d66:     	xorps	%xmm0, %xmm0
100000d69:     	xorl	%ecx, %ecx
100000d6b:     	jmp	0x100000dc7 <_vdot+0x77>
100000d6d:     	xorps	%xmm0, %xmm0
100000d70:     	popq	%rbp
100000d71:     	retq
100000d72:     	andl	$0x7ffffffc, %r8d       ## imm = 0x7FFFFFFC
100000d79:     	xorps	%xmm0, %xmm0
100000d7c:     	xorl	%ecx, %ecx
100000d7e:     	nop
100000d80:     	movss	(%rdi,%rcx,4), %xmm1
100000d85:     	movss	0x4(%rdi,%rcx,4), %xmm2
100000d8b:     	mulss	(%rsi,%rcx,4), %xmm1
100000d90:     	mulss	0x4(%rsi,%rcx,4), %xmm2
100000d96:     	addss	%xmm0, %xmm1
100000d9a:     	movss	0x8(%rdi,%rcx,4), %xmm3
100000da0:     	mulss	0x8(%rsi,%rcx,4), %xmm3
100000da6:     	addss	%xmm1, %xmm2
100000daa:     	movss	0xc(%rdi,%rcx,4), %xmm0
100000db0:     	mulss	0xc(%rsi,%rcx,4), %xmm0
100000db6:     	addss	%xmm2, %xmm3
100000dba:     	addss	%xmm3, %xmm0
100000dbe:     	addq	$0x4, %rcx
100000dc2:     	cmpq	%rcx, %r8
100000dc5:     	jne	0x100000d80 <_vdot+0x30>
100000dc7:     	testq	%rax, %rax
100000dca:     	je	0x100000df6 <_vdot+0xa6>
100000dcc:     	leaq	(%rsi,%rcx,4), %rdx
100000dd0:     	leaq	(%rdi,%rcx,4), %rcx
100000dd4:     	xorl	%esi, %esi
100000dd6:     	nopw	%cs:(%rax,%rax)
100000de0:     	movss	(%rcx,%rsi,4), %xmm1
100000de5:     	mulss	(%rdx,%rsi,4), %xmm1
100000dea:     	addss	%xmm1, %xmm0
100000dee:     	incq	%rsi
100000df1:     	cmpq	%rsi, %rax
100000df4:     	jne	0x100000de0 <_vdot+0x90>
100000df6:     	popq	%rbp
100000df7:     	retq
100000df8:     	nopl	(%rax,%rax)

0000000100000e00 <_md5_init>:
100000e00:     	pushq	%rbp
100000e01:     	movq	%rsp, %rbp
100000e04:     	movaps	0xb15(%rip), %xmm0      ## 0x100001920 <_strncmp+0x100001920>
100000e0b:     	movups	%xmm0, (%rdi)
100000e0e:     	popq	%rbp
100000e0f:     	retq

0000000100000e10 <_crc32_make_table>:
100000e10:     	pushq	%rbp
100000e11:     	movq	%rsp, %rbp
100000e14:     	movdqa	0xb14(%rip), %xmm3      ## 0x100001930 <_strncmp+0x100001930>
100000e1c:     	xorl	%eax, %eax
100000e1e:     	movdqa	0xb1a(%rip), %xmm4      ## 0x100001940 <_strncmp+0x100001940>
100000e26:     	leaq	0x21d3(%rip), %rcx      ## 0x100003000 <_crc_table>
100000e2d:     	movdqa	0xb1b(%rip), %xmm5      ## 0x100001950 <_strncmp+0x100001950>
100000e35:     	nopw	%cs:(%rax,%rax)
100000e40:     	movdqa	%xmm3, %xmm1
100000e44:     	psrld	$0x1, %xmm1
100000e49:     	movdqa	%xmm1, %xmm2
100000e4d:     	movdqa	%xmm3, %xmm0
100000e51:     	pxor	%xmm4, %xmm2
100000e55:     	pslld	$0x1f, %xmm0
100000e5a:     	blendvps	%xmm0, %xmm2, %xmm1
100000e5f:     	movaps	%xmm1, %xmm2
100000e62:     	psrld	$0x1, %xmm2
100000e67:     	movdqa	%xmm2, %xmm6
100000e6b:     	pxor	%xmm4, %xmm6
100000e6f:     	pslld	$0x1f, %xmm1
100000e74:     	movdqa	%xmm1, %xmm0
100000e78:     	blendvps	%xmm0, %xmm6, %xmm2
100000e7d:     	movaps	%xmm2, %xmm1
100000e80:     	psrld	$0x1, %xmm1
100000e85:     	movdqa	%xmm1, %xmm6
100000e89:     	pxor	%xmm4, %xmm6
100000e8d:     	pslld	$0x1f, %xmm2
100000e92:     	movdqa	%xmm2, %xmm0
100000e96:     	blendvps	%xmm0, %xmm6, %xmm1
100000e9b:     	movaps	%xmm1, %xmm2
100000e9e:     	psrld	$0x1, %xmm2
100000ea3:     	movdqa	%xmm2, %xmm6
100000ea7:     	pxor	%xmm4, %xmm6
100000eab:     	pslld	$0x1f, %xmm1
100000eb0:     	movdqa	%xmm1, %xmm0
100000eb4:     	blendvps	%xmm0, %xmm6, %xmm2
100000eb9:     	movaps	%xmm2, %xmm1
100000ebc:     	psrld	$0x1, %xmm1
100000ec1:     	movdqa	%xmm1, %xmm6
100000ec5:     	pxor	%xmm4, %xmm6
100000ec9:     	pslld	$0x1f, %xmm2
100000ece:     	movdqa	%xmm2, %xmm0
100000ed2:     	blendvps	%xmm0, %xmm6, %xmm1
100000ed7:     	movaps	%xmm1, %xmm2
100000eda:     	psrld	$0x1, %xmm2
100000edf:     	movdqa	%xmm2, %xmm6
100000ee3:     	pxor	%xmm4, %xmm6
100000ee7:     	pslld	$0x1f, %xmm1
100000eec:     	movdqa	%xmm1, %xmm0
100000ef0:     	blendvps	%xmm0, %xmm6, %xmm2
100000ef5:     	movaps	%xmm2, %xmm1
100000ef8:     	psrld	$0x1, %xmm1
100000efd:     	movdqa	%xmm1, %xmm6
100000f01:     	pxor	%xmm4, %xmm6
100000f05:     	pslld	$0x1f, %xmm2
100000f0a:     	movdqa	%xmm2, %xmm0
100000f0e:     	blendvps	%xmm0, %xmm6, %xmm1
100000f13:     	movaps	%xmm1, %xmm2
100000f16:     	psrld	$0x1, %xmm2
100000f1b:     	movdqa	%xmm2, %xmm6
100000f1f:     	pxor	%xmm4, %xmm6
100000f23:     	pslld	$0x1f, %xmm1
100000f28:     	movdqa	%xmm1, %xmm0
100000f2c:     	blendvps	%xmm0, %xmm6, %xmm2
100000f31:     	movaps	%xmm2, (%rax,%rcx)
100000f35:     	paddd	%xmm5, %xmm3
100000f39:     	addq	$0x10, %rax
100000f3d:     	cmpq	$0x400, %rax            ## imm = 0x400
100000f43:     	jne	0x100000e40 <_crc32_make_table+0x30>
100000f49:     	popq	%rbp
100000f4a:     	retq
100000f4b:     	nopl	(%rax,%rax)

0000000100000f50 <_crc32_buf>:
100000f50:     	testq	%rsi, %rsi
100000f53:     	je	0x100000f66 <_crc32_buf+0x16>
100000f55:     	pushq	%rbp
100000f56:     	movq	%rsp, %rbp
100000f59:     	cmpq	$0x1, %rsi
100000f5d:     	jne	0x100000f69 <_crc32_buf+0x19>
100000f5f:     	movl	$0xffffffff, %eax       ## imm = 0xFFFFFFFF
100000f64:     	jmp	0x100000faf <_crc32_buf+0x5f>
100000f66:     	xorl	%eax, %eax
100000f68:     	retq
100000f69:     	movq	%rsi, %rcx
100000f6c:     	andq	$-0x2, %rcx
100000f70:     	movl	$0xffffffff, %eax       ## imm = 0xFFFFFFFF
100000f75:     	leaq	0x2084(%rip), %rdx      ## 0x100003000 <_crc_table>
100000f7c:     	nopl	(%rax)
100000f80:     	movzbl	(%rdi), %r8d
100000f84:     	xorb	%al, %r8b
100000f87:     	movzbl	%r8b, %r8d
100000f8b:     	shrl	$0x8, %eax
100000f8e:     	xorl	(%rdx,%r8,4), %eax
100000f92:     	movzbl	0x1(%rdi), %r8d
100000f97:     	xorb	%al, %r8b
100000f9a:     	addq	$0x2, %rdi
100000f9e:     	movzbl	%r8b, %r8d
100000fa2:     	shrl	$0x8, %eax
100000fa5:     	xorl	(%rdx,%r8,4), %eax
100000fa9:     	addq	$-0x2, %rcx
100000fad:     	jne	0x100000f80 <_crc32_buf+0x30>
100000faf:     	testb	$0x1, %sil
100000fb3:     	je	0x100000fca <_crc32_buf+0x7a>
100000fb5:     	movzbl	(%rdi), %ecx
100000fb8:     	xorb	%al, %cl
100000fba:     	movzbl	%cl, %ecx
100000fbd:     	leaq	0x203c(%rip), %rdx      ## 0x100003000 <_crc_table>
100000fc4:     	shrl	$0x8, %eax
100000fc7:     	xorl	(%rdx,%rcx,4), %eax
100000fca:     	notl	%eax
100000fcc:     	popq	%rbp
100000fcd:     	retq
100000fce:     	nop

0000000100000fd0 <_tea_encrypt>:
100000fd0:     	pushq	%rbp
100000fd1:     	movq	%rsp, %rbp
100000fd4:     	pushq	%r14
100000fd6:     	pushq	%rbx
100000fd7:     	movl	(%rdi), %eax
100000fd9:     	movl	0x4(%rdi), %ebx
100000fdc:     	movl	(%rsi), %ecx
100000fde:     	movl	0x4(%rsi), %edx
100000fe1:     	movl	0x8(%rsi), %r8d
100000fe5:     	movl	0xc(%rsi), %esi
100000fe8:     	movl	$0x20, %r9d
100000fee:     	movl	$0x9e3779b9, %r10d      ## imm = 0x9E3779B9
100000ff4:     	nopw	%cs:(%rax,%rax)
100001000:     	movl	%ebx, %r11d
100001003:     	shll	$0x4, %ebx
100001006:     	addl	%ecx, %ebx
100001008:     	leal	(%r11,%r10), %r14d
10000100c:     	xorl	%ebx, %r14d
10000100f:     	movl	%r11d, %ebx
100001012:     	shrl	$0x5, %ebx
100001015:     	addl	%edx, %ebx
100001017:     	xorl	%r14d, %ebx
10000101a:     	addl	%ebx, %eax
10000101c:     	movl	%eax, %ebx
10000101e:     	shll	$0x4, %ebx
100001021:     	addl	%r8d, %ebx
100001024:     	leal	(%r10,%rax), %r14d
100001028:     	xorl	%ebx, %r14d
10000102b:     	movl	%eax, %ebx
10000102d:     	shrl	$0x5, %ebx
100001030:     	addl	%esi, %ebx
100001032:     	xorl	%r14d, %ebx
100001035:     	addl	%r11d, %ebx
100001038:     	addl	$0x9e3779b9, %r10d      ## imm = 0x9E3779B9
10000103f:     	decl	%r9d
100001042:     	jne	0x100001000 <_tea_encrypt+0x30>
100001044:     	movl	%eax, (%rdi)
100001046:     	movl	%ebx, 0x4(%rdi)
100001049:     	popq	%rbx
10000104a:     	popq	%r14
10000104c:     	popq	%rbp
10000104d:     	retq
10000104e:     	nop

0000000100001050 <_main>:
100001050:     	pushq	%rbp
100001051:     	movq	%rsp, %rbp
100001054:     	pushq	%r15
100001056:     	pushq	%r14
100001058:     	pushq	%r13
10000105a:     	pushq	%r12
10000105c:     	pushq	%rbx
10000105d:     	subq	$0x648, %rsp            ## imm = 0x648
100001064:     	movl	%edi, %r13d
100001067:     	movq	0xfb2(%rip), %rax       ## 0x100002020 <_strncmp+0x100002020>
10000106e:     	movq	(%rax), %rax
100001071:     	movq	%rax, -0x30(%rbp)
100001075:     	leaq	0xb04(%rip), %rax       ## 0x100001b80 <_strncmp+0x100001b80>
10000107c:     	movq	%rax, -0x5d8(%rbp)
100001083:     	movl	$0x3, %eax
100001088:     	cmpl	$0x2, %edi
10000108b:     	movq	%rsi, -0x5f0(%rbp)
100001092:     	jl	0x1000010b1 <_main+0x61>
100001094:     	movq	%rsi, %rbx
100001097:     	movq	0x8(%rsi), %rdi
10000109b:     	callq	0x10000189a <_atoi@stub>
1000010a0:     	cmpl	$0x2, %r13d
1000010a4:     	je	0x1000010b1 <_main+0x61>
1000010a6:     	movq	0x10(%rbx), %rcx
1000010aa:     	movq	%rcx, -0x5d8(%rbp)
1000010b1:     	movslq	%eax, %r14
1000010b4:     	cvtsi2ss	%r14d, %xmm0
1000010b9:     	shufps	$0x0, %xmm0, %xmm0      ## xmm0 = xmm0[0,0,0,0]
1000010bd:     	movd	%r14d, %xmm1
1000010c2:     	pshufd	$0x0, %xmm1, %xmm1      ## xmm1 = xmm1[0,0,0,0]
1000010c7:     	movdqa	0x861(%rip), %xmm2      ## 0x100001930 <_strncmp+0x100001930>
1000010cf:     	movdqa	%xmm1, %xmm3
1000010d3:     	pxor	%xmm2, %xmm3
1000010d7:     	movdqa	0x881(%rip), %xmm4      ## 0x100001960 <_strncmp+0x100001960>
1000010df:     	movdqa	%xmm1, %xmm5
1000010e3:     	pxor	%xmm4, %xmm5
1000010e7:     	movdqa	%xmm3, -0x2b0(%rbp)
1000010ef:     	movdqa	%xmm5, -0x2a0(%rbp)
1000010f7:     	paddd	%xmm1, %xmm2
1000010fb:     	paddd	%xmm1, %xmm4
1000010ff:     	movdqa	%xmm2, -0x3b0(%rbp)
100001107:     	movdqa	%xmm4, -0x3a0(%rbp)
10000110f:     	movaps	0x85a(%rip), %xmm2      ## 0x100001970 <_strncmp+0x100001970>
100001116:     	movaps	%xmm2, -0x4b0(%rbp)
10000111d:     	movaps	0x85c(%rip), %xmm2      ## 0x100001980 <_strncmp+0x100001980>
100001124:     	movaps	%xmm2, -0x4a0(%rbp)
10000112b:     	movaps	%xmm0, -0x5b0(%rbp)
100001132:     	movaps	%xmm0, -0x5a0(%rbp)
100001139:     	movdqa	0x84f(%rip), %xmm2      ## 0x100001990 <_strncmp+0x100001990>
100001141:     	movdqa	%xmm1, %xmm3
100001145:     	pxor	%xmm2, %xmm3
100001149:     	movdqa	0x84f(%rip), %xmm4      ## 0x1000019a0 <_strncmp+0x1000019a0>
100001151:     	movdqa	%xmm1, %xmm5
100001155:     	pxor	%xmm4, %xmm5
100001159:     	movdqa	%xmm3, -0x290(%rbp)
100001161:     	movdqa	%xmm5, -0x280(%rbp)
100001169:     	paddd	%xmm1, %xmm2
10000116d:     	paddd	%xmm1, %xmm4
100001171:     	movdqa	%xmm2, -0x390(%rbp)
100001179:     	movdqa	%xmm4, -0x380(%rbp)
100001181:     	movaps	0x828(%rip), %xmm2      ## 0x1000019b0 <_strncmp+0x1000019b0>
100001188:     	movaps	%xmm2, -0x490(%rbp)
10000118f:     	movaps	0x82a(%rip), %xmm2      ## 0x1000019c0 <_strncmp+0x1000019c0>
100001196:     	movaps	%xmm2, -0x480(%rbp)
10000119d:     	movaps	%xmm0, -0x590(%rbp)
1000011a4:     	movaps	%xmm0, -0x580(%rbp)
1000011ab:     	movdqa	0x81d(%rip), %xmm2      ## 0x1000019d0 <_strncmp+0x1000019d0>
1000011b3:     	movdqa	%xmm1, %xmm3
1000011b7:     	pxor	%xmm2, %xmm3
1000011bb:     	movdqa	0x81d(%rip), %xmm4      ## 0x1000019e0 <_strncmp+0x1000019e0>
1000011c3:     	movdqa	%xmm1, %xmm5
1000011c7:     	pxor	%xmm4, %xmm5
1000011cb:     	movdqa	%xmm3, -0x270(%rbp)
1000011d3:     	movdqa	%xmm5, -0x260(%rbp)
1000011db:     	paddd	%xmm1, %xmm2
1000011df:     	paddd	%xmm1, %xmm4
1000011e3:     	movdqa	%xmm2, -0x370(%rbp)
1000011eb:     	movdqa	%xmm4, -0x360(%rbp)
1000011f3:     	movaps	0x7f6(%rip), %xmm2      ## 0x1000019f0 <_strncmp+0x1000019f0>
1000011fa:     	movaps	%xmm2, -0x470(%rbp)
100001201:     	movaps	0x7f8(%rip), %xmm2      ## 0x100001a00 <_strncmp+0x100001a00>
100001208:     	movaps	%xmm2, -0x460(%rbp)
10000120f:     	movaps	%xmm0, -0x570(%rbp)
100001216:     	movaps	%xmm0, -0x560(%rbp)
10000121d:     	movdqa	0x7eb(%rip), %xmm2      ## 0x100001a10 <_strncmp+0x100001a10>
100001225:     	movdqa	%xmm1, %xmm3
100001229:     	pxor	%xmm2, %xmm3
10000122d:     	movdqa	0x7eb(%rip), %xmm4      ## 0x100001a20 <_strncmp+0x100001a20>
100001235:     	movdqa	%xmm1, %xmm5
100001239:     	pxor	%xmm4, %xmm5
10000123d:     	movdqa	%xmm3, -0x250(%rbp)
100001245:     	movdqa	%xmm5, -0x240(%rbp)
10000124d:     	paddd	%xmm1, %xmm2
100001251:     	paddd	%xmm1, %xmm4
100001255:     	movdqa	%xmm2, -0x350(%rbp)
10000125d:     	movdqa	%xmm4, -0x340(%rbp)
100001265:     	movaps	0x7c4(%rip), %xmm2      ## 0x100001a30 <_strncmp+0x100001a30>
10000126c:     	movaps	%xmm2, -0x450(%rbp)
100001273:     	movaps	0x7c6(%rip), %xmm2      ## 0x100001a40 <_strncmp+0x100001a40>
10000127a:     	movaps	%xmm2, -0x440(%rbp)
100001281:     	movaps	%xmm0, -0x550(%rbp)
100001288:     	movaps	%xmm0, -0x540(%rbp)
10000128f:     	movdqa	0x7b9(%rip), %xmm2      ## 0x100001a50 <_strncmp+0x100001a50>
100001297:     	movdqa	%xmm1, %xmm3
10000129b:     	pxor	%xmm2, %xmm3
10000129f:     	movdqa	0x7b9(%rip), %xmm4      ## 0x100001a60 <_strncmp+0x100001a60>
1000012a7:     	movdqa	%xmm1, %xmm5
1000012ab:     	pxor	%xmm4, %xmm5
1000012af:     	movdqa	%xmm3, -0x230(%rbp)
1000012b7:     	movdqa	%xmm5, -0x220(%rbp)
1000012bf:     	paddd	%xmm1, %xmm2
1000012c3:     	paddd	%xmm1, %xmm4
1000012c7:     	movdqa	%xmm2, -0x330(%rbp)
1000012cf:     	movdqa	%xmm4, -0x320(%rbp)
1000012d7:     	movaps	0x792(%rip), %xmm2      ## 0x100001a70 <_strncmp+0x100001a70>
1000012de:     	movaps	%xmm2, -0x430(%rbp)
1000012e5:     	movaps	0x794(%rip), %xmm2      ## 0x100001a80 <_strncmp+0x100001a80>
1000012ec:     	movaps	%xmm2, -0x420(%rbp)
1000012f3:     	movaps	%xmm0, -0x530(%rbp)
1000012fa:     	movaps	%xmm0, -0x520(%rbp)
100001301:     	movdqa	0x787(%rip), %xmm2      ## 0x100001a90 <_strncmp+0x100001a90>
100001309:     	movdqa	%xmm1, %xmm3
10000130d:     	pxor	%xmm2, %xmm3
100001311:     	movdqa	0x787(%rip), %xmm4      ## 0x100001aa0 <_strncmp+0x100001aa0>
100001319:     	movdqa	%xmm1, %xmm5
10000131d:     	pxor	%xmm4, %xmm5
100001321:     	movdqa	%xmm3, -0x210(%rbp)
100001329:     	movdqa	%xmm5, -0x200(%rbp)
100001331:     	paddd	%xmm1, %xmm2
100001335:     	paddd	%xmm1, %xmm4
100001339:     	movdqa	%xmm2, -0x310(%rbp)
100001341:     	movdqa	%xmm4, -0x300(%rbp)
100001349:     	movaps	0x760(%rip), %xmm2      ## 0x100001ab0 <_strncmp+0x100001ab0>
100001350:     	movaps	%xmm2, -0x410(%rbp)
100001357:     	movaps	0x762(%rip), %xmm2      ## 0x100001ac0 <_strncmp+0x100001ac0>
10000135e:     	movaps	%xmm2, -0x400(%rbp)
100001365:     	movaps	%xmm0, -0x510(%rbp)
10000136c:     	movaps	%xmm0, -0x500(%rbp)
100001373:     	movdqa	0x755(%rip), %xmm2      ## 0x100001ad0 <_strncmp+0x100001ad0>
10000137b:     	movdqa	%xmm1, %xmm3
10000137f:     	pxor	%xmm2, %xmm3
100001383:     	movdqa	0x755(%rip), %xmm4      ## 0x100001ae0 <_strncmp+0x100001ae0>
10000138b:     	movdqa	%xmm1, %xmm5
10000138f:     	pxor	%xmm4, %xmm5
100001393:     	movdqa	%xmm3, -0x1f0(%rbp)
10000139b:     	movdqa	%xmm5, -0x1e0(%rbp)
1000013a3:     	paddd	%xmm1, %xmm2
1000013a7:     	paddd	%xmm1, %xmm4
1000013ab:     	movdqa	%xmm2, -0x2f0(%rbp)
1000013b3:     	movdqa	%xmm4, -0x2e0(%rbp)
1000013bb:     	movaps	0x72e(%rip), %xmm2      ## 0x100001af0 <_strncmp+0x100001af0>
1000013c2:     	movaps	%xmm2, -0x3f0(%rbp)
1000013c9:     	movaps	0x730(%rip), %xmm2      ## 0x100001b00 <_strncmp+0x100001b00>
1000013d0:     	movaps	%xmm2, -0x3e0(%rbp)
1000013d7:     	movaps	%xmm0, -0x4f0(%rbp)
1000013de:     	movaps	%xmm0, -0x4e0(%rbp)
1000013e5:     	movdqa	0x723(%rip), %xmm2      ## 0x100001b10 <_strncmp+0x100001b10>
1000013ed:     	movdqa	%xmm1, %xmm3
1000013f1:     	pxor	%xmm2, %xmm3
1000013f5:     	movdqa	0x723(%rip), %xmm4      ## 0x100001b20 <_strncmp+0x100001b20>
1000013fd:     	movdqa	%xmm1, %xmm5
100001401:     	pxor	%xmm4, %xmm5
100001405:     	movdqa	%xmm3, -0x1d0(%rbp)
10000140d:     	movdqa	%xmm5, -0x1c0(%rbp)
100001415:     	paddd	%xmm1, %xmm2
100001419:     	paddd	%xmm4, %xmm1
10000141d:     	movdqa	%xmm2, -0x2d0(%rbp)
100001425:     	movdqa	%xmm1, -0x2c0(%rbp)
10000142d:     	movaps	0x6fc(%rip), %xmm1      ## 0x100001b30 <_strncmp+0x100001b30>
100001434:     	movaps	%xmm1, -0x3d0(%rbp)
10000143b:     	movaps	0x6fe(%rip), %xmm1      ## 0x100001b40 <_strncmp+0x100001b40>
100001442:     	movaps	%xmm1, -0x3c0(%rbp)
100001449:     	movaps	%xmm0, -0x4d0(%rbp)
100001450:     	movaps	%xmm0, -0x4c0(%rbp)
100001457:     	movl	%r14d, %edi
10000145a:     	callq	0x100000720 <_popcount_loop>
10000145f:     	movl	%eax, -0x5e8(%rbp)
100001465:     	movdqa	0x4c3(%rip), %xmm0      ## 0x100001930 <_strncmp+0x100001930>
10000146d:     	pinsrd	$0x0, %r14d, %xmm0
100001474:     	movdqa	%xmm0, -0x660(%rbp)
10000147c:     	leaq	-0x670(%rbp), %rdi
100001483:     	leaq	-0x660(%rbp), %rsi
10000148a:     	callq	0x100000780 <_copy16>
10000148f:     	movslq	-0x664(%rbp), %rax
100001496:     	movq	%rax, -0x648(%rbp)
10000149d:     	leaq	-0xb0(%rbp), %rbx
1000014a4:     	movq	%rbx, %rdi
1000014a7:     	callq	0x100000790 <_zero64>
1000014ac:     	movl	%r14d, %r12d
1000014af:     	andl	$0x3f, %r12d
1000014b3:     	movq	%rbx, %rdi
1000014b6:     	movq	%r12, %rsi
1000014b9:     	callq	0x1000007b0 <_zero_n>
1000014be:     	movq	-0x5d8(%rbp), %r15
1000014c5:     	movq	%r15, %rdi
1000014c8:     	callq	0x1000007d0 <_strcmp_const>
1000014cd:     	movq	%rax, -0x5f8(%rbp)
1000014d4:     	movq	%r15, %rdi
1000014d7:     	callq	0x1000007f0 <_strncmp_const>
1000014dc:     	movl	%eax, -0x5d0(%rbp)
1000014e2:     	leaq	-0x1b0(%rbp), %rdi
1000014e9:     	movl	%r12d, %esi
1000014ec:     	callq	0x100000810 <_loop_zero>
1000014f1:     	movq	%r15, %rdi
1000014f4:     	callq	0x1000018e2 <_strlen@stub>
1000014f9:     	movq	%rbx, %rdi
1000014fc:     	movq	%r15, %rsi
1000014ff:     	movl	%eax, %edx
100001501:     	callq	0x100000830 <_loop_copy>
100001506:     	movq	%r15, %rdi
100001509:     	callq	0x100000850 <_loop_strlen>
10000150e:     	movq	%rax, -0x640(%rbp)
100001515:     	leal	0x1(%r14), %edx
100001519:     	leal	0x2(%r14), %ecx
10000151d:     	movl	$0x3, %edi
100001522:     	movl	%r14d, %esi
100001525:     	xorl	%eax, %eax
100001527:     	callq	0x100000900 <_sum_va>
10000152c:     	movl	%eax, -0x620(%rbp)
100001532:     	movq	%r15, %rdi
100001535:     	callq	0x100000a50 <_ssp_copy>
10000153a:     	movl	%eax, -0x61c(%rbp)
100001540:     	movq	%r15, %rdi
100001543:     	callq	0x1000018e2 <_strlen@stub>
100001548:     	andl	$0x1f, %eax
10000154b:     	movq	%rbx, %rdi
10000154e:     	movq	%r15, %rsi
100001551:     	movq	%rax, %rdx
100001554:     	callq	0x100000ab0 <_fortify_memcpy>
100001559:     	movl	$0x80, %esi
10000155e:     	movq	%rbx, %rdi
100001561:     	movl	%r14d, %edx
100001564:     	callq	0x100000b10 <_fortify_snprintf>
100001569:     	movl	%eax, -0x618(%rbp)
10000156f:     	cmpl	$0x4, %r13d
100001573:     	jl	0x100001582 <_main+0x532>
100001575:     	movq	-0x5f0(%rbp), %rax
10000157c:     	movq	0x18(%rax), %rax
100001580:     	jmp	0x100001589 <_main+0x539>
100001582:     	leaq	0x619(%rip), %rax       ## 0x100001ba2 <_strncmp+0x100001ba2>
100001589:     	movq	%rax, -0x628(%rbp)
100001590:     	movl	%r14d, %edi
100001593:     	callq	0x1000008e0 <_make_small>
100001598:     	movq	%rax, -0x630(%rbp)
10000159f:     	movq	%r14, %rdi
1000015a2:     	callq	0x1000008b0 <_use_big>
1000015a7:     	movq	%rax, -0x5f0(%rbp)
1000015ae:     	movl	%r14d, %edi
1000015b1:     	callq	0x100000760 <_is_pow2>
1000015b6:     	movl	%eax, -0x614(%rbp)
1000015bc:     	movl	%r14d, %edi
1000015bf:     	movl	%r14d, %esi
1000015c2:     	callq	0x100000750 <_rotl32>
1000015c7:     	movl	%eax, %r15d
1000015ca:     	movl	%r14d, %edi
1000015cd:     	callq	0x100000740 <_bswap32_manual>
1000015d2:     	movl	%eax, -0x610(%rbp)
1000015d8:     	movl	%r14d, %edi
1000015db:     	xorl	%esi, %esi
1000015dd:     	movl	$0x9, %edx
1000015e2:     	callq	0x100000700 <_sel_clamp>
1000015e7:     	movl	%eax, -0x60c(%rbp)
1000015ed:     	movl	%r14d, %edi
1000015f0:     	callq	0x1000006f0 <_sel_abs>
1000015f5:     	movl	%eax, -0x608(%rbp)
1000015fb:     	movl	%r14d, %edi
1000015fe:     	movl	$0x5, %esi
100001603:     	callq	0x1000006e0 <_sel_max>
100001608:     	movl	%eax, -0x604(%rbp)
10000160e:     	movq	%r14, %rdi
100001611:     	callq	0x1000006b0 <_udiv1000_64>
100001616:     	movq	%rax, -0x638(%rbp)
10000161d:     	movl	%r14d, %edi
100001620:     	callq	0x100000690 <_sdiv16>
100001625:     	movl	%eax, -0x5e0(%rbp)
10000162b:     	movl	%r14d, %edi
10000162e:     	callq	0x100000670 <_umod10>
100001633:     	movl	%eax, %r12d
100001636:     	movl	%r14d, %edi
100001639:     	callq	0x100000650 <_sdiv7>
10000163e:     	movl	%eax, -0x600(%rbp)
100001644:     	movl	%r14d, %edi
100001647:     	callq	0x100000630 <_udiv7>
10000164c:     	movl	%eax, %ebx
10000164e:     	movl	%r14d, %edi
100001651:     	callq	0x100000600 <_sw_bittest>
100001656:     	movl	%eax, -0x5fc(%rbp)
10000165c:     	movl	%r14d, %edi
10000165f:     	callq	0x100000580 <_sw_sparse>
100001664:     	movl	%eax, %r13d
100001667:     	movl	%r14d, %edi
10000166a:     	callq	0x100000560 <_sw_dense>
10000166f:     	addl	-0x5e0(%rbp), %r12d
100001676:     	addl	-0x600(%rbp), %ebx
10000167c:     	addl	%r12d, %ebx
10000167f:     	movq	%rbx, -0x5e0(%rbp)
100001686:     	addl	-0x5fc(%rbp), %r13d
10000168d:     	addl	%eax, %r13d
100001690:     	movl	-0x60c(%rbp), %ecx
100001696:     	addl	-0x5e8(%rbp), %ecx
10000169c:     	movl	-0x604(%rbp), %eax
1000016a2:     	addl	-0x608(%rbp), %eax
1000016a8:     	addl	%ecx, %eax
1000016aa:     	movl	%eax, %ecx
1000016ac:     	addl	-0x614(%rbp), %r15d
1000016b3:     	addl	-0x610(%rbp), %r15d
1000016ba:     	movq	-0x5f8(%rbp), %rbx
1000016c1:     	addl	-0x5d0(%rbp), %ebx
1000016c7:     	movslq	-0x61c(%rbp), %rax
1000016ce:     	movslq	-0x618(%rbp), %r12
1000016d5:     	addq	%rax, %r12
1000016d8:     	movq	-0x630(%rbp), %rax
1000016df:     	sarq	$0x20, %rax
1000016e3:     	addq	%rax, %r12
1000016e6:     	movslq	%r13d, %rax
1000016e9:     	movq	%rax, -0x5d0(%rbp)
1000016f0:     	movslq	%ecx, %rax
1000016f3:     	movq	%rax, -0x5f8(%rbp)
1000016fa:     	movslq	-0x620(%rbp), %rax
100001701:     	movq	%rax, -0x5e8(%rbp)
100001708:     	leaq	-0xb0(%rbp), %rsi
10000170f:     	movl	$0x80, %edx
100001714:     	movq	-0x628(%rbp), %rdi
10000171b:     	callq	0x100000b30 <_read_file_head>
100001720:     	movslq	%eax, %r13
100001723:     	addq	-0x5d0(%rbp), %r13
10000172a:     	movl	%r14d, %edi
10000172d:     	callq	0x100000c10 <_tail_caller>
100001732:     	movl	%eax, %r14d
100001735:     	movq	-0x5d8(%rbp), %rdi
10000173c:     	callq	0x100000c20 <_tail_ext>
100001741:     	addl	%r14d, %eax
100001744:     	movslq	%eax, %r14
100001747:     	addq	%r13, %r14
10000174a:     	leaq	-0x1b0(%rbp), %r13
100001751:     	leaq	-0x2b0(%rbp), %rsi
100001758:     	leaq	-0x3b0(%rbp), %rdx
10000175f:     	movq	%r13, %rdi
100001762:     	movl	$0x40, %ecx
100001767:     	callq	0x100000c30 <_vadd>
10000176c:     	movq	%r13, %rdi
10000176f:     	movl	$0x40, %esi
100001774:     	callq	0x100000cc0 <_vsum>
100001779:     	movslq	%eax, %r13
10000177c:     	addq	%r14, %r13
10000177f:     	leaq	-0x4b0(%rbp), %rdi
100001786:     	leaq	-0x5b0(%rbp), %rsi
10000178d:     	movl	$0x40, %edx
100001792:     	callq	0x100000d50 <_vdot>
100001797:     	cvttss2si	%xmm0, %rax
10000179c:     	movq	%rax, -0x5d0(%rbp)
1000017a3:     	leaq	-0x5c0(%rbp), %rdi
1000017aa:     	callq	0x100000e00 <_md5_init>
1000017af:     	callq	0x100000e10 <_crc32_make_table>
1000017b4:     	movq	-0x5d8(%rbp), %r14
1000017bb:     	movq	%r14, %rdi
1000017be:     	callq	0x1000018e2 <_strlen@stub>
1000017c3:     	movq	%r14, %rdi
1000017c6:     	movq	%rax, %rsi
1000017c9:     	callq	0x100000f50 <_crc32_buf>
1000017ce:     	movl	%eax, %r14d
1000017d1:     	addq	-0x5d0(%rbp), %r14
1000017d8:     	movq	-0x5c0(%rbp), %rax
1000017df:     	movq	%rax, -0x5c8(%rbp)
1000017e6:     	leaq	0x363(%rip), %rsi       ## 0x100001b50 <_strncmp+0x100001b50>
1000017ed:     	leaq	-0x5c8(%rbp), %rdi
1000017f4:     	callq	0x100000fd0 <_tea_encrypt>
1000017f9:     	movl	-0x5c8(%rbp), %eax
1000017ff:     	addq	-0x640(%rbp), %rbx
100001806:     	addq	-0x5e8(%rbp), %rbx
10000180d:     	addq	-0x648(%rbp), %rbx
100001814:     	addq	-0x5f0(%rbp), %r12
10000181b:     	addq	%rbx, %r12
10000181e:     	addq	-0x638(%rbp), %r15
100001825:     	addq	-0x5f8(%rbp), %r15
10000182c:     	addq	-0x5e0(%rbp), %r15
100001833:     	addq	%r12, %r15
100001836:     	addq	%r13, %r15
100001839:     	addq	%r14, %r15
10000183c:     	leaq	(%rax,%r15), %rsi
100001840:     	addq	$0x7, %rsi
100001844:     	leaq	0x362(%rip), %rdi       ## 0x100001bad <_strncmp+0x100001bad>
10000184b:     	xorl	%eax, %eax
10000184d:     	callq	0x1000018c4 <_printf@stub>
100001852:     	movq	0x7c7(%rip), %rax       ## 0x100002020 <_strncmp+0x100002020>
100001859:     	movq	(%rax), %rax
10000185c:     	cmpq	-0x30(%rbp), %rax
100001860:     	jne	0x100001876 <_main+0x826>
100001862:     	xorl	%eax, %eax
100001864:     	addq	$0x648, %rsp            ## imm = 0x648
10000186b:     	popq	%rbx
10000186c:     	popq	%r12
10000186e:     	popq	%r13
100001870:     	popq	%r14
100001872:     	popq	%r15
100001874:     	popq	%rbp
100001875:     	retq
100001876:     	callq	0x10000188e <___stack_chk_fail@stub>

Disassembly of section __TEXT,__stubs:

000000010000187c <__stubs>:
10000187c:     	jmpq	*0x77e(%rip)            ## 0x100002000 <_strncmp+0x100002000>
100001882:     	jmpq	*0x780(%rip)            ## 0x100002008 <_strncmp+0x100002008>
100001888:     	jmpq	*0x782(%rip)            ## 0x100002010 <_strncmp+0x100002010>
10000188e:     	jmpq	*0x784(%rip)            ## 0x100002018 <_strncmp+0x100002018>
100001894:     	jmpq	*0x796(%rip)            ## 0x100002030 <_strncmp+0x100002030>
10000189a:     	jmpq	*0x798(%rip)            ## 0x100002038 <_strncmp+0x100002038>
1000018a0:     	jmpq	*0x79a(%rip)            ## 0x100002040 <_strncmp+0x100002040>
1000018a6:     	jmpq	*0x79c(%rip)            ## 0x100002048 <_strncmp+0x100002048>
1000018ac:     	jmpq	*0x79e(%rip)            ## 0x100002050 <_strncmp+0x100002050>
1000018b2:     	jmpq	*0x7a0(%rip)            ## 0x100002058 <_strncmp+0x100002058>
1000018b8:     	jmpq	*0x7a2(%rip)            ## 0x100002060 <_strncmp+0x100002060>
1000018be:     	jmpq	*0x7a4(%rip)            ## 0x100002068 <_strncmp+0x100002068>
1000018c4:     	jmpq	*0x7a6(%rip)            ## 0x100002070 <_strncmp+0x100002070>
1000018ca:     	jmpq	*0x7a8(%rip)            ## 0x100002078 <_strncmp+0x100002078>
1000018d0:     	jmpq	*0x7aa(%rip)            ## 0x100002080 <_strncmp+0x100002080>
1000018d6:     	jmpq	*0x7ac(%rip)            ## 0x100002088 <_strncmp+0x100002088>
1000018dc:     	jmpq	*0x7ae(%rip)            ## 0x100002090 <_strncmp+0x100002090>
1000018e2:     	jmpq	*0x7b0(%rip)            ## 0x100002098 <_strncmp+0x100002098>
1000018e8:     	jmpq	*0x7b2(%rip)            ## 0x1000020a0 <_strncmp+0x1000020a0>
