
bin/k2_x86_64-apple-macos13.o:	file format mach-o 64-bit x86-64

Disassembly of section __TEXT,__text:

0000000000000000 <_dispatch>:
       0:      	pushq	%rbp
       1:      	movq	%rsp, %rbp
       4:      	cmpl	$0x6, %edi
       7:      	ja	0x43 <_dispatch+0x43>
       9:      	movl	%edi, %eax
       b:      	leaq	0x56(%rip), %rcx        ## 0x68 <_dispatch+0x68>
      12:      	movslq	(%rcx,%rax,4), %rax
      16:      	addq	%rcx, %rax
      19:      	jmpq	*%rax
      1b:      	movl	%esi, %edi
      1d:      	popq	%rbp
      1e:      	jmp	0x23 <_dispatch+0x23>
		000000000000001f:  X86_64_RELOC_BRANCH	_f0
      23:      	xorl	$0x3, %esi
      26:      	movl	%esi, %edi
      28:      	popq	%rbp
      29:      	jmp	0x2e <_dispatch+0x2e>
		000000000000002a:  X86_64_RELOC_BRANCH	_f4
      2e:      	addl	%esi, %esi
      30:      	movl	%esi, %edi
      32:      	popq	%rbp
      33:      	jmp	0x38 <_dispatch+0x38>
		0000000000000034:  X86_64_RELOC_BRANCH	_f2
      38:      	addl	$-0x7, %esi
      3b:      	movl	%esi, %edi
      3d:      	popq	%rbp
      3e:      	jmp	0x43 <_dispatch+0x43>
		000000000000003f:  X86_64_RELOC_BRANCH	_f3
      43:      	movl	$0xffffffff, %eax       ## imm = 0xFFFFFFFF
      48:      	popq	%rbp
      49:      	retq
      4a:      	incl	%esi
      4c:      	movl	%esi, %edi
      4e:      	popq	%rbp
      4f:      	jmp	0x54 <_dispatch+0x54>
		0000000000000050:  X86_64_RELOC_BRANCH	_f1
      54:      	movl	%esi, %edi
      56:      	popq	%rbp
      57:      	jmp	0x5c <_dispatch+0x5c>
		0000000000000058:  X86_64_RELOC_BRANCH	_f5
      5c:      	sarl	%esi
      5e:      	movl	%esi, %edi
      60:      	popq	%rbp
      61:      	jmp	0x66 <_dispatch+0x66>
		0000000000000062:  X86_64_RELOC_BRANCH	_f6
      66:      	nop
      68:      	movb	$-0x1, %bl
      6a:      	<unknown>
      6c:      	loop	0x6d <_dispatch+0x6d>
      6e:      	<unknown>
      70:      	<unknown>
      72:      	<unknown>
      74:      	sarb	%bh
      76:      	<unknown>
      78:      	movl	$0xecffffff, %ebx       ## imm = 0xECFFFFFF
      7d:      	<unknown>
      7f:      	pushq	%rsp
      81:      	<unknown>
      83:      	jmpq	*0x66(%rsi)
      86:      	nopw	%cs:(%rax,%rax)

0000000000000090 <_canary>:
      90:      	pushq	%rbp
      91:      	movq	%rsp, %rbp
      94:      	pushq	%rbx
      95:      	subq	$0x48, %rsp
      99:      	movq	%rdi, %rsi
      9c:      	movq	(%rip), %rax            ## 0xa3 <_canary+0x13>
		000000000000009f:  X86_64_RELOC_GOT_LOAD	___stack_chk_guard@GOTPCREL
      a3:      	movq	(%rax), %rax
      a6:      	movq	%rax, -0x10(%rbp)
      aa:      	leaq	-0x50(%rbp), %rbx
      ae:      	movq	%rbx, %rdi
      b1:      	callq	0xb6 <_canary+0x26>
		00000000000000b2:  X86_64_RELOC_BRANCH	_strcpy
      b6:      	movq	%rbx, %rdi
      b9:      	callq	0xbe <_canary+0x2e>
		00000000000000ba:  X86_64_RELOC_BRANCH	_strlen
      be:      	movq	(%rip), %rcx            ## 0xc5 <_canary+0x35>
		00000000000000c1:  X86_64_RELOC_GOT_LOAD	___stack_chk_guard@GOTPCREL
      c5:      	movq	(%rcx), %rcx
      c8:      	cmpq	-0x10(%rbp), %rcx
      cc:      	jne	0xd5 <_canary+0x45>
      ce:      	addq	$0x48, %rsp
      d2:      	popq	%rbx
      d3:      	popq	%rbp
      d4:      	retq
      d5:      	callq	0xda <_canary+0x4a>
		00000000000000d6:  X86_64_RELOC_BRANCH	___stack_chk_fail
      da:      	nopw	(%rax,%rax)

00000000000000e0 <_seterr>:
      e0:      	pushq	%rbp
      e1:      	movq	%rsp, %rbp
      e4:      	pushq	%rbx
      e5:      	pushq	%rax
      e6:      	movl	%edi, %ebx
      e8:      	callq	0xed <_seterr+0xd>
		00000000000000e9:  X86_64_RELOC_BRANCH	___errno_location
      ed:      	movl	%ebx, (%rax)
      ef:      	movl	$0xffffffff, %eax       ## imm = 0xFFFFFFFF
      f4:      	addq	$0x8, %rsp
      f8:      	popq	%rbx
      f9:      	popq	%rbp
      fa:      	retq
