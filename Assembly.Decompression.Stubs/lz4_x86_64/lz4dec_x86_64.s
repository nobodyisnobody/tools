	.globl lz4dec
	.intel_syntax noprefix
// lz4dec(const void *dst, void *src, void *srcend);
lz4dec:
.l0:
	xor ecx,ecx
	xor eax,eax
	lodsb
	movzx	ebx,al
.cpy:
	shr al,4
	call buildfullcount
	rep movsb
	cmp rsi,rdx
	jae next

.copymatches:
	lodsw
	xchg ebx,eax
	and al,15
	call buildfullcount
.matchcopy:
	push rsi
	push rdi
	pop rsi
	sub rsi,rbx
	add ecx,4
	rep movsb
	pop rsi
	jmp .l0

buildfullcount:
	cmp al,15
	xchg ecx,eax
	jne .done1
.buildloop:
	lodsb
	add ecx,eax
	cmp al,255
	je .buildloop
.done1:
	ret
next:
