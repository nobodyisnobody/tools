[bits 64]

loop1:
	lodsb
	shr al,1
	movzx ecx,al
	jrcxz exit
	jnc .cpy
	rep movsb
	jmp loop1
.cpy:	lodsb
	rep stosb
	jmp loop1
exit:
