# The Quest for "Small Assembly Decompression Stubs"

​    Recently, I played a CTF where we had to send a long shellcode with some data that does not fit in the provided buffer.

So we used compression to make it fit, and we used an assembly lzma decompression stub that we found on internet.

It took us some time to find the good candidate in term of additional size for the stub, and compression ratio..

So for not loosing time searching on internet again next time,

I decided to collect some assembly decompression stubs I found on internet,

and that I have sometimes improved, sometimes rewrite.

* The goal is not to optimize them for speed but only for size.

In general the more the compression algorithm is complex and efficient , the more big is the decompression stub..

Let's start with an ultra basic compression algorithm..

------

## 1- Run Length Encoding (a.k.a. RLE)

You can not make simpler algorithm than run length encoding --> https://en.wikipedia.org/wiki/Run-length_encoding

you can code a decompression stub of it on x86 in only 10 bytes:

```assembly
; rle decompress
; rsi = compressed data     rdi = destination buffer
loop1:
00000000  AC				lodsb					; read first byte
00000001  0FB6C8            movzx ecx,al			; ecx is length
00000004  AC                lodsb					; read data
00000005  E304              jrcxz exit				; if length ecx = 0 we exit
00000007  F3AA              rep stosb				; copy data * ecx times
00000009  EBF5              jmp short 0x0
exit:
```

in fact, is you are sure that register `rcx` is already containing zero, you can even replace `movzx ecx,al`  by `mov cl,al` and save one additional byte, to reduce it to 9 bytes. This code works on 32 bits or 64 bit x86 assembly.

That is the ultra simplest possible run length encoding, it encodes a byte that represent the length of repetition, or zero if it's the end of the encrypted stream, and the next a byte for the data:

for example a suite of 100 zeroes, will be replaced by

```
64 00
```

so only two bytes, for coding 100 bytes.

but if you have 5 different consecutive bytes , for example `01 02 03 04 05`, it will encode to:

```
01 01 01 02 01 03 01 04 01 05
```

so 10 bytes for coding 5 bytes, which is really bad 😩

#### ok so let's improve it..

for example, instead of coding a length byte for each byte coded, we can use the LSB bit (bit 0) to indicates if it's repetition or uncompressed data, and used the 7 upper bits, to encode the length of the repetition, or of the non compressed data.

We can encode numbers between 0 and 127 with 7 bits. So for example for a suite of 100 uncompressed (non-repetiting bytes), we will have only one additional byte for encoding length..  which is a lot better.

the decompression stub is only 19 bytes on x86/x86_64 assembly:

```assembly
; rle (improved) decompress
; rsi = compressed data     rdi = destination buffer
loop1:
00000000  AC                lodsb				; read first byte
00000001  D0E8              shr al,1			; shift size right and put LSB bit 0 in C flag
00000003  0FB6C8            movzx ecx,al		; put size in ecx
00000006  E30B              jrcxz exit			; if ecx == 0 then we exit
00000008  7304              jc .memset			; if bit 0 was set, just fill memory with repetiting byte
0000000A  F3A4              rep movsb			; copy the uncompressed zone to dest
0000000C  EBF2              jmp short loop1		
.memset:
0000000E  AC                lodsb				; load data byte
0000000F  F3AA              rep stosb			; fill memory with data byte
00000011  EBED              jmp short loop1
exit:
```

and here is a simple RLE (improved) encoder written in python to test the function:

```python
from pwn import *
import sys

def rle_encode2(data):
    encoded_data = bytearray()
    i = 0
    while i < len(data):
        count = 1
        j = i + 1
        # Check if the next data is a repetition
        while j < len(data) and data[j] == data[i] and count<127:
            count += 1
            j += 1
        if count > 1:
            # If it's a repetition, set the LSB to 1
            encoded_data.append((count << 1) | 1)
            encoded_data.append(data[i])
            i += count
            count = 1
        else:
           while j < len(data) and data[i] != data[i+1] and count<127:
             count += 1
             i += 1
           encoded_data.append((count-1) << 1)
           encoded_data.extend(data[(i-(count-1)):i])
    return encoded_data

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python compress.py <inputfile> <outputfile>")
    else:
        uncompressed = open(sys.argv[1], "rb").read()
        compressed = rle_encode2(open(sys.argv[1], "rb").read())
        print('uncompressed size: '+str(len(uncompressed))+' bytes\n')
        print('compressed size: '+str(len(compressed))+' bytes\n')
 	    open(sys.argv[2],"wb").write(compressed)
```

#### so how bad or good is RLE compression ?

let's make some tests, first file will be a simple `x86_64` elf executable file, generated with gcc, it's original size is 13784 bytes

| Compressor     | Ratio | Compressed | Original |
| -------------- | ----- | ---------- | -------- |
| RLE (improved) | 2,083 | 6617       | 13784    |
| lz4c -1        | 2,877 | 4791       | 13784    |
| lz4c -hc       | 3,335 | 4132       | 13784    |
| gzip -1        | 3,776 | 3650       | 13784    |
| gzip -9        | 4,205 | 3278       | 13784    |

So as you can see , in this case RLE divided the size of the file by two, for only an additional 19 bytes for the decompression stub.

Not very efficient, but still can be useful for code golf with limited size buffer..or for compressing simple image, or data with a lot of repetition.

Ok , now let's move to something more efficient

------

## 2- LZ4 compression

LZ4 is a more efficient compression algorithm, it's one of the many derivates of LZ77, and it is known for it speed in decompression, that makes it a first choice for realtime compression of filesystems, it is used by ZFS for example. (<https://en.wikipedia.org/wiki/LZ4_(compression_algorithm)>)

In term of compression efficiency, it is a bit less efficient than zlib deflate algorithm, but in maximum compression mode (-hc mode) it's not far from zlib compression ratio.

Here is a decompression stub in **x86_64 assembly**, it's only 60 bytes, and can be called from a C program too:

```assembly
       .globl lz4dec
       .intel_syntax noprefix
// lz4dec(const void *dst, void *src, void *srcend);
// rdi = dst, destination buffer
// rsi = src, compressed data
// rdx points to end of compressed data
lz4dec:
.l0:    xor ecx,ecx
        xor eax,eax
        lodsb
        movzx   ebx,al
.cpy:   shr al,4
        call buildfullcount
        rep movsb
        cmp rsi,rdx
        jae exit
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
        jne exit
.buildloop:
        lodsb
        add ecx,eax
        cmp al,255
        je .buildloop
exit:   ret
```



In file `lz4dec_aarch64.s` you can find the **aarch64** version which is only 144 bytes long.

```assembly
// extern uint64_t lz4dec(const void *src, void *dst, uint64_t srcsz);
// 144 bytes lz4 aarch64 decompress
//
.p2align 2
    .globl lz4dec
lz4dec:
    // Register allocation:
    // x0   next input byte ptr
    // x1   next output byte ptr
    // x2   end of input buffer
    // x3   end of output buffer
    // x4   literals length / matchlength
    // x5   scratch / offset
    // x6   scratch

    // x14  original start of output buffer
    // x15  return address
    mov x15, x30
    mov x14, x1
    // Calculate end of the buffer
    adds x2, x0, x2
Lsequence:
    // New sequence
    ldrb w4, [x0], 1
    and w5, w4, 0xf
    // Extract literals length
    ubfx w4, w4, 4, 4
    cbz w4, Lmatchlength
    bl Llongsz
    // Copy literals to output buffer
Lliterals:
    ldrb w6, [x0], 1
    strb w6, [x1], 1
    sub x4, x4, 1
    cbnz x4, Lliterals
Lmatchlength:
    // End of the block only happens if matchlength is zero *and* we're at the
    // end of the input stream. If we're not at the end of the input stream,
    // then a matchlength of 0 means a copy of 4 bytes.
    cmp w5, 0
    ccmp x0, x2, 0, eq
    b.hs Lend
    mov w4, w5
    // Offset
    ldrb w5, [x0], 1
    ldrb w6, [x0], 1
    bfi w5, w6, 8, 8
    // Extract matchlength
    bl Llongsz
    adds x4, x4, 4
    // Copy match
    subs x5, x1, x5
Lmatch:
    ldrb w6, [x5], 1
    strb w6, [x1], 1
    sub x4, x4, 1
    cbnz x4, Lmatch
    b Lsequence
Llongsz:
    // Extract more size bytes
    cmp w4, 0xf
    b.ne Ldonesz
Lmoresz:
    ldrb w6, [x0], 1
    adds x4, x4, x6
    cmp w6, 0xff
    b.eq Lmoresz
Ldonesz:
    ret
Lend:
    sub x0, x1, x14
    ret x15
```

in file `lz4dec_arm.s` you can find the arm (Cortex-M0) version which is only 88 bytes long.

```assembly
	.syntax             unified
	.cpu                cortex-m0
	.thumb
/* Entry point = lz4dec
On entry:
	r0 = compressed data
	r1 = destination buffer
	r2 = compressed data length
*/
		.func lz4dec
		.global lz4dec
		.thumb_func

lz4dec:		push                {r4-r6,lr}          /* save r4, r5, r6 and return-address */
		adds                r5,r2,r0            /* point r5 to end of compressed data */
getToken:	ldrb                r6,[r0]             /* get token */
		adds                r0,r0,#1            /* advance source pointer */
		lsrs                r4,r6,#4            /* get literal length, keep token in r6 */
		beq                 getOffset           /* jump forward if there are no literals */
		bl                  getLength           /* get length of literals */
		movs                r2,r0               /* point r2 to literals */
		bl                  copyData            /* copy literals (r2=src, r1=dst, r4=len) */
		movs                r0,r2               /* update source pointer */
getOffset:	ldrb                r3,[r0,#0]          /* get match offset's low byte */
		subs                r2,r1,r3            /* subtract from destination; this will become the match position */
		ldrb                r3,[r0,#1]          /* get match offset's high byte */
		lsls                r3,r3,#8            /* shift to high byte */
		subs                r2,r2,r3            /* subtract from match position */
		adds                r0,r0,#2            /* advance source pointer */
		lsls                r4,r6,#28           /* get rid of token's high 28 bits */
		lsrs                r4,r4,#28           /* move the 4 low bits back where they were */
		bl                  getLength           /* get length of match data */
		adds                r4,r4,#4            /* minimum match length is 4 bytes */
		bl                  copyData            /* copy match data (r2=src, r1=dst, r4=len) */
		cmp                 r0,r5               /* check if we've reached the end of the compressed data */
		blt                 getToken            /* if not, go get the next token */
		pop                 {r4-r6,pc}          /* restore r4, r5 and r6, then return */

		.thumb_func
getLength:	cmp                 r4,#0x0f            /* if length is 15, then more length info follows */
		bne                 gotLength           /* jump forward if we have the complete length */

getLengthLoop:	ldrb                r3,[r0]             /* read another byte */
		adds                r0,r0,#1            /* advance source pointer */
		adds                r4,r4,r3            /* add byte to length */
		cmp                 r3,#0xff            /* check if end reached */
		beq                 getLengthLoop       /* if not, go round loop */
gotLength:	bx                  lr                  /* return */

		.thumb_func
copyData:	rsbs                r4,r4,#0            /* index = -length */
		subs                r2,r2,r4            /* point to end of source */
		subs                r1,r1,r4            /* point to end of destination */
copyDataLoop:	ldrb                r3,[r2,r4]          /* read byte from source_end[-index] */
		strb                r3,[r1,r4]          /* store byte in destination_end[-index] */
		adds                r4,r4,#1            /* increment index */
		bne                 copyDataLoop        /* keep going until index wraps to 0 */
		bx                  lr                  /* return */
```



The decompression stubs takes raw lz4 compressed data without any headers. The command line tools (lz4, lz4c) that came with lz4 library all add a header.

So you can compress a file with `high_compression`mode without any header with a small python script like this:

```python
import sys
import lz4.block

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python lz4_compress.py <infile> <outfile>")
        sys.exit(1)
    data = open(sys.argv[1],'rb').read()
    compressed = lz4.block.compress(data, mode='high_compression', acceleration=0, compression=12, store_size=False, return_bytearray=False)
    with open(sys.argv[2], 'wb') as f_out:
        f_out.write(compressed)
```



With only 60 bytes you can appreciate the code density of x86/x86_64 assembly,

with a lot of one byte instructions, it is by far the smallest one..



------

## 3- LZMA compression

LZMA is a very efficient algorithm with great compression ratio, it also derivates from LZ77, but with a range coder that code with bits instead of bytes, and many more improvements..

But of course, more complexity will result in a bigger decompression stub.

The lzma decompression stub came from the wonderful work of Ilya Kurdyukov , that did the porting to x86_64 assembly

<https://github.com/ilyakurdyukov/micro-lzmadec>

his x86_64 Linux binary is only 817 bytes (120 headers, 697 code) which is an amazing performance when you know the complexity of LZMA algorithm.

```assembly
; -*- tab-width: 8 -*-
; Copyright (c) 2022, Ilya Kurdyukov
; All rights reserved.
;
; Micro LZMA decoder utility for x86_64 Linux
;
; This software is distributed under the terms of the
; Creative Commons Attribution 3.0 License (CC-BY 3.0)
; http://creativecommons.org/licenses/by/3.0/
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
; OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
; THE SOFTWARE.

; build: nasm -f bin -O9 lzmadec.x86_64.asm -o lzmadec && chmod +x lzmadec
;
; usage: ./lzmadec < input.lzma > output.bin
;
; exit codes:
; 0 - success
; 1 - error at reading header or wrong header
; 2 - cannot allocate memory for dictionary
; 3 - error at reading
; 4 - error at decoding, lzma stream is damaged
; 5 - cannot write output

; Ways to make the code even smaller:
; 1. Place code in unused fields in the ELF header.
; 2. Remove error reporting via exit codes.
; 3. Immediate writing of each byte (makes decompression very slow). 

%ifndef @pie
%define @pie 0
%endif

BITS 64
%if @pie
ORG 0
%else
ORG 0x400000
%endif

%define @sys_read 0
%define @sys_write 1
%define @sys_mmap 9
%define @sys_exit 60

section .text

%define @bits 64

_code_seg:
_elf:	db 0x7f,'ELF',2,1,1,0	; e_ident
	dq 0
	dw 2+@pie	; e_type
	dw 62		; e_machine
	dd 1		; e_version
	dq _start	; e_entry
	dq .ph-_elf	; e_phoff
	dq 0		; e_shoff
	dd 0		; e_flags
	dw 0x40		; e_ehsize
	dw 0x38, 1	; e_phentsize, e_phnum
	dw 0x40, 0	; e_shentsize, e_shnum
	dw 0		; e_shstrndx
.ph:	dd 1, 5			; p_type, p_flags
	dq 0			; p_offset
	dq _code_seg		; p_vaddr
	dq _code_seg		; p_paddr (unused)
	dq _code_end-_code_seg	; p_filesz
	dq _code_end-_code_seg	; p_memsz
	dq 0x1000		; p_align

%assign loc_pos 0
%macro LOC 1-3 4, dword
%assign loc_pos loc_pos+%2
%ifidn %3, none
%xdefine %1 [rbp-loc_pos]
%else
%xdefine %1 %3 [rbp-loc_pos]
%endif
%endmacro
LOC _dummyA, 8
LOC OutSize, 8, qword
LOC DictSize1
LOC _dummyB
%assign loc_pos1 loc_pos	; 24
LOC _rep0
LOC _rep1
LOC _rep2
LOC _rep3
%assign loc_rep loc_pos		; 40
LOC Code, 8
%assign loc_code loc_pos
LOC Range
%assign loc_range loc_pos
LOC _dummyF
LOC _dummy1, 8
LOC _pb, 8
LOC _lp, 7, none
LOC _lc, 1, none
LOC DictSize, 8
LOC _dummy2, 8
LOC _state, 8

%define _rc_bit rdi
%define Pos r9d
%define Total r13

; 12*5 - (12*2+6+4) = 26 ; call rdi
; 12*5 - (12*3+5) = 19 ; call [rbp-N]

%macro READ_REP0 1
	mov	%1, Pos
	sub	%1, _rep0
	jae	%%1
	add	%1, DictSize
%%1:
%endmacro

_loop:	xor	r15d, r15d	; _len
	mov	rcx, Total
	mov	bh, cl
	pop	rsi		; _state
	push	rsi
	and	ecx, _pb	; posState, 0..15
	shl	esi, 5		; state * 16

	; probs + state * 16 + posState
	lea	esi, [rsi+rcx*2+64]
	call	_rc_bit
	cdq
	pop	rax
	jc	_case_rep
	mov	ecx, _lc
	and	bh, ch	; _lp
	shl	ebx, cl
	mov	bl, 0
	lea	ecx, [rbx+rbx*2+2048]
_case_lit:
	lea	ebx, [rdx+1]
	; state = 0x546543210000 >> state * 4 & 15;
	; state = state < 4 ? 0 : state - (state > 9 ? 6 : 3)
.4:	add	al, -3
	sbb	dl, dl
	and	al, dl
	cmp	al, 7
	jae	.4
	push	rax		; _state
%if 0	; -2 bytes, but slower
	add	al, -4
	sbb	bh, bh
%else
	cmp	al, 7-3
	jb	.2
	mov	bh, 1	 ; offset
%endif
	READ_REP0 eax
	; dl = -1, dh = 0, bl = 1
	xor	dl, [r12+rax]
.1:	xor	dh, bl
	and	bh, dh
.2:	shl	edx, 1
	mov	esi, ebx
	and	esi, edx
	add	esi, ebx
	add	esi, ecx
	call	_rc_bit
	adc	bl, bl
	jnc	.1
	jmp	_copy.2

_case_rep:
	mov	ebx, esi
	lea	esi, [rdx+rax*4+16]	; IsRep
	add	al, -7
	sbb	al, al
	and	al, 3
	push	rax		; _state
	call	_rc_bit
	jc	.2
	; r3=r2, r2=r1, r1=r0
%if 1
	; [3*4 -> 4*2, -4]
	movups	xmm0, [rbp-loc_rep]
	movups	[rbp-loc_rep-4], xmm0
%else
	; 0 0 1 2
	; shufps xmm0, xmm0, 0x90 [3*4 -> 4, -9]
	mov	rsi, [rbp-loc_rep+8]
	xchg	rsi, [rbp-loc_rep+4]
	mov	_rep3, esi
%endif
	; state = state < 7 ? 0 : 3
	mov	dl, 819/9	; LenCoder
	jmp	_case_len

.2:	inc	esi
	call	_rc_bit
	jc	.3
	lea	esi, [rbx+1]	; IsRep0Long
	call	_rc_bit
	jc	.5
	; state = state < 7 ? 9 : 11
	or	_state, 9
	jmp	_copy

.3:	mov	dl, 3
	mov	ebx, _rep0
.6:	inc	esi
	dec	edx
	xchg	[rbp-loc_rep+rdx*4], ebx
	je	.4
	call	_rc_bit
	jc	.6
.4:	mov	_rep0, ebx
.5:	; state = state < 7 ? 8 : 11
	or	_state, 8
	mov	dl, 1332/9	; RepLenCoder
_case_len:
	lea	esi, [rdx*8+rdx]
	cdq
	call	_rc_bit
	inc	esi
	lea	ebx, [rsi+rcx*8]	; +1 unnecessary
	mov	cl, 3
	jnc	.4
	mov	dl, 8/8
	call	_rc_bit
	jnc	.3
	; the first byte of BitTree tables is not used,
	; so it's safe to add 255 instead of 256 here
	lea	ebx, [rsi+127]
	mov	cl, 8
	add	edx, 16/8-(1<<8)/8	; edx = -29
.3:	sub	ebx, -128	; +128
.4:	; BitTree
	push	1
	pop	rsi
	push	rsi
.5:	push	rsi
	add	esi, ebx
	call	_rc_bit
	pop	rsi
	adc	esi, esi
	loop	.5
	lea	ebx, [rsi+rdx*8+2-8-1]
	mov	r15d, ebx
	cmp	_state, 4
	pop	rdx	; edx = 1
	jae	_copy
_case_dist:
	add	_state, 7
	sub	ebx, 3+2-1
	sbb	eax, eax
	and	ebx, eax
	lea	ebx, [rdx-1+rbx*8+(432+16-128)/8+(3+2)*8]	; PosSlot
	; BitTree
	push	rdx
.5:	lea	esi, [rdx+rbx*8]
	call	_rc_bit
	adc	edx, edx
	mov	ecx, edx
	sub	ecx, 1<<6
	jb	.5
	pop	rbx	; ebx = 1
_case_model:
	cmp	ecx, 4
	jb	.9
	mov	esi, ebx
	shr	ecx, 1
%if 1
	; -3
	rcl	ebx, cl
	dec	ecx
%else
	adc	ebx, ebx
	dec	ecx
	shl	ebx, cl
%endif
	not	dl	; 256-edx-1
	mov	dh, 2
	add	edx, ebx
;	lea	edx, [rdx+rbx+688+16+64-256*3]	; SpecPos
	cmp	ecx, 6
	jb	.4
.1:	dec	ecx
	call	_rc_norm
	shr	Range, 1
	mov	edx, Range
	cmp	Code, edx
	jb	.3
	sub	Code, edx
	bts	ebx, ecx
.3:	cmp	ecx, 4
	jne	.1
	cdq		; Align
.4:
.5:	push	rsi
	add	esi, edx
	call	_rc_bit
	pop	rsi
	adc	esi, esi
	loop	.5
.6:	adc	ecx, ecx
	shr	esi, 1
	jne	.6
	add	ecx, ebx
.9:	inc	ecx
	mov	_rep0, ecx
	je	_end
	; movss xmm0, _rep0 [5]
_copy:	mov	ecx, _rep0
	cmp	Total, rcx
.4:	push	4
	jb	_end.2
	cmp	DictSize, ecx
	jb	_end.2
	pop	rbx
.1:	READ_REP0 ecx
	mov	bl, [r12+rcx]
.2:	mov	[r12+r9], bl	; Dict + Pos
	inc	Total
	inc	Pos
	cmp	OutSize, Total
	jb	.4
	cmp	Pos, DictSize
	jb	.8
	call	_write
.8:	dec	r15d
	jns	.1
	push	rdi
.9:	pop	rdi
	cmp	OutSize, Total
.10:	jne	_loop
	cmp	Code, 0
	jne	.10
_end:	neg	Code
	jc	_copy.4
	push	0	; exit code
.2:	call	_write
.0:	pop	rdi
.1:	push	@sys_exit
	pop	rax
	syscall

_rc_norm:
	cmp	byte [rbp-loc_range+3], 0
	jne	.1
%if 1	; -2
	shl	qword [rbp-loc_range], 8
%else
	shl	Range, 8
	shl	Code, 8
%endif
	push	rsi
	push	rdi
	push	3
	; ax dx si di + cx r11
	xor	edi, edi	; 0 (stdin)
	lea	rsi, [rbp-loc_code]
	lea	edx, [rdi+1]
%if @sys_read != 0 || @sys_write != 1
	lea	eax, [rdi+@sys_read]
%endif
.2:	push	rcx
%if @sys_read == 0 && @sys_write == 1
	mov	eax, edi
%endif
	syscall
	cmp	eax, edx
	pop	rcx
	jne	_end.2
	pop	rax
	pop	rdi
	pop	rsi
.1:	ret

_write:
	push	rsi
	push	rdi
	push	5
	cdq
	lea	edi, [rdx+1]
%if @sys_read != 0 || @sys_write != 1
	lea	eax, [rdx+@sys_write]
%endif
	xchg	edx, Pos
	mov	rsi, r12
	jmp	_rc_norm.2

_start:	enter	loc_pos1, 0
	xor	edi, edi	; 0 (stdin)
	or	eax, -1		; 0xffffffff
	; movd xmm0, eax [4]
	; shufps xmm0, xmm0, 0 [4]
	add	rax, 2		; 0x100000001
	push	rax
	push	rax
	; (3)+1+4+8+(1)+4
	lea	edx, [rdi+5+8+5]
	lea	rsi, [rbp-loc_pos1+3]
%if @sys_read == 0
	mov	eax, edi
%else
	lea	eax, [rdi+@sys_read]
%endif
	syscall
	mov	ecx, [rsi+14]
	bswap	ecx
	push	rcx	; Code
	push	-1	; Range
	or	dh, [rsi+13]
	sub	edx, eax
	push	1
.err:	jne	_end.0
	; rdx = 0, rax = 5+8+5, rdi = 0
	lodsb
	cmp	al, 9*5*5
	jae	_end.0
	mov	ebx, (768<<5)+31
	clc
.1:	adc	edx, edx
	add	al, -9*5
	jc	.1
	push	rdx	; _pb
	cdq
.2:	shr	ebx, 1
	add	al, 9
	jnc	.2
	xchg	ah, bl
	xchg	ecx, eax
	shl	ebx, cl
	push	rcx	; _lc, _lp
%if 1	; -3, allocates 404 bytes more
	add	bh, 8	; 2048 >> 8
%else
	add	ebx, 1846
%endif

	lodsd
	mov	dh, 0x1000>>8
	cmp	eax, edx
	jae	.3
	xchg	eax, edx
.3:	push	rax	; DictSize
	lea	rsi, [rax+rbx*2]

	xor	r9, r9	; off
	or	r8, -1	; fd
	; xor	edi, edi	; addr
	lea	eax, [rdi+@sys_mmap]
	; prot: 1-read, 2-write, 4-exec
	lea	edx, [rdi+3]
	; map: 2-private, 0x20-anonymous
	lea	r10d, [rdi+0x22]
	syscall
	; err = ret >= -4095u
	; (but negative pointers aren't used)
	add	rdi, rax
	push	2
	js	.err
	mov	ecx, ebx
	xchg	r14, rax	; _prob
	mov	ax, 1<<10
	rep	stosw
	push	rcx		; _state
	mov	r12, rdi	; Dict
	xor	ebx, ebx	; Prev = 0
	; Pos = r9 = 0
	xor	Total, Total
	call	_copy.9
_rc_bit1:
	push	rdx
	call	_rc_norm
	movzx	eax, word [r14+rsi*2]
	mov	edx, Range
	shr	edx, 11
	imul	edx, eax	; bound
	sub	Range, edx
	sub	Code, edx
	jae	.1
	mov	Range, edx
	add	Code, edx
	cdq
	sub	eax, 2048-31
.1:	shr	eax, 5		; eax >= 0
	sub	[r14+rsi*2], ax
	neg	edx
	pop	rdx
	ret

_code_end:
```

------

**P.S.:**

*I've always found data compression a fascinating subject. I read the first edition of  "Data Compression" by Mark Nelson, and, even if it's an old book,  I recommend you read it if you want to understand what LZ77, LZSS, JPEG, Huffman coding, Arithmetic coding, Markov Modelling are all about.  You can read the second edition online here: https://hlevkin.com/hlevkin/02imageprocC/The%20Data%20Compression%20Book%202nd%20edition.pdf*