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

LZ4 is a more efficient compression algorithm, it is known for it speed in decompression, that makes it a first choice for realtime compression of filesystems, it is used by ZFS for example. (<https://en.wikipedia.org/wiki/LZ4_(compression_algorithm)>)

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

in file `lz4dec_arm.s` you can find the arm version which is only 92 bytes long.

```assembly
	.syntax             unified
	.cpu                cortex-m0
	.thumb
/* Entry point = lz4dec.
On entry: 
r0 = source
r1 = destination. The first two bytes of the source must contain the length of the compressed data.
r2 = length of source compressed data */
		.func lz4dec
		.global lz4dec,lz4dec_len
		.thumb_func

lz4dec:	push                {r4-r6,lr}          /* save r4, r5, r6 and return-address */
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
		cmp                 r0,r5               /* check if we reached the end of the compressed data*/
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