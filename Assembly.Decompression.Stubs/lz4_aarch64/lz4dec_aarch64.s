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

