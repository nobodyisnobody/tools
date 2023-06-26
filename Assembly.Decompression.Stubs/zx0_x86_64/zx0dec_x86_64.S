        .intel_syntax noprefix
	.global zx0_decompress
zx0_decompress:
        cld                     /* make string operations go forward */
        mov     al,0x80         /* initialize empty bit queue */
                                /* plus bit to roll into carry */
	push -1
	pop 	rdx           /* initialize rep-offset to 1 */
.literals:
        call    .get_elias     /* read number of literals to copy */
        rep     movsb           /* copy literal bytes */

        add     al,al           /* shift bit queue, and high bit into carry */
        jc      .get_offset     /* if 1: read offset, if 0: rep-match */

        call    .get_elias      /* read rep-match length (starts at 1) */

.copy_match:
	push rsi              /* save rsi (current pointer to compressed data) */
	lea rsi,[rdi+rdx]	/* point to destination in rdi + rdx */
        rep     movsb           /* copy matched bytes */
	pop rsi

        add     al,al           /* read 'literal or match' bit */
        jnc     .literals       /* if 0: go copy literals */

.get_offset:
        mov     cl,0xfe         /* initialize value to 0xFE */
        call    .elias_loop     /* read high byte of match offset */
        inc     cl              /* obtain negative offset high byte */
        je      .done           /* exit if EOD marker */

        mov     dh,cl           /* transfer negative high byte into dh */
	push 1
	pop rcx           /* initialize match length value to 1 */
        mov     dl,[rsi]         /* read low byte of offset + 1 bit of len */
        inc     rsi
        stc                     /* set high bit that is shifted into bit 15 */
        rcr     rdx,1            /* shift len bit into carry/offset in place */
        jc      .got_offs       /* if len bit is set, no need for more */
        call    .elias_bt       /* read rest of elias-encoded match length */
.got_offs:
        inc     ecx              /* fix match length */
        jmp     short .copy_match /* go copy match  */


.get_elias:
	push 1
	pop rcx			/* initialize value to 1 */
.elias_loop:
        add     al,al           /* shift bit queue, and high bit into carry */
        jnz     .got_bit        /* queue not empty, bits remain */
        lodsb                   /* read 8 new bits */
        adc     al,al           /* shift bit queue, and high bit into carry */
.got_bit:
        jc      .got_elias      /* done if control bit is 1 */
.elias_bt:
        add     al,al           /* read data bit */
        adc     ecx,ecx           /* shift into cx */
        jmp     short .elias_loop /* keep reading */
.got_elias:
.done:
        ret
