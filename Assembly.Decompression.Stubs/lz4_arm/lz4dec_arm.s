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


