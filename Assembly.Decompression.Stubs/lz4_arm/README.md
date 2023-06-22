Using the decompressor is quite easy. When calling the routine, you just need to point r0 to the compressed data, 
r1 to the address in RAM, where you want the decompressed data to go,
r2 contains the length of compressed data

the decompression function is only 88 bytes

to use it from C:

void lz4dec_len(const void *aSource, void *aDestination, uint32_t aLength);
