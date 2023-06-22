decompress stub is only 60 bytes!! in x86_64 assembly
rdi -> points to destination buffer
rsi -> points to compressed data
rdx -> point to compressed data+length of compressed data

to use it from C:

extern uint64_t lz4dec(const void *dst, void *src, void *srcend);
