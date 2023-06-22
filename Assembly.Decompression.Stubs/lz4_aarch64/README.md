the decompress function is in lz4dec_aarch64.s
it's 144 bytes

to use if from C:

extern uint64_t lz4dec(const void *src, void *dst, uint64_t srcsz);

