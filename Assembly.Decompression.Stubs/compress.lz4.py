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
