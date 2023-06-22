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
