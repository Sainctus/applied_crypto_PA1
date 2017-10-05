#!/usr/bin/env python3

import argparse
import sys
import os
import random
import binascii
from Crypto.Cipher import AES



IV = binascii.hexlify(os.urandom(16))



def main(KEYFILE, IFILE, OFILE):
    v = IV
    try:
        f = open(v, 'r')
        v = f.read()
        f.close()
    except IOError:
        pass

    print(v)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--f", help="Key file", required=True)
    parser.add_argument("--i", help="Input file", required=True)
    parser.add_argument("--o", help="Output file", required=True)
    parser.add_argument("--v", help = "IV file", required=False, type = str, default=IV)
    args = parser.parse_args()

    IV = args.v
    main(args.f, args.i, args.o)
