#!/usr/bin/env python

import argparse
import sys
import os
import random
import string
import binascii
from Crypto.Cipher import AES
from multiprocessing import Pool

#####################################################################

def generate():
    size = 32
    chars=string.digits
    return ''.join(random.choice(chars) for _ in range(size))

#####################################################################

def encrypt(key, raw):
    if(raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return binascii.hexlify(bytearray(ciphertext)).decode('utf-8')

#####################################################################

def decrypt(key, enc):
    if(enc is None) or (len(enc) == 0):
        raise ValueError('input text cannot be null or empty set')
    enc = binascii.unhexlify(enc)
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    enc = cipher.decrypt(enc)
    return enc.decode('utf-8')

#####################################################################

#Performs the conversion and XOR operations
def XOR(plain_text, counter):
    hex_text = binascii.hexlify(plain_text)
    hex_text = int(hex_text, 16)
    counter = int(counter, 16)
    temp = hex_text ^ counter
    temp = hex(temp)
    temp = temp[2:-1]
    return temp

#####################################################################

def unXOR(cipher_text, counter):
    cipher_text = int(cipher_text, 16)
    counter = int(counter, 16)
    temp = cipher_text ^ counter
    temp = hex(temp)
    temp = temp[2:-1]
    return binascii.unhexlify(temp)

#####################################################################

def parallelize(key, text, counter):
    enc_ctr = binascii.unhexlify(str(counter))
    enc_ctr = encrypt(key, enc_ctr)
    output = XOR(text, enc_ctr)
    encrypted.append(output)

#####################################################################

IV = generate() 

def main(KEYFILE, IFILE, OFILE):
    #This block looks at the value of IV and attempts to open it as a file. If successful, it reads the IV value from file. If unsuccessful, it uses a randomly generated IV.

    try:
        f = open(IV, 'r')
        ctr = f.read()
        ctr = ctr.rstrip("\n")
        ctr = int(ctr)
        f.close()
    except IOError:
        ctr = int(IV)
        pass
    except TypeError:
        ctr = int(IV)
        pass

    #Reads the key from file and prints
    f = open(KEYFILE, 'r')
    key = f.read()
    f.close()

    f = open(IFILE, 'r')
    blocks = []
    while 1:
        s = ''
        for i in range(16):
            c = f.read(1)
            if c is None:
                f.close()
                s += c
                break
            else:
                s += c

        if s is not None:
            blocks.append(s)
        if len(s) < 16:
            break
    
    temp = blocks[len(blocks) - 1]
    temp = temp.rstrip("\n")
    blocks[len(blocks) - 1] = temp

    if blocks[len(blocks) - 1] == '':
        blocks.pop()

    for i in blocks:
        print i

    print "\n"


    encrypted = []

    for i in range(len(blocks)):    
        enc_ctr = binascii.unhexlify(str(ctr))
        enc_ctr = encrypt(key, enc_ctr)
        output = XOR(blocks[i], enc_ctr)
        encrypted.append(output)
        ctr += 1


#Couldn't figure out how to make this multiprocessing work. Documentation for it is awful. All I could find were examples of functions using single iterators. I tried to manipulate my funciton so that the only thing that needed to change was 'i', but I couldn't figure out the syntax to make it work.
#    p = Pool(4)
#    results = p.map(parallelize, (key, blocks[0 + i], ctr + i) for i in range(len(blocks)))
#    print results

    for i in encrypted:
        print i

    f = open(OFILE, 'w')
    f.write(ctr)
    for i in encrypted:
        f.write(i)
    f.write("\n")
    f.close()


#####################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--f", help="Key file", required=True)
    parser.add_argument("--i", help="Input file", required=True)
    parser.add_argument("--o", help="Output file", required=True)
    parser.add_argument("--v", help="IV file", required=False, type = str, default=IV)
    args = parser.parse_args()

    IV = args.v
    main(args.f, args.i, args.o)
