#!/usr/bin/env python

import argparse
import sys
import os
import random
import binascii
from Crypto.Cipher import AES

#####################################################################

IV = binascii.hexlify(os.urandom(16))

#####################################################################

def pad(data):
    if(len(data) % 16 == 0):
        padding_required = 16
    else:
        padding_required = 16 - (len(data) % 16)


    #Horrible, but nothing would translate a 2-digit integer to its hex
    #equivallent. Everything translated each digit individually.
    if padding_required >= 1 and padding_required < 10:
        padChar = str(padding_required)
    elif padding_required == 10:
        padChar = 'a'
    elif padding_required == 11:
        padChar = 'b'
    elif padding_required == 12:
        padChar = 'c'
    elif padding_required == 13:
        padChar = 'd'
    elif padding_required == 14:
        padChar = 'e'
    elif padding_required == 15:
        padChar = 'f'
    elif padding_required == 16:
        padChar = '0'


    for i in range(padding_required):
        data += padChar

    return data

#####################################################################

def unpad(data):
    padChar = data[-1]



    #Horrible, but nothing would translate a 2-digit integer to its hex
    #equivallent. Everything translated each digit individually.
    if int(padChar) >= 1 and int(padChar) < 10:
        padChar_int = int(padChar)
    elif padChar == 'a':
        padChar_int = 10
    elif padChar == 'b':
        padChar_int = 11
    elif padChar == 'c':
        padChar_int = 12
    elif padChar == 'd':
        padChar_int = 13
    elif padChar == 'e':
        padChar_int = 14
    elif padChar == 'f':
        padChar_int = 15
    elif padChar == '0':
        padChar_int = 16


    data = data[:-padChar_int]

    return data

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
def prepare(plain_text, previous):
    enc1 = binascii.hexlify(plain_text)
    enc1 = int(enc1, 16)
    enc2 = int(previous, 16)
    temp = enc1 ^ enc2
    temp = hex(temp)
    temp = temp[2:-1]
    if(len(temp) % 2 != 0):
        foo = hex(0)
        foo = foo[2:]
        temp = foo + temp
    temp = binascii.unhexlify(temp)
    return temp

#####################################################################

def main(KEYFILE, IFILE, OFILE):
    #Try to open and read IV from file, otherwise use default value
    v = IV
    try:
        f = open(v, 'r')
        v = f.read()
        v = binascii.hexlify(v)
        f.close()
    except IOError:
        pass

    #Reads the key from file and prints
    f = open(KEYFILE, 'r')
    key = f.read()
    f.close()

    #Read in blocks from file
    f = open(IFILE, 'r')
    blocks = []
    while 1:
        c = f.read(16)
        if c is None:
            f.close()
            break

        blocks.append(c)
        if len(c) < 16:
            break
    
    #Strip newline character from last block
    temp = blocks[len(blocks) - 1]
    temp = temp.rstrip("\n")
    blocks[len(blocks) - 1] = temp

    #Add an empty block for padding if necessary
    if len(blocks[len(blocks) - 1]) == 16:
        blocks.append('')

    #Perform padding
    blocks[len(blocks) - 1] = pad(blocks[len(blocks) - 1])

    #Encrypt
    encrypted = []
    prior = v
    for tblock in blocks:
        temp = encrypt(key, prepare(tblock, prior))
        encrypted.append(temp)
        prior = temp
    
    #Print output to file
    f = open(OFILE, 'w')
    f.write(v)
    for i in encrypted:
        f.write(i)
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
