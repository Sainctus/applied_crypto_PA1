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

#FIXME    print "The amount to pad is ", padding_required

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

#FIXME    print "The padding character is ", padChar

    for i in range(padding_required):
        data += padChar

    return data

#####################################################################

def unpad(data):
    padChar = data[-1]

#FIXME    print "The character to be removed is: ", padChar


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

#FIXME    print "The number of characters to be removed is: ", padChar_int

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
    hex_text = binascii.hexlify(plain_text)
    hex_text = int(hex_text, 16)
    previous = int(previous, 16)
    temp = hex_text ^ previous
    temp = hex(temp)
    temp = temp[2:-1]
    print temp
    temp = binascii.unhexlify(temp)
    return temp

#####################################################################

#def unXOR(previous, decrypted):

#####################################################################

def main(KEYFILE, IFILE, OFILE):
    #This block looks at the value of IV and attempts to open it as a file. If successful, it reads the IV value from file. If unsuccessful, it uses a randomly generated IV.
    v = IV
    try:
        f = open(v, 'r')
        v = f.read()
        f.close()
    except IOError:
        pass
#FIXME    print "The IV is: ", v, len(v)
#FIXME    print "\n"

    #Reads the key from file and prints
    f = open(KEYFILE, 'r')
    key = f.read()
    f.close()

#FIXME    print "The key is: ", key, len(key)
#FIXME    print "\n"

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

        blocks.append(s)
        if len(s) < 16:
            break
    
    temp = blocks[len(blocks) - 1]
    temp = temp[:-1]
    blocks[len(blocks) - 1] = temp

    if len(blocks[len(blocks) - 1]) == 16:
        blocks.append('')

    blocks[len(blocks) - 1] = pad(blocks[len(blocks) - 1])

#FIXME
    for i in blocks:
        print i

    print "\n"

    encrypted = []
    first = encrypt(key, prepare(blocks[0], v))
    encrypted.append(first)

    i = 0
    for i in range(len(blocks)):
        temp = prepare(blocks[i], encrypted[i - 1])
        temp = encrypt(key, temp)
        encrypted.append(temp)

#FIXME
    print "\n"
    for i in encrypted:
        print i

#    f = open(OFILE, 'w')
#    f.write(v)
#    for i in encrypted:
#        f.write(i)
#    f.close()

    decrypted = []
    for i in encrypted:
        temp = decrypt(key, i)

    print "\n"
    for i in decrypted:
        print i

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
