#!/usr/bin/python
#test
#test
#test
#test

from varibles import *

def EncryptionRounds(permblock, key):
    Leftbits, Rightbits = permblock[:32], permblock[32:]
    roundnumber = 0
    KeySchedule(key)
    while roundnumber <= 15:
        Leftbits, Rightbits = Rightbits, format((int(Leftbits, 2) ^ int(Ffunction(Rightbits, key[roundnumber]), 2)), '032b')
        roundnumber += 1
    final = Permutation(IPI, Rightbits+Leftbits)
    return final
        
def Ffunction(rightbits, subkey):
    sboxinput = Permutation(SE, rightbits)
    sboxinput = int(sboxinput, 2) ^ int(subkey)
    sboxinput = format(sboxinput, '048b')
    sboxinputsplit = [sboxinput[i:i+6] for i in range(0, len(sboxinput), 6)]
    sboxnumber = 0
    sboxoutput = []
    for bits in sboxinputsplit:
        bits = list(bits)
        row = [bits.pop(0), bits.pop(-1)]
        coloumn = bits
        row = int(''.join(row),2)
        coloumn = int(''.join(coloumn),2)
        sboxin = format(Sbox[sboxnumber][row][coloumn], '04b') 
        sboxoutput.append(sboxin)
        sboxnumber += 1
    ffunctionoutput = Permutation(P, ''.join(sboxoutput))
    ("ffunctionoutput output:\t", ffunctionoutput)
    return ffunctionoutput 

def KeySchedule(key):
    listofkeys = []
    keyperm = Permutation(PC, key)
    leftkey, rightkey = keyperm[:28], keyperm[28:]
    leftkey = list(leftkey)
    rightkey = list(rightkey)
    RoundNumber = 1
    while RoundNumber <= 16:
        if any(SingleShiftRounds) == RoundNumber:
            leftkey, rightkey  = KeyEncryption(leftkey, rightkey)
        else:
            leftkey, rightkey  = KeyEncryption(leftkey, rightkey)
            leftkey, rightkey  = KeyEncryption(leftkey, rightkey)
        subkey = Permutation(PC2, ''.join(leftkey+rightkey))
        listofkeys.append(subkey)
        RoundNumber += 1;
    return listofkeys

def KeyEncryption(left, right):
    left.append(left.pop(0))
    right.append(right.pop(0))
    return left, right
    
def KeyDecryption(left, right):
    left = [left.pop(-1)] + left
    right= [right.pop(-1)] + right
    return left, right

def Permutation(table, bits):
    permbits = []
    for position in table:
        permbits.append(bits[position-1])
    return ''.join(permbits)

if __name__ == '__main__':
    keytextfile = open('key.txt', 'r')
    key = bin(int(keytextfile.read(), 16))[2:]
    plaintextfile = open('plain.txt', 'r')
    plaintextbits = ''.join(format(ord(char), 'b') for char in plaintextfile.read())
    bitlengthcheck = len(plaintextbits) % 64
    if bitlengthcheck != 0:
        print("Input string not correct length must be 64bit blocks")
        print("Last block currently at: {}", bitlengthcheck)
    plaintextblocks = [plaintextbits[i:i+64] for i in range(0, len(plaintextbits), 64)]
    ciphertext = []
    for block in plaintextblocks:
        ciphertext.append(EncryptionRounds(Permutation(IP, block), key))
    ciphertextfile = ''.join(ciphertext)
    ciphertext = open('cipher.txt', 'w')
    ciphertext.write(ciphertextfile)
