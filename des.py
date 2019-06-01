#!/usr/bin/python

from varibles import *

def EncryptionRounds(permblock, key):
    Leftbits, Rightbits = permblock[:32], permblock[32:]
    roundnumber = 0
    keyfunc(key)
    while roundnumber <= 15:
        #print("Round: ", roundnumber + 1)
        #print("The Left bits:\t\t",Leftbits)
        #print("The Right bits:\t\t",Rightbits)
        Leftbits, Rightbits = Rightbits, format((int(Leftbits, 2) ^ int(Ffunction(Rightbits, key[roundnumber]), 2)), '032b')
        roundnumber += 1
    final = Permutation(IPI, Leftbits+Rightbits)
    #print("output block:\t\t", final)
    #print()
    return final
        
def Ffunction(rightbits, subkey):
    sboxinput = Permutation(SE, rightbits)
    #print("sbox expansion:\t\t", sboxinput)
    sboxinput = int(sboxinput, 2) ^ int(subkey)
    sboxinput = format(sboxinput, '048b')
    #print("sboxinput:\t\t", sboxinput)
    sboxinputsplit = [sboxinput[i:i+6] for i in range(0, len(sboxinput), 6)]
    sboxnumber = 0
    sboxoutput = []
    for bits in sboxinputsplit:
        #print("sbox {0} input: {1}".format(sboxnumber+1, bits))
        bits = list(bits)
        row = [bits.pop(0), bits.pop(-1)]
        coloumn = bits
        row = int(''.join(row),2)
        coloumn = int(''.join(coloumn),2)
        #print("\tcoloumn:",coloumn)
        #print("\trow:\t",row)
        sboxin = format(Sbox[sboxnumber][row][coloumn], '04b') 
        #print("\tsboxoutput: ", sboxin)
        sboxoutput.append(sboxin)
        sboxnumber += 1
    ffunctionoutput = Permutation(P, ''.join(sboxoutput))
    #print("ffunctionoutput output:\t", ffunctionoutput)
    return ffunctionoutput 

def keyfunc(key):
    listofkeys = []
    #print("input key:\t\t", key)
    SingleShiftRounds = [1, 2, 9, 16]
    keyperm = Permutation(PC, key)
    #print("permkey:\t\t", keyperm)
    leftkey, rightkey = keyperm[:28], keyperm[28:]
    #print("leftkey:\t\t", leftkey)
    #print("rightkey:\t\t", rightkey)
    leftkey = list(leftkey)
    rightkey = list(rightkey)
    RoundNumber = 1
    while RoundNumber <= 16:
        #print(RoundNumber)
        if any(SingleShiftRounds) == RoundNumber:
            #print("Single shift")
            leftkey.append(leftkey.pop(0))
            rightkey.append(rightkey.pop(0))
            #print("leftkey:\t\t {}".format(''.join(leftkey)))
            #print("rightkey:\t\t {}".format(''.join(rightkey)))
        else:
            #print("double shift")
            leftkey.append(leftkey.pop(0))
            leftkey.append(leftkey.pop(0))
            rightkey.append(rightkey.pop(0))
            rightkey.append(rightkey.pop(0))
            #print("leftkey:\t\t {}".format(''.join(leftkey)))
            #print("rightkey:\t\t {}".format(''.join(rightkey)))
        subkey = Permutation(PC2, ''.join(leftkey+rightkey))
        listofkeys.append(subkey)
        RoundNumber += 1;
    return listofkeys

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
    #print("Plaintext in bits: "+plaintextbits+"\n")
    bitlengthcheck = len(plaintextbits) % 64
    if bitlengthcheck != 0:
        print("Input string not correct length must be 64bit blocks")
        print("Last block currently at: ", bitlengthcheck)
    plaintextblocks = [plaintextbits[i:i+64] for i in range(0, len(plaintextbits), 64)]
    ciphertext = []
    for block in plaintextblocks:
        #print("input block: \t\t", block)
        ciphertext.append(EncryptionRounds(Permutation(IP, block), key))
    ciphertextfile = ''.join(ciphertext)
    ciphertext = open('cipher.txt', 'w')
    ciphertext.write(ciphertextfile)
