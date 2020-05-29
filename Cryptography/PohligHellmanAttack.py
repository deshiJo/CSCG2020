import math
import Crypto.PublicKey
import Crypto.PublicKey.RSA as rsa
from math import gcd
from Crypto.Util.number import *
import gmpy2
import OpenSSL.crypto as crypto
import Crypto.Util.number as number
import time
import random
import Crypto.Util.number as num
import sympy.ntheory as sym

#First try was to choose d and calculate N from it. The resulting N was so big, that i could not get the primefactors to calculte q,p,phi(N) and e. But i thought that my approach must be correct and i have to calculate the key N,d such that C^d mod N = M.
#After a pause of 1 or two weeks from this challange i thought again about the problem and i came up with the idea to swap the order of my calculation. What if i choose an N and caclulate d with the discrete log or another method. 
#So i did some reasearch on attacking rsa by calulating the private exponent d. Wikipedia show some algorithms which make the calculation of the discrete logarithm more efficient.
#I also found a writeup of a similar challange from the BSidesSF2020 CTF, where the Pohlig-Hellman algorithm is used to calculate the discrete logarithm and find the correct (d,N) pair. https://blog.skullsecurity.org/2020/bsidessf-ctf-choose-your-own-keyventure-rsa-debugger-challenge. This seems to be the solution for our problem. So i decided to implement this in python (props to https://blog.skullsecurity.org/2020/bsidessf-ctf-choose-your-own-keyventure-rsa-debugger-challenge)

#given C,M
#calculate d,N such that C^d mod N = M

#https://blog.skullsecurity.org/2020/bsidessf-ctf-choose-your-own-keyventure-rsa-debugger-challenge
#https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
#we can use Pohlig-Hellman algorithm and calculate the discrete log from C^d mod N = M 
#if the order of the Group is smooth
#here is phi(N) = (p-1)*(q-1)

#Plan calculate P-1 and Q-1 with very small primes such that P,Q are prime
#Then we find the discrete log from C^d mod N = C (possible if we can map every element of the Group N and N>M)
#N must be at least as big as M, because C^d mod N = M. If N is smaller then M, the result of C^d mod N could never be equal M.


#choose Q = 2 as first prime -> just calculate smooth number P-1
q = 2


M = 1067267517149537754067764973523953846272152062302519819783794287703407438588906504446261381994947724460868747474504670998110717117637385810239484973100105019299532993569
C = 6453808645099481754496697330465
print("M (kind answer): {}".format(M))
print("C (Quak): {}".format(C))

sizeN = math.log2(M)/math.log2(2)
primes = [i for i in range(2,100000) if num.isPrime(i)]
#print(size)

#listOfSmoothNumbers = 
#calulate a smooth number of at least size "sizeNumber"
def calcSmoothNumberOfAtLeast(sizeNumber):
    p = 2
    l = [2]
    while(math.log2(p)/math.log2(2) < sizeNumber):
        n = random.choice(primes)
        l.append(n)
        p = p * n
        #print(p)
    #print("candidate : {}".format(p))
    return p, l

#find prime p with p-1 smooth
def calculateP(size):
    p = 1
    while(not num.isPrime(p)):
        cand, l = calcSmoothNumberOfAtLeast(size) 
        p = cand + 1
    return p, l

p, l = calculateP(sizeN)
N = p * q
phi = (p-1)*(q-1)
d = sym.discrete_log(N,M,C)
print("N : {}".format(N))
print("q : {}".format(q))
print("p : {}".format(p))
print("d : {}".format(d))
assert(gmpy2.powmod(C, d, N)==M)

e = gmpy2.divm(1,d,phi)
d = int(d)
e = int(e)

#export key
key = rsa.construct((N,e,d,p,q))
print(key)
f = open('final.pem', 'wb')
f.write(key.exportKey('PEM'))
f.close()



