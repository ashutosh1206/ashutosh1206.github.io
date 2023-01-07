---
title: "RSA Quest - Pragyan CTF"
author: Ashutosh Ahelleya
date: 2018-03-04
categories:
  - Crypto
tags:
  - RSA
slug: pragyan18-rsaquest
math: true
---

**Challenge Points**: 200  
**Challenge Description**:

> Rivest comes up with an encryption, and Shamir creates a service for decrypting any cipher text encrypted using Rivests’s encryption. Adleman is asked to decrypt a specific ciphertext, but he is not able to do so directly through Shamir’s service. Help him out.

The server code running at 128.199.224.175:34000 allows encryption and decryption of messages using unpadded RSA except decryption of ciphertext of the flag.

> **Note**: In this challenge int to hex and hex to int encoding takes place using python3 commands; with a difference in endianness, and due to this issue many people doubted if there is a problem with the server. (Cleared by the admin later)

We are given the following parameteres
```
n = 130179694811800312207570599375436760545290337088218304459561443227543838919879210106932826718964709957832014565448443505831989481273635332857613422064190271780814608757655668142589722653217662666575372999741816137327886126560719421767007673263336883710369488981181599726557800745601802965236812530181411723711

e = 65537

ct = 69444498599002416146060355394198780924781341588951735779837421286848968498675554009357869905898781520148872399183326755878612193934013951525822693629914603289302941879673741297386997183303536805694154814524708401271363470581810272090735001235877055650310458867045448669590067228718232647309402304869321062304
```

\\(ct \equiv m^e\mod n\\), where `m` is the flag
We have to somehow decrypt `ct` using services provided by the server. We cannot send `ct` as the server has blacklisted that from decryption!

## Chosen Ciphertext Attack
If we send \\(c = ct\*2^e\mod n\\) as ciphertext (`c` is not blacklisted!) to the server, the following calculations will take place during the process of decryption:  
$$(ct\*2^e)^d\equiv (ct^d\*2^{ed})\mod n$$
$$\equiv (ct^d\mod n)\*(2^{ed}\mod n) \mod n$$
$$\equiv m\*2^{1+k\*\phi(n)}\mod n$$
$$\equiv m\*2\*2^{k\*\phi(n)}\mod n$$

From [Euler's Theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem), we can write:  
\\(m\*2\*2^{k\*\phi(n)}\equiv m\*2\mod n\\)  

Hence,  
\\(c = ct\*2^e \equiv 2\*m\mod n\\)

To calculate `m`, simply divide the resultant value returned by the server by 2!

## Getting the flag

Sent `c`, and got this value in return:
![picture](/pragyanctf-rsaquest.png)

Wrote the following script to get the flag:
~~~python
from Crypto.Util.number import *

# Conversion between bigendian and little endian
def conv(str1):
    str1 = str1[::-1]
    list1 = [str1[i:i+2] for i in range(0, len(str1), 2)]
    list1 = [i[::-1] for i in list1]
    return "".join(list1)

ct = "a0b75ef5dfd9ab0de9aa8c36a9c5aa28a924128a62826740ac3986efac69e2b85fc0df803e80da04c5f803726689e5f3134178de3cb203f6aebca22b376f7205d93a7224aca82cbbdc382200a1749fee095dfebe2aaabf99b622e4343bf5423cf6527433e26273e67d576157bf65a9258f613be9ad88d7b50350a89e676ae462"
ct = int(conv(ct), 16)

e = 65537
n = 130179694811800312207570599375436760545290337088218304459561443227543838919879210106932826718964709957832014565448443505831989481273635332857613422064190271780814608757655668142589722653217662666575372999741816137327886126560719421767007673263336883710369488981181599726557800745601802965236812530181411723711

print "n: ", n
print "ct: ", ct

mul = pow(2, e, n)
input = ct*mul % n

print "input: ", conv(hex(input)[2:-1])

output = "e0c6e8ccf66266f0e8c4609ed6bca4e66856d2e6c0ecaad8dc66e468c462ca58e06888fcd262fa0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
output = conv(output)
output = int(output, 16)/2
print long_to_bytes(output)[::-1]
~~~

**Flag**: ```pctf{13xtb0Ok^Rs4+is`vUln3r4b1e,p4D~i1}```
