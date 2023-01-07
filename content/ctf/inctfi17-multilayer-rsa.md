---
title: Multi Layer RSA - InCTFi 2017
date: 2017-12-18
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - RSA
  - Wiener's-Attack
math: true
---

**Challenge Points**: 100  
**Challenge Description**: [None]

Intended Solution

This is probably the easiest challenge in the Crypto section for this year's InCTF. The encryption script:  
```python
from Crypto.Util.number import *

flag = open("flag.txt").read()
flag = int(flag.encode("hex"),16)

p = getPrime(512)
q = getPrime(512)
n = p*q
phin = (p-1)*(q-1)

encryption_keys = [34961, 3617491, 68962801, 293200159531, 1191694878666066510321450623792489136756229172407332230462797663298426983932272792657383336660801913848162204216417540955677965706955404313949733712340714861638106185597684745174398501025724130404133569866642454996521744281284226124355987843894614599718553178595963014434904833]

for i in encryption_keys:
    assert GCD(i,phin) == 1

for i in encryption_keys:
    flag = pow(flag, i, n)

flag = hex(flag)[2:].replace("L","")

obj1 = open("ciphertext.txt",'w')
obj1.write(flag)
```

As we can see, the encryption is **layered**; after the message is encrypted using the first public key i.e. first element of `encryption_keys`, the result is then encrypted with the next public key i.e. second element of `encryption_keys` and so on. We can write it mathematically as:
$$c_1 \equiv m_1^{e_1}\mod n$$
$$c_2 \equiv c_1^{e_2}\mod n$$
$$...$$
$$c_5 \equiv c_4^{e_5}\mod n$$

Hence, we can write:
$$c_5\equiv m^{e_1e_2e_3e_4e_5}\mod n$$

Here \\(e_1, e_2, ..., e_5\\) elements of `encryption_keys`; \\(c_1, c_2, ..., c_5\\) are the ciphertexts in each iteration.

The result of multiplication of \\(e_1, e_2, e_3, e_4, e_5\\) becomes quite large and can be checked for [Wiener’s Attack](https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Wiener).

```python
e = 3047442173541658754667464233797118324917469250436575767227172319344577259865313428705759330024959317716760816959590728238918140105663188172228696589411452947738069773833351725455888549656717874059636289036277785342126992626060696063089487811946920569580454880169977542532087635095357205433679009382368108273
```

The final exploit (Implementation of Wiener’s Attack in python/sage):
```python
from sage.all import *

encryption_keys = [34961, 3617491, 68962801, 293200159531, 1191694878666066510321450623792489136756229172407332230462797663298426983932272792657383336660801913848162204216417540955677965706955404313949733712340714861638106185597684745174398501025724130404133569866642454996521744281284226124355987843894614599718553178595963014434904833]

e = 1
for i in encryption_keys:
    e *= i
n = 135568509670260054049994954417860747085442883428459182441559553532993752593294067458983143521109377661295622146963670193783017382697726454953197805014428888491744355387957923382241961401063461549210355871385000347645387907568135032087942016502668629010859519249039662555733548461551175133582871220209515648241

c = int("5d695edb47b81a303d162611f7d407579160ef8818929031e1e13ca20cb7094eddbb0658d95980e1753182c5d5c529fb45062891bb5da573c618e35df0103233ded582a53ed807846b19ea82be427f2bbc63e5c7eb685d8a22b2b7539cf45d4ad93bbf5b892b66288b568b6bbff6bb263d809475e6f0aa3cfd01539d8364c243", 16)

lst = continued_fraction(Integer(e)/Integer(n))
conv = lst.convergents()
for i in conv:
    k = i.numerator()
    d = int(i.denominator())
    try:
        m = hex(pow(c, d, n))[2:].replace("L","").decode("hex")
        if "inctf" in m:
            print m
    except:
        continue
```

Running the above script gives us the flag: **inctf{w13n3r’s_4774ck_s0lv3d_17_4ll_r1gh7?}**
