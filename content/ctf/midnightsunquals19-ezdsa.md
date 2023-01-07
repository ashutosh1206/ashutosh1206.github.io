---
title: "EZDSA - Midnight Sun CTF Quals"
date: 2019-04-09
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - NumberTheory
math: true
---

**Challenge Points**: 223  
**Challenge Description**:

> Someone told me not to use DSA, so I came up with this.

In this challenge, we are given a script that signs any message given as an input:
```python
class PrivateSigningKey:

    def __init__(self):
        self.gen = 0x44120dc98545c6d3d81bfc7898983e7b7f6ac8e08d3943af0be7f5d52264abb3775a905e003151ed0631376165b65c8ef72d0b6880da7e4b5e7b833377bb50fde65846426a5bfdc182673b6b2504ebfe0d6bca36338b3a3be334689c1afb17869baeb2b0380351b61555df31f0cda3445bba4023be72a494588d640a9da7bd16L
        self.q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4bL
        self.p = 0x80000000000001cda6f403d8a752a4e7976173ebfcd2acf69a29f4bada1ca3178b56131c2c1f00cf7875a2e7c497b10fea66b26436e40b7b73952081319e26603810a558f871d6d256fddbec5933b77fa7d1d0d75267dcae1f24ea7cc57b3a30f8ea09310772440f016c13e08b56b1196a687d6a5e5de864068f3fd936a361c5L
        self.key = int(FLAG.encode("hex"), 16)

    def sign(self, m):

        def bytes_to_long(b):
            return long(b.encode("hex"), 16)

        h = bytes_to_long(sha1(m).digest())
        u = bytes_to_long(Random.new().read(20))
        assert(bytes_to_long(m) % (self.q - 1) != 0)

        k = pow(self.gen, u * bytes_to_long(m), self.q)
        r = pow(self.gen, k, self.p) % self.q
        s = pow(k, self.q - 2, self.q) * (h + self.key * r) % self.q
        assert(s != 0)

        return r, s
```

We will use the notation below to represent the following variables:
```
`m`: integer representation of message input given to the server for signing  
`h`: integer representation of SHA-1 of a message `m`  
`u`: integer representation of a 20 byte randomly generated string in every session  
`key`: integer representation of the flag   
`g`: base element of the group; alias `gen`
```

The signature is similar to ElGamal signature, but works as follows:  
\\( k = g^{u\;\*\;m}\;\%\;q \\)  

\\( r = (g^{k}\;\%\;p)\;\%\;q \\)  

\\( s = ((k^{q-2}\;\%\;q)\*(h+(key\*r)))\;\%\;q \\)  

Server returns `(r, s)` pair for any \\(m\\) given as input (with one exception that we will see later in the post)

Our **motive** is to recover the value of `key`, since it is the integer representation of the flag!

## Setting a tentative target
If by giving some input, `k` becomes equal to 1, then recovering `key` becomes very easy:  
\\(s = ((k^{(q-2)}\;\%\;q)\*(h+(key\*r)))\;\%\;q \\)  
\\(s = ((1^{(q-2)}\;\%\;q)\*(h+(key\*r)))\;\%\;q \\)  
\\(s = (h+(key\*r))\;\%\;q\\)  
\\((s-h)\*r^{-1}\equiv key \mod q \\)  

We know the values of `h`, `r` and `s`, hence `key` can be calculated using the above formula,
on one **condition** that `k` becomes equal to 1

The question now is: **how** do we make the value of `k` equal to 1?

## Finding input such that k=1
We now need to find an input message `m` such that
\\(k = g^{u\;\*\;m}\;\%\;q = 1\\)

### Trivial Approach
The easiest approach is to send `q-1` as `m`. This is because   
\\(k = g^{u\;\*\;m}\;\%\;q\\)  
\\(k = g^{u\;\*\;(q-1)}\;\%\;q\\)  
\\(k = (g^{(q-1)}\;\%\;q)^{u}\;\%\;q\\)  
\\(k = 1^u\;\%\;q\\)  
\\(k = 1\\)  

The above set of equations is a direct consequence of Fermat's Little Theorem:

> if GCD(a, p) == 1 then:  
> \\(a^{(p-1)}\equiv 1 \mod p\\)

But there is a **problem**. If we look at an assert statement in the function that signs our message:
```python
assert(bytes_to_long(m) % (self.q - 1) != 0)
```

The above statement means that our message cannot be a multiple of q-1, hence we cannot send `q-1` as `m`.

### Applying Euler's Criterion
**Case-1**: `u` is an even number
In such a case, we can send `m = (q-1)/2` and get the following:  
\\(k = g^{u\;\*\;m}\;\%\;q \\)  
\\(k = g^{u'\;\*\;2\;\*\;m}\;\%\;q \\)  
\\(k = g^{u'\;\*\;2\;\*\;((q-1)/2)}\;\%\;q \\)  
\\(k = (g^{(q-1)}\;\%\;q)^{u'}\;\%\;q \\)  
\\(k = 1\;\%\;q = 1 \\)  

**Case-2**: `u` is an odd number, we send `m = (q-1)/2` and get the following:  
\\(k = g^{u\;\*\;m}\;\%\;q\\)  
\\(k = g^{u\;\*\;((q-1)/2)}\;\%\;q\\)  
\\(k = (g^{((q-1)/2)}\;\%\;q)^{u}\;\%\;q\\)  

From [Euler's Criterion](https://en.wikipedia.org/wiki/Euler%27s_criterion), we have:

>If GCD(a, p) == 1  
$$a^{(p-1)/2}\equiv \begin{cases} 1\;(mod\;p),\exists x\mid x^2\equiv a\mod p\\\ -1\;(mod\;p), otherwise \end{cases}$$

There are equal number of quadratic residues and quadratic non-residues in a group over a prime number. A proof of this is illustrated in Wikipedia:
![picture](/midnightsunquals19-ezdsa-1.png)
**Source**: *[Euler's Criterion proof - Wikipedia](https://en.wikipedia.org/wiki/Euler%27s_criterion)*

This basically means that no matter what, if `m = (q-1)/2`, value of `k` will be either `1` or `-1`. So, we sent `m = (q-1)/2` to the server, and got `r = g % q`. This straightaway implies that `k` turned out to be equal to 1.

`key` can then be simply calculated as:
$$ (s-h)\*r^{-1}\equiv key \mod p $$


```python
from Crypto.Util.number import *
h = 1317885328399162707374481214163502540222211181040L
q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4bL
# r, s values we got from the server after sending m = (q-1)/2
r = 698847418084580852997663919979623019513778951409L
s = 629758878500372559472644038362239654961033814558L
print long_to_bytes((s - h)*inverse(r, q) % q)
```

Flag: **th4t_w4s_e4sy_eh?**
