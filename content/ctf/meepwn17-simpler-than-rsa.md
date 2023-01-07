---
title: "Simpler Than RSA - MeePwn CTF"
date: 2018-03-02
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - RSA
  - NumberTheory
math: true
---

**Challenge Points**: 100

We are given an encryption script [simple.py](https://github.com/ashutosh1206/Crypto-CTF-Writeups/blob/master/2017/MeePwn-CTF/Simpler-Than-RSA/simple.py):  

Other than the ciphertext, values of `n`, `g`, `h` are also public. The following function is used to generate values for the challenge:
~~~python
def generate(nbits):
	p = getPrime(nbits)
	q = getPrime(nbits)
	n = p * q * p
	g = random.randint(1, n)
	h = pow(g, n, n)
	return (n, g, h)
~~~

The encryption function:
~~~python
def encrypt(m, n, g, h):
	r = random.randint(1, n)
	c = pow(pow(g, m, n) * pow(h, r, n), 1, n)
	return c
~~~

As we can see, the ciphertext for each character in the plaintext is generated separately.  
For \\(i^{th}\\) byte of message we can write the corresponding ciphertext as:  
$$c_i \equiv ((g^{m_i}\mod n) \* (h^r\mod n)) \mod n$$
Given: \\(h \equiv g^n \mod n\\). We can now write:  
$$c_i \equiv ((g^{m_i}\mod n) \* (g^{nr}\mod n)) \mod n$$
$$\implies c_i \equiv g^{m_i + nr}\mod n$$

Since \\(n = p\*p\*q\\),  
\\(c_i \equiv g^{m_i + p^2qr}\mod n\\)  
\\(c_i \equiv g^{m_i + npr}\mod n\\) --> **(1)**  

Taking power \\((p-1)\*(q-1)\\) on both sides of **(1)**, we get:  
\\(c_i^{(p-1)(q-1)}\equiv g^{(m_i + npr)(p-1)(q-1)}\mod n\\)  
\\(c_i^{(p-1)(q-1)}\equiv g^{m_i(p-1)(q-1)}\*g^{nrp(p-1)(q-1)}\mod n \\)  

Since \\(\phi(n) = p(p-1)(q-1)\\),  
$$c_i^{(p-1)(q-1)}\equiv g^{m_i(p-1)(q-1)}\*g^{nr\phi(n)}\mod n $$  

From Euler's Theorem, we have:  
\\(a^{\phi(n)}\equiv 1\mod n\\)  

Hence, we can write:  
\\(c_i^{(p-1)(q-1)}\equiv g^{m_i(p-1)(q-1)}\mod n\\) --> **(2)**  

Now that we have eliminated `r` from the equation, let us first get the factors of `n` using [factordb.com](factordb.com):
```
    p = 1057817919251064684989791981
    q = 1103935256393984899021164397
```

Now that we have the factors, we can use **(2)** to get solution for each ciphertext byte.  
For each byte, we just have to check for 256 possibilities of corresponding message byte and a total of 54*256 brute-force checks to get the flag (We already know the other values in **(2)**: p, q, \\(c_i\\)).

Full exploit:
~~~python
import gmpy2
from Crypto.Util.number import *

n = 1235280093599323856390922798440377476467763531842392869674688408727824382702235317
g = 1110549711091392805024587195974719739929628997819528005374351081843256209971586072
h = 610466084395822279908554174354632326166097007218620288020807622478449585661028278

p = 1057817919251064684989791981
q = 1103935256393984899021164397
assert (p**2)*q == n

phin = p*(p-1)*(q-1)
# enc.txt is the ciphertext file
list1 = open("enc.txt",'r').read()[1:-2]
list1 = list1.split(",")
list1 = [int(i[:-1]) for i in list1]

# Exploit
list1 = [pow(i, (p-1)*(q-1), n) for i in list1]
msg = ""
for i in list1:
	for j in range(1, 256):
		if pow(g, j*(p-1)*(q-1), n) == i:
			msg += chr(j)
	print msg
~~~

**Flag**: MeePwnCTF{well_is_fact0rizati0n_0nly_w4y_to_s0lve_it?}
