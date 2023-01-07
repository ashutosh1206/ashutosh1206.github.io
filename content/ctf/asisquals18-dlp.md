---
title: "DLP - ASIS CTF Quals"
date: 2018-01-16
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - NumberTheory
  - DLP
math: true
---

**Challenge Points**: 158

Ciphertext is generated as following:

~~~python
def encrypt(nbit, msg):
    msg = bytes_to_long(msg)
    p = getPrime(nbit)
    q = getPrime(nbit)
    n = p*q
    s = getPrime(4)
    enc = pow(n+1, msg, n**(s+1))
    return n, enc
~~~
We have: \\((n+1)^{msg}\mod n^{s+1}\\)  

Expanding the above equation Binomially, we get:  
$$\binom{msg}{0}n^{msg} + \binom{msg}{1}n^{msg-1} + \binom{msg}{2}n^{msg-2} + ... + \binom{msg}{msg-1}n + \binom{msg}{msg}n^0$$
$$(\binom{msg}{0}n^{msg-2} + \binom{msg}{1}n^{msg-3} + ... + \binom{msg}{2})n^2 + \binom{msg}{msg-1}n + \binom{msg}{msg}n^0$$
This can be written as:
\\((x)n^2 + mn + 1\\), where  
$$x = \binom{msg}{0}n^{msg-2} + \binom{msg}{1}n^{msg-3} + ... + \binom{msg}{2}$$

If we take the above result and divide it with \\(n^2\\), the following can be written:  
\\(xn^2 + mn + 1\equiv mn + 1\mod n^2\\) --> **(1)**

We know that \\(n^{s+1}\\) > \\(n^2\\) and \\(n^{s+1}\;\%\;n^2 = 0\\)  

Thus,  
\\(enc\equiv (n+1)^{msg}\mod n^{s+1}\\)  
\\(\implies enc\equiv (n+1)^{msg}\mod n^2\\)  

From (1), we can write:  
\\(enc\equiv msg\*n + 1\mod n^2\\)  
\\(\implies msg = \frac{(enc \mod n^2) - 1}{n}\\)

~~~python
hex(int(((enc%(n^2))-1)/n))[2:].replace("L","").decode("hex")
~~~
