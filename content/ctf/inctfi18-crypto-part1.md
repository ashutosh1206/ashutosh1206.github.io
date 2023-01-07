---
title: "Crypto writeups [Part-1] - InCTFi 2018"
date: 2018-10-11
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - RSA
  - Coppersmith
math: true
---

InCTF is over and I must say that we enjoyed a lot! We stayed for two days straight in front of our laptop screens, sleep deprived, fixing services, solving queries on IRC, eating and what not! My experience organising InCTF-2018, creating crypto challenges, how I came across the idea of creating all the crypto challenges etc. is another blog post I have to write soon, let us jump to what is in scope of this blog post.

We will also be posting all the challenge source scripts, exploit scripts and write-ups to our team’s GitHub account- https://github.com/teambi0s by next week, so keep checking that!

This blog post covers intended solutions of two crypto challenges from InCTF-2018:  
Throwback and baby-Alice-Bob.

<br>

# Throwback

![picture](/inctfi18-crypto-part1-1.png)  
*Challenge Description*

This was the first and a warmup crypto challenge for InCTF International-2018. In this challenge you are given a ciphertext file `ciphertext.txt`, encryption script `encryptRSA.py`, and a public key file `public.pem`.

Let us see the contents of `encryptRSA.py`:
```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

key = RSA.importKey(open("public.pem").read())
n = key.n
e = key.e
flag = bytes_to_long(open("flag.txt").read())
ct = long_to_bytes(pow(flag, e, n))
open("ciphertext.txt",'w').write(ct)
```

Nothing suspicious, flag file is being encrypted in unpadded RSA using the public key. Let us have a look at the values of public key parameters, which we can get using the following python code:
```python
from Crypto.PublicKey import RSA
key = RSA.importKey(open("public.pem").read())
n = key.n
e = key.e
print n, e
```

Running the above script gives values of public key parameters:
```python
n = 698491229018617866913439446346471163472558208924077226680142788666975310538145321929146447762905069894035917431326487956250957720571978572823687849059920787303025692154070829036217928749360678725398133415179255935742309941010132694576977689456112119629015193398461689794498824641575321133336366067022953975900092198038260902623522501246578776626162635825107771722711940199404818420573142581587276540226521274722941752974216982918201384775694541078556882367813031L

e = 473942956098597820220469792845742500778787667370139945336962851836944820611758016955838474056135974449429651523689707189746956503090573007038882592192662108009105988801240992546857461015645973313376512628146439789647175954429224823945115651118751480270762628324283169644336180720618427405011551606650256747631187135571937711488876112426342905154035663354772248678642559769320890564854022113441429962294088612832697262354998514171764811530183386631750738577941129L
```

Hmm, looks like [Wiener’s Attack](https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Wiener)? No it isn’t. Try it! And does not give any output on running [RSACtfTool](https://github.com/Ganapati/RsaCtfTool) too. As we know that Wiener’s Attack works when \\(d < N^\frac{1}{4}\\).

To understand the attack used in this challenge, it would be great if you know the internals of Wiener’s Attack which you can read here: https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Wiener. Now, assuming that you now know the internals of Wiener’s Attack, let us head towards the attack in this challenge.

There is a cool attack, known as a variant of Wiener’s Attack on RSA, which works in cases when \\(d\\) is a few bits greater than \\(N^\frac{1}{4}\\). Here is a paper on it by Andrej Dujella: https://www.math.tugraz.at/~cecc08/abstracts/cecc08_abstract_20.pdf

I have also explained and implemented the attack in my library Crypton here: https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Wiener-variant. In short, variant of Wiener’s Attack on RSA states that in case \\(d\\) is a few bits greater than \\(N^\frac{1}{4}\\), candidates for private key are of the form:

$$rq_{m+1} + sq_m$$

where \\(q\_{m+1}\\) and \\(q\_{m}\\) are (m+1)th and (m)th convergent of continued fraction of \\(\frac{e}{n}\\).

Implementation of the attack in python/sage:
```python
from sage.all import *

def wiener(e, n):
    m = 12345
    c = pow(m, e, n)
    q0 = 1

    list1 = continued_fraction(Integer(e)/Integer(n))
    conv = list1.convergents()
    for i in conv:
        k = i.numerator()
        q1 = i.denominator()

        for r in range(30):
            for s in range(30):
                d = r*q1 + s*q0
                m1 = pow(c, d, n)
                if m1 == m:
                    return d
        q0 = q1
        return None
wiener(e, n)
```

Ran the script for around 1 and a half minute to get \\(d\\): 101163513230017858871883136800341227994997965012215130183396962583124452930473

Now, we can get the flag by simply decrypting the ciphertext using the private key we just obtained:
```python
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
ct = bytes_to_long(open("ciphertext.txt").read())
d = 101163513230017858871883136800341227994997965012215130183396962583124452930473
key = RSA.importKey(open("public.pem").read())
print long_to_bytes(pow(ct, d, key.n))
```

Which gives us the flag: **inctf{w4rmup_sh0uld_b3_wi3n3r_bu7_ext3nd3d}**! Voila!

I guess even Boneh Durfee attack can solve this challenge, but this attack is much shorter and easier to implement 🙂

Let me know your feedback on InCTF-2018 crypto challenges by [pinging me on Twitter](https://twitter.com/ashutosha_), or in the comments section!

<br>
# Baby-Alice-Bob
![picture](/inctfi18-crypto-part1-2.png)  
*Challenge Description*

This was the second challenge that was given for InCTF-2018. In this challenge you are given two ciphertext files `ciphertext1.txt` and `ciphertext2.txt`, encryption script `encrypt.py`, and two public key files `publickey1.pem` and `publickey2.pem`.

Let us analyse `encrypt.py`:
```python
#!/usr/bin/env python2.7

from Crypto.PublicKey import RSA
from Crypto.Util.number import *
import gmpy2
import sys

def get_e(N, p, q):
    e = getRandomInteger(30)
    while GCD(e, (p-1)*(q-1)) == 1:
        e += 1
    assert GCD(e, (p-1)*(q-1)) != 1
    return e

def prima(p):
    while not isPrime(p):
        p += 1
    assert isPrime(p)
    return p

def gen_publickey(sz):
    while True:
        coeff = getRandomInteger(5)
        p = getPrime(1024)
        q = coeff*p + getRandomInteger(512)
        p = prima(p)
        print "size(p): ", size(p)
        q = prima(q)
        print "size(q): ", size(q)
        print ""
        N = p*q
        e = get_e(N, p, q)
        return (e, N, p, q)

e1, N1, p1, q1 = gen_publickey(1024)
e2, N2, p2, q2 = gen_publickey(1024)

# Exporting private key for admin
priv_key = RSA.construct((N1, e1, None, p1, q1))
priv_key2 = RSA.construct((N2, e2, None, p2, q2))
open("privatekey1.pem","w").write(priv_key.exportKey("PEM"))
open("privatekey2.pem","w").write(priv_key2.exportKey("PEM"))

# Exporting public keys
pub_key = RSA.construct((N1, e1))
pub_key2 = RSA.construct((N2, e2))
open("publickey1.pem","w").write(pub_key.exportKey("PEM"))
open("publickey2.pem","w").write(pub_key2.exportKey("PEM"))

flag = open("flag.txt",'r').read()
flag_num = bytes_to_long(flag)
ct1 = pow(flag_num, e1, N1)
ct2 = pow(flag_num, e2, N2)

print "ciphertext1: ", ct1
print "ciphertext2: ", ct2
f1 = open("ciphertext1.txt", 'w')
f2 = open("ciphertext2.txt", 'w')
f1.write(long_to_bytes(ct1))
f2.write(long_to_bytes(ct2))
```

Some peculiar things to notice in this script:

 1. ​​​​​The two ciphertext files `ciphertext1.txt` and `ciphertext2.txt` are encrypted form of the same message.
 2. `get_e(N, p, q)` function:  e returned from this function satisfies the following condition: ​GCD(e, (p-1)\*(q-1)) != 1.  This implies that we cannot calculate \\(e^{-1}\mod (p-1)\*(q-1)\\) and hence \\(d\\) cannot be calculated directly.
 3. `gen_publickey()` function: something interesting - primes are related:  

```python
p = getPrime(1024)  
q = getRandomInteger(5)*p + getRandomInteger(512)  
p = prima(p)  
q = prima(q)  
```
   + They are not so close to allow Fermat’s Factorisation, and `getRandomInteger(512)` function is not pseudo-random. Hence, we cannot do anything with that.
   + `getRandomInteger(5)` generates numbers upto 32, so that can be bruteforced, remember that.

But one question that arises is: why two public keys? We don’t know that yet.

Let us approximate the values of \\(p\\) and \\(q\\) and see if we can find anything:

 1. `papprox` can be written as \\(N^\frac{1}{i}\\) where ​`i` is a brute-force iterator from 1-32.
 2. Upper bound for `qapprox` (maximum possible value) can be written as \\(i\*papprox + 2^{512}\\)
 3. Now that we have an upper bound for \\(​​q\\). If we make a univariate polynomial over modulo \\(N\\), for \\(P(x) = x - qapprox\\) , from Coppersmith’s theorem we know that we can find small roots of this polynomial efficiently to get \\(x\\) and then calculate ​\\(q\\) as qapprox (upper bound) - x. This will give us one of the factors of \\(N\\)! Voila!

We implement the same in sage/python (Similar to https://github.com/p4-team/ctf/tree/master/2017-09-02-tokyo/crypto_rsa):

```python
from sage.all import *

n = sys.argv[1]
e = sys.argv[2]
for i in range(1, 32):
    div = int(n/i)
    papprox = isqrt(div)
    qapprox = i*papprox + 2**512
    F. = PolynomialRing(Zmod(n))
    f = x - qapprox
    d = f.small_roots(X=2**512, beta=0.5)
    if d:
        d = d[0]
        print qapprox - d
        break
```

The above script gives us one factor each from \\(N_1\\) (publickey modulus from publickey1.pem) and \\(N_2\\) (publickey modulus from publickey2.pem), let us say they are \\(q_1\\) and \\(q_2\\) respectively.

```python
q1 = 3807106592404975601125033090180503344264174569255897409284423052897092445417674962362221548320775037781978870632221456368716628390293018864172214774714465531462065303179649214122810035176785416262624632995978331814185099550531145861149188438984893130980572838590794755709091002422200644150512364254454557260789

q2 = 2751296681586435626720222057380271100763911689072786354291138095461126286215853115732617512578076591584325152559069002543980487680247274388725342124525719292925128397536955722536120578433729304047954769670529111876899791612062118642496846657307745240072073877747762856779534078553583788593091249350529237188097
```

We can calculate \\(p_1\\) and \\(p_2\\) as: \\(\frac{N\_1}{q\_1}\\) and \\(\frac{N\_2}{q\_2}\\) respectively.

What after this? Remember, we cannot directly calculate decryption \\(d\\) from \\(e\\), \\(p\\), \\(q\\) due to reasons mentioned earlier. Why did the author give two ciphertext files and two pairs of public keys? Maybe we can use this somewhere? Moving on to the second and final level:

Notice that \\(GCD(e_1, p_1-1) = 1\\), where \\(e_1\\) is the encryption exponent of the first public key- `publickey1.pem`. Also, \\(GCD(e_2, p_2-1) = 1\\), where \\(e_2\\) is the encryption exponent of the second public key- `​publickey2.pem`. Umm, sounds like some progress? We probably have to do something with this...

We can calculate \\(m\mod p_1\\) from \\(ct_1\\) (ciphertext in `ciphertext1.txt`) as:
![picture](/inctfi18-crypto-part1-3.gif)

By Euler's Theorem, we can write:  
![picture](/inctfi18-crypto-part1-4.gif)

I made sure that \\(m\\) is not less than \\(p_1\\) 😉  
So you cannot directly get \\(m\\) from here, you will have to use the second key as well 😉

Now that we have \\(m\mod p_1\\), we can do the same calculations as above to get \\(m\mod p_2\\):  
![picture](/inctfi18-crypto-part1-5.gif)

We now have \\(m\mod p_1\\) and \\(m\mod p_2\\). We can now use CRT to calculate \\(m\mod p_1\*p_2\\). Ofcourse, now we can get ​​`m` (Try to think why!)

I wrote the following script in python that computes necessary operations discussed above and then CRT to give the flag!
```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

def crt(list_a, list_m):
    for i in range(len(list_m)):
        for j in range(len(list_m)):
            if GCD(list_m[i], list_m[j])!= 1 and i!=j:
                return None
    M = 1
    for i in list_m:
        M *= i
    list_b = [M/i for i in list_m]
    assert len(list_b) == len(list_m)
    list_b_inv = [inverse(list_b[i], list_m[i]) for i in range(len(list_m))]
    x = 0
    for i in range(len(list_m)):
        x += list_a[i]*list_b[i]*list_b_inv[i]
    return x % M

key1 = RSA.importKey(open("publickey1.pem").read())
key2 = RSA.importKey(open("publickey2.pem").read())
N1 = key1.n
e1 = key1.e
N2 = key2.n
e2 = key2.e

ct1 = bytes_to_long(open("ciphertext1.txt").read())
ct2 = bytes_to_long(open("ciphertext2.txt").read())

q1 = 3807106592404975601125033090180503344264174569255897409284423052897092445417674962362221548320775037781978870632221456368716628390293018864172214774714465531462065303179649214122810035176785416262624632995978331814185099550531145861149188438984893130980572838590794755709091002422200644150512364254454557260789
assert N1 % q1 == 0
p1 = N1 / q1

q2 = 2751296681586435626720222057380271100763911689072786354291138095461126286215853115732617512578076591584325152559069002543980487680247274388725342124525719292925128397536955722536120578433729304047954769670529111876899791612062118642496846657307745240072073877747762856779534078553583788593091249350529237188097
assert N2 % q2 == 0
p2 = N2 / q2

assert GCD(e1, (p1-1)) == 1
assert GCD(e2, (p2-1)) == 1

d1 = inverse(e1, (p1-1))
d2 = inverse(e2, (p2-1))
print "d1: ", d1
print "d2: ", d2
a1 = pow(ct1, d1, p1)
a2 = pow(ct2, d2, p2)
print long_to_bytes(crt([a1, a2], [p1, p2]))
```

Running the above script gives us the flag: **inctf{s4y\_hell0\_2\_c0pp3rsm1th\_&\_CRT}**! Voila! You must have understood by now why we need two ciphertext files, two public keys to solve this challenge! Go ahead and read the description of this challenge again 😉

Hope you enjoyed solving my challenges! I have to post writeups of 3 more crypto challenges which will be out soon! If you have any feedback or query regarding any of the crypto challenges from InCTF-2018, you can [ping me on Twitter](https://twitter.com/ashutosha_) or comment in the comments section below!  
