---
title: "GCM - Nullcon HackIM CTF"
date: 2019-02-05
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - CTR-Bit-Flippping
  - GCM
math: true
---

**Challenge Points**: 300  
**Challenge Description**: [None]

tl;dr

 1. CTR Bit Flipping
 2. Break GHASH to get authentication key **H** (unintended approach)
 3. Bypass authentication

The way we solved it (unintended approach) was pretty interesting!

## Challenge Internals

We are given a service that allows us to encrypt/decrypt data using AES-CTR mode. Code for this is as follows:
```python
def main():
    global sessionid
    username = input('Enter username: ')
    sessionid = sha256(username.encode()).digest()[:10]

    while True:
        print("Menu")
        print("[1] Encrypt")
        print("[2] Decrypt")
        print("[3] Exit")

        choice = input("> ")

        if choice == '1':
            msg = input('Enter message to be encrypted: ')
            if 'flag' in msg:
                print("You cant encrypt flag :(")
                continue
            c = encrypt(msg.encode())
            nonce = hexlify(c[0]).decode()
            ciphertext = hexlify(c[1]).decode()
            tag = hexlify(c[2]).decode()
            print(nonce + ':' + ciphertext + ':' + tag)
            continue

        if choice == '2':
            nonce, ciphertext, tag = input(
                'Enter message to be decrypted: ').split(':')
            nonce = long_to_bytes(int(nonce, 16))
            ciphertext = long_to_bytes(int(ciphertext, 16))
            tag = long_to_bytes(int(tag, 16))
            pt = decrypt(nonce, ciphertext, tag).decode()
            if pt == 'may i please have the flag':
                print("Congrats %s" % username)
                print("Here is your flag: %s" % flag)
            print(pt)
            continue

        if choice == '3':
            break
```
As you can see, the service does not allow encrypting messages that contain "flag" as a substring. Also, when we choose to decrypt data, the service checks if the decrypted data is equal to "may i please have the flag"
and gives the flag only if it is true.

Clearly, we will have to bypass the above service:  

 1. Encrypt some data that does not contain "flag", let us say "may i please have the flak"
 2. Flip some bytes and get ciphertext of "may i please have the flag"
 3. Send ciphertext obtained in step-(2) for decryption and get the actual flag

If what we just described in the above steps is correct, then a simple [CTR Bit Flipping attack](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher/Attack-CTR-Bit-Flipping) would be
sufficient to get the flag.

But things are not easy as they seem to be. Let us look at the encryption and decryption functions:
```python
def encrypt(msg):
    nonce = sessionid + Random.get_random_bytes(2)
    assert len(nonce) == 12
    ctr = Counter.new(32, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(msg)
    tag = GHASH(ciphertext, nonce)
    return (nonce, ciphertext, tag)


def decrypt(nonce, ciphertext, tag):
    assert len(nonce) == 12
    assert GHASH(ciphertext, nonce) == tag
    ctr = Counter.new(32, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext
```

As you can see, `encrypt()` not only encrypts our plaintext, but also creates an authentication tag - `tag` that happens to be a mitigation to CTR Bit Flipping Attack. Also, `decrypt()` function verifies if the authentication tag calculated from the ciphertext and authentication tag - `tag` given as input, match.

An authentication tag is basically a string assigned to a plaintext/ciphertext as a unique identifier. This means that if we flip bytes, we will not have the authentication tag of the corresponding new flipped data and we won't be able to get the flag.

> **Note**: If you want to read more about Authenticated Encryption, you can read it [from Crypton](https://github.com/ashutosh1206/Crypton/tree/master/Authenticated-Encryption). In case you only want to read about Message Authentication Code (MACs), you can read about them [from Crypton here](https://github.com/ashutosh1206/Crypton/tree/master/Message-Authentication-Code).

This immediately shifts our target to the function that creates an authentication tag, and search for vulnerabilities that can be exploited, so that we can bypass the authentication.

## Analysis of GHASH
Function for generating authentication tag - `GHASH()`
```python
def GHASH(ciphertext, nonce):
    assert len(nonce) == 12
    c = AES.new(key, AES.MODE_ECB).encrypt(nonce + bytes(3) + b'\x01')
    blocks = group(ciphertext)
    tag = bytes_to_long(c)
    for i, b in enumerate(blocks):
        tag += (bytes_to_long(b) * pow(bytes_to_long(H), i + 1, n)) % n
    return long_to_bytes(tag)
```

```
`nonce` : 10 most significant bytes of sha256 of username + 2 random bytes    
`c`     : AES ECB encryption of (nonce + "\x00\x00\x00\x01")  
`b`     : ciphertext block in each iteration (16 bytes)
```

Authentication tag - `tag` for a `k`-block plaintext is generated as:  
$$ tag = c + ((b_1 \*(H^1\;\%\;n))\;\%\;n) + ((b_2 \*(H^2\;\%\;n))\;\%\;n) + ... + ((b_k \*(H^k\;\%\;n))\;\%\;n) $$


For a `1`-block ciphertext, we can write:  
$$ tag = c+((b_1 + (H^1\;\%\;n))\;\%\;n) $$

Thus, if we have `c` for every session, we can calculate secret value `H` as:
$$ (tag-c)\*(b^{-1}\mod n) \equiv H^1 \mod n $$

## Retrieving `c` - unintended approach
We know that `c` is AES ECB encryption of (nonce + "\x00\x00\x00\x01")

We observe that:
AES ECB encryption of (nonce + "\x00\x00\x00\x01") is the same as "z"\*16 (one block containing of `z`'s - 16 bytes) XORed with AES CTR encryption of "z"\*16 (one block of `z`'s - 16 bytes).

That is:  
`(AES_ECB_enc(nonce + "\x00\x00\x00\x01"))` ==  `(("zzzzzzzzzzzzzzzz") xor (AES_CTR_enc("zzzzzzzzzzzzzzzz")))`.

To get `c`, we simply send "z"\*16 to the service for encryption and xor the result with "z"\*16 to get `c`

## Getting the flag
Now that we know how to calculate `c`, we can get the flag with the following steps:

 1. Encrypt some data that does not contain "flag", let us say "may i please have the flak"
 2. Flip some bytes and get ciphertext of "may i please have the flag"
 3. Calculate `H`, get authentication tag for "may i please have the flag"
 4. Send ciphertext obtained in (2) for decryption, along with authentication tag obtained in (3) and get the actual flag!

Full exploit:
```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import *
import hashlib

n = 327989969870981036659934487747327553919

def _encrypt(plaintext):
    r.recvuntil("> ")
    r.sendline("1")
    r.recvuntil("encrypted: ")
    r.sendline(plaintext)
    return r.recvline().strip()

def group(a, length=16):
    count = len(a) // length
    if len(a) % length != 0:
        count += 1
    return [a[i * length: (i + 1) * length] for i in range(count)]

def GHASH(ciphertext, nonce, c, H):
    assert len(nonce) == 12
    blocks = group(ciphertext)
    tag = bytes_to_long(c)
    for i, b in enumerate(blocks):
        tag += (bytes_to_long(b) * pow(H, i + 1, n)) % n
    return long_to_bytes(tag)

def xor(a, b):
    assert len(a) == len(b)
    return ''.join([chr(ord(ai)^ord(bi)) for ai, bi in zip(a,b)])

r = remote("crypto.ctf.nullcon.net","5000")
r.recvuntil("username: ")
r.sendline("test")

# Code for getting the authentication tag
# nonce, ciphertext, tag = _encrypt("z"*16).split(":")
# nonce = nonce.decode("hex")
# ciphertext = ciphertext.decode("hex")
# tag = tag.decode("hex")
#
# assert GCD(bytes_to_long("z"*16), n) == 1
# assert bytes_to_long("z"*16) < n
#
# assert len(ciphertext) == 16
# c = xor(ciphertext, "z"*16)
# b_inv = inverse(bytes_to_long("z"*16), n)
# H = ((bytes_to_long(tag) - bytes_to_long(c)) * b_inv) % n
#
# print H
# print type(H)
# print GHASH(ciphertext, nonce, c, H)
# print tag

H = 1100811469918366171773680758187695733

_plaintext = "may i please have the flak"
_nonce, _ciphertext, _tag = _encrypt(_plaintext).split(":")
_nonce = _nonce.decode("hex")
_ciphertext = _ciphertext.decode("hex")
_tag = _tag.decode("hex")

_c = xor(_ciphertext[:16], _plaintext[:16])
_ciphertext = _ciphertext[:-1] + chr(ord(_ciphertext[-1]) ^ ord('k') ^ ord('g'))
__tag = GHASH(_ciphertext, _nonce, _c, H)

_ciphertext = _ciphertext.encode("hex")
__tag = __tag.encode("hex")
_nonce = _nonce.encode("hex")

r.recvuntil("> ")
r.sendline("2")
r.recvuntil("decrypted: ")
r.sendline(_nonce + ":" + _ciphertext + ":" + __tag)

print r.recvline()
print r.recvline()
```
Running this script gave us the flag: **hackim19{forb1dd3n_made_e4sy_a7gh12}**
