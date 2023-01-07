---
title: CBC Bit Flipping Attack
date: 2017-05-03
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - CBC-Bit-Flipping
  - BlockCipher
---

In this blog post, the attack on CBC mode of block cipher encryption will be discussed and in the end, detailed writeup for the [16th challenge of Matasano-Crypto-Challenge](https://cryptopals.com/sets/2/challenges/16) i.e. about the Bit Flipping Attack in AES-CBC will be provided with explanation!

I want the reader to go through these concepts discussed in the following blog posts, before actually understanding how the CBC Bit-Flipping Attack works:

 1. [Mode Detection Oracle](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher#mode-detection)
 2. [Blocksize Detection Oracle](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher#block-size-detection)

We will list down all the information one must have access to, in order to initiate this attack:

 1. Cipher text
 2. Encryption Oracle as E(“random string” || payload || “another random string”)
    + Here, in this function, the attacker is allowed to supply input to the encryption function as payload. This function is literally the heart of the attack. All the arguments for the attack will be supplied here.
 3. Decryption Oracle

## What is Bit Flipping Attack?

Bit Flipping Attack requires the mode of encryption used for encryption to be CBC(Cipher Block Chaining) about which you can read [here](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher).

This attack is usually in scenarios where the encryption function takes in some input as a payload, prepends a random string, appends another string to it before encrypting it. There are cases where the encryption function escapes some characters or character sequences from the payload supplied, before encrypting it. For example let us consider this function:

~~~python
def encrypt(payload):
    obj = AES.new(key, AES.MODE_CBC, iv)
    for i in xrange(len(payload)):
        if payload[i] == ";" or payload[i] == "=":
            payload = payload.replace(payload[i], "?")
    str1 = "comment1=cooking%20MCs;userdata=" + payload + ";comment2=%20like%20a%20pound%20of%20bacon"
    str1 = padding(str1)
    ciphertext = obj.encrypt(str1)
    return ciphertext
~~~

The function escapes “;” and “=” characters from the payload and then prepends and appends strings. It then encrypts the resultant string(concatenation of prepend string, payload and appended string).

The decryption function:
~~~python
def decrypt(ciphertext):
    obj1 = AES.new(key,AES.MODE_CBC,iv)
    plaintext = obj1.decrypt(ciphertext)
    if ";admin=true;" in plaintext:
        print "Yes, you did it"
    else:
        print "Nope, you didn't"
~~~

The given decryption function checks if “;admin=true;” is still present in the decrypted string. If yes, then the payload leads to successful login as the admin. But the problem here is: during the encryption since the “;” and “=” characters are escaped from the payload, one cannot directly give “;admin=true;” as payload since the encryption function will change it to “?admin?true?” before encryption.

**Brief summary**:

 1. The encryption function takes in payload and escapes some characters from it
 2. It then appends and prepends random string to the payload --> resultant string.
 3. Encrypts the resultant string and returns the cipher text.
 4. Decryption function decrypts the cipher text returned by the encryption function and checks if “;admin=true;” is present in the decrypted text. Since “;” and “=” are no longer present beside “admin”(due to escaping of characters), the decryption function does not allow login as the admin!

To understand the attack, we need to closely look how decryption takes place in this mode:

The decryption in CBC mode takes place as:  
![picture](/ctfzone18-ussh-11.png)

Let us suppose our “?admin?true?” is in the second block of plain text. This plain text block, is a result of XORing of cipher text of the same block and cipher text of the previous block, as we can see from the figure given above. Pay attention closely now.

What we am in control of, are the cipher text blocks. The attacker can manipulate them, before sending them as a parameter to the decryption function. A rule says that whenever one changes one byte(call this “flips”) at an offset in a cipher text block, the same offset is changed in the next plain text block (See the figure below!). Of course, when one flips one byte in a cipher text block, plain text of the corresponding block also changes; but we are not worried about the flip in the plain text block where the “random bytes” of the prepend string are present. What we are focusing now is the second plain text block, which essentially contains our “?admin?true?”.

![picture](/cbc-bit-flip-1.jpg)

Let us consider:

 1. The plain text block containing “?admin?true?” to be ‘P’.
 2. The cipher text block next to which we have the plain text block containing “?admin?true?” to be ‘A’.
 3. The cipher text block of the corresponding plain text block containing “?admin?true?” to be ‘B’.

Then we can write, (refer to the figure above)

**A = P xor BlockCipherDecryption(B)**

“BlockCipherDecryption” is the large block present in the figure as “Block Cipher Decryption” which decrypts a cipher text block based upon the standard encryption used. BlockCipherDecryption(B) is a constant since we are not flipping bits in “B” (Remember this!). For the nth byte of each block we can thus write,

**A[n] = P[n] xor BlockCipherDecryption(B[n])**    ——–> **1.**

BlockCipherDecryption(B[n]) can be written as:

**BlockCipherDecryption(B[n]) = A[n] xor P[n]**     ——–> **2.**

Value at **2.** is fixed. We know that we want P[n] in **1.** to be of our desired value(Let this be ‘PD’) whereas P[n] in **2.** is the actual value of the plain text (Let this be ‘PA’) after the decryption of cipher text without flipping any of them. So, A[n] then becomes:

**A[n] = PD xor A[n] xor PA**

or **A[n] = A[n] xor (PD xor PA)**

PD xor PA —> XOR of the desired plain text byte with the actual byte present in the plain text block.

So, we simply XOR the result (PD xor PA) with the actual value of the A[n]. The result is the value we should give at that byte in the cipher text block previous to the plain text containing “?admin?true?”.  
Repeat this for all other blocks.

## Cryptopals Challenge 16
In this challenge, “;” and “=” are replaced by “?”. Here in this case, the desired value is “;” or “=”.

XORing each with the actual value of plain text “?”, we get 4 and 2 respectively. Now we XOR this result with the offset in the actual cipher text block (A[n]). Repeat this for each byte to be manipulated. This gives the value to be supplied in the same offset so that the resultant plain text contains “;admin=true;” instead of “?admin?true?”.

Here is the exploit:

~~~python
cipher_list = []
payload = ";admin=true;"
ciphertext = encrypt(payload)
i = 0
while i*16 <= len(ciphertext):
    cipher_list.append(ciphertext[i*16: 16 + (i*16)])
    i += 1
cipher_list.remove(cipher_list[6])

attack_on_block = cipher_list[1]
list1 = list(attack_on_block)
list1[0] = chr(ord(list1[0]) ^ ord("?") ^ ord(";"))
list1[6] = chr(ord(list1[6]) ^ ord("?") ^ ord("="))
list1[11] = chr(ord(list1[11]) ^ ord("?") ^ ord(";"))
cipher_list[1] = ''.join(list1)
ciphertext = ''.join(cipher_list)

decrypt(ciphertext)
~~~

The entire solver script for this challenge can be found here: https://github.com/ashutosh1206/Matasano-Crypto-Challenges/blob/master/set2/p16/exploit.py


## References
[Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
