---
title: "Locked Dungeons 2 - Swamp CTF"
date: 2018-04-03
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - CBC-Bit-Flipping
math: true
---

**Challenge Points**: 498  
**Challenge Description**:  

> The Dungeon Keeper learned from its mistake. This next lock is protected by even stronger encryption. We’re so close to the final level…there has to be a way in.

The Dark Dungeon series of crypto challenges were the only ones I enjoyed solving in the CTF. Rest of the crypto challenges were pathetic, involved a lot of guessing and were not really crypto challenges and can be called as puzzles.

However, I did not get time to solve Dark-Dungeons-2 during the CTF, since I was stuck in Pagoda challenges that ate up almost all of my time during the CTF (I solved them during the CTF, but did not enjoy at all)

Similar challenge: **HITCON CTF Quals 2017** - Secret Server

Locked Dungeons-2 is an improved version of Locked-Dungeon-1 challenge from the same CTF. I will post a write-up of Locked Dungeons-1 soon.

In this challenge, we are given an encryption code that is running on the server: `nc chal1.swampctf.com 1460`

Looking at the source code:
~~~python
if __name__ == "__main__":
    with open("flag.txt") as fd:
        flag = fd.read()
    flag_size = len(flag)

    key=KEY
    insertion_range = flag_size//BLOCK_SIZE
    insertion_position = random.randrange(insertion_range)*BLOCK_SIZE
    mod_flag = flag[:insertion_position] + "send_modflag_enc" + flag[insertion_position:]

    aescipher = AESCipher(key)
    enc_mod_flag = aescipher.encrypt_wrapper(mod_flag, IV)
    sys.stdout.write(enc_mod_flag)
    sys.stdout.write('\n')
    sys.stdout.flush()
    next_level = False

    for i in range(insertion_range):
        sys.stdout.write("What do you want me to do?\n")
        sys.stdout.flush()
        enc_recv_str = raw_input()
        dec_recv_str = aescipher.decrypt_wrapper(enc_recv_str)
        if "get_modflag_md5" in dec_recv_str:
            next_level = True
            sys.stdout.write("Dungeon goes deeper..\n")
            sys.stdout.flush()
            break
        else:
            sys.stdout.write("I am gonna ask again!\n")
            sys.stdout.flush()

    if next_level:
        len_enc_mod_flag = len(enc_mod_flag)
        inp_size_limit = int(len_enc_mod_flag*4/3) + 50
        for i in xrange(500):
            enc_recv_str = raw_input()
            if len(enc_recv_str) > inp_size_limit:
                continue
            dec_recv_str = aescipher.decrypt_wrapper(enc_strrecv_str)
            sys.stdout.write(b64encode(md5(dec_recv_str).digest()))
            sys.stdout.write("\n")
            sys.stdout.flush()
~~~

## The Vulnerability

There are two levels in the challenge, each level involving the following attacks:

 1. CBC Bit Flipping Attack
 2. Byte by Byte decryption due to vulnerable unpadding

Let us have a look at the first level:
![picture](/swamp18-lockeddungeons-1.png)

 1. The program encrypts **mod_flag** = flag[:insertion_position] +  “send_modflag_enc” + flag[insertion_position:] using AES in CBC mode.
 2. *insertion_position* is generated using a pseudo-random number generator, with its limits being from 0 to flag_size\*16. <u>Small enough to be brute-forced</u>.

To pass level-1, our motive as an attacker, is to flip “send_modflag_enc” to “get_modflag_md5\x01”, given the ciphertext of **mod_flag**. The server allows decryption of ciphertext. We can do this using CBC Bit Flipping attack, about which you can read here: https://masterpessimistaa.wordpress.com/2017/05/03/cbc-bit-flipping-attack/

This is what decryption looks like in CBC mode:
![picture](/ctfzone18-ussh-11.png)

To pass level-1 we brute-force the program until *insertion_position* becomes zero, so that “send_modflag_enc” comes in the first block of ciphertext and we can then flip it easily as we are in control of the **Initialisation Vector**. We know can do this by changing IV to:  

    IV = IV xor “send_modflag_enc” xor “get_modflag_md5\x01”

Code snippet implementing the brute force first and then Bit Flipping Attack on CBC mode:
~~~python
while fl == 0:
    r = remote("chal1.swampctf.com","1460")
    ct = r.recvline()
    ct = ct.replace("\n","")
    ct = ct.decode("base64")

    r.recvline()

    init_vector = ct[:16]
    ciphertext = ct[16:]

    res = xor("get_modflag_md5\x00","send_modflag_enc")
    assert xor(res, "send_modflag_enc") == "get_modflag_md5\x00"

    # CBC Bit Flipping Attack
    iv = xor(xor("get_modflag_md5\x00","send_modflag_enc"), init_vector)

    send_string = (iv + ciphertext).encode("base64").replace("\n","")
    print "Sending string: ", send_string

    r.sendline(send_string)
    recvline1 = r.recvline()
    print recvline1.strip("\n")
    if recvline1[:21] == "Dungeon goes deeper..":
        fl = 1
        break
    r.close()
~~~

Now that we have bypassed the first level of the challenge, we can look at the code for the **second level**:
![picture](/swamp18-lockeddungeons-2.png)

The server allows the user to decrypt the ciphertext, but only returns the md5 of the plaintext. Oops!

Looks secure in the first place since a hash is a one-way function and it becomes such a long task to find a preimage. But when we look at the function for removing the padding after decryption:
~~~python
unpad = lambda inp: inp[:-ord(inp[-1])]
~~~

Strange, isn’t it? No validation, no checks if the last character is really less than or equal to 16 or if it really satisfies PKCS#7 padding criteria? Totally vulnerable to Byte-at-a-time decryption!

We can flip last byte of second last block of ciphertext to make last byte of the plaintext equal to chr(len(`plaintext`)-1), so when the server decrypts it, it straight away removes all the characters in the plaintext other than the first character and returns the md5 hash of this character. We can now brute force the value returned by checking if it matches with the md5 hash of a printable character, if yes then that character is first character of the flag.

For the next character, flip last byte of second last block of ciphertext to make last byte of the plaintext equal to chr(len(plaintext)-2), so the server will now return the md5 hash of the first two characters of the plaintext, we have the first byte of plaintext from above, we just have to brute the second byte like we did above.

Do the same to get all characters of the plaintext.

Let’s see how we can implement this exploit:

 1. Given the ciphertext containing the flag and “send_modflag_enc” prepended in the beginning (Since we have bypassed level-1, remember we had to brute force until insertion_position became 0? ), we have to add two more blocks of ciphertext ie. 32 bytes: 15*”a” + x + 16*”a”, x is the value we are going to brute force. We are adding two more random blocks to the ciphertext to be decrypted so that our Bit Flipping does not affect the original plaintext string (Remember CBC mode?)

 2. We need to know the last byte of the plaintext who ciphertext is the payload that we will send, only then we will be able to flip it to the desired value. Note that we will have to do it only once for a session. I wrote the following script to implement this:

    ~~~python
    for i in range(len(flag)+1, 16):
    last_ptchar = ''
    if i == 1:
        for j in range(256):
            _ciphertext = init_vector + ciphertext
            _payload = _ciphertext + "a"*15 + chr(ord("a") ^ (len(ct)+32-i) ^ j) + "a"*16
            _payload = _payload.encode("base64").replace("\n","")
            print "Sending payload: ", _payload

            assert len(_payload.decode("base64")) % 16 == 0
            assert len(_payload) <= inp_size_limit

            r.sendline(_payload)
            hash1 = r.recvline()
            hash1 = hash1.replace("\n","")

            print "Hash: ", hash1
            print "Hash of s: ", hashlib.md5("s").digest().encode("base64").replace("\n","")
            print "\n \n"

            if hash1 == hashlib.md5("s").digest().encode("base64").replace("\n",""):
                last_ptchar += chr(j)
                print "Last character of plaintext: ", chr(j).encode("hex")
                break
            counter += 1
    ~~~
 3. Now that we have our last character, we flip the last byte of second last block of our payload ('x') such that x = x xor (len(ct)+32-1) xor last_ptchar. Get the hash output from the server, check md5 hash of which character matches with the hash output. Repeat the same thing to get all the bytes of the plaintext.

Here is the entire exploit script. Note that I had to run this script multiple times, updating the value of flag in each run with the value I got in the previous run. This is because the server allows only 500 requests per session.
~~~python
from pwn import *
import IPython
import string
import hashlib

printables = string.uppercase + string.lowercase + string.digits

def xor(s1,s2):
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s1,s2))

fl = 0

while fl == 0:
    r = remote("chal1.swampctf.com","1460")
    ct = r.recvline()
    ct = ct.replace("\n","")
    ct = ct.decode("base64")

    r.recvline()

    init_vector = ct[:16]
    ciphertext = ct[16:]

    res = xor("get_modflag_md5\x00","send_modflag_enc")
    assert xor(res, "send_modflag_enc") == "get_modflag_md5\x00"

    # CBC Bit Flipping Attack
    iv = xor(xor("get_modflag_md5\x00","send_modflag_enc"), init_vector)

    send_string = (iv + ciphertext).encode("base64").replace("\n","")
    print "Sending string: ", send_string

    r.sendline(send_string)
    recvline1 = r.recvline()
    print recvline1.strip("\n")
    if recvline1[:21] == "Dungeon goes deeper..":
        fl = 1
        break
    r.close()

# Script stops as soon as the counter reaches 500
# 500 is the server request limit
counter = 0
inp_size_limit = int(len(ct.encode("base64"))*4/3) + 50
print "[*] Brute Force Worked, now onto the exploit"
print "Input string limit: ", inp_size_limit

flag = ""

# Original Ciphertext: ciphertext
# Original IV: init_vector
last_ptchar = ''
for i in range(len(flag)+1, 16):
    if i == 1:
        for j in range(256):
            _ciphertext = init_vector + ciphertext
            _payload = _ciphertext + "a"*15 + chr(ord("a") ^ (len(ct)+32-i) ^ j) + "a"*16
            _payload = _payload.encode("base64").replace("\n","")
            print "Sending payload: ", _payload

            assert len(_payload.decode("base64")) % 16 == 0
            assert len(_payload) <= inp_size_limit

            r.sendline(_payload)
            hash1 = r.recvline()
            hash1 = hash1.replace("\n","")

            print "Hash: ", hash1
            print "Hash of s: ", hashlib.md5("s").digest().encode("base64").replace("\n","")
            print "\n \n"

            if hash1 == hashlib.md5("s").digest().encode("base64").replace("\n",""):
                print "Gotit!"
                last_ptchar = chr(j)
                print "Last character of plaintext: ", chr(j).encode("hex")
                # We already know that the first 16 characters of the plaintext is "send_modflag_enc"
                flag += "s"
                break
            counter += 1
    else:
        print "Counter: ", counter
        _ciphertext = init_vector + ciphertext
        _payload = _ciphertext + "a"*15 + chr(ord("a") ^ (len(ct)+32-i) ^ last_ptchar) + "a"*16
        _payload = _payload.encode("base64").replace("\n","")
        print "Sending payload: ", _payload

        assert len(_payload.decode("base64")) % 16 == 0
        assert len(_payload) <= inp_size_limit

        r.sendline(_payload)
        hash1 = r.recvline()
        hash1 = hash1.replace("\n","")

        for j in printables:
            if hash1 == hashlib.md5(flag + j).digest().encode("base64").replace("\n",""):
                flag += j
                break
~~~
Note that we took advantage of the fact that the first 16 characters of the plaintext are "send_modflag_enc".

This will give us the flag: **flag{Ev3n_dunge0ns_are_un5af3_wIth_vu1n_padding}**
