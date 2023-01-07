---
title: "BabyCrypto - CSAW CTF Quals"
date: 2017-12-05
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - BlockCipher
  - ECB-byte-at-a-time
math: true
---

This challenge was a bit overrated, there were no complications in the challenge, as you will see when we discuss the writeup.

In this challenge, we are supposed to get the flag which is present in the server.  
The server has an input-output program running, which gives AES-ECB encryption of the input given to it. The encryption takes place as follows:

 1. Takes the input from the user
 2. Appends `secret` (which is the flag here) to the input
 3. Pads to make it a multiple of blocksize
 4. Encrypts the resultant string using AES in ECB mode
 5. Gives the ciphertext as the output

We are only in control of the input to the server. Using the input that we give, we need to get the `secret`.

Let us have a look at how the blocks are divided when we send an input of size equal to the blocksize = 16:
```
       1st Block | 2nd Block | 3rd Block | ...
       Input     | Secret    | secret+padding ...
```

The first block contains 16 bytes of our input, which is known to us.  
When we send an input of size one less than the blocksize, then the block division is as follows:
```
        1st Block | 2nd Block    | 3rd Block | ...
        x         | Secret[1:17] | secret[17:]+padding ...
```

We can apply ECB Byte at a time attack in such a scenario about which you can read here:

 1. [https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher/Attack-ECB-Byte-at-a-Time](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher/Attack-ECB-Byte-at-a-Time)
 2. [http://cryptopals.com/sets/2/challenges/12](http://cryptopals.com/sets/2/challenges/12)  


Here `x = input + Secret[0]` and let the output in this case be `c1`.

We know the first 15 bytes of `block #1`, we can simply brute force 256 possibilities of the 16th byte in `block #1` by checking the corresponding ciphertexts of `block #1`.

![picture](/csawquals17-babycrypto-1.png)

For the second byte we send 14 random bytes + 1 byte of secret(we got from previous step) as the input to the server and then brute force for 2nd byte of secret which again has 256 possibilties. We keep on continuing this process to get each byte of the secret and finally get the flag:

![picture](/csawquals17-babycrypto-2.png)

**Flag**: flag{Crypt0_is_s0_h@rd_t0_d0...}  

To practice challenges based on this attack, check out challenges given [here](https://github.com/ashutosh1206/Crypton/tree/master/Block-Cipher/Attack-ECB-Byte-at-a-Time/Challenges)
