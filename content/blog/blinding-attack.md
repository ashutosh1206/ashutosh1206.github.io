---
title: Blinding Attack on RSA Signatures
author: Ashutosh Ahelleya
date: 2017-07-10
categories:
  - Crypto
tags:
  - Blinding-Attack
slug: rsa-blinding-attack
math: true
---

This blog primarily focuses on Blinding Attack- an elementary vulnerability in unpadded RSA digital signature algorithm that can be exploited to forge signatures. The working and properties of Digital Signatures will be described before directly jumping onto the attack. In the end, we discuss ways to prevent this attack.

## Unpadded Digital Signatures using RSA

RSA is a kind of **Trapdoor One-way Function**. Wikipedia describes a one-way function as a function that is easy to compute on every input, but hard to invert given the image of a random input. Here, “easy” and “hard” are to be understood in the sense of computational complexity theory, specifically the theory of polynomial time problems.

A trapdoor one-way function can only be inverted with the help of a **trapdoor** i.e. our \\(d\\), the private key in [public key cryptosystems](https://en.wikipedia.org/wiki/Public-key_cryptography).

Let \\(N\\) be the public modulus, \\(e\\) be the public key exponent and \\(d\\) be the private key exponent.

The relation between the three is as follows:
$$ed\equiv 1\mod \phi(n)$$

Let Alice and Bob be two generic parties wishing to communicate with each other and Marvin be the eavesdropper, trying to tamper the data transfer between the two parties.

The scenario here is as follows: Alice is trying to get Bob's signature on a message \\(M \in Z^\*\_N\\). To get a signature, Alice sends the message \\(M\\) where Bob signs the message \\(M\\) as follows:
$$S\equiv M^d\mod N$$

Here, \\(S\\) is the signature of the message \\(M\\).

In the above step, Bob applies his private key to the message and obtains a signature \\(S\\). Bob then sends this \\(S\\) to Alice or any other authentic party which needs the signature of Bob on \\(M\\). Since public key of Bob, as the name suggests, is known to the parties, the signature can be easily verified if it is generated from Bob or not by simply calculating:
$$S^e\equiv M\mod N$$

Only Bob has his private key and so the parties can conclude that the signature is authenticate and legible. In the next section, we will discuss some vulnerabilities in the above algorithm.

## Blinding Attack

Consider the same scenario here, except for the fact that this time Marvin wants the Bob's signature on a message \\(M\\) which Bob refuses. So instead of the signature on \\(M\\), Marvin asks for Bob's signature on “innocent looking” \\(M’\\) which he calculates as following:
$$M' = r^eM\mod N$$

Here \\(r\\) in the above equation is any arbitrary positive integer in the same interval as \\(M\\).

Bob agrees to sign this message \\(M’\\). Let \\(S’\\) be the signature generated in case of \\(M’\\). We can write \\(S’\\) as:
$$S'\equiv (M')^d\mod N$$

Upon receiving the signature of this message \\(M'\\), signature of message \\(M\\) can be easily forged by computing: \\(S\equiv S'r^{-1}\mod N\\)

Why does the above equation hold true? Let us see how:  
$$S' \equiv (M')^d\mod N$$
$$S' \equiv (r^eM)^d\mod N$$
$$S' \equiv rM^d\mod N$$

Multiplying both sides of the above equation with \\(r^{-1}\mod N\\)
$$S'r^{-1}\equiv rM^dr^{-1}\mod N$$
$$S'r^{-1}\equiv M^d\mod N$$
$$S\equiv S'r^{-1}\mod N$$

So without actually getting the signature on \\(M\\), Marvin could successfully manipulate the signature \\(S’\\) to gain the signature of \\(M\\) i.e. \\(S\\). This technique allows an attacker to get signature on a message of his choice without the consent of the one who is signing it.

## Preventing Blinding Attack

The question which arises now is, what could be the possible measures to prevent such attacks?

 1. If the signatory signs the Hash of the message \\(M\\) instead of signing the message itself, all the four steps in the attack would make no sense since \\(M'\\) would then be replaced by H(M’) (The hash function) and hence it cannot be divided by blinding factor to get back \\(M\\).

 2. Another advantage of using hash of the message instead of using the message is that a cryptographic hash can take an arbitrarily long message, and literally 'compress' it into a short string, in such a way that we cannot find two messages that hash to the same value. Hence, signing the hash is just as good as signing the original message, without the length restrictions we would have if we didn’t use a hash. This overcomes the size problem in RSA operation where the key has to be very large in order to sign smaller messages!

## References

1. Twenty years of Attacks on RSA: https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf
