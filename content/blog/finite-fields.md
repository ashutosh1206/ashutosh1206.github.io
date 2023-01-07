---
title: "Finite Fields - Number Theory"
date: 2017-11-28
author: Ashutosh Ahelleya
Categories:
  - Mathematics
  - Crypto
math: true
---

This blog post covers one of the most important Mathematical Structures for Cryptography- **Fields**. It is used in both Symmetric and Asymmetric key Cryptography.

This blog post gives a basic introduction to Finite Fields and arithmetic operations on it, but I hope the purpose of it is served- to make people, who don’t have basic knowledge about this, understand a few upcoming CTF write-ups, that are based on Finite Fields.

# Field

A set \\(F\\) of elements with an operation \\(o\\) that combines two elements of \\(F\\) using the following criteria:

 1. **Closure**: If \\(A\\) and \\(B\\) are two elements belonging to Field \\(F\\), then the result of the operation \\(A\;o\;B\\) must also belong to \\(F\\).

 2. **Associativity**: If \\(A\\), \\(B\\) and \\(C\\) are elements belong to \\(F\\), then \\((A\;o\;B)\;o\;C\\) = \\(A\;o\;(B\;o\;C)\\)

 3. **Identity Element**: There exists an element \\(e\\) in \\(F\\) such that for any \\(A\\) belonging to \\(F\\), \\(A\;o\;e = A\\), where \\(o\\) can be + or *

 4. **Additive Inverse**: For every element \\(A\\) in \\(F\\), there exists \\(A^{-1}\\) in F such that \\(A + A-1 = 0\\)

 5. **Multiplicative Inverse**: For all elements \\(A\\) except \\(0\\) in \\(F\\), there exists \\(A^{-1}\\) in \\(F\\) such that \\(A * A^{-1} = 1\\)

 6. **Distributive**


**Theorem of Finite Fields**: Finite Fields only exist if they have \\(p^m\\) elements, where \\(p\\) is a prime number and \\(m\\) is a positive integer

 1. For example: GF(11**1), GF(81) = GF(3**4), GF(256) = GF(2**8)
 2. Note that finite fields with p = 2 are of very importance
 3. GF(256 = 2**8) is used in AES

**Classification of Finite Fields**:

 1. \\(m = 1, \;\;GF(p)\\) → **Prime Fields**
 2. \\(m > 1, \;\;GF(p^m)\\) → **Extension Fields**

<br>
## Prime Field Arithmetic

 1. **Elements** of a prime field \\(GF(p)\\) are the integers \\({0, 1, ..., p-1}\\), where p is a prime number

 2. **Addition**, **subtraction** and **multiplication**
   + For \\(a\\), \\(b\\) belonging to \\(GF(p) = {0, 1, ..., p-1}\\)
   + \\(a\;o\;b\equiv c\mod p\\), where \\(o\\) can be +, - or *

 3. **Inversion**
   + If \\(a \in GF(p)\\), then \\(a^{-1}\\) must satisfy \\(a\;o\;a^{-1}\equiv 1 \mod p\\) (Multiplicative Inverse). Multiplicative inverse can be calculated using [Euclid’s Extended Algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)
   + If \\(a \in GF(p)\\), then \\(a^{-1}\\) must satisfy \\(a\;o\;a^{-1}\equiv 0 \mod p\\) (Additive Inverse)

<br>
## Extension Field Arithmetic \\(GF(2^m)\\)

 1. **Element Representation**

    + The elements of \\(GF(2^m)\\) are polynomials \\(a\_{m-1}x^{m-1} + a\_{m-2}x^{m-2} + ... + a_1x + a_0\\)
    + \\(a_i \in GF(2) = \\{0,1\\}\\)
    + Example: \\(GF(2^3) = a_2x^2 + a_1x + a_0 = (a_2, a_1, a_0)\\) ---> A vector
      + Since the value of \\(a_i\\) can only be 0 or 1, we can enumerate all the possible values to get the Galois Field.
      + \\(GF(2^3) = {0, 1, x, x+1, x^2, x^2+1, x^2+x, x^2+x+1}\\)

 2. **Addition** and **Subtraction** in \\(GF(2^m)\\)

    + Let \\(A(x)\\) and \\(B(x)\\) be elements belonging to \\(GF(2^m)\\). Then
      + \\(C(x) = A(x) \pm B(x) = \sum{c_ix^i}\\)
      + \\(c_i = (a_i \pm b_i) \mod 2 = (a_i + b_i) \mod 2\\)
    + \\(GF(2^3)\\): \\(A(x) = x^2 + x + 1\\), \\(B(x) = x^2 + 1\\), Compute \\(A(x) + B(x)\\)
      + \\(C(x) = ((1+1)\;\%\;2)x^2 + ((1+0)\;\%\;2)x + ((1+1)%2)\\)
      + \\(C(x) = x\\)

 3. **Multiplication** in \\(GF(2^m)\\)

    + Let \\(A(x)\\) and \\(B(x)\\) be elements belonging to \\(GF(2^3)\\). Then
      + \\(C'(x) = A(x)\*B(x) = (x^2+x+1)\*(x^2+1)\\)
      + \\(C'(x) = x^4+x^3+x^2+x^2+x+1 = x^4+x^3+x+1\\)
      + The present \\(C'(x)\\) we have, does not belong to the Galois Field, so we divide it by a polynomial that behaves like a prime (so that it cannot be factored). These polynomials are called **irreducible polynomials**.
      + \\(P(x) = p_ix_i\\), \\(p_i \in GF(2)\\)
        + \\(C(x) = A(x).B(x) \mod P(x)\\) where \\(P(x)\\) is an irreducible polynomial.
        + \\(P(x)\\) in this case is \\(x^3+x+1\\)
      + Therefore, \\(C(x) = x^2+x\\)
    + For every field, \\(GF(2^m)\\) there are several irreducible polynomials. Therefore, the irreducible polynomial has to be given in the first place.

 4. **Inversion** in \\(GF(2^m)\\)
    + For \\(A(x) \in GF(2m)\\), \\(A^{-1}(x)\\) can be calculated by [Extended Euclidean Algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)
