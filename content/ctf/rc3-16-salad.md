---
title: "Salad - RC3 CTF 2016"
date: '2016-11-22'
author: Ashutosh Ahelleya
categories:
  - Crypto
tags:
  - stream-cipher
slug: rc3-16-salad
math: true
---

**Challenge Points**: 100  
**Challenge Description**:  

> “The fault, dear Brutus, is not in our stars, but in ourselves.”  
> (I.ii.141) Julius Caesar in William Shakespeare’s Julius Caesar  
>  
> **Ciphertext**: 7sj-ighm-742q3w4t

Since every flag in the CTF had to start with "RC3-2016", we know partial plaintext value.

This led me to find a relation between the letters and the digits using the first 7 characters of the ciphertext and "RC3-2016". The pattern that I could figure out was this:

<table align="left">
    <tr>
      <th> plaintext </th>
      <th> ciphertext </th>
    </tr>
    <tr>
      <td> K </td>
      <td> 0 </td>
    </tr>
    <tr>
      <td> L </td>
      <td> 1 </td>
    </tr>
    <tr>
      <td> M </td>
      <td> 2 </td>
    </tr>
    <tr>
      <td> N </td>
      <td> 3 </td>
    </tr>
    <tr>
      <td> O </td>
      <td> 4 </td>
    </tr>
    <tr>
      <td> P </td>
      <td> 5 </td>
    </tr>
    <tr>
      <td> Q </td>
      <td> 6 </td>
    </tr>
    <tr>
      <td> R </td>
      <td> 7 </td>
    </tr>
    <tr>
      <td> S </td>
      <td> 8 </td>
    </tr>
    <tr>
      <td> T </td>
      <td> 9 </td>
    </tr>
    <tr>
      <td> U </td>
      <td> A </td>
    </tr>
    <tr>
      <td> V </td>
      <td> B </td>
    </tr>
</table>

<table align="right">
    <tr>
      <th> plaintext </th>
      <th> ciphertext </th>
    </tr>
    <tr>
      <td> 8 </td>
      <td> O </td>
    </tr>
    <tr>
      <td> 9 </td>
      <td> P </td>
    </tr>
    <tr>
      <td> A </td>
      <td> Q </td>
    </tr>
    <tr>
      <td> B </td>
      <td> R </td>
    </tr>
    <tr>
      <td> C </td>
      <td> S </td>
    </tr>
    <tr>
      <td> D </td>
      <td> T </td>
    </tr>
    <tr>
      <td> E </td>
      <td> U </td>
    </tr>
    <tr>
      <td> F </td>
      <td> V </td>
    </tr>
    <tr>
      <td> G </td>
      <td> W </td>
    </tr>
    <tr>
      <td> H </td>
      <td> X </td>
    </tr>
    <tr>
      <td> I </td>
      <td> Y </td>
    </tr>
    <tr>
      <td> J </td>
      <td> Z </td>
    </tr>
</table>

 plaintext| ciphertext |
 ---------| ---------- |
    W    |     C      |
    X    |     D      |
    Y    |     E      |
    Z    |     F      |
    0    |     G      |
    1    |     H      |
    2    |     I      |
    3    |     J      |
    4    |     K      |
    5    |     L      |
    6    |     M      |
    7    |     N      |


**Ciphertext**: 7sj-ighm-742q3w4t  

Using lookup table to substitute ciphertext character with its corresponding plaintext character, we get:   
**Flag**: RC3-2016-ROMANGOD  

Pretty basic :)  
Looking forward to exploring and solving more questions in Cryptography!
