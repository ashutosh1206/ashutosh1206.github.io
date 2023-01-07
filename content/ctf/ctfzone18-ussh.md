---
title: "USSH 3.0 - CTFZone"
date: 2018-07-23
author: Ashutosh Ahelleya
Categories:
  - Crypto
Tags:
  - BlockCipher
  - CBC-Bit-Flipping
math: true
---

**Challenge Points**: 138  
**Challenge Description**:  

> We've developed a new restricted shell. It also allows to manage user access more securely. Let's try it  
> `nc crypto-01.v7frkwrfyhsjtbpfcppnu.ctfz.one 1337`

In this post, I will be discussing my solution for USSH-3.0 challenge from CTFZone which I think is the unintended way. The challenge was quite peculiar, involving “blind” exploit as you will see in this write-up. Some parts of the challenge might look like guessing, but if you read this write-up start-to-end, you will see that it was a well-tailored challenge.

Also, this write-up is a timeline of my progress throughout the challenge- key observations, patterns that helped me move forward in the challenge and finally helped me make a payload that got me the flag!

So let us dive into the challenge details:
We are provided with a service running on `crypto-01.v7frkwrfyhsjtbpfcppnu.ctfz.one` and port number `1337`. On accessing the service using nc gives:
![picture](/ctfzone18-ussh-1.png)
![picture](/ctfzone18-ussh-2.png)

We are allowed to login using any username (see the limits on the username below). We are also assigned a group- **regular** to restrict permissions.

Some observations from the above pictures:

 1. We cannot login with username `admin​` or `root`.  Because login with that username will give us privileges to something in the service that we don’t know yet at this point of time in the challenge.

 2. After logging in, we get a *shell* kind-of interface where we can supply commands & if the command is recognised, it will be executed. Quickly going through commands- `help​`, `id`​, `session`, `exit`, `ls​`, `cat`.
   + Giving `ls` as the input gives us the output shown below. There are 3 files- flag.txt, info.txt, ​backup.sh. As the name suggests, flag.txt file contains the flag.

   + We can use the `cat` command to display the contents of any of the 3 files. We will try to display the contents of flag.txt because that is what seems to be the motive of this challenge. Feeding this command gives us: ![picture](/ctfzone18-ussh-3.png) We need to be of group **root**, to read this file (We don’t have permission to change our group, as it is done by the service. We are only allowed to give the username as the input). We will try displaying contents of other files: ![picture](/ctfzone18-ussh-4.png) Nothing that could be of help. So that seems a dead end. Let us try out other commands.

   + `id` -- shows the permissions of the user to which we are logged in ![picture](/ctfzone18-ussh-5.png)

   + `session` -- shows the base64 encoded session cookie, in a format we know nothing about. It also allows us to set a valid cookie, if we have it. ![picture](/ctfzone18-ussh-6.png)

All these findings, helped me clear the **objective** of the challenge

 1. **Login as admin** by getting it’s cookie
 2. Set the group as **root**.

At the current stage of solving the challenge, we still don’t know how the cookie is being generated. The only possible way to exploit the service would be to somehow know the format of the cookie and also how it is generated.

There is nothing else in the service, that could lead us to the admin login and root privileges except the cookie information.

## Exploring the session cookie
This is how a cookie looks like in the challenge: ![picture](/ctfzone18-ussh-7.png)  

This looks like two base64 encoded strings concatenated using a separator ‘:’ (colon), so let us check the contents and the length of these strings, to see what we can get:
![picture](/ctfzone18-ussh-8.png)  

Nothing in the content of these strings, but notice their lengths? They are a multiple of 16, reminds me of block cipher!

**Observations**: I tried the same giving different input strings, noting each of their lengths, and observed that no matter how long our login name is, the first part of the cookie (ie. the part before “:”), is always 16. Also, the length of the second part of the cookie depends on our input--- the longer our input is, longer will be the length of the second part of the cookie.

**Conclusions/Speculations**: I speculated that the first part of the cookie could be the Initialisation Vector for a CBC encrypted plaintext (of an unknown format, which contains our username somewhere), the ciphertext of which is the second part of the cookie.

But we need that our speculation is correct, so let us play around with the cookie’s first part.

 1. Remember that if the blocksize of a block cipher is 16 then it’s IV has to be of length 16 as well.

 2. We can use this property to check if the cookie is really encrypted using CBC mode or not. All we have to do is modify the cookie by setting it’s first part of length!=16. If the service shows an error, then our assumption is certainly correct. ![picture](/ctfzone18-ussh-9.png)  
 I just removed last byte from the first part of the cookie to check for any errors and fortunately I got one.

 3. Now that we certainly know that the cookie is being generated using a block cipher in CBC mode, we need to strengthen our assumption further, so let us try changing the length in the second part of the ciphertext too. We can also try changing the last byte in the second part of the cookie. (Note that the last byte in the ciphertext is the padding byte, so the service should throw a padding error if we change it’s value). ![picture](/ctfzone18-ussh-10.png)

 4. Slowly, the case scenario is getting clearer. We now know:
   + The cookie format (It consists of two strings separated by a colon)
   + The service is using a block cipher in CBC mode to encrypt the plaintext.
   + Plaintext is padded using PKCS#7

 5. What we do not know:
   + The contents and orientation of the plaintext before getting encrypted to generate the cookie
   + Location of the username in plaintext string

Let us find out what we do not know!

## Finding plaintext format of the cookie
Decryption in CBC mode:  
![picture](/ctfzone18-ussh-11.png)

The easiest way to check this is by modifying the IV by one byte such that we notice change in some byte of the username. As soon as we notice this, we get the index at which that flipped byte of the username is present, which can then be used to trace the location of our username in the plaintext.

We did it the same way- I changed the 11th index (12th character) of IV and noticed a changed in the 3rd character of my username:
![picture](/ctfzone18-ussh-12.png)

We can use this to trace the **positioning** of our username- 12th character in IV changes 3rd character of our username implies that our username starts from 10th character in the plaintext version of the cookie.

If I try to change any other index in IV other than the indices occupied by our username, the service throws an authentication error.

## Playing with the username - CBC Bit Flipping

Since the cookie is encrypted using CBC mode of encryption, we can flip IV bytes to get a username of our choice. Check out my [blog post](https://masterpessimistaa.wordpress.com/2017/05/03/cbc-bit-flipping-attack/) to read more about CBC Bit Flipping Attack.

I did a similar thing on the service; logged in as admun, flipped ‘u’ to ‘i’ and got the cookie for admin:
![picture](/ctfzone18-ussh-13.png)

Although we are able to login as admin, it still doesn’t give us the flag because cookie also contains the group to which a username belongs and it can only show the contents of flag.txt for users belonging to the root group :(

After this, I talked to the admin and he told me that the group is present after username in the cookie. So we got another lead, we surely have to work on it!

**Important**: One thing to notice is that, **group=root** could be in the second block of plaintext and that we will have to flip some bytes in the first block of ciphertext to change corresponding bytes in the plaintext.  Flipping even a single byte in the first block of ciphertext could lead to scrambling of the entire first block of plaintext (because block cipher!). This makes the task of flipping even more difficult (Check this challenge, if you want to test your Bit Flipping skills- [CNVService- ACEBEAR CTF 2018](https://masterpessimistaa.wordpress.com/2018/01/31/cnvservice-acebear-ctf-2018-writeup/))

## Towards developing payload
In every challenge, I always try to find some unusual solution to a challenge that makes things simpler. Same was the case with this challenge.

Our sole motive now that remains, is to exploit the authentication mechanism. Through some experience of solving challenges based on CBC Bit Flipping Attacks, I have now gained some knowledge of how authentication in most of the vuln services work. If you want to solve more challenges based on the same vuln, make sure you check out the following challenges:

 1. CNVService: ACEBEAR CTF 2018
 2. Level-21: [websec.fr](http://websec.fr/)

Let us see what could be the possible auth mechanism:

 1. Service separates IV and the ciphertext by splitting the cookie from the separator (which is a colon in our challenge)

 2. Decrypts the ciphertext using key and iv, gets the plaintext

 3. There could be a possible special character separating the username and the group (For most vuln servers it is username and password).
   + The first step in authentication is to split the plaintext into username and group using this special character acting as a separator.

   + The server then has two decrypted parts:
     + *First part*: contains `username=`
     + *Second part*: contains `group=` (You must be wondering why “group=” only and why not any other format? Because the error message in some case itself says “Permission denied, expect group=root” –> Check any of the above pictures to observe this)

   + Server auth mechanism:
     + **First check**: The server would then check if the first 9 bytes of the first part of the plaintext equal “username=”, if not, then it straightaway throws a VerificationError. If yes, then it moves to next step. (Why 9 bytes? Remember that when we were finding the index at which our username was located, we found it to be starting from 10th byte, the string prior to our username must be “username=”!).

     + After first check holds true, the server would store any subsequent characters of first part of the plaintext that come after “username=” as the actual username (for example: `testuser`, `admun` etc.).

     + **Second check**: The server would then check if the first 6 bytes of the second part of the plaintext equal “group=”, if not, then it straightaway throws a `VerificationError`. If yes, then it moves to the next step.

     + After second check holds true, the server would store any subsequent characters of the second part of the plaintext that come after “group=” as the group to which the username belongs (for example: `regular`, `root`) (Remember that in our challenge there exist only two groups: regular and root, so any other group other than these two would throw a `VerificationError`)

     + **Third check**: Server checks if the padding is valid or not. Not of interest as of now (we can come back to testing vulnerability here, if the next exploit doesn’t work)

     + Only after all the checks pass, does the service allow us to login using the username and group that it obtained from the previous steps.

## Exploiting python split() function implementation

For the auth mechanism above, the service would mostly split the plaintext as follows (Assuming that the character separating username and the group is “:” used only for illustration):
~~~python
list1 = plaintext.split(":")
username = list1[0]
group = list1[1]
~~~

Note that if there are multiple occurrences of “:” (ie. the separator), the above command would ignore any other “:” characters except it’s first occurrence! See this example to understand it better: ![picture](/ctfzone18-ussh-14.png)

(Observe the above picture carefully!)

What if we introduce this separator in the plaintext itself? Won’t that result in ignoring other occurrences of the separator and hence the string after the second “:” (This string is `group=regular`)? Yes, it will!

We can give the same username as the one just shown above: `admin:group=root` to get root access and also login as admin! We are very close to getting the flag!

But, not everything comes so easy:

 1. We don’t know the separator separating username and it’s group
 2. Even if we know the separator, we won’t be able to login using `​admin:group=root`, because login does not allow special characters in the input.

### Adding special characters to the username

This is fairly easy, as we can login as `​adminkgroup=root` and then flip 6th byte of the username from ‘k’ to the separator. Note that 6th byte in the username corresponds to 15th byte (14th index) in the IV according to our payload login username: `adminkgroup=root`.

### Finding the separator

I wrote the following script to brute force all the special characters. We can do this by registering under username `adminkgroup=root` and then flip ‘k’ with a special character in each iteration and check if username to which we are logged in is exactly equal to `​admin` or not. This happens because as soon as we get the correct separator, our exploit will work and we will be able to login as admin, otherwise the service would simply log us in with username `admin+<special_operator>+group=root`.

~~~python
from pwn import *
import string

def session_flip(iv, index, present_char, flip_char):
    assert len(present_char) == 1
    assert len(flip_char) == 1
    session = iv[:index] + chr(ord(iv[index]) ^ ord(present_char) ^ ord(flip_char)) + iv[index+1:]
    return session.encode("base64").strip()

possible_chars = string.punctuation

r = remote("crypto-01.v7frkwrfyhsjtbpfcppnu.ctfz.one","1337")
print r.recvuntil("Login:")
r.sendline("adminkgroup=root")
print r.recvuntil("@crypto: $ ")
r.sendline("session --get")

str1 = r.recvline("@crypto: $ ")
str1 = str1.strip()
"""
Session cookie consists of two parts: IV and the ciphertext,
separated by a some character `a` that we are going to find out by brute force
"""
print str1
iv, ciphertext = str1.split(":")
print "iv: ", iv
print "ciphertext: ", ciphertext

iv = iv.decode("base64")
for i in possible_chars:
    r.sendline("session --set " + session_flip(iv, 14, 'k', i)+":"+ciphertext)
    temp = r.recvuntil("@crypto: $ ")
    print "sent: " + i + " " + temp
~~~

Running this script gave me the following output:
![picture](/ctfzone18-ussh-15.png)

Notice that our exploit works for one particular special character- ‘&’

Now that we have everything, let us give input as `adminkgroup=root` and flip ‘k‘ with ‘&‘ to get the flag! Wrote the following script to flip characters:
~~~python
def session_flip(iv, index, present_char, flip_char):
    assert len(present_char) == 1
    assert len(flip_char) == 1
    session = iv[:index] + chr(ord(iv[index]) ^ ord(present_char) ^ ord(flip_char)) + iv[index+1:]
    return session.encode("base64")

input_str = raw_input("Enter the base64 cookie: ")
str1, str2 = input_str.split(":")
str1 = str1.decode("base64")

print session_flip(str1, 14, 'k','&').strip() + ":" + str2
~~~

This gives us: ![picture](/ctfzone18-ussh-16.png)
![picture](/ctfzone18-ussh-17.png)

Found the flag! I thoroughly enjoyed solving this challenge!  
We (team bi0s) – https://ctftime.org/team/662 stood 19th in this CTF!

This post is a bit long, so if you have some doubts or have found some mistake, feel free to post it in the comments or [reach me out on Twitter](https://twitter.com/ashutosha_)!
