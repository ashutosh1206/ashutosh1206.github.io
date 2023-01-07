---
title: "Announcing Crypton v1.0"
date: 2018-08-12
author: Ashutosh Ahelleya
---

In this blog post, I will be talking about my new library Crypton, my journey of building this library, future plans and much more!

Check out the library on GitHub: https://github.com/ashutosh1206/Crypton

## Introduction

This library is an attempt by the author to help provide a platform to learn and practice Offensive and Defensive cryptography for people interested in this field .

With the increasing number of attacks on implementations of cryptographic protocols every year, it has become essential that we give as much importance to secure implementation of these protocols as we give to internals of the protocol itself.

While the protocol designers make sure that a secure cryptosystems is selected for a protocol along with various other factors that decide the security of a protocol, developers designing implementation of these protocols too must make sure that they neither leave behind silly bugs nor forget some checks in some part of the implementation of the protocol, in a way that it creates problems to users/organisations using it.

Matasano Crypto Challenges have provided a very nice headstart to learning crypto, but it has been years since the challenges were updated.

This library is an attempt to bridge the gap between theoretical and applied cryptography, by means of analysing how various cryptosystems work, their internals, the math behind the concepts etc.

The library consists of explanation and implementation of all the existing attacks on various Encryption Systems, Digital Signatures and Hashing Algorithms along with example challenges from “Capture The Flag” and their respective writeups.

As of now the library consists of around 45 attacks on various cryptosystems, there are a lot more to be added which you can check in the “TODO” section of the library’s GitHub source- https://github.com/ashutosh1206/Crypton#todo.

## Who can use the library?

Anyone, who is interested in the field of cryptography can use this library. While people who are new to this field can use it as a tool to learn new concepts/attacks and implement them at the same time, it can also be used by CTF players to practice crypto challenges based on a particular attack.

GitHub repo of the library contains all it’s details- *Library Structure*, *Domain Coverage*, *ToDo* etc. : https://github.com/ashutosh1206/Crypton

## Future Plans
Right now, I feel Crypton is just in it’s baby stage. There are many more attacks to be covered- on Elliptic Curves and other public key cryptosystems which have been added to ToDo list of the repo. But I have some other interesting ideas about making this library more informative and helpful.

What if we add this section “Cryptographic Protocols” where all the internals of protocols are discussed? For example: TLS-1.2 -- we can have it’s directory in the library which discusses all the details of this protocol (handshake, key exchange, encryption etc.) and it’s trivial implementation in python/Golang (I will have to learn Golang for it >\_<).  Then in the same section we can have all the attacks that happened on libraries implementing this protocol. I think that will be an awesome way to learn things!

Another plan I have is to implement class based implementation of all the attacks on these cryptosystems in python. This would be mainly useful for CTF players. After this is done all we need to do is import the python library and call the required function for the attack. I know that there is a similar library by [p4 CTF team](https://ctftime.org/team/5152) : [crypto-commons](https://github.com/p4-team/crypto-commons) , so either I will work on enhancing that library by adding more attacks to it, or make a library right from the beginning! Let’s see how that goes!


The next section might be boring for some of the people, as it is just a story of how the development progressed, so the reader can feel free to skip the next section 😛

## Timeline

It all started during CSAW CTF Quals 2017, when an alumni of our CTF team-  [Seshagiri](https://github.com/seshagiriprabhu) suggested that I create some sort of a library of all the attacks in crypto to help the incoming batches of our CTF team solve crypto challenges faster.

I found the project exciting and I knew that I would learn a lot building this small library.

It was his idea of building the library and I am grateful to him!

During early November 2017, I got a scholarship to visit [ECC Winter School](https://ecc2017.cs.ru.nl/) in Radboud University, Netherlands where I met some awesome people doing research in the field of Elliptic Curve and other theoretical aspects of ECC. Almost all the talks given in 3 days were theory based (I still found them interesting, because math <3), and only one of the talks was on secure software implementation of Elliptic Curves. I noticed stark differences in the talks that were on theoretical crypto and implementation based crypto. This motivated me to work on something that bridges the gap between theoretical and applied cryptography.

After I came back from ECC, I started working on the repository in December. At that time the repo was very rough, with disorganised attack directories, with ugly code (I still suspect my code to be ugly, but surely less than what I wrote that time :P).

And then as time passed, I learnt to organise my repository using a pre-defined structure (I had to refactor my library), learnt writing in Markdown with those silly cheat sheets and learnt to write those heavy mathematical equations in LaTeX and what not!

So what started as a private repository containing only the exploit scripts ended up becoming a library that it is now 😀

## Submitting a CFP

Amidst developing Crypton v1.0 (Feb-March 2018), I thought of giving a talk and releasing the library at a security conference.

Having no prior knowledge of writing a Call For Paper submission,  I searched for resources, found a couple of them on the BlackHat submission page- http://hexsec.blogspot.com/2012/12/create-good-security-cfp-responses.html, https://www.helpnetsecurity.com/2016/03/30/how-to-get-your-talk-accepted-at-black-hat/, and created a CFP submission.

Honestly, I didn’t expect anything in my first submission (was at BSides SF). But to my surprise, it got accepted! Sadly, I could not afford to go to SF at that time so I had no choice but to politely deny.

But everything evolves with time, and so did my CFP. Whenever I faced a rejection, I always saw it as an opportunity to work upon my CFP and improve. I submitted to multiple conferences, faced multiple rejections, but I think I was patient (thanks to all those complex CTF challenges ¯\\\_(ツ)\_/¯), waited for my moment because I trusted that my library would be helpful to the community in some or the other way.

I missed speaking at one of the conferences (44CON) only by 0.25 points (Yes, it still hits me :P).  I was given a rating of 4 out of 5 while the required rating to speak at the conference was 4.25. There were other factors involved, but that’s a different story. One of the members of the reviewing committee- [Steve](https://twitter.com/stevelord) was very generous and he listed out all the points that resulted in my submission being a 4 out of 5, gave a few suggestions that have helped me and I am grateful!

Next was CryptoVillage at DEFCON 26- I submitted it as soon as the CFP opened (because past experiences ¯\\\_(ツ)\_/¯), with the best possible CFP I could ever make. And on June 30, 2018, I got the confirmation of acceptance. This time too, I did not anticipate it. I happily confirmed my talk at CryptoVillage, DEFCON 26. I was so excited! It would have been the first time I would have attended DEFCON and CryptoVillage and that too as a speaker was so thrilling! Plus Vegas! Man, what a feeling that was 😛

But time ¯\\\_(ツ)\_/¯, I could not get a VISA to travel to Vegas. I missed the opportunity to meet so many awesome people at DEFCON and CryptoVillage!

But thanks to [Whitney Merrill](https://twitter.com/wbm312), founder of CryptoVillage, for her kind words of encouragement, that has kept motivated to continue submitting talks. She and CryptoVillage have been very helpful during the entire process.

I decided that although I could not make it to Vegas, I would still release the tool on 12th of August, the day I would have released the tool had I been in Vegas.

And so, today is the day!

I encourage everyone in the community to have a look at Crypton- https://github.com/ashutosh1206/Crypton . Feel free to post any kind of reviews, suggestions, criticism regarding the library in the comments section or shoot me with your reviews on Twitter: https://twitter.com/ashutosha_!
