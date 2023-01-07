---
title: Playing around with MQTT Protocol
date: 2018-11-04
author: Ashutosh Ahelleya
---

Recently, I happened to come across MQTT Protocol while doing background work for a project as a part of IoT course offered at the University. I liked it due to reasons which I will justify, hence this blog post!

I spent some time yesterday looking at the working and specifications of MQTT v3.1.1 from the [blog post by teserakt](https://blog.teserakt.io/2018/11/01/introduction-to-mqtt/) and through the documentation: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html, since I enjoy reading about the protocols and their implementation.

This blog post will mostly cover what I read and learned about MQTT, so let’s get into it!

<br>
## Contents

 1. Introduction
    + What is MQTT?
    + Fundamental entities
 2. Communication using MQTT Protocol
 3. Data analysis
    + Using mosquitto and Wireshark
 4. Security aspects
    + Need for encrypted IoT communications

<br>
## Introduction

### What is MQTT?
MQTT stands for “Message Queuing Telemetry Transport” and is described as “a publish/subscribe, extremely simple and lightweight messaging protocol, designed for constrained devices and low-bandwidth, high-latency or unreliable networks” as per their site: http://mqtt.org/faq. Due to these reasons, this protocol finds it use in IoT and other machine-to-machine communications.

### Telemetry wut?
It is a method to collect data/measurements at remote points and sent to another location for analysis (For example, imagine an IoT device connected to an animal, that gives the location coordinates of that animal and also it’s pulse rate, to a zoology organisation for analysis located at a remote location)

### Fundamental Entities

 1. Publisher– creates messages, tags them with a topic and sends it to the broker server.
 2. Subscriber– has the capability to subscribe to multiple topics and will receive all messages tagged with these topics published by the publisher
 3. Broker Server– acts as an intermediate between publishers and subscribers and ensures integrity of the data that is being sent.

Any device a.k.a. client can act as both publisher and subscriber, but only one role at a time.  

![picture](/mqtt-protocol-1.png)  
*Reference*: https://wso2.com/library/articles/2016/06/article-the-basics-of-mqtt-and-how-wso2-products-support-mqtt-protocol/

<br>

## Communication using MQTT protocol

### Subscription

 1. To subscribe, the subscriber connects to the broker server (using TCP)
 2. After a connection between the subscriber and broker is established, subscriber requests the broker to subscribe to a topic.
 3. Broker acknowledges this and sends a SUBACK message that confirms the subscription.

### Publishing messages

 1. To publish a message, the publisher first connects to the broker (using TCP)
 2. After a connection between the publisher and broker is established, the publisher sends the message to the broker tagged as a specific topic and disconnects

After the publisher sends the message to the broker and disconnects, broker sends the message to all the clients that have subscribed to the topic of the message.

### Retain messages
MQTT protocol has the functionality to retain the last published message for a given topic. This is useful in cases when the subscriber connects to the broker after the publisher has connected and published it’s message. (In the above example, the subscriber connected to the broker before the publisher)

All the functionalities discussed above can be implemented by installing an open source MQTT broker- mosquitto

In the next topic, we will see how to establish and send data over publish/subscribe communication using mosquitto and analyse the packets sent using Wireshark.

<br>

## Data Analysis

In this section, we will send and receive data packets locally using MQTT protocol and analyse it on Wireshark.

First of all, you need to install Mosquitto and Wireshark on your machine:

### Mosquitto

 1. Install mosquitto- https://mosquitto.org/download/
    + I executed the following commands to install it on my ubuntu-16.04 machine
      + `sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa`
      + `sudo apt-get update`

Make sure that **mosquitto** broker is running before moving on to the next step (Check the status using `systemctl status mosquitto.service`)  

![picture](/mqtt-protocol-2.png)  

*The above command starts a client that connects to the broker (iot.eclipse.org) and then subscription is given to the topic “mqttest1”*

At the same time when the above command is running locally, open another terminal window and type:  

![picture](/mqtt-protocol-3.png)  

*The above command starts a client that connects to the broker, sends “hello” with topic “mqttest1”*

You can see the below output on the subscriber’s side when the publisher publishes a message:  

![picture](/mqtt-protocol-4.png)  

This is an abstract view of how the communication takes place in MQTT protocol.

To understand things better, we can analyse the packets sent during this communication using Wireshark, just start listening to `wlo1` before the communication starts.

We will get lots of data in the captured file, because all the data that is sent via WiFi will be included in the pcap. We will just filter out packets sent using MQTT protocol and analyse them.

### Subscriber connection to Broker
<img src="/mqtt-protocol-5.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*The source (subscriber) is sending a connection request to the destination (broker).*

 1. **Subscriber IP, Port**: 192.168.43.224, 56178
 2. **Broker IP, Port**: 198.41.39.241, 1883

<img src="/mqtt-protocol-6.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*The source (broker) acknowledges the connection request and a connection gets established between the two.*

### Subscription to a topic
<img src="/mqtt-protocol-7.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*Subscriber (src) sends a request to the Broker (dest) to subscribe to the topic “mqttest1”.*

<img src="/mqtt-protocol-8.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*Subscriber (dest) gets subscribed to the topic, after the Broker (src) acknowledges and accepts the request*

### Publisher connection to Broker

 1. **Publisher IP, Port**: 192.168.43.224, 56180

<img src="/mqtt-protocol-9.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*The Publisher (src) is sending a connection request to the broker (dest)*

<img src="/mqtt-protocol-10.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*The source (broker) acknowledges the connection request and a connection gets established between the two*

### Publication with a topic

<img src="/mqtt-protocol-11.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*Publisher (src) sends the message to the broker (dest) tagged as the topic “mqttest1”*

<img src="/mqtt-protocol-12.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*Publisher (src) sends a disconnect request to Broker (dest)*

### Subscribers receiving data

<img src="/mqtt-protocol-13.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*All clients subscribed to the topic “mqttest1” receive “hello”*

<br>

## Security aspects

Notice that by default, packets sent by MQTT Protocol are unencrypted!  

<img src="/mqtt-protocol-14.png" style="max-width:120%;min-width:100px;" alt="Twitter Account"/>  
*Notice the “hello” message? Yeah, unencrypted*

So, if anyone can intercept the communication channel he/she can access the data that is being sent. This is quite a serious issue that can exist in real world IoT device communication.

`mosquitto` provides a feature to encrypt the data that is being sent using TLS-1.2, which makes things quite secure “if implemented correctly” (Stress upon ‘if’). However, IoT world needs a more light weight protocol for ensuring security, hence NIST is now demanding light weight crypto to secure IoT devices: https://csrc.nist.gov/Projects/Lightweight-Cryptography

You can also read about this research by Teserakt on their end-to-end encryption solution for MQTT, which is quite interesting: https://teserakt.io/#products and https://teserakt.io/doc/teserakt-e4.pdf

<br>

## Future Work

As soon as I get sometime, I will try to post a write-up of analysis of data sent through encrypted media in case of vulnerable keys (such as TLS tunnels etc.)

Hope you had fun reading about MQTT! If you have any doubts, feel free to comment on this post or [ping me on twitter](https://twitter.com/ashutosha_)!
