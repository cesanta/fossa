# Fossa: Multi-Protocol Networking Library

# Note: As of September 21st 2015, Fossa project has been merged back into [Mongoose](http://t.sidekickopen21.com/e1t/c/5/f18dQhb0S7lM8dDMPbW2n0x6l2B9nMJW7t5XX45w2sgKVcVW4q2BgH-gMQszCH1tQDwf61QVLl03?t=https%3A%2F%2Fgithub.com%2Fcesanta%2Fmongoose&si=4999990023290880&pi=5cbfa88b-4d9d-475f-f33d-494b2b8f6ccf) project

![](https://img.shields.io/badge/license-GPL_2-green.svg "License")

[Fossa](https://www.cesanta.com/fossa) is a
multi-protocol networking library written in C.
It provides easy to use event-driven interface that allows to implement
network protocols or scalable network applications  with little effort.
Fossa helps developers to manage the complexity of network programming
and let them concentrate on the logic, saving time and money.

Fossa has built-in support for several protocols, like
HTTP, Websocket, MQTT, mDNS. Example applications include
Websocket-based chat server, JSON-RPC server,
database server with RESTful API, MQTT broker, netcat with SSL and hexdump,
Raspberry PI camera video feed + led control, and more.

Fossa is ideal for the embedded environments, it has been designed as
an open source platform for connecting devices and bringing them online.

## Features

* Cross-platform: works on Linux/UNIX, QNX, eCos, Windows, Android, iPhone, etc
* Single-threaded, asynchronous, non-blocking core with simple event-based API
* Builtin protocols:
   - plain TCP, plain UDP, SSL/TLS (over TCP, one-way or two-way)
   - HTTP client, HTTP server
   - Websocket client, Websocket server
   - JSON-RPC client, JSON-RPC server
   - MQTT client, MQTT broker
   - CoAP client, CoAP server
   - DNS client, DNS server, async DNS resolver
* Tiny static and run-time footprint
* Source code is both ISO C and ISO C++ compliant
* Very easy to integrate: just copy
  [fossa.c](https://raw.githubusercontent.com/cesanta/fossa/master/fossa.c) and
  [fossa.h](https://raw.githubusercontent.com/cesanta/fossa/master/fossa.h)
  files to your build tree
* Extensively tested and production-ready, trusted by many blue chip businesses

## Examples & Documentation

- [User Guide](https://docs.cesanta.com/fossa) - Detailed User Guide and API reference
- [examples](examples) - Collection of well-commented examples. To build any example,
go into respective directory and type `make`

## Contributions

People who have agreed to the
[Cesanta CLA](https://docs.cesanta.com/contributors_la.shtml)
can make contributions. Note that the CLA isn't a copyright
_assigment_ but rather a copyright _license_.
You retain the copyright on your contributions.

## License

Fossa is released under
[GNU GPL v.2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
Businesses have an option to get non-restrictive, royalty-free commercial
license and professional support from [Cesanta](https://www.cesanta.com).
