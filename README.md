# Secure multicast in 6LoWPAN protocol on Contiki-NG

This repository contains a proposition of centralized system that can secure
multicast communication on 6LoWPAN-based networks. Implementation bases on
Contiki-NG system.

To see how it works, look into `tests/21-secure-multicast` and check examples.
The documentation is available as part of doxygen docs (see 
`os/net/ipv6/multicast/secure`).

The system act as additional layer (implemented as a "multicast engine") and 
after initialization is fully transparent to the application use standard
Contiki UDP interface. In underlay can be used use any multicast delivery
protocol (SMRF by default).

Devices are authenticated using ECC-based certificates. Coordinator manages
group keys (using AES-CBC is implemented, but it's easy to provide support
for others) and share it with authenticated devices when requested.

**Warning:** This is a limited try to secure communication. It's not ready to
usage and probably shouldn't be used in real environment.

Original Contiki-NG README description:

## Contiki-NG: The OS for Next Generation IoT Devices

Contiki-NG is an open-source, cross-platform operating system for Next-Generation IoT devices. It focuses on dependable (secure and reliable) low-power communication and standard protocols, such as IPv6/6LoWPAN, 6TiSCH, RPL, and CoAP. Contiki-NG comes with extensive documentation, tutorials, a roadmap, release cycle, and well-defined development flow for smooth integration of community contributions.

Unless explicitly stated otherwise, Contiki-NG sources are distributed under
the terms of the [3-clause BSD license](LICENSE.md). This license gives
everyone the right to use and distribute the code, either in binary or
source code format, as long as the copyright license is retained in
the source code.

Contiki-NG started as a fork of the Contiki OS and retains some of its original features.

Find out more:

* GitHub repository: https://github.com/contiki-ng/contiki-ng
* Documentation: https://github.com/contiki-ng/contiki-ng/wiki
* Web site: http://contiki-ng.org
* Nightly testbed runs: https://contiki-ng.github.io/testbed

Engage with the community:

* Gitter: https://gitter.im/contiki-ng
* Twitter: https://twitter.com/contiki_ng
