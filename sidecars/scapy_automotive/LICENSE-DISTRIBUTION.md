# Sidecar distribution and license notice

The Python source written for this `oxfuzz` sidecar is offered under the
project's MIT license. The sidecar has a mandatory runtime dependency on
Scapy 2.7.0, whose installed package metadata identifies it as
GPL-2.0-only. The optional `can` extra pins python-can 4.6.1, whose installed
package metadata identifies it as LGPL-3.0-only.

The sidecar image also pins Debian bookworm `iproute2` 6.1.0-3 for the tightly
bounded virtual-interface setup commands. The Debian package contains files
under multiple licenses; its authoritative installed copyright record is
`/usr/share/doc/iproute2/copyright`. The image installs pinned `packaging`,
`typing_extensions`, and `wrapt` releases required by python-can. Their
upstream notices remain independently applicable.

The default Rust application does not import, link, vendor, or require these
Python packages or `iproute2`. A release that distributes this optional
sidecar, its container, or a bundle containing its dependencies must
separately review and satisfy all applicable notice, corresponding-source,
relinking, and other license obligations. Retain all upstream license texts,
copyright notices, Debian copyright files, and package metadata in the
distributed artifact. The container label records the major MIT, GPL, and
LGPL components but is not a substitute for those notices.

Keeping the sidecar process-separated is an engineering and packaging
boundary. It does not by itself decide whether a particular distribution is a
combined or derivative work. This note is not legal advice; release owners
must obtain the appropriate legal review before shipping the optional bundle.
