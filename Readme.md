**This project is in alpha stage. Do not use in production.**

*jayoh* is a SSH jump server. Also known as *bastion* server, it is a
gateway to a private network. Instead of hardening every host in the
infrastructure, you harden this one host and firewall the rest, reducing
the attack surface.

*jayoh* is not a full fledged SSH server. In fact, it's intentionally
crippled to only forwarding TCP traffic. For example, you cannot login
to a shell session on the jump host and run commands.

*jayoh* is written in pure Go with the help of `x/crypto/ssh` package
which is well maintained by authors of Go and used extensively in
various production projects.
