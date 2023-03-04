## Golang Proto Danksharding

## Intro

This is a golang version of the proto danksharding specs using gnark.

Audit of gnark code: <https://github.com/ConsenSys/gnark-crypto/blob/master/audit_oct2022.pdf>

In particular, we only use the group operations and pairings code.


## Minimum Supported Golang Version

We use generics and so the minimum golang version is 1.18.

go 1.18 seems to be fairly conservative, however if a lower version is needed,
replacing the generics is fairly straightforward.