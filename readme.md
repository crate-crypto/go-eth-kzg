## Go-KZG-4844

This library provides the necessary cryptographic functions for EIP-4844. If one is not familiar with 4844, you can think of this library as a KZG library where the polynomial degree is set to 4095 and opening proofs are computed on polynomials in lagrange form (4096 evaluations at 4096'th roots of unity).

## Packages

There are two exposed packages that one should be aware of, if you intend to integrate this
codebase into a EIP-4844 client.

### Serialization

This package contains the opaque byte types. The types themselves are implemented as type aliases so one is not necessarily dependent on the types in this package.

They are useful as it means that as an upstream client, you will not need to keep track of what size your array's need to be. Instead one can simply use `Commitment` for example, to get an array that represents a serialized commitment.

### Api

This package provides all of the necessary methods needed to:

- Create/Verify blob proofs
- Verify and compute KZG proofs

For more information on usage of this API, check out `examples_test.go`

We note that this library can also be used to implement the 4844 precompile.
## Getting started

### Installation 

```
$ go get github.com/crate-crypto/go-kzg-4844
```


## Consensus specs

This version of the code is conformant with the consensus specs as of the following commit:
3a2304981a3b820a22b518fe4859f4bba0ebc83b

## Benchmarks

To run the benchmarks, execute the following command:

```
$ go test -bench=.
```

## Security

- For security bugs in this library, send an email to kev@the.dev
- This library uses [gnark-crypto](https://github.com/ConsenSys/gnark-crypto/tree/master) for elliptic curve operations. An audit of gnark can be seen [here](https://github.com/ConsenSys/gnark-crypto/blob/master/audit_oct2022.pdf). We only rely on gnark-crypto's underlying group operations and pairing code for bls12-381. For code that we do need to use, that has not been audited, we have copied it into this library so that it can be a part of this libraries audit. We have noted in the comments which functions we have done this for. 

### Panics

Panics can be a DoS vector when running code in a node. This library endeavors to only panic on startup, ie only methods which are called when we create the `Context` object should panic.

## Minimum Supported Golang Version

We use generics and so the minimum golang version is 1.18.

go 1.18 seems to be fairly conservative. However if a lower version is needed,
replacing the generics is fairly straightforward.

## License

This project is licensed under the APACHE-2 license.