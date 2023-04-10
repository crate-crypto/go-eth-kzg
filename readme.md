## Go-KZG-4844

This library provides the necessary cryptographic functions for EIP-4844. If one
is not familiar with EIP-4844, you can think of this library as a KZG library
where the polynomial degree is set to 4095 and opening proofs are computed on
polynomials in lagrange form (4096 evaluations at 4096'th roots of unity).

## Installation 

```
$ go get github.com/crate-crypto/go-kzg-4844
```

## Example

Check out [`examples_test.go`](./examples_test.go) for an example of how to use
this library.

## Consensus specs

This version of the code is conformant with the consensus-specs as of the
following commit: `3a2304981a3b820a22b518fe4859f4bba0ebc83b`

## Benchmarks

To run the benchmarks, execute the following command:

```
$ go test -bench=.
```

## Security

- For security bugs in this library, email kev@the.dev.
- This library uses
  [gnark-crypto](https://github.com/ConsenSys/gnark-crypto/tree/master) for
  elliptic curve operations. An audit of gnark can be seen
  [here](https://github.com/ConsenSys/gnark-crypto/blob/master/audit_oct2022.pdf).
  This library uses a more recent version than the audited version, since that 
  version had a serialization bug.
  We only rely on gnark-crypto's underlying group operations and pairing code
  for bls12-381. For code that we do need to use, that has not been audited, we
  have copied it into this library so that it can be a part of this libraries
  audit. We have noted in the comments which functions we have done this for.
  

### Panics

Panics can be a DoS vector when running code in a node. This library endeavors
to only panic on startup; only methods which are called when we create the
`Context` object should panic.

## Minimum Supported Golang Version

Because we use generics, the minimum golang version is 1.18, which seems to be
fairly conservative. However, if a lower version is needed, replacing the
generics is fairly straightforward.

## License

This project is licensed under the APACHE-2 license.
