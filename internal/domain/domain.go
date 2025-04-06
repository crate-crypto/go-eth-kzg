package domain

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/utils"
)

// Domain is a struct defining the set of points that polynomials are evaluated over.
// To enable efficient FFT-based algorithms, these points are chosen as 2^i'th roots of unity and we precompute and store
// certain values related to that inside the struct.
type Domain struct {
	// Size of the domain as a uint64. This must be a power of 2.
	// Since the base field has 2^i'th roots of unity for i<=32, Cardinality is <= 2^32)
	Cardinality uint64
	// Inverse of the size of the domain as
	// a field element. This is useful for
	// inverse FFTs.
	CardinalityInv fr.Element
	// Generator for the multiplicative subgroup
	// Not a primitive element (i.e. generator) for the *whole* field.
	//
	// This generator will have order equal to the
	// cardinality of the domain.
	Generator fr.Element
	// Inverse of the Generator. This is precomputed
	// and useful for inverse FFTs.
	GeneratorInv fr.Element

	// Roots of unity for the multiplicative subgroup
	// Note that these may or may not be in bit-reversed order.
	Roots []fr.Element
}

// NewDomain returns a new domain with the desired number of points x.
//
// We only support powers of 2 for x.
//
// Modified from [gnark-crypto].
//
// [gnark-crypto]: https://github.com/ConsenSys/gnark-crypto/blob/8f7ca09273c24ed9465043566906cbecf5dcee91/ecc/bls12-381/fr/fft/domain.go#L66
func NewDomain(x uint64) *Domain {
	if bits.OnesCount64(x) != 1 {
		panic(fmt.Sprintf("x (%d) is not a power of 2. This library only supports domain sizes that are powers of two", x))
	}
	domain := &Domain{}
	domain.Cardinality = x

	// Generator of the largest 2-adic subgroup.
	// This particular element has order 2^maxOrderRoot == 2^32.
	var rootOfUnity fr.Element
	_, err := rootOfUnity.SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131")
	if err != nil {
		panic("failed to initialize root of unity")
	}
	const maxOrderRoot uint64 = 32

	// Find generator subgroup of order x.
	// This can be constructed by powering a generator of the largest 2-adic subgroup of order 2^32 by an exponent
	// of (2^32)/x, provided x is <= 2^32.
	logx := uint64(bits.TrailingZeros64(x))
	if logx > maxOrderRoot {
		panic(fmt.Sprintf("x (%d) is too big: the required root of unity does not exist", x))
	}
	expo := uint64(1 << (maxOrderRoot - logx))
	domain.Generator.Exp(rootOfUnity, big.NewInt(int64(expo))) // Domain.Generator has order x now.

	// Store Inverse of the generator and inverse of the domain size (as field elements).
	domain.GeneratorInv.Inverse(&domain.Generator)
	domain.CardinalityInv.SetUint64(x)
	domain.CardinalityInv.Inverse(&domain.CardinalityInv)

	// Compute all relevant roots of unity, i.e. the multiplicative subgroup of size x.
	domain.Roots = make([]fr.Element, x)
	current := fr.One()
	for i := uint64(0); i < x; i++ {
		domain.Roots[i] = current
		current.Mul(&current, &domain.Generator)
	}

	return domain
}

// BitReverse applies the bit-reversal permutation to `list`.
// `len(list)` must be a power of 2
//
// This means that for post-state list output and pre-state list input,
// we have output[i] == input[bitreverse(i)], where bitreverse reverses the bit-pattern
// of i, interpreted as a log2(len(list))-bit integer.
//
// This is in no way needed for basic KZG and is included in this library as
// a stepping-stone to full Dank-sharding.
//
// Modified from [gnark-crypto].
//
// [gnark-crypto]: https://github.com/ConsenSys/gnark-crypto/blob/8f7ca09273c24ed9465043566906cbecf5dcee91/ecc/bls12-381/fr/fft/fft.go#L245
//
// [reverse_bits]: https://github.com/ethereum/consensus-specs/blob/017a8495f7671f5fff2075a9bfc9238c1a0982f8/specs/deneb/polynomial-commitments.md#reverse_bits
func BitReverse[K interface{}](list []K) {
	n := uint64(len(list))

	for i := uint64(0); i < n; i++ {
		// Find index irev, such that i and irev get swapped
		irev := BitReverseInt(i, n)
		if irev > i {
			list[i], list[irev] = list[irev], list[i]
		}
	}
}

func BitReverseInt(k, bitsize uint64) uint64 {
	if !utils.IsPowerOfTwo(bitsize) {
		panic("bitsize given to bitReverse must be a power of two")
	}

	// The standard library's bits.Reverse64 inverts its input as a 64-bit unsigned integer.
	// However, we need to invert it as a log2(len(list))-bit integer, so we need to correct this by
	// shifting appropriately.
	shiftCorrection := uint64(64 - bits.TrailingZeros64(bitsize))
	return bits.Reverse64(k) >> shiftCorrection
}
