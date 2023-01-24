package utils

import (
	"bytes"
	"math"
	"math/big"
	"math/bits"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Store the modulus here
var _modulus big.Int // q stored as big.Int
var zero big.Int

func init() {
	_modulus.SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
}

func ComputePowers(x fr.Element, n uint) []fr.Element {
	if n == 0 {
		return []fr.Element{}
	}

	return computePowers(x, n)
}
func computePowers(x fr.Element, n uint) []fr.Element {
	powers := make([]fr.Element, n)
	powers[0].SetOne()
	for i := uint(1); i < n; i++ {
		powers[i].Mul(&powers[i-1], &x)
	}

	return powers
}

func IsPowerOfTwo(value uint64) bool {
	return value > 0 && (value&(value-1) == 0)
}

func ReverseArray(s *[32]uint8) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// Raise an element to the power of two
// exp is of the form 2^y
// TODO: benchmark this versus using a .Exp which does not make the
// TODO assumption of power of 2. I expect this to be about 30% faster
// TODO: though since we are talking about nanoseconds, we can probably
// TODO use the non optimised version, since its only a small percentage
func Pow2(x fr.Element, exp uint64) *fr.Element {
	if !IsPowerOfTwo(exp) {
		// This can only happen if we stop using roots of unity whose domain is a power of 2
		panic("The domain should always be a power of two, for our use-case")
	}
	pow := int(math.Log2(float64(exp)))
	if pow == 0 {
		one := fr.One()
		return &one
	}

	var result = x
	for i := 0; i < pow; i++ {
		result.Square(&result)
	}
	return &result
}

func ReverseSlice(b []byte) {
	last := len(b) - 1
	for i := 0; i < len(b)/2; i++ {
		b[i], b[last-i] = b[last-i], b[i]
	}
}

// Reduces a scalar and return a boolean to indicate whether the
// byte representation was a canonical representation of the field element
// canonical meaning that the big integer interpretation was less than the modulus
func ReduceCanonical(serScalar []byte) (fr.Element, bool) {
	var scalar fr.Element
	scalar.SetBytes(serScalar)

	reducedBytes := scalar.Bytes()
	isCanon := bytes.Equal(reducedBytes[:], serScalar[:])

	return scalar, isCanon
}

func BytesToBigIntCanonical(b *big.Int) bool {

	// fast path
	c := b.Cmp(&_modulus)
	if c == 0 {
		// v == 0
		return true
	} else if c != 1 && b.Cmp(&zero) != -1 {
		// 0 < v < q
		return true
	}
	return false
}

// BitReverse applies the bit-reversal permutation to a.
// len(a) must be a power of 2
// Taken and modified from gnark-crypto
func BitReverseRoots(a []fr.Element) {
	n := uint64(len(a))
	if !IsPowerOfTwo(n) {
		panic("size of slice must be a power of two")
	}

	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}

func BitReversePoints(a []curve.G1Affine) {
	n := uint64(len(a))
	if !IsPowerOfTwo(n) {
		panic("size of slice must be a power of two")
	}

	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}

// Copied from prysm code
func bitReversalPermutation(l []fr.Element) []fr.Element {
	size := uint64(len(l))
	if !IsPowerOfTwo(size) {
		panic("size of slice must be a power of two")
	}

	out := make([]fr.Element, size)

	for i := range l {
		j := bits.Reverse64(uint64(i)) >> (65 - bits.Len64(size))
		out[i] = l[j]
	}

	return out
}
