package utils

import (
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Store the modulus here
var _modulus big.Int // q stored as big.Int

func init() {
	_modulus.SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
}

// Computes x^0 to x^n-1
// If n==0: an empty slice is returned
func ComputePowers(x fr.Element, n uint) []fr.Element {
	if n == 0 {
		return []fr.Element{}
	}
	return computePowers(x, n)
}

// Computes x^0 to x^n-1
// This function assumes that n > 0
func computePowers(x fr.Element, n uint) []fr.Element {
	powers := make([]fr.Element, n)
	powers[0].SetOne()
	for i := uint(1); i < n; i++ {
		powers[i].Mul(&powers[i-1], &x)
	}

	return powers
}

// Return true if `value` is a power of two
// `0` will return false
func IsPowerOfTwo(value uint64) bool {
	return value > 0 && (value&(value-1) == 0)
}

func ReverseArray(s *[32]uint8) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
func ReverseSlice(b []byte) {
	last := len(b) - 1
	for i := 0; i < len(b)/2; i++ {
		b[i], b[last-i] = b[last-i], b[i]
	}
}

// Tries to convert a byte slice to a field element.
// Returns an error if the byte slice was not a canonical representation
// of the field element.
// Canonical meaning that the big integer interpretation was less than the field modulus
func ReduceCanonical(serScalar []byte) (fr.Element, error) {
	var scalar fr.Element
	err := scalar.SetBytesCanonical(serScalar)
	return scalar, err
}

// BitReverse applies the bit-reversal permutation to `list`.
// len(list) must be a power of 2
// Taken and modified from gnark-crypto
func BitReverse[K interface{}](list []K) {
	n := uint64(len(list))
	if !IsPowerOfTwo(n) {
		panic("size of slice must be a power of two")
	}

	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			list[i], list[irev] = list[irev], list[i]
		}
	}
}
