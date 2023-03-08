package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

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

// Reverses the list in-place
func Reverse[K interface{}](list []K) {
	last := len(list) - 1
	for i := 0; i < len(list)/2; i++ {
		list[i], list[last-i] = list[last-i], list[i]
	}
}

// Tries to convert a byte slice to a field element.
// Returns an error if the byte slice was not a canonical representation
// of the field element.
// Canonical meaning that the big integer interpretation was less than
// the field's prime. ie it lies within the range [0, p-1] (inclusive)
func ReduceCanonical(serScalar []byte) (fr.Element, error) {
	var scalar fr.Element
	err := scalar.SetBytesCanonical(serScalar)
	return scalar, err
}
