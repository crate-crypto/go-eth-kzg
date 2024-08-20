package domain

import (
	"math"
	"math/big"
	"math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/utils"
)

func TestRootsSmoke(t *testing.T) {
	domain := NewDomain(4)

	roots0 := domain.Roots[0]
	roots1 := domain.Roots[1]
	roots2 := domain.Roots[2]
	roots3 := domain.Roots[3]

	// First root should be 1 : omega^0
	if !roots0.IsOne() {
		t.Error("the first root should be one")
	}

	// Second root should have an order of 4 : omega^1
	var res fr.Element
	res.Exp(roots1, big.NewInt(4))
	if !res.IsOne() {
		t.Error("root does not have an order of 4")
	}

	// Third root should have an order of 2 : omega^2
	res.Exp(roots2, big.NewInt(2))
	if !res.IsOne() {
		t.Error("root does not have an order of 2")
	}

	// Fourth root when multiplied by first root should give 1 : omega^3
	res.Mul(&roots3, &roots1)
	if !res.IsOne() {
		t.Error("root is not last element in subgroup")
	}
}

func TestBitReversal(t *testing.T) {
	powInt := func(x, y int) int {
		return int(math.Pow(float64(x), float64(y)))
	}

	// We only go up to 20 because we don't want a long running test
	for i := 0; i < 20; i++ {
		size := powInt(2, i)

		scalars := testScalars(size)
		reversed := bitReversalPermutation(scalars)

		BitReverse(scalars)

		for i := 0; i < size; i++ {
			if !reversed[i].Equal(&scalars[i]) {
				t.Error("bit reversal methods are not consistent")
			}
		}
	}
}

// This is simply another way to do the bit reversal,
// if these were incorrect then integration tests would
// fail.
func bitReversalPermutation(l []fr.Element) []fr.Element {
	size := uint64(len(l))
	if !utils.IsPowerOfTwo(size) {
		panic("size of slice must be a power of two")
	}

	out := make([]fr.Element, size)

	for i := range l {
		j := bits.Reverse64(uint64(i)) >> (65 - bits.Len64(size))
		out[i] = l[j]
	}

	return out
}

func testScalars(size int) []fr.Element {
	res := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		res[i] = fr.NewElement(uint64(i))
	}
	return res
}
