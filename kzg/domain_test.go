package kzg

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestReversal(t *testing.T) {
	powInt := func(x, y int) int {
		return int(math.Pow(float64(x), float64(y)))
	}

	// We only go up to 20 because we don't want a long running test
	for i := 0; i < 20; i++ {
		size := powInt(2, i)

		scalars := randomScalars(size)
		reversed := bitReversalPermutation(scalars)

		BitReverse(scalars)

		for i := 0; i < size; i++ {
			if !reversed[i].Equal(&scalars[i]) {
				t.Error("bit reversal methods are not consistent")
			}
		}

	}

}
func TestRootsSmoke(t *testing.T) {
	domain := NewDomain(4)

	roots_0 := domain.Roots[0]
	roots_1 := domain.Roots[1]
	roots_2 := domain.Roots[2]
	roots_3 := domain.Roots[3]

	// First root should be 1 : omega^0
	if !roots_0.IsOne() {
		t.Error("the first root should be one")
	}

	// Second root should have an order of 4 : omega^1
	var res fr.Element
	res.Exp(roots_1, big.NewInt(4))
	if !res.IsOne() {
		t.Error("root does not have an order of 4")
	}

	// Third root should have an order of 2 : omega^2
	res.Exp(roots_2, big.NewInt(2))
	if !res.IsOne() {
		t.Error("root does not have an order of 2")
	}

	// Fourth root when multiplied by first root should give 1 : omega^3
	res.Mul(&roots_3, &roots_1)
	if !res.IsOne() {
		t.Error("root does not have an order of 2")
	}
}

func randomScalars(size int) []fr.Element {
	res := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		res[i] = fr.NewElement(uint64(i))
	}
	return res
}
