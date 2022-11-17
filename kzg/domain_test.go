package kzg

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func powInt(x, y int) int {
	return int(math.Pow(float64(x), float64(y)))
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
