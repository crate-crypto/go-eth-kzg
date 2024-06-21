package kzgmulti

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestVanishingPoly(t *testing.T) {
	points := []fr.Element{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4)}
	vanishingPoly := vanishingPolyCoeff(points)
	for _, point := range points {
		eval := PolyEval(vanishingPoly, point)
		if !eval.IsZero() {
			t.Fatalf("expected evaluation at the vanishing polynomial to be zero")
		}
	}
}
