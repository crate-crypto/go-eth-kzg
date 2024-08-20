package erasure_code

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	poly "github.com/crate-crypto/go-eth-kzg/internal/poly"
)

func TestVanishingPoly(t *testing.T) {
	points := []fr.Element{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4)}
	vanishingPoly := vanishingPolyCoeff(points)
	for _, point := range points {
		eval := poly.PolyEval(vanishingPoly, point)
		if !eval.IsZero() {
			t.Fatalf("expected evaluation at the vanishing polynomial to be zero")
		}
	}
}
