package domain

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// randomG1Points returns n points on the curve, deterministically.
func randomG1Points(n int) []bls12381.G1Affine {
	_, _, g, _ := bls12381.Generators()
	points := make([]bls12381.G1Affine, n)
	var s fr.Element
	var si big.Int
	for i := range points {
		s.SetUint64(uint64(i) + 3)
		s.Square(&s)
		s.Add(&s, &s)
		s.BigInt(&si)
		points[i].ScalarMultiplication(&g, &si)
	}
	return points
}

// TestIfftG1UnscaledMatchesScaled establishes the property the FK20 aggregation relies
// on: IfftG1Unscaled differs from IfftG1 by exactly the factor 1/n, so applying that
// factor anywhere upstream is equivalent.
func TestIfftG1UnscaledMatchesScaled(t *testing.T) {
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64, 128, 256} {
		domain := NewDomain(uint64(n))
		input := randomG1Points(n)

		scaled := make([]bls12381.G1Affine, n)
		copy(scaled, input)
		domain.IfftG1(scaled)

		unscaled := make([]bls12381.G1Affine, n)
		copy(unscaled, input)
		domain.IfftG1Unscaled(unscaled)

		// Scaling the unscaled output by 1/n must reproduce IfftG1 exactly.
		var invDomainBI big.Int
		domain.CardinalityInv.BigInt(&invDomainBI)
		for i := range unscaled {
			unscaled[i].ScalarMultiplication(&unscaled[i], &invDomainBI)
			if !unscaled[i].Equal(&scaled[i]) {
				t.Fatalf("n=%d: point %d differs after rescaling", n, i)
			}
		}
	}
}

// TestIfftG1ScalingIsLinearInTheScalars establishes the other half: scaling the scalars
// that produced the points is the same as scaling the points. This is what lets
// BatchMulAggregation move the 1/n onto its multi-exponentiation scalars.
func TestIfftG1ScalingIsLinearInTheScalars(t *testing.T) {
	const n = 64
	domain := NewDomain(n)
	_, _, g, _ := bls12381.Generators()

	scalars := make([]fr.Element, n)
	for i := range scalars {
		scalars[i].SetUint64(uint64(i)*7 + 1)
	}

	// Path A: build the points from the scalars, inverse transform, scale by 1/n.
	pointsA := make([]bls12381.G1Affine, n)
	var si big.Int
	for i := range scalars {
		scalars[i].BigInt(&si)
		pointsA[i].ScalarMultiplication(&g, &si)
	}
	domain.IfftG1(pointsA)

	// Path B: scale the scalars by 1/n first, then inverse transform without scaling.
	pointsB := make([]bls12381.G1Affine, n)
	for i := range scalars {
		var s fr.Element
		s.Mul(&scalars[i], &domain.CardinalityInv)
		s.BigInt(&si)
		pointsB[i].ScalarMultiplication(&g, &si)
	}
	domain.IfftG1Unscaled(pointsB)

	for i := range pointsA {
		if !pointsA[i].Equal(&pointsB[i]) {
			t.Fatalf("point %d differs between scaling the points and scaling the scalars", i)
		}
	}
}
