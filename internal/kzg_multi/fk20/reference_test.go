package fk20

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
)

// computeEvaluationSetReference is the implementation of computeEvaluationSet
// before the half-FFT fast path was added, kept verbatim for differential
// testing: zero-pad the coefficients to the size of the extension domain and
// do one full-size FFT.
func (fk *FK20) computeEvaluationSetReference(polyCoeff []fr.Element) [][]fr.Element {
	polyCoeff = slices.Clone(polyCoeff)
	// Pad to the correct length
	for i := len(polyCoeff); i < len(fk.extDomain.Roots); i++ {
		polyCoeff = append(polyCoeff, fr.Element{})
	}

	fk.extDomain.FftFr(polyCoeff)
	evaluations := polyCoeff

	domain.BitReverse(evaluations)
	return partition(evaluations, fk.evalSetSize)
}

// newFK20ForExtension builds an FK20 instance with a dummy SRS; only the
// domains matter for the extension code under test.
func newFK20ForExtension(polyLen, numPointsToOpen, evalSetSize int) FK20 {
	srs := make([]bls12381.G1Affine, polyLen)
	return NewFK20(srs, numPointsToOpen, evalSetSize)
}

func randomPoly(t *testing.T, n int) []fr.Element {
	t.Helper()
	poly := make([]fr.Element, n)
	for i := range poly {
		if _, err := poly[i].SetRandom(); err != nil {
			t.Fatalf("SetRandom: %v", err)
		}
	}
	return poly
}

// requireCosetEvalsBitIdentical byte-compares two partitioned evaluation sets.
func requireCosetEvalsBitIdentical(t *testing.T, expected, got [][]fr.Element) {
	t.Helper()
	if len(expected) != len(got) {
		t.Fatalf("number of cosets differ: expected %d, got %d", len(expected), len(got))
	}
	for i := range expected {
		if len(expected[i]) != len(got[i]) {
			t.Fatalf("coset %d: length differs: expected %d, got %d", i, len(expected[i]), len(got[i]))
		}
		for j := range expected[i] {
			expBytes := expected[i][j].Bytes()
			gotBytes := got[i][j].Bytes()
			if !bytes.Equal(expBytes[:], gotBytes[:]) {
				t.Fatalf("coset %d, element %d: expected %x, got %x", i, j, expBytes, gotBytes)
			}
		}
	}
}

// TestComputeExtendedPolynomialHalfFFTDifferential checks that the half-FFT
// extension is bit-identical to the previous full-size FFT implementation,
// with and without the caller supplying the first-half evaluations.
func TestComputeExtendedPolynomialHalfFFTDifferential(t *testing.T) {
	cases := []struct {
		polyLen     int
		evalSetSize int
	}{
		{32, 4},
		{128, 8},
		{4096, 64}, // production shape
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("polyLen=%d/cosetSize=%d", tc.polyLen, tc.evalSetSize), func(t *testing.T) {
			fk := newFK20ForExtension(tc.polyLen, 2*tc.polyLen, tc.evalSetSize)
			poly := randomPoly(t, tc.polyLen)

			expected := fk.computeEvaluationSetReference(poly)

			got := fk.ComputeExtendedPolynomial(slices.Clone(poly))
			requireCosetEvalsBitIdentical(t, expected, got)

			// Compute the first-half evaluations independently of the code
			// under test: an FFT over the half-size domain, bit-reversed.
			evals := slices.Clone(poly)
			domain.NewDomain(uint64(tc.polyLen)).FftFr(evals)
			domain.BitReverse(evals)

			gotWithEvals := fk.ComputeExtendedPolynomialWithEvals(evals, slices.Clone(poly))
			requireCosetEvalsBitIdentical(t, expected, gotWithEvals)
		})
	}
}

// TestComputeExtendedPolynomialGeneralPath checks that extension factors other
// than two still take the reference path and agree with it.
func TestComputeExtendedPolynomialGeneralPath(t *testing.T) {
	const polyLen = 64
	fk := newFK20ForExtension(polyLen, 4*polyLen, 8)
	poly := randomPoly(t, polyLen)

	expected := fk.computeEvaluationSetReference(poly)
	got := fk.ComputeExtendedPolynomial(slices.Clone(poly))
	requireCosetEvalsBitIdentical(t, expected, got)
}
