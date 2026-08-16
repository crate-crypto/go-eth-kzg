package domain

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// The G1 transform is checked against the implementation it replaced, which is the de
// facto specification. The reference below is the pre-optimisation code verbatim: a
// recursive Cooley-Tukey in affine coordinates.
//
// The test sweeps every power-of-two domain size from 1 to 128 at four goroutine budgets
// including an odd one, and repeats every case with the roots table bit-reversed. That
// second axis exists because the G1 rewrite briefly took its twiddles from the mutable
// Roots slice, which ReverseRoots permutes in place -- a regression that no test at the
// time could see, since nothing reverses a domain and then transforms G1 points on it.

// referenceFFTG1 is the original recursive G1 transform.
func referenceFFTG1(values []bls12381.G1Affine, nthRootOfUnity fr.Element) []bls12381.G1Affine {
	n := len(values)
	if n == 1 {
		return values
	}

	var generatorSquared fr.Element
	generatorSquared.Square(&nthRootOfUnity)

	even, odd := takeEvenOdd(values)
	fftEven := referenceFFTG1(even, generatorSquared)
	fftOdd := referenceFFTG1(odd, generatorSquared)

	inputPoint := fr.One()
	evaluations := make([]bls12381.G1Affine, n)
	for k := 0; k < n/2; k++ {
		var tmp bls12381.G1Affine

		var inputPointBI big.Int
		inputPoint.BigInt(&inputPointBI)

		if inputPoint.IsOne() {
			tmp.Set(&fftOdd[k])
		} else {
			tmp.ScalarMultiplication(&fftOdd[k], &inputPointBI)
		}

		evaluations[k].Add(&fftEven[k], &tmp)
		evaluations[k+n/2].Sub(&fftEven[k], &tmp)

		inputPoint.Mul(&inputPoint, &nthRootOfUnity)
	}

	return evaluations
}

func randomPoints(rng *rand.Rand, n int) []bls12381.G1Affine {
	_, _, g, _ := bls12381.Generators()
	out := make([]bls12381.G1Affine, n)
	for i := range out {
		var bi big.Int
		bi.SetUint64(rng.Uint64()%1000 + 1)
		out[i].ScalarMultiplication(&g, &bi)
		if i%5 == 0 {
			out[i].SetInfinity()
		}
	}

	return out
}

// TestG1TransformsMatchReference covers FftG1 and IfftG1, including inputs containing the
// point at infinity, and every goroutine budget.
func TestG1TransformsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20260816))

	for logN := uint(0); logN <= 7; logN++ {
		n := uint64(1) << logN
		for _, reversed := range []bool{false, true} {
			for _, budget := range []int{1, 2, 3, 0} {
				t.Run(fmt.Sprintf("n=%d/reversedRoots=%v/budget=%d", n, reversed, budget), func(t *testing.T) {
					d := NewDomain(n)
					if reversed {
						d.ReverseRoots()
					}

					src := randomPoints(rng, int(n))

					got := append([]bls12381.G1Affine(nil), src...)
					d.FftG1(got, budget)
					want := referenceFFTG1(append([]bls12381.G1Affine(nil), src...), d.Generator)
					requirePointsEqual(t, "FftG1", got, want)

					got = append([]bls12381.G1Affine(nil), src...)
					d.IfftG1(got, budget)
					want = referenceFFTG1(append([]bls12381.G1Affine(nil), src...), d.GeneratorInv)
					var invDomainBI big.Int
					d.CardinalityInv.BigInt(&invDomainBI)
					for i := range want {
						want[i].ScalarMultiplication(&want[i], &invDomainBI)
					}
					requirePointsEqual(t, "IfftG1", got, want)
				})
			}
		}
	}
}

func requirePointsEqual(t *testing.T, what string, got, want []bls12381.G1Affine) {
	t.Helper()
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Fatalf("%s: point %d differs from the reference", what, i)
		}
	}
}
