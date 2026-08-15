package domain

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// The scalar field transforms are checked against the implementation they replace, which
// is the de facto specification. The reference below is the pre-optimisation code
// verbatim: a hand-rolled radix-2 Gentleman-Sande.
//
// The tests sweep every power-of-two domain size from 1 to 8192, for all four entry
// points -- FftFr, IfftFr and both coset variants -- and repeat every case with the roots
// table bit-reversed, since Roots is mutable and ReverseRoots permutes it in place.

// referenceFFTFr is the original scalar field transform.
func referenceFFTFr(values []fr.Element, nthRootOfUnity fr.Element) {
	n := len(values)
	if n <= 1 {
		return
	}

	for size := n; size >= 2; size >>= 1 {
		half := size >> 1

		var wStep fr.Element
		wStep.Set(&nthRootOfUnity)
		for i := n / size; i > 1; i-- {
			wStep.Mul(&wStep, &nthRootOfUnity)
		}

		for start := 0; start < n; start += size {
			w := fr.One()
			for k := 0; k < half; k++ {
				i0 := start + k
				i1 := i0 + half

				var tmp fr.Element
				tmp.Sub(&values[i0], &values[i1])
				values[i0].Add(&values[i0], &values[i1])
				values[i1].Mul(&tmp, &w)

				w.Mul(&w, &wStep)
			}
		}
	}

	BitReverse(values)
}

func randomScalars(rng *rand.Rand, n int) []fr.Element {
	out := make([]fr.Element, n)
	var buf [32]byte
	for i := range out {
		rng.Read(buf[:])
		// Full-width scalars, not just 64-bit ones; SetBytes reduces modulo the field
		// order, which is fine for test inputs.
		out[i].SetBytes(buf[:])
	}

	return out
}

// TestFrTransformsMatchReference covers FftFr, IfftFr and both coset variants.
func TestFrTransformsMatchReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20260815))

	var cosetGen, invCosetGen fr.Element
	cosetGen.SetUint64(7)
	invCosetGen.Inverse(&cosetGen)

	for logN := uint(0); logN <= 13; logN++ {
		n := uint64(1) << logN
		for _, reversed := range []bool{false, true} {
			t.Run(fmt.Sprintf("n=%d/reversedRoots=%v", n, reversed), func(t *testing.T) {
				d := NewDomain(n)
				if reversed {
					d.ReverseRoots()
				}
				cd := NewCosetDomain(d, FFTCoset{CosetGen: cosetGen, InvCosetGen: invCosetGen})

				src := randomScalars(rng, int(n))

				// Forward.
				got := append([]fr.Element(nil), src...)
				d.FftFr(got)
				want := append([]fr.Element(nil), src...)
				referenceFFTFr(want, d.Generator)
				requireScalarsEqual(t, "FftFr", got, want)

				// Inverse: reference transform with the inverse generator, then 1/n.
				got = append([]fr.Element(nil), src...)
				d.IfftFr(got)
				want = append([]fr.Element(nil), src...)
				referenceFFTFr(want, d.GeneratorInv)
				for i := range want {
					want[i].Mul(&want[i], &d.CardinalityInv)
				}
				requireScalarsEqual(t, "IfftFr", got, want)

				// Coset forward: scale by generator powers, then the plain transform.
				got = append([]fr.Element(nil), src...)
				cd.CosetFFtFr(got)
				want = append([]fr.Element(nil), src...)
				scale := fr.One()
				for i := range want {
					want[i].Mul(&want[i], &scale)
					scale.Mul(&scale, &cosetGen)
				}
				referenceFFTFr(want, d.Generator)
				requireScalarsEqual(t, "CosetFFtFr", got, want)

				// Coset inverse: the inverse transform, then scale by inverse powers.
				got = append([]fr.Element(nil), src...)
				cd.CosetIFFtFr(got)
				want = append([]fr.Element(nil), src...)
				referenceFFTFr(want, d.GeneratorInv)
				scale = fr.One()
				for i := range want {
					want[i].Mul(&want[i], &d.CardinalityInv)
					want[i].Mul(&want[i], &scale)
					scale.Mul(&scale, &invCosetGen)
				}
				requireScalarsEqual(t, "CosetIFFtFr", got, want)
			})
		}
	}
}

func requireScalarsEqual(t *testing.T, what string, got, want []fr.Element) {
	t.Helper()
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Fatalf("%s: element %d differs from the reference", what, i)
		}
	}
}
