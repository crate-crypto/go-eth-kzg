package domain

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestFFt(t *testing.T) {
	n := uint64(8)
	polyMonomial := []fr.Element{
		fr.NewElement(1),
		fr.NewElement(2),
		fr.NewElement(3),
		fr.NewElement(4),
		fr.NewElement(5),
		fr.NewElement(6),
		fr.NewElement(7),
		fr.NewElement(8),
	}

	d := NewDomain(8)
	polyLagrange := make([]fr.Element, len(polyMonomial))
	copy(polyLagrange, polyMonomial)
	d.FftFr(polyLagrange)

	invCopy := make([]fr.Element, len(polyLagrange))
	copy(invCopy, polyLagrange)
	d.IfftFr(invCopy)
	gotPolyMonomial := invCopy

	for i := uint64(0); i < n; i++ {
		if !polyMonomial[i].Equal(&gotPolyMonomial[i]) {
			t.Fatalf("fft on fr is incorrect")
		}
	}

	fftCoset := FFTCoset{}
	fftCoset.CosetGen = fr.NewElement(7)
	fftCoset.InvCosetGen.Inverse(&fftCoset.CosetGen)
	cosetDomain := NewCosetDomain(d, fftCoset)

	polyLagrangeCoset := make([]fr.Element, len(polyMonomial))
	copy(polyLagrangeCoset, polyMonomial)
	cosetDomain.CosetFFtFr(polyLagrangeCoset)

	gotPolyMonomial = make([]fr.Element, len(polyLagrangeCoset))
	copy(gotPolyMonomial, polyLagrangeCoset)
	cosetDomain.CosetIFFtFr(gotPolyMonomial)

	for i := uint64(0); i < n; i++ {
		if !polyMonomial[i].Equal(&gotPolyMonomial[i]) {
			t.Fatalf("coset fft on fr is incorrect")
		}
	}
}

func TestFFtInPlaceKernel(t *testing.T) {
	d := NewDomain(8)

	original := []fr.Element{
		fr.NewElement(1), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4),
		fr.NewElement(5), fr.NewElement(6), fr.NewElement(7), fr.NewElement(8),
	}

	v := fftFrRef(original, d.Generator)
	d.IfftFr(v)

	for i := range original {
		if !original[i].Equal(&v[i]) {
			t.Fatalf("reference FFT round-trip mismatch at %d", i)
		}
	}
}

// fftFrRef is a local reference FFT (recursive Cooley–Tukey) used for testing.
func fftFrRef(values []fr.Element, nthRootOfUnity fr.Element) []fr.Element {
	n := len(values)
	if n == 1 {
		out := make([]fr.Element, 1)
		out[0] = values[0]
		return out
	}

	var generatorSquared fr.Element
	generatorSquared.Square(&nthRootOfUnity)

	even, odd := takeEvenOddFr(values)
	fftEven := fftFrRef(even, generatorSquared)
	fftOdd := fftFrRef(odd, generatorSquared)

	inputPoint := fr.One()
	evaluations := make([]fr.Element, n)
	for k := 0; k < n/2; k++ {
		var tmp fr.Element
		tmp.Mul(&inputPoint, &fftOdd[k])
		evaluations[k].Add(&fftEven[k], &tmp)
		evaluations[k+n/2].Sub(&fftEven[k], &tmp)
		inputPoint.Mul(&inputPoint, &nthRootOfUnity)
	}
	return evaluations
}

func takeEvenOddFr(values []fr.Element) ([]fr.Element, []fr.Element) {
	n := len(values)
	even := make([]fr.Element, 0, n/2)
	odd := make([]fr.Element, 0, n/2)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			even = append(even, values[i])
		} else {
			odd = append(odd, values[i])
		}
	}
	return even, odd
}
