package domain

import (
	"math/rand/v2"
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
	polyLagrange := d.FftFr(polyMonomial)

	gotPolyMonomial := d.IfftFr(polyLagrange)

	for i := uint64(0); i < n; i++ {
		if !polyMonomial[i].Equal(&gotPolyMonomial[i]) {
			t.Fatalf("fft on fr is incorrect")
		}
	}

	fftCoset := FFTCoset{}
	fftCoset.CosetGen = fr.NewElement(7)
	fftCoset.InvCosetGen.Inverse(&fftCoset.CosetGen)
	cosetDomain := NewCosetDomain(d, fftCoset)

	polyLagrangeCoset := cosetDomain.CosetFFtFr(polyMonomial)
	gotPolyMonomial = cosetDomain.CosetIFFtFr(polyLagrangeCoset)

	for i := uint64(0); i < n; i++ {
		if !polyMonomial[i].Equal(&gotPolyMonomial[i]) {
			t.Fatalf("coset fft on fr is incorrect")
		}
	}
}

func BenchmarkFftFr4096(b *testing.B) {
	// Set up the polynomial of size 4096
	n := uint64(4096)
	polyMonomial := make([]fr.Element, n)
	for i := uint64(0); i < n; i++ {
		polyMonomial[i] = fr.NewElement(uint64(rand.Uint32()))
	}

	// Create the domain
	d := NewDomain(n)

	// Run the benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.FftFr(polyMonomial)
	}
}
