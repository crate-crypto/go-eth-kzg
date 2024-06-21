package kzg

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestSRSConversion(t *testing.T) {
	n := uint64(4096)
	domain := NewDomain(n)
	secret := big.NewInt(100)
	srsMonomial, err := newMonomialSRSInsecureUint64(n, secret)
	if err != nil {
		t.Error(err)
	}
	srsLagrange, err := newLagrangeSRSInsecure(*domain, secret)
	if err != nil {
		t.Error(err)
	}

	lagrangeSRS := domain.IfftG1(srsMonomial.CommitKey.G1)

	for i := uint64(0); i < n; i++ {
		if !lagrangeSRS[i].Equal(&srsLagrange.CommitKey.G1[i]) {
			t.Fatalf("conversion incorrect")
		}
	}
}

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

	polyLagrangeCoset := d.CosetFFtFr(polyMonomial)
	gotPolyMonomial = d.CosetIFFtFr(polyLagrangeCoset)

	for i := uint64(0); i < n; i++ {
		if !polyMonomial[i].Equal(&gotPolyMonomial[i]) {
			t.Fatalf("coset fft on fr is incorrect")
		}
	}
}
