package kzg

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Evaluates a polynomial in coefficient form
func evaluatePolyCoeff(coeffs []fr.Element, point fr.Element) fr.Element {
	result := fr.NewElement(0)
	for i := 0; i < len(coeffs); i++ {
		var tmp fr.Element
		tmp.Exp(point, big.NewInt(int64(i)))
		tmp.Mul(&tmp, &coeffs[i])
		result.Add(&result, &tmp)
	}
	return result
}

func TestSmokeFFtFr(t *testing.T) {
	// The polynomial in question is: f(x) =  x^2 + x

	// coefficient form -- padded so we have a power of two number of coefficients
	// 0 * x^0 + 1 * x^1 + 1 * x^2 + 0 * x^4
	fCoeffs := []fr.Element{fr.NewElement(0), fr.NewElement(1), fr.NewElement(1), fr.NewElement(0)}

	domain := NewDomain(uint64(len(fCoeffs)))
	roots := domain.Roots

	gotEvals := fftFr(fCoeffs, domain.Generator)

	var expectedEvals []fr.Element
	for i := 0; i < len(fCoeffs); i++ {
		expectedEvals = append(expectedEvals, evaluatePolyCoeff(fCoeffs, roots[i]))
	}

	if len(gotEvals) != len(expectedEvals) {
		t.Fatalf("got evals and expected evals are not equal size")
	}

	for i := 0; i < len(gotEvals); i++ {
		if !gotEvals[i].Equal(&expectedEvals[i]) {
			t.Fatalf("evaluations are different")
		}
	}
}

func TestSRSConversion(t *testing.T) {
	n := uint64(4096)
	domain := NewDomain(n)
	secret := big.NewInt(100)
	srsMonomial, err := newSRS(n, secret)
	if err != nil {
		t.Error(err)
	}
	srsLagrange, err := NewSRSInsecure(*domain, secret)
	if err != nil {
		t.Error(err)
	}

	lagrangeSRS := IfftG1(srsMonomial.CommitKey.G1, domain.GeneratorInv)

	for i := uint64(0); i < n; i++ {
		if !lagrangeSRS[i].Equal(&srsLagrange.CommitKey.G1[i]) {
			t.Fatalf("conversion incorrect")
		}
	}
}

func TestRandPolyFFT(t *testing.T) {
	n := 256

	fCoeffs := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		var element fr.Element
		element.SetRandom()
		fCoeffs[i] = element
	}

	domain := NewDomain(uint64(n))
	roots := domain.Roots

	gotEvals := FftFr(fCoeffs, domain.Generator)

	var expectedEvals []fr.Element
	for i := 0; i < len(fCoeffs); i++ {
		expectedEvals = append(expectedEvals, evaluatePolyCoeff(fCoeffs, roots[i]))
	}

	if len(gotEvals) != len(expectedEvals) {
		t.Fatalf("got evals and expected evals are not equal size")
	}

	for i := 0; i < len(gotEvals); i++ {
		if !gotEvals[i].Equal(&expectedEvals[i]) {
			t.Fatalf("evaluations are different")
		}
	}

	// Compute the IFFT

	gotCoeffs := IfftFr(gotEvals, domain.GeneratorInv)
	for i := 0; i < len(fCoeffs); i++ {

		if !gotCoeffs[i].Equal(&fCoeffs[i]) {
			t.Fatalf("coeffs are different, %d", i)
		}

	}
}
