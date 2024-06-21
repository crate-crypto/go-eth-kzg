package kzgmulti

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

type PolynomialCoeff = []fr.Element

// PolyEval evaluates a polynomial f(x) at a point `z`; f(z)
// We denote `z` as `inputPoint`
func PolyEval(poly PolynomialCoeff, inputPoint fr.Element) fr.Element {
	result := fr.NewElement(0)

	for i := len(poly) - 1; i >= 0; i-- {
		tmp := fr.Element{}
		tmp.Mul(&result, &inputPoint)
		result.Add(&tmp, &poly[i])
	}

	return result
}

// DividePolyByXminusA computes f(x) / (x - a) and returns the quotient.
//
// This was copied and modified from the gnark codebase.
func DividePolyByXminusA(poly PolynomialCoeff, a fr.Element) []fr.Element {
	// clone the slice so we do not modify the slice in place
	quotient := cloneSlice(poly)

	var t fr.Element

	for i := len(quotient) - 2; i >= 0; i-- {
		t.Mul(&quotient[i+1], &a)

		quotient[i].Add(&quotient[i], &t)
	}

	// the result is of degree deg(f)-1
	return quotient[1:]
}

// cloneSlice creates a copy of the original slice
//
// It is up to the user to handle the case of a nil slice.
func cloneSlice(original []fr.Element) []fr.Element {
	if original == nil {
		return nil
	}
	cloned := make([]fr.Element, len(original))
	copy(cloned, original)
	return cloned
}
