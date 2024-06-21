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

	var t fr.Element

	for i := len(poly) - 2; i >= 0; i-- {
		t.Mul(&poly[i+1], &a)

		poly[i].Add(&poly[i], &t)
	}

	// the result is of degree deg(f)-1
	return poly[1:]
}
