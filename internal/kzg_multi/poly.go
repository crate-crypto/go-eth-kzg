package kzgmulti

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

type PolynomialCoeff = []fr.Element

func PolyAdd(a, b PolynomialCoeff) PolynomialCoeff {
	minPolyLen := min(numCoeffs(a), numCoeffs(b))
	maxPolyLen := max(numCoeffs(a), numCoeffs(b))

	result := make([]fr.Element, maxPolyLen)

	for i := 0; i < int(minPolyLen); i++ {
		result[i].Add(&a[i], &b[i])
	}

	// If a has more coefficients than b, copy the remaining coefficients from a
	// into result
	// If b has more coefficients than a, copy the remaining coefficients of b
	// and copy them into result
	if int(numCoeffs(a)) > int(minPolyLen) {
		for i := minPolyLen; i < numCoeffs(a); i++ {
			result[i].Set(&a[i])
		}
	} else if numCoeffs(b) > minPolyLen {
		for i := minPolyLen; i < numCoeffs(b); i++ {
			result[i].Set(&b[i])
		}
	}
	return result
}

func PolyMul(a, b PolynomialCoeff) PolynomialCoeff {
	// The degree of result will be degree(a) + degree(b) = numCoeffs(a) + numCoeffs(b) - 1
	productDegree := numCoeffs(a) + numCoeffs(b)
	result := make([]fr.Element, productDegree-1)

	for i := uint64(0); i < numCoeffs(a); i++ {
		for j := uint64(0); j < numCoeffs(b); j++ {
			mulRes := fr.Element{}
			mulRes.Mul(&a[i], &b[j])
			result[i+j].Add(&result[i+j], &mulRes)
		}
	}

	return result
}

func Interpolate(xVec, yVec []fr.Element) PolynomialCoeff {
	n := len(xVec)
	if n != len(yVec) {
		panic("Input vectors must have the same length")
	}

	result := make([]fr.Element, n)

	for i := 0; i < n; i++ {
		summand := []fr.Element{yVec[i]}
		for j := 0; j < n; j++ {
			if j != i {
				weightAdjustment := fr.Element{}
				weightAdjustment.Sub(&xVec[i], &xVec[j])
				weightAdjustment.Inverse(&weightAdjustment)

				negWeightAdjustment := fr.Element{}
				negWeightAdjustment.Neg(&weightAdjustment)

				tmpA := fr.Element{}
				tmpA.Mul(&xVec[j], &negWeightAdjustment)

				summand = PolyMul(summand, []fr.Element{tmpA, weightAdjustment})
			}
		}
		result = PolyAdd(result, summand)
	}

	return result
}

func equalPoly(a, b PolynomialCoeff) bool {
	a = removeTrailingZeros(a)
	b = removeTrailingZeros(b)

	// Two polynomials that do not have the same
	if numCoeffs(a) != numCoeffs(b) {
		return false
	}

	polyLen := numCoeffs(a)
	if polyLen == 0 {
		return true
	}
	// Check element-wise equality
	for i := uint64(0); i < polyLen; i++ {
		if !a[i].Equal(&b[i]) {
			return false
		}
	}
	return true
}

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
	// TODO: use slices.Clone
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

func numCoeffs(p PolynomialCoeff) uint64 {
	return uint64(len(p))
}

// Removes the higher coefficients from the polynomial
// that are zero.
//
// This has no impact on the actual polynomial. Its just normalizing.
func removeTrailingZeros(slice []fr.Element) []fr.Element {
	for len(slice) > 0 && slice[len(slice)-1].IsZero() {
		slice = slice[:len(slice)-1]
	}
	return slice
}
