package kzgmulti

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
)

// ComputeMultiPointKZGProof create a proof that when a polynomial f(x), is evaluated at a set of points `z_i`, the output is `y_i = f(z_i)`.
//
// The `y_i` values are computed and returned as part of the output.
func ComputeMultiPointKZGProof(poly PolynomialCoeff, inputPoints []fr.Element, ck *kzg.CommitKey) (bls12381.G1Affine, []fr.Element, error) {

	// Compute the evaluations of the polynomial on the input points
	outputPoints := evalPolynomialOnInputPoints(poly, inputPoints)

	// Compute the quotient polynomial by dividing the polynomial by each input point
	var quotient PolynomialCoeff = poly
	for _, inputPoint := range inputPoints {
		quotient = DividePolyByXminusA(quotient, inputPoint)
	}

	// Commit to the quotient polynomial
	proof, err := kzg.Commit(quotient, ck, 0)
	if err != nil {
		return bls12381.G1Affine{}, nil, err
	}

	return *proof, outputPoints, nil
}

// evalPolynomialOnInputPoints evaluates a polynomial on a set of input points.
func evalPolynomialOnInputPoints(poly PolynomialCoeff, inputPoints []fr.Element) []fr.Element {
	result := make([]fr.Element, 0, len(inputPoints))

	for _, x := range inputPoints {
		eval := PolyEval(poly, x)
		result = append(result, eval)
	}

	return result
}
