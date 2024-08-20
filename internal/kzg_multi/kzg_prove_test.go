package kzgmulti

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg_multi/fk20"
	"github.com/crate-crypto/go-eth-kzg/internal/poly"
)

func NaiveComputeMultiPointKZGProofs(fk20 *fk20.FK20, poly poly.PolynomialCoeff, inputPoints [][]fr.Element, ck *kzg.CommitKey) ([]bls12381.G1Affine, [][]fr.Element, error) {
	outputPointsSet := make([][]fr.Element, len(inputPoints))
	proofs := make([]bls12381.G1Affine, len(inputPoints))

	for i, inputPoint := range inputPoints {
		proof, outputPoints, err := computeMultiPointKZGProof(poly, inputPoint, ck)
		if err != nil {
			return nil, nil, err
		}
		proofs[i] = proof
		outputPointsSet[i] = outputPoints
	}

	return proofs, outputPointsSet, nil
}

// computeMultiPointKZGProof create a proof that when a polynomial f(x), is evaluated at a set of points `z_i`, the output is `y_i = f(z_i)`.
//
// The `y_i` values are computed and returned as part of the output.
func computeMultiPointKZGProof(polyCoeff poly.PolynomialCoeff, inputPoints []fr.Element, ck *kzg.CommitKey) (bls12381.G1Affine, []fr.Element, error) {
	// Compute the evaluations of the polynomial on the input points
	outputPoints := evalPolynomialOnInputPoints(polyCoeff, inputPoints)

	// Compute the quotient polynomial by dividing the polynomial by each input point
	var quotient poly.PolynomialCoeff = polyCoeff
	for _, inputPoint := range inputPoints {
		quotient = poly.DividePolyByXminusA(quotient, inputPoint)
	}

	// Commit to the quotient polynomial
	proof, err := ck.Commit(quotient, 0)
	if err != nil {
		return bls12381.G1Affine{}, nil, err
	}

	return *proof, outputPoints, nil
}

// evalPolynomialOnInputPoints evaluates a polynomial on a set of input points.
func evalPolynomialOnInputPoints(polyCoeff poly.PolynomialCoeff, inputPoints []fr.Element) []fr.Element {
	result := make([]fr.Element, 0, len(inputPoints))

	for _, x := range inputPoints {
		eval := poly.PolyEval(polyCoeff, x)
		result = append(result, eval)
	}

	return result
}
