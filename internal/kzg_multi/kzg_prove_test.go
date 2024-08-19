package kzgmulti

import (
	"math/big"
	"slices"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg_multi/fk20"
	"github.com/crate-crypto/go-eth-kzg/internal/poly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNaiveVsOptimizedMultiPointKZGProofs(t *testing.T) {
	const EXTENSION_FACTOR = 2
	const NUM_COEFFS_IN_POLY = 4096
	const COSET_SIZE = 64
	const NUM_COSETS = 128

	// Initialize domain and SRS
	extendedDomain := domain.NewDomain(NUM_COEFFS_IN_POLY * EXTENSION_FACTOR)
	secret := big.NewInt(1234)
	srs, err := newMonomialSRSInsecureUint64(NUM_COEFFS_IN_POLY, NUM_COEFFS_IN_POLY*EXTENSION_FACTOR, COSET_SIZE, secret)
	require.NoError(t, err)

	// Initialize FK20 instance
	fk20Instance := fk20.NewFK20(srs.CommitKey.G1, NUM_COEFFS_IN_POLY*EXTENSION_FACTOR, COSET_SIZE)

	// Generate a random polynomial
	poly := make([]fr.Element, NUM_COEFFS_IN_POLY)
	for i := 0; i < NUM_COEFFS_IN_POLY; i++ {
		poly[i].SetInt64(int64(i))
	}

	// Generate input points (cosets) using bit-reversed roots of unity
	domain.BitReverse(extendedDomain.Roots)
	inputPoints := partition(extendedDomain.Roots, COSET_SIZE)
	assert.Equal(t, len(inputPoints), NUM_COSETS)

	// Compute proofs using the naive method
	naiveProofs, naiveCosetsEvals, err := naiveComputeMultiPointKZGProofs(poly, inputPoints, &srs.CommitKey)
	require.NoError(t, err)

	// Compute proofs using the optimized method
	optimizedProofs, optimizedCosetsEvals, err := fk20Instance.ComputeMultiOpenProof(slices.Clone(poly))
	require.NoError(t, err)

	// Compare results
	assert.Equal(t, len(optimizedProofs), len(naiveProofs), "Number of proofs should be equal")
	assert.Equal(t, len(optimizedCosetsEvals), len(naiveCosetsEvals), "Number of coset evaluations should be equal")

	for i := 0; i < len(optimizedProofs); i++ {
		assert.True(t, optimizedProofs[i].Equal(&naiveProofs[i]), "Proof %d should be equal", i)
		assert.Equal(t, optimizedCosetsEvals[i], naiveCosetsEvals[i], "Coset evaluation %d should be equal", i)
	}

	// Verify the proofs
	commitment, err := srs.CommitKey.Commit(poly, 0)
	require.NoError(t, err)

	cosetIndices := make([]uint64, NUM_COSETS)
	for k := 0; k < NUM_COSETS; k++ {
		cosetIndices[k] = uint64(k)
	}

	commitmentIndices := make([]uint64, NUM_COSETS) // There is only one polynomial, so set the commitmentIndex to 0
	err = VerifyMultiPointKZGProofBatch([]bls12381.G1Affine{*commitment}, commitmentIndices, cosetIndices, optimizedProofs, optimizedCosetsEvals, &srs.OpeningKey)
	assert.NoError(t, err, "Optimized proofs should verify correctly")
}

func naiveComputeMultiPointKZGProofs(poly poly.PolynomialCoeff, inputPointsSet [][]fr.Element, ck *kzg.CommitKey) ([]bls12381.G1Affine, [][]fr.Element, error) {
	outputPointsSet := make([][]fr.Element, len(inputPointsSet))
	proofs := make([]bls12381.G1Affine, len(inputPointsSet))

	for i, inputPoints := range inputPointsSet {
		proof, outputPoints, err := computeMultiPointKZGProof(poly, inputPoints, ck)
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

func partition(slice []fr.Element, k int) [][]fr.Element {
	var result [][]fr.Element

	for i := 0; i < len(slice); i += k {
		end := i + k
		if end > len(slice) {
			panic("all partitions should have the same size")
		}
		result = append(result, slice[i:end])
	}

	return result
}
