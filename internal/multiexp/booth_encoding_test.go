package multiexp

import (
	"math/big"
	"slices"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestSimpleScalarMul(t *testing.T) {

	_, _, basePoint, _ := bls12381.Generators()

	scalar := new(fr.Element).SetUint64(1)
	scalar.Neg(scalar)

	bi := new(big.Int)
	scalar.BigInt(bi)

	result := boothEncodedScalarMul(*scalar, basePoint, 4)

	expectedAffine := new(bls12381.G1Affine)
	expectedAffine.ScalarMultiplication(&basePoint, bi)

	if !result.Equal(expectedAffine) {
		t.Errorf("Scalar multiplication failed. Got %v, expected %v", result, expectedAffine)
	}
}

func boothEncodedScalarMul(scalar fr.Element, point bls12381.G1Affine, windowSize int) *bls12381.G1Affine {
	// Convert scalar to bytes in little-endian
	scalarBytes := scalar.Bytes()
	slices.Reverse(scalarBytes[:])

	// Calculate number of windows
	n := (fr.Bits + windowSize - 1) / windowSize

	// Create lookup table
	tableSize := 1 << (windowSize - 1)
	table := make([]*bls12381.G1Affine, tableSize+1)
	table[0] = new(bls12381.G1Affine)
	table[0].Set(&bls12381.G1Affine{}) // Set to identity/zero point

	// Initialize first point
	table[1] = new(bls12381.G1Affine)
	table[1].Set(&point)

	// Fill lookup table with scalar multiples
	for i := 2; i <= tableSize; i++ {
		table[i] = new(bls12381.G1Affine)
		table[i].Add(table[i-1], &point)
	}

	// Initialize accumulator in projective coordinates for efficient addition
	acc := new(bls12381.G1Jac)
	acc.Set(&bls12381.G1Jac{}) // Set to identity/zero point

	for i := int(n - 1); i >= 0; i-- {
		// Double the accumulator 'window' times
		for j := 0; j < int(windowSize); j++ {
			acc.Double(acc)
		}

		// Get booth index for current window
		idx := getBoothIndex(int(i), windowSize, scalarBytes[:])

		temp := new(bls12381.G1Jac)

		if idx < 0 {
			temp.FromAffine(table[uint(-idx)])
			temp.Neg(temp)
		} else if idx > 0 {
			temp.FromAffine(table[uint(idx)])
		}

		acc.AddAssign(temp)
	}

	// Convert back to affine coordinates
	result := new(bls12381.G1Affine)
	result.FromJacobian(acc)
	return result
}
