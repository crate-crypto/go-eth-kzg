package multiexp

import (
	"math"
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

func TestSimpleScalarMulOneBit(t *testing.T) {
	_, _, basePoint, _ := bls12381.Generators()

	scalar := new(fr.Element)
	scalar.SetString("0x4da9736fb164395ed1586b8355262aa07005818269d2763319faf1d682c01458")

	bi := new(big.Int)
	scalar.BigInt(bi)

	result := boothEncodedScalarMul(*scalar, basePoint, 1)

	expectedAffine := new(bls12381.G1Affine)
	expectedAffine.ScalarMultiplication(&basePoint, bi)

	if !result.Equal(expectedAffine) {
		t.Errorf("Scalar multiplication failed. Got %v, expected %v", result, expectedAffine)
	}
}

func boothEncodedScalarMul(scalar fr.Element, point bls12381.G1Affine, window int) *bls12381.G1Affine {
	// Get the little-endian bytes of the scalar.
	u := scalar.Bytes()
	slices.Reverse(u[:])

	// Determine the number of windows.
	numBits := fr.Bits
	n := numBits/window + 1

	// Precompute the table:
	//   table[i] = point * i, for i = 0,1,..., (1 << (window-1)).
	tableSize := (1 << (window - 1)) + 1
	table := make([]bls12381.G1Affine, tableSize)
	for i := 0; i < tableSize; i++ {
		var bi = big.NewInt(int64(i))
		table[i].ScalarMultiplication(&point, bi)
	}

	// Initialize the accumulator in projective (Jacobian) coordinates to the identity.
	var acc bls12381.G1Jac

	// Process the scalar windows from most-significant to least-significant.
	for i := n - 1; i >= 0; i-- {
		for j := 0; j < window; j++ {
			acc.Double(&acc)
		}

		// Extract the Booth-encoded index for the current window.
		idx := getBoothIndex(i, window, u[:])
		if idx < 0 {
			// Lookup and negate the corresponding table entry.
			idxAbs := int(math.Abs(float64(idx)))
			var ptNeg bls12381.G1Affine = table[idxAbs]
			ptNeg.Neg(&ptNeg)
			var tmpJac bls12381.G1Jac
			tmpJac.FromAffine(&ptNeg)
			acc.AddAssign(&tmpJac)
		} else if idx > 0 {
			idxAbs := int(idx)
			var tmpJac bls12381.G1Jac
			tmpJac.FromAffine(&table[idxAbs])
			acc.AddAssign(&tmpJac)
		}
	}

	var res bls12381.G1Affine
	res.FromJacobian(&acc)
	return &res
}
