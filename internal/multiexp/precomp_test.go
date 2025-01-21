package multiexp

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestMSMTable(t *testing.T) {
	// Test small known values first
	t.Run("single point multiplication", func(t *testing.T) {
		// Generate a point and scalar
		_, _, point, _ := bls12381.Generators()

		scalar := fr.Element{}
		scalar.SetOne()

		bi := new(big.Int)
		scalar.BigInt(bi)

		// Create MSM table
		points := []bls12381.G1Affine{point}
		scalars := []fr.Element{scalar}
		table := NewMSMTable(points, 4) // window size 4

		// Compute result
		result := table.MultiScalarMul(scalars)

		expected := bls12381.G1Jac{}
		expected.FromAffine(&point)
		expected.ScalarMultiplication(&expected, bi)

		if !result.Equal(&expected) {
			t.Error("single point multiplication failed")
		}
	})

	t.Run("zero scalar", func(t *testing.T) {
		_, _, point, _ := bls12381.Generators()

		scalar := fr.Element{} // zero

		points := []bls12381.G1Affine{point}
		scalars := []fr.Element{scalar}
		table := NewMSMTable(points, 4)

		result := table.MultiScalarMul(scalars)

		resultAff := bls12381.G1Affine{}
		resultAff.FromJacobian(&result)

		if !resultAff.IsInfinity() {
			t.Error("multiplication by zero should give point at infinity")
		}
	})

	t.Run("multiple points", func(t *testing.T) {
		// Create points P and 2P
		_, _, P, _ := bls12381.Generators()

		twoP := bls12381.G1Affine{}
		tmp := bls12381.G1Jac{}
		tmp.FromAffine(&P)
		tmp.Double(&tmp)
		twoP.FromJacobian(&tmp)

		// Create scalars 2 and 3
		scalar1 := fr.Element{}
		scalar1.SetUint64(2)

		scalar2 := fr.Element{}
		scalar2.SetUint64(3)

		points := []bls12381.G1Affine{P, twoP}
		scalars := []fr.Element{scalar1, scalar2}

		table := NewMSMTable(points, 4)
		result := table.MultiScalarMul(scalars)
		resultAff := bls12381.G1Affine{}
		resultAff.FromJacobian(&result)

		// Expected: 2*P + 3*(2P) = 8P
		expected := naiveMultiScalarMul(scalars, points)

		if !resultAff.Equal(&expected) {
			t.Error("multiple point multiplication failed")
		}
	})

	t.Run("large random scalars", func(t *testing.T) {
		numPoints := 10
		points := make([]bls12381.G1Affine, numPoints)
		scalars := make([]fr.Element, numPoints)

		// Generate random points and scalars
		for i := 0; i < numPoints; i++ {
			points[i] = randomPoint()
			_, err := scalars[i].SetRandom()
			if err != nil {
				t.Fatal(err)
			}
		}

		// Create MSM table and compute result
		table := NewMSMTable(points, 4)
		msmResult := table.MultiScalarMul(scalars)
		msmResultAff := bls12381.G1Affine{}
		msmResultAff.FromJacobian(&msmResult)

		// Compute expected result using naive method
		expectedResult := naiveMultiScalarMul(scalars, points)

		if !msmResultAff.Equal(&expectedResult) {
			t.Error("MSM result doesn't match naive implementation")
		}
	})

	t.Run("window size edge cases", func(t *testing.T) {
		_, _, point, _ := bls12381.Generators()

		// Test different window sizes
		for _, wbits := range []uint8{2, 4, 8, 16} {
			table := NewMSMTable([]bls12381.G1Affine{point}, wbits)

			scalar := fr.Element{}
			scalar.SetUint64(2)

			result := table.MultiScalarMul(
				[]fr.Element{scalar},
			)

			expected := bls12381.G1Jac{}
			expected.FromAffine(&point)
			expected.Double(&expected)

			if !result.Equal(&expected) {
				t.Errorf("multiplication failed for window size %d", wbits)
			}
		}
	})
}

func naiveMultiScalarMul(scalars []fr.Element, points []bls12381.G1Affine) bls12381.G1Affine {
	if len(scalars) == 0 || len(points) == 0 {
		return bls12381.G1Affine{}
	}

	// Initialize result in Jacobian coordinates
	result := new(bls12381.G1Jac)
	temp := new(bls12381.G1Jac)

	// For each scalar-point pair
	for i := 0; i < len(scalars); i++ {
		if scalars[i].IsZero() {
			continue
		}

		// Convert scalar to big.Int
		scalar := scalars[i].BigInt(new(big.Int))

		// Convert point to Jacobian
		temp.FromAffine(&points[i])

		// Scalar multiply
		temp.ScalarMultiplication(temp, scalar)

		// Add to result
		if i == 0 {
			result.Set(temp)
		} else {
			result.AddAssign(temp)
		}
	}

	// Convert back to affine
	var affineResult bls12381.G1Affine
	affineResult.FromJacobian(result)
	return affineResult
}
