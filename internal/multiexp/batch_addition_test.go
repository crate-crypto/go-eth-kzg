package multiexp

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestMultiBatchAdditionBinaryStride(t *testing.T) {
	numPoints := 99
	numSets := 5

	// Generate random sets of points
	randomSetsOfPoints := make([][]bls12381.G1Affine, numSets)
	for i := range randomSetsOfPoints {
		randomSetsOfPoints[i] = make([]bls12381.G1Affine, numPoints)
		for j := range randomSetsOfPoints[i] {
			randPoint := randomPoint()
			randomSetsOfPoints[i][j].Set(&randPoint)
		}
	}

	randomSetsOfPointsClone := make([][]bls12381.G1Affine, len(randomSetsOfPoints))
	for i := range randomSetsOfPoints {
		randomSetsOfPointsClone[i] = make([]bls12381.G1Affine, len(randomSetsOfPoints[i]))
		copy(randomSetsOfPointsClone[i], randomSetsOfPoints[i])
	}

	// Calculate expected results using single batch addition
	expectedResults := make([]bls12381.G1Jac, len(randomSetsOfPoints))
	for i, points := range randomSetsOfPoints {
		expectedResults[i] = BatchAdditionBinaryTreeStride(points)
	}

	// Calculate results using multi-batch addition
	gotResults := MultiBatchAdditionBinaryTreeStride(randomSetsOfPointsClone)

	// Compare results
	for i := range expectedResults {
		if !expectedResults[i].Equal(&gotResults[i]) {
			t.Errorf("Results don't match for set %d", i)
		}
	}
}

func TestBatchAdditionBinaryTreeStride(t *testing.T) {
	numPoints := 101

	// Generate random points
	points := make([]bls12381.G1Affine, numPoints)
	for i := range points {
		points[i] = randomPoint()
	}

	// clone the points since they get modified in `BatchAdditionBinaryTreeStride`
	pointsClone := make([]bls12381.G1Affine, len(points))
	copy(pointsClone, points)

	// Calculate result using batch addition
	gotResult := BatchAdditionBinaryTreeStride(points)

	// Calculate expected result using regular point addition
	expectedResult := bls12381.G1Jac{}
	for i := 0; i < len(pointsClone); i++ {
		expectedResult.AddMixed(&pointsClone[i])
	}

	// Compare results
	if !expectedResult.Equal(&gotResult) {
		t.Error("Batch addition result doesn't match regular addition")
	}

	// Test empty slice
	emptyResult := BatchAdditionBinaryTreeStride([]bls12381.G1Affine{})
	identityPoint := new(bls12381.G1Jac)
	if !emptyResult.Equal(identityPoint) {
		t.Error("Empty slice should return identity point")
	}

	// Test single point
	singlePoint := randomPoint()
	singleResult := BatchAdditionBinaryTreeStride([]bls12381.G1Affine{singlePoint})
	var expectedSingle bls12381.G1Jac
	expectedSingle.FromAffine(&singlePoint)
	if !singleResult.Equal(&expectedSingle) {
		t.Error("Single point addition failed")
	}
}

func randomPoint() bls12381.G1Affine {
	_, _, point, _ := bls12381.Generators()

	var s fr.Element
	_, err := s.SetRandom()
	if err != nil {
		panic(err)
	}
	bi := new(big.Int)
	s.BigInt(bi)

	point.ScalarMultiplicationBase(bi)

	return point
}
