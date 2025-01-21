package multiexp

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

const BatchInverseThreshold = 16

var three = fp.NewElement(3)

// pointAddDouble adds two elliptic curve points using the point addition/doubling formula
func pointAddDouble(p1, p2 bls12381.G1Affine, inv *fp.Element) bls12381.G1Affine {
	var lambda, x, y fp.Element

	if p1.Equal(&p2) {
		// Point doubling
		// lambda = 3x²/2y
		var temp fp.Element
		temp.Square(&p1.X)      // x²
		temp.Mul(&temp, &three) // 3x²
		lambda.Mul(&temp, inv)
	} else {
		// Point addition
		// lambda = (y2-y1)/(x2-x1)
		lambda.Sub(&p2.Y, &p1.Y)
		lambda.Mul(&lambda, inv)
	}

	// x3 = lambda² - x1 - x2
	x.Square(&lambda)
	x.Sub(&x, &p1.X)
	x.Sub(&x, &p2.X)

	// y3 = lambda * (x1 - x3) - y1
	y.Sub(&p1.X, &x)
	y.Mul(&y, &lambda)
	y.Sub(&y, &p1.Y)

	return bls12381.G1Affine{X: x, Y: y}
}

// chooseAddOrDouble computes the appropriate denominator for point addition/doubling
func chooseAddOrDouble(p1, p2 bls12381.G1Affine) fp.Element {
	var result fp.Element
	if p1.Equal(&p2) {
		// For doubling: denominator is 2y
		result.Add(&p2.Y, &p2.Y)
	} else {
		// For addition: denominator is x2-x1
		result.Sub(&p2.X, &p1.X)
	}
	return result
}

// BatchAdditionBinaryTreeStride performs batch addition of elliptic curve points
//
// Note: points is mutated in this function, to preserve it copy the points before passing
// it to this function.
func BatchAdditionBinaryTreeStride(points []bls12381.G1Affine) bls12381.G1Jac {
	if len(points) == 0 {
		return bls12381.G1Jac{}
	}

	workingPoints := points

	result := bls12381.G1Jac{}

	denominators := make([]fp.Element, 0, len(points)/2)

	for len(workingPoints) > BatchInverseThreshold {
		// Handle odd number of points
		if len(workingPoints)%2 != 0 {
			lastPoint := workingPoints[len(workingPoints)-1]
			result.AddMixed(&lastPoint)
			workingPoints = workingPoints[:len(workingPoints)-1]
		}

		denominators = denominators[:0] // Clear slice while keeping capacity

		// Collect denominators for batch inversion
		for i := 0; i < len(workingPoints)-1; i += 2 {
			denominator := chooseAddOrDouble(workingPoints[i], workingPoints[i+1])
			denominators = append(denominators, denominator)
		}

		// Perform batch inversion
		denominators = fp.BatchInvert(denominators)

		// Perform point additions
		newLen := len(workingPoints) / 2
		for i := 0; i < len(denominators); i++ {
			workingPoints[i] = pointAddDouble(
				workingPoints[i*2],
				workingPoints[i*2+1],
				&denominators[i],
			)
		}

		workingPoints = workingPoints[:newLen]
	}

	for i := 0; i < len(workingPoints); i++ {
		result.AddMixed(&workingPoints[i])
	}

	return result
}

// MultiBatchAdditionBinaryTreeStride performs multi-batch addition of multiple sets of points
//
// Note: multiPoints is mutated in this function, to preserve it copy the points before passing
// it to this function.
func MultiBatchAdditionBinaryTreeStride(multiPoints [][]bls12381.G1Affine) []bls12381.G1Jac {
	// Calculate total number of points across all sets
	totalPoints := 0
	for _, points := range multiPoints {
		totalPoints += len(points)
	}

	// Find the largest bucket length
	maxBucketLength := 0
	for _, points := range multiPoints {
		if len(points) > maxBucketLength {
			maxBucketLength = len(points)
		}
	}

	// Initialize results slice
	sums := make([]bls12381.G1Jac, len(multiPoints))
	denominators := make([]fp.Element, 0, maxBucketLength)

	// Helper function to compute threshold
	computeThreshold := func(points [][]bls12381.G1Affine) int {
		total := 0
		for _, p := range points {
			if len(p)%2 == 0 {
				total += len(p) / 2
			} else {
				total += (len(p) - 1) / 2
			}
		}
		return total
	}

	totalAmountOfWork := computeThreshold(multiPoints)

	workingPoints := multiPoints
	// workingPoints := make([][]bls12381.G1Affine, len(multiPoints))
	// for i, points := range multiPoints {
	// 	workingPoints[i] = make([]bls12381.G1Affine, len(points))
	// 	copy(workingPoints[i], points)
	// }

	for totalAmountOfWork > BatchInverseThreshold {
		// Handle odd number of points in each set
		for i, points := range workingPoints {
			if len(points)%2 != 0 && len(points) > 0 {
				lastPoint := points[len(points)-1]
				sums[i].AddMixed(&lastPoint)
				workingPoints[i] = points[:len(points)-1]
			}
		}

		denominators = denominators[:0] // Clear slice while keeping capacity

		// Collect denominators for all sets
		for _, points := range workingPoints {
			if len(points) < 2 {
				continue
			}
			for i := 0; i < len(points)-1; i += 2 {
				denominator := chooseAddOrDouble(points[i], points[i+1])
				denominators = append(denominators, denominator)
			}
		}

		denominators = fp.BatchInvert(denominators)

		// Process each set with the inverted denominators
		denominatorOffset := 0
		for i, points := range workingPoints {
			if len(points) < 2 {
				continue
			}

			newLen := len(points) / 2
			for j := 0; j < newLen; j++ {
				workingPoints[i][j] = pointAddDouble(
					points[j*2],
					points[j*2+1],
					&denominators[denominatorOffset+j],
				)
			}
			workingPoints[i] = workingPoints[i][:newLen]
			denominatorOffset += newLen
		}

		totalAmountOfWork = computeThreshold(workingPoints)
	}

	// We don't use range points because we get `G601: Implicit memory aliasing in for loop`
	for i := 0; i < len(workingPoints); i++ {
		points := workingPoints[i]

		for k := 0; k < len(points); k++ {
			sums[i].AddMixed(&points[k])
		}
	}

	return sums
}
