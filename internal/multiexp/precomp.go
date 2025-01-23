package multiexp

import (
	"slices"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bls12381_copied "github.com/crate-crypto/go-eth-kzg/internal/bls12381"
)

// MSMTable holds precomputed points for fixed base multi-scalar multiplication
type MSMTable struct {
	table     [][]bls12381.G1Affine
	numPoints int
	wbits     uint8
}

// NewMSMTable creates a new lookup table for fixed base multi-scalar multiplication
//
// points: slice of input points in affine coordinates
// wbits: window size for the precomputation
// For every point P, wbits indicates that we should compute
// 1 * P, ..., (2^{wbits} - 1) * P
//
// The total amount of memory is roughly (numPoints * 2^{wbits} - 1)
// where each point is 64 bytes.
func NewMSMTable(points []bls12381.G1Affine, wbits uint8) *MSMTable {
	// Preallocate slice for all precomputed points
	precomputedPoints := make([][]bls12381.G1Affine, len(points))

	// For each input point, compute its multiples
	for i := 0; i < len(points); i++ {
		precomputedPoints[i] = precomputePoints(wbits, &points[i])
	}

	return &MSMTable{
		table:     precomputedPoints,
		numPoints: len(points),
		wbits:     wbits,
	}
}

func precomputePoints(wbits uint8, point *bls12381.G1Affine) []bls12381.G1Affine {
	// Calculate table size: 2^(w-1)
	tableSize := 1 << (wbits - 1)

	// Initialize lookup table
	lookupTable := make([]bls12381.G1Jac, tableSize)

	// Convert to Jacobian coordinates for faster operations
	current := new(bls12381.G1Jac)
	current.FromAffine(point)

	// Store the point for conversion later
	pointJac := new(bls12381.G1Jac)
	pointJac.FromAffine(point)

	// Compute and store multiples
	for i := 0; i < tableSize; i++ {
		lookupTable[i] = *current
		current.AddAssign(pointJac)
	}

	return bls12381_copied.BatchJacobianToAffineG1(lookupTable)
}

func (msmt *MSMTable) MultiScalarMul(scalars []fr.Element) bls12381.G1Jac {
	if len(scalars) != msmt.numPoints {
		// TODO: change panic to error
		panic("number of scalars must match number of points")
	}
	if len(scalars) == 0 {
		return bls12381.G1Jac{}
	}

	scalarsBytes := scalarsToBytes(scalars)

	numWindows := (fr.Bits / msmt.wbits) + 1

	windowsOfPoints := make([][]bls12381.G1Affine, numWindows)

	for windowIdx := 0; windowIdx < int(numWindows); windowIdx++ {
		for scalarIdx := 0; scalarIdx < len(scalarsBytes); scalarIdx++ {
			subTable := msmt.table[scalarIdx]
			scalarBytes := scalarsBytes[scalarIdx]
			pointIdx := getBoothIndex(windowIdx, int(msmt.wbits), scalarBytes)

			if pointIdx == 0 {
				continue
			}

			digitIsPositive := pointIdx > 0
			pointIdx = absInt32(pointIdx) - 1
			point := subTable[pointIdx]

			if !digitIsPositive {
				point.Neg(&point)
			}
			windowsOfPoints[windowIdx] = append(windowsOfPoints[windowIdx], point)
		}
	}

	accumulatedPoints := MultiBatchAdditionBinaryTreeStride(windowsOfPoints)

	// Reverse the points, so that the highest window is first
	slices.Reverse(accumulatedPoints)

	// Take the first window
	result := accumulatedPoints[0]

	// Iterate the points, but skip the first element
	for i := 1; i < len(accumulatedPoints); i++ {
		for k := 0; k < int(msmt.wbits); k++ {
			result.DoubleAssign()
		}
		result.AddAssign(&accumulatedPoints[i])
	}

	return result
}

// absInt32 computes the absolute value of `x`
func absInt32(x int32) int32 {
	if x < 0 {
		return -x
	} else {
		return x
	}
}
