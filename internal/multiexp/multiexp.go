package multiexp

import (
	"errors"
	"math"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// MultiExpG1 computes a multi exponentiation -- That is, an inner product between points and scalars.
//
// More precisely, the result is set to scalars[0]*points[0] + ... + scalars[n-1]*points[n-1], where n is the length of both slices
// If the slices differ in length, this function returns an error.
//
// numGoRoutines is used to configure the amount of concurrency needed. Setting this
// value to a negative number or 0 will make it default to the number of CPUs.
//
// Returns an error if the numGoRoutines exceeds 1024.
//
// [g1_lincomb]: https://github.com/ethereum/consensus-specs/blob/017a8495f7671f5fff2075a9bfc9238c1a0982f8/specs/deneb/polynomial-commitments.md#g1_lincomb
func MultiExpG1(scalars []fr.Element, points []bls12381.G1Affine, numGoRoutines int) (*bls12381.G1Affine, error) {
	err := isValidNumGoRoutines(numGoRoutines)
	if err != nil {
		return nil, err
	}
	return new(bls12381.G1Affine).MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: numGoRoutines})
}

func MultiExpG2(scalars []fr.Element, points []bls12381.G2Affine, numGoRoutines int) (*bls12381.G2Affine, error) {
	err := isValidNumGoRoutines(numGoRoutines)
	if err != nil {
		return nil, err
	}
	return new(bls12381.G2Affine).MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: numGoRoutines})
}

// isValidNumGoRoutines will return an error if the number
// of go routines to be used is not Valid.
//
// Valid meaning that is less than 1024.
//
// 1024 is chosen here as the underlying gnark-crypto library will
// return an error for more than 1024.
// Instead of waiting until the user tries to call an algorithm
// which requires numGoRoutines, we return the error here instead.
func isValidNumGoRoutines(value int) error {
	if value >= 1024 {
		return ErrTooManyGoRoutines
	}
	return nil
}

// TODO: Remove _nbThreads since this is single threaded
// TODO: It is only here to not break the API
func MultiExpG1Pippenger(scalars []fr.Element, points []bls12381.G1Affine, _nbThreads int) (*bls12381.G1Affine, error) {
	if _nbThreads >= 1024 {
		// TODO: Just putting this here for tests and to match old impl
		// TODO: This impl is single threaded anyways
		return nil, ErrTooManyGoRoutines
	}
	if len(scalars) != len(points) {
		return nil, errors.New("number of scalars should be equal the number of points")
	}

	// Convert scalars to bytes
	scalarsBytes := scalarsToBytes(scalars)

	// First need to compute a window length
	var c = computeWindowSize(len(points))

	// Compute number of windows needed
	numWindows := (fr.Bits / c) + 1
	windowSums := make([]bls12381.G1Jac, numWindows)

	// Create all of the buckets for window size
	buckets := make([][]bls12381.G1Affine, 1<<(c-1))

	for currentWindow := 0; currentWindow < numWindows; currentWindow++ {

		// Clear all buckets (but keep capacity)
		for i := range buckets {
			buckets[i] = buckets[i][:0]
		}

		for i := 0; i < len(scalars); i++ {
			scalarBytes := scalarsBytes[i]
			point := points[i]

			digit := getBoothIndex(currentWindow, c, scalarBytes)
			if digit > 0 {
				buckets[digit-1] = append(buckets[digit-1], point)
			} else if digit < 0 {
				var negPoint bls12381.G1Affine
				negPoint.Neg(&point)
				buckets[uint(-digit)-1] = append(buckets[uint(-digit)-1], negPoint)
			}
		}

		summedBuckets := MultiBatchAdditionBinaryTreeStride(buckets)

		runningSum := bls12381.G1Jac{}
		for i := len(summedBuckets) - 1; i >= 0; i-- {
			runningSum.AddAssign(&summedBuckets[i])
			windowSums[currentWindow].AddAssign(&runningSum)
		}
	}

	result := bls12381.G1Jac{}

	result.Set(&windowSums[numWindows-1]) // Set the accumulator to the last point
	for currentWindow := numWindows - 2; currentWindow >= 0; currentWindow-- {
		for i := 0; i < c; i++ {
			result.DoubleAssign()
		}
		result.AddAssign(&windowSums[currentWindow])
	}

	var resultAff bls12381.G1Affine
	resultAff.FromJacobian(&result)

	return &resultAff, nil
}

func computeWindowSize(numPoints int) int {
	if numPoints < 8 {
		return 2
	} else if numPoints < 16 {
		return 3
	} else if numPoints < 32 {
		return 4
	} else {
		return int(math.Ceil(math.Log(float64(numPoints))))
	}
}
