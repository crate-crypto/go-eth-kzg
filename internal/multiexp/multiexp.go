package multiexp

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func MultiExp(scalars []fr.Element, points []curve.G1Affine) (*curve.G1Affine, error) {
	len_scalars := len(scalars)
	len_points := len(points)
	if len_scalars != len_points {
		return nil, errors.New("number of scalars != number of points")
	}

	// If there is no work to do, we return the identity point.
	// This is not an error, though it would be reasonable to make it so
	// as our use-case should never encounter this case.
	var result curve.G1Affine
	if len(scalars) == 0 {
		return &result, nil
	}

	// We assume that all numbers are in montgomery form
	// This does not hurt interoperability with field element implementations
	// that use a different reduction strategy like Barret, because
	// in the MultiExp function numbers are converted to their normal form
	config := ecc.MultiExpConfig{ScalarsMont: true}

	return result.MultiExp(points, scalars, config)
}
