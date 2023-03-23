package multiexp

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// MultiExp computes a multi exponentiation -- That is, an inner product between points and scalars.
//
// More precisely, the result is set to scalars[0]*points[0] + ... + scalars[n-1]*points[n-1], where n is the length of both slices
// If the slices differ in length, this function returns an error.
//
// [g1_lincomb](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#g1_lincomb)
func MultiExp(scalars []fr.Element, points []bls12381.G1Affine) (*bls12381.G1Affine, error) {
	var result bls12381.G1Affine

	return result.MultiExp(points, scalars, ecc.MultiExpConfig{})
}
