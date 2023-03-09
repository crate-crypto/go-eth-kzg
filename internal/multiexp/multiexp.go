package multiexp

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Computes a multi exponentiation -- This is inner product between points and scalars
//
// [g1_lincomb](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#g1_lincomb)
func MultiExp(scalars []fr.Element, points []bls12381.G1Affine) (*bls12381.G1Affine, error) {
	var result bls12381.G1Affine
	return result.MultiExp(points, scalars, ecc.MultiExpConfig{})
}
