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
// numGoRoutines is used to configure the amount of concurrency needed. Setting this
// value to a negative number or 0 will make it default to the number of CPUs.
//
// [g1_lincomb]: https://github.com/ethereum/consensus-specs/blob/50a3f8e8d902ad9d677ca006302eb9535d56d758/specs/deneb/polynomial-commitments.md#g1_lincomb
func MultiExp(scalars []fr.Element, points []bls12381.G1Affine, numGoRoutines int) (*bls12381.G1Affine, error) {
	return new(bls12381.G1Affine).MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: numGoRoutines})
}
