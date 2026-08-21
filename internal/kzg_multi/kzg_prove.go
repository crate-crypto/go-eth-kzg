package kzgmulti

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg_multi/fk20"
	"github.com/crate-crypto/go-eth-kzg/internal/poly"
)

// numGoRoutines is used to configure the amount of concurrency needed. Setting this
// value to a negative number or 0 will make it default to the number of CPUs.
func ComputeMultiPointKZGProofs(fk20 *fk20.FK20, poly poly.PolynomialCoeff, numGoRoutines int) ([]bls12381.G1Affine, error) {
	return fk20.ComputeMultiOpenProof(poly, numGoRoutines)
}
