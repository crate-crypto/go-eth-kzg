package kzgmulti

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg_multi/fk20"
)

func ComputeMultiPointKZGProofs(fk20 *fk20.FK20, poly PolynomialCoeff, inputPoints [][]fr.Element, ck *kzg.CommitKey) ([]bls12381.G1Affine, [][]fr.Element, error) {
	proofs, err := fk20.ComputeMultiOpenProof(poly, ck.G1)
	if err != nil {
		return nil, nil, err
	}
	outputPointsSet := fk20.ComputeEvaluationSet(poly)

	return proofs, outputPointsSet, nil
}
