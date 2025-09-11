package kzgmulti

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg_multi/fk20"
	"github.com/stretchr/testify/assert"
)

func TestProveVerify(t *testing.T) {
	const EXTENSION_FACTOR = 2
	const NUM_COEFFS_IN_POLY = 4096
	const COSET_SIZE = 64
	domain := domain.NewDomain(NUM_COEFFS_IN_POLY)

	srs, err := newMonomialSRSInsecureUint64(domain.Cardinality, NUM_COEFFS_IN_POLY*EXTENSION_FACTOR, COSET_SIZE, big.NewInt(1234))
	assert.NoError(t, err)

	fk20Instance := fk20.NewFK20(srs.CommitKey.G1, NUM_COEFFS_IN_POLY*EXTENSION_FACTOR, COSET_SIZE)

	poly := make([]fr.Element, NUM_COEFFS_IN_POLY)
	for i := 0; i < NUM_COEFFS_IN_POLY; i++ {
		poly[i].SetBigInt(big.NewInt(int64(i)))
	}
	cosetsEvals := fk20Instance.ComputeExtendedPolynomial(poly)
	proofs, err := fk20Instance.ComputeMultiOpenProof(poly)
	assert.True(t, len(cosetsEvals[0]) == COSET_SIZE)
	assert.NoError(t, err)
	commitment, err := srs.CommitKey.Commit(poly, 0)
	assert.NoError(t, err)

	cosetIndices := make([]uint64, 128)
	for k := 0; k < 128; k++ {
		cosetIndices[k] = uint64(k)
	}
	commitmentIndices := make([]uint64, 128)
	err = VerifyMultiPointKZGProofBatch([]bls12381.G1Affine{*commitment}, commitmentIndices, cosetIndices, proofs, cosetsEvals, &srs.OpeningKey)
	assert.NoError(t, err)
}
