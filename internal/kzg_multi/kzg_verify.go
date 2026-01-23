package kzgmulti

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/multiexp"
	"github.com/crate-crypto/go-eth-kzg/internal/pool"
	"github.com/crate-crypto/go-eth-kzg/internal/utils"
)

// Verifies Multiple KZGProofs
//
// Note: `cosetEvals` is mutated in-place, ie it should be treated as a mutable reference
func VerifyMultiPointKZGProofBatch(deduplicatedCommitments []bls12381.G1Affine, commitmentIndices, cosetIndices []uint64, proofs []bls12381.G1Affine, cosetEvals [][]fr.Element, openKey *OpeningKey) error {
	// Sample random numbers for sampling.
	//
	// We only need to sample one random number and
	// compute powers of that random number. This works
	// since powers will produce a vandermonde matrix
	// which is linearly independent.
	var r fr.Element
	_, err := r.SetRandom()
	if err != nil {
		return err
	}

	numCosets := len(cosetIndices)
	numUniqueCommitments := len(deduplicatedCommitments)
	cosetSize := int(openKey.CosetSize)

	// Get buffers from pool (thread-safe)
	buf, err := pool.Get[*VerifyBuffers](&openKey.verifyBufPool)
	if err != nil {
		return err
	}
	defer pool.Put(&openKey.verifyBufPool, buf)

	// Compute powers of r
	rPowers := utils.ComputePowers(r, uint(numCosets))

	commRandomSumProofs, err := multiexp.MultiExpG1(rPowers, proofs, 0)
	if err != nil {
		return err
	}

	// Use pooled weights buffer - needs clearing since we accumulate into it
	buf.weights = utils.ClearAndResize(buf.weights, numUniqueCommitments, true)
	weights := buf.weights
	for k := 0; k < numCosets; k++ {
		commitmentIndex := commitmentIndices[k]
		weights[commitmentIndex].Add(&weights[commitmentIndex], &rPowers[k])
	}
	commRandomSumComms, err := multiexp.MultiExpG1(weights, deduplicatedCommitments, 0)
	if err != nil {
		return err
	}

	// Use pooled interpolation polynomial buffer and clear it
	interpolationPoly := buf.interpolationPoly[:cosetSize]
	for i := range interpolationPoly {
		interpolationPoly[i].SetZero()
	}

	// Use pooled coset monomial buffer
	cosetMonomialBuf := buf.cosetMonomialBuf[:cosetSize]

	// Compute random linear sum of interpolation polynomials
	for k, cosetEval := range cosetEvals {
		domain.BitReverse(cosetEval)

		// Coset IFFT into pooled buffer
		cosetIndex := cosetIndices[k]
		cosetDomain := openKey.cosetDomains[cosetIndex]

		copy(cosetMonomialBuf, cosetEval)
		cosetDomain.CosetIFFtFr(cosetMonomialBuf)

		// Accumulate: interpolationPoly += rPowers[k] * cosetMonomial
		rPower := &rPowers[k]
		for i := 0; i < cosetSize; i++ {
			var tmp fr.Element
			tmp.Mul(&cosetMonomialBuf[i], rPower)
			interpolationPoly[i].Add(&interpolationPoly[i], &tmp)
		}
	}

	commRandomSumInterPoly, err := openKey.CommitG1(interpolationPoly)
	if err != nil {
		return err
	}

	// Use pooled weightedRPowers buffer - fully overwritten so no clear needed
	buf.weightedRPowers = utils.ClearAndResize(buf.weightedRPowers, numCosets, false)
	weightedRPowers := buf.weightedRPowers
	for k := 0; k < numCosets; k++ {
		cosetIndex := cosetIndices[k]
		cosetShiftPowN := openKey.CosetShiftsPowCosetSize[cosetIndex]
		weightedRPowers[k].Mul(&cosetShiftPowN, &rPowers[k])
	}
	randomWeightedSumProofs, err := multiexp.MultiExpG1(weightedRPowers, proofs, 0)
	if err != nil {
		return err
	}

	rl := bls12381.G1Affine{}
	rl.Sub(commRandomSumComms, commRandomSumInterPoly)
	rl.Add(&rl, randomWeightedSumProofs)

	negG2Gen := bls12381.G2Affine{}
	negG2Gen.Neg(openKey.genG2())

	sPowCosetSize := openKey.G2[cosetSize]

	check, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{*commRandomSumProofs, rl},
		[]bls12381.G2Affine{sPowCosetSize, negG2Gen},
	)
	if err != nil {
		return err
	}
	if !check {
		return kzg.ErrVerifyOpeningProof
	}
	return nil
}
