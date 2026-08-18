package kzgmulti

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/multiexp"
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
	rPowers := utils.ComputePowers(r, uint(len(commitmentIndices)))

	numCosets := len(cosetIndices)
	numUniqueCommitments := len(deduplicatedCommitments)
	commRandomSumProofs, err := multiexp.MultiExpG1(rPowers, proofs, 0)
	if err != nil {
		return err
	}

	weights := make([]fr.Element, numUniqueCommitments)
	for k := 0; k < numCosets; k++ {
		commitmentIndex := commitmentIndices[k]
		weights[commitmentIndex].Add(&weights[commitmentIndex], &rPowers[k])
	}
	commRandomSumComms, err := multiexp.MultiExpG1(weights, deduplicatedCommitments, 0)
	if err != nil {
		return err
	}

	cosetSize := openKey.CosetSize

	// Compute random linear sum of interpolation polynomials
	interpolationPoly := sumRandomScaledInterpolationPolys(cosetEvals, cosetIndices, rPowers, openKey)

	commRandomSumInterPoly, err := openKey.CommitG1(interpolationPoly)
	if err != nil {
		return err
	}

	weightedRPowers := make([]fr.Element, numCosets)
	for k := 0; k < len(rPowers); k++ {
		cosetIndex := cosetIndices[k]
		rPower := rPowers[k]
		cosetShiftPowN := openKey.CosetShiftsPowCosetSize[cosetIndex]
		weightedRPowers[k].Mul(&cosetShiftPowN, &rPower)
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

// sumRandomScaledInterpolationPolys computes the random linear combination of
// the interpolation polynomials over the cells' cosets:
//
//	sum_k r^k * I_k(X)
//
// where I_k is the polynomial interpolating the k-th cell's evaluations over
// the coset given by cosetIndices[k].
//
// Instead of performing one coset IFFT per cell, the r^k-scaled evaluations of
// all cells that share a coset (i.e. a column of the extended-blob matrix) are
// summed first, and a single coset IFFT is performed per *distinct* coset.
// Both the bit-reversal permutation and the coset IFFT are linear maps, and
// cells with the same coset index are evaluated over the same coset, so:
//
//	sum_k r^k * CosetIFFT_c(BitReverse(evals_k)) = CosetIFFT_c(BitReverse(sum_k r^k * evals_k))
//
// This bounds the number of coset IFFTs by the number of cosets (128), no
// matter how many cells are in the batch.
func sumRandomScaledInterpolationPolys(cosetEvals [][]fr.Element, cosetIndices []uint64, rPowers []fr.Element, openKey *OpeningKey) []fr.Element {
	// Sum the r^k-scaled evaluations of all cells that share a coset.
	// The scaling must happen before the aggregation (and hence before the
	// IFFT): each cell carries its own randomizer power r^k, which is what
	// binds the cell to its commitment and proof in the pairing check.
	aggregatedColumnEvals := make([][]fr.Element, len(openKey.cosetDomains))
	for k, cosetEval := range cosetEvals {
		cosetIndex := cosetIndices[k]
		aggregatedEval := aggregatedColumnEvals[cosetIndex]
		if aggregatedEval == nil {
			// First cell seen for this coset: adopt its storage as the
			// column accumulator, scaling in place. This is why cosetEvals
			// must be treated as a mutable reference.
			for i := 0; i < len(cosetEval); i++ {
				cosetEval[i].Mul(&cosetEval[i], &rPowers[k])
			}
			aggregatedColumnEvals[cosetIndex] = cosetEval
			continue
		}

		var scaledEval fr.Element
		for i := 0; i < len(cosetEval); i++ {
			scaledEval.Mul(&cosetEval[i], &rPowers[k])
			aggregatedEval[i].Add(&aggregatedEval[i], &scaledEval)
		}
	}

	// One coset IFFT per distinct coset present in the batch. The first
	// transformed column is adopted as the final accumulator and every
	// further column is added into it in place (all columns have coset-size
	// length), so the summation itself performs no allocations.
	interpolationPoly := []fr.Element{}
	for cosetIndex, aggregatedEval := range aggregatedColumnEvals {
		if aggregatedEval == nil {
			continue
		}

		domain.BitReverse(aggregatedEval)

		// Coset IFFT
		cosetDomain := openKey.cosetDomains[cosetIndex]
		cosetDomain.CosetIFFtFr(aggregatedEval)
		cosetMonomial := aggregatedEval

		if len(interpolationPoly) == 0 {
			interpolationPoly = cosetMonomial
		} else {
			for i := 0; i < len(cosetMonomial); i++ {
				interpolationPoly[i].Add(&interpolationPoly[i], &cosetMonomial[i])
			}
		}
	}

	return interpolationPoly
}
