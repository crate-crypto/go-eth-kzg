package kzgmulti

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg_multi/fk20"
	"github.com/crate-crypto/go-eth-kzg/internal/poly"
	"github.com/crate-crypto/go-eth-kzg/internal/utils"
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

// referenceSumRandomScaledInterpolationPolys is the pre-column-aggregation
// implementation of the interpolation step of VerifyMultiPointKZGProofBatch:
// one coset IFFT per cell, scaling by r^k after the IFFT. It is kept here as
// the reference for the differential tests below.
func referenceSumRandomScaledInterpolationPolys(cosetEvals [][]fr.Element, cosetIndices []uint64, rPowers []fr.Element, openKey *OpeningKey) []fr.Element {
	interpolationPoly := []fr.Element{}
	for k, cosetEval := range cosetEvals {
		// The reference implementation mutated cosetEval in place; work on a
		// copy so both implementations can be fed the same inputs.
		cosetEval = append([]fr.Element{}, cosetEval...)
		domain.BitReverse(cosetEval)

		// Coset IFFT
		cosetIndex := cosetIndices[k]
		cosetDomain := openKey.cosetDomains[cosetIndex]
		cosetDomain.CosetIFFtFr(cosetEval)
		cosetMonomial := cosetEval

		// Scale the interpolation polynomial
		for i := 0; i < len(cosetMonomial); i++ {
			cosetMonomial[i].Mul(&cosetMonomial[i], &rPowers[k])
		}

		interpolationPoly = poly.PolyAdd(interpolationPoly, cosetMonomial)
	}
	return interpolationPoly
}

type multiVerifyTestSetup struct {
	srs *SRS
	// cosetsEvals[b][c] holds the evaluations of blob b over coset c
	cosetsEvals [][][]fr.Element
	proofs      [][]bls12381.G1Affine
	commitments []bls12381.G1Affine
}

func newMultiVerifyTestSetup(t *testing.T, numBlobs int, withProofs bool) *multiVerifyTestSetup {
	t.Helper()
	const NUM_COEFFS_IN_POLY = 4096
	const EXTENSION_FACTOR = 2
	const COSET_SIZE = 64
	d := domain.NewDomain(NUM_COEFFS_IN_POLY)

	srs, err := newMonomialSRSInsecureUint64(d.Cardinality, NUM_COEFFS_IN_POLY*EXTENSION_FACTOR, COSET_SIZE, big.NewInt(1234))
	assert.NoError(t, err)

	fk20Instance := fk20.NewFK20(srs.CommitKey.G1, NUM_COEFFS_IN_POLY*EXTENSION_FACTOR, COSET_SIZE)

	setup := &multiVerifyTestSetup{srs: srs}
	for b := 0; b < numBlobs; b++ {
		p := make([]fr.Element, NUM_COEFFS_IN_POLY)
		for i := 0; i < NUM_COEFFS_IN_POLY; i++ {
			p[i].SetBigInt(big.NewInt(int64(i*numBlobs + b + 1)))
		}
		setup.cosetsEvals = append(setup.cosetsEvals, fk20Instance.ComputeExtendedPolynomial(p))
		if withProofs {
			proofs, err := fk20Instance.ComputeMultiOpenProof(p)
			assert.NoError(t, err)
			setup.proofs = append(setup.proofs, proofs)
			commitment, err := srs.CommitKey.Commit(p, 0)
			assert.NoError(t, err)
			setup.commitments = append(setup.commitments, *commitment)
		}
	}
	return setup
}

// TestSumRandomScaledInterpolationPolysDifferential asserts that the
// column-aggregated interpolation step produces bit-identical polynomials to
// the per-cell reference implementation, across batch shapes.
func TestSumRandomScaledInterpolationPolysDifferential(t *testing.T) {
	setup := newMultiVerifyTestSetup(t, 3, false)

	type cellRef struct {
		blob  int
		coset uint64
	}
	shapes := map[string][]cellRef{
		"empty":  {},
		"1 cell": {{blob: 0, coset: 17}},
		"single blob, all 128 columns": func() []cellRef {
			var refs []cellRef
			for c := uint64(0); c < 128; c++ {
				refs = append(refs, cellRef{blob: 0, coset: c})
			}
			return refs
		}(),
		"3 blobs, all 128 columns shared": func() []cellRef {
			var refs []cellRef
			for b := 0; b < 3; b++ {
				for c := uint64(0); c < 128; c++ {
					refs = append(refs, cellRef{blob: b, coset: c})
				}
			}
			return refs
		}(),
		"duplicate column indices from different blobs": {
			{blob: 0, coset: 5}, {blob: 1, coset: 5}, {blob: 2, coset: 5}, {blob: 0, coset: 7},
		},
		"3 blobs, sparse shared columns": {
			{blob: 0, coset: 0}, {blob: 1, coset: 0}, {blob: 2, coset: 0},
			{blob: 0, coset: 63}, {blob: 1, coset: 63},
			{blob: 2, coset: 127},
		},
	}

	var r fr.Element
	r.SetUint64(0xc0ffee)

	for name, refs := range shapes {
		t.Run(name, func(t *testing.T) {
			cosetEvals := make([][]fr.Element, len(refs))
			cosetIndices := make([]uint64, len(refs))
			for k, ref := range refs {
				cosetEvals[k] = setup.cosetsEvals[ref.blob][ref.coset]
				cosetIndices[k] = ref.coset
			}
			rPowers := utils.ComputePowers(r, uint(len(refs)))

			expected := referenceSumRandomScaledInterpolationPolys(cosetEvals, cosetIndices, rPowers, &setup.srs.OpeningKey)

			// sumRandomScaledInterpolationPolys may mutate its input; give it copies.
			cosetEvalsCopy := make([][]fr.Element, len(cosetEvals))
			for k := range cosetEvals {
				cosetEvalsCopy[k] = append([]fr.Element{}, cosetEvals[k]...)
			}
			got := sumRandomScaledInterpolationPolys(cosetEvalsCopy, cosetIndices, rPowers, &setup.srs.OpeningKey)

			assert.Equal(t, len(expected), len(got))
			for i := range expected {
				assert.True(t, expected[i].Equal(&got[i]), "coefficient %d differs", i)
			}
		})
	}
}

// TestVerifyMultiPointKZGProofBatchShapes asserts the end-to-end verification
// outcome for multi-blob batches, including duplicate column indices, and that
// invalid inputs are still rejected with the same error.
func TestVerifyMultiPointKZGProofBatchShapes(t *testing.T) {
	setup := newMultiVerifyTestSetup(t, 2, true)
	openKey := &setup.srs.OpeningKey

	buildBatch := func(refs [][2]int) (commitmentIndices, cosetIndices []uint64, proofs []bls12381.G1Affine, cosetEvals [][]fr.Element) {
		for _, ref := range refs {
			b, c := ref[0], ref[1]
			commitmentIndices = append(commitmentIndices, uint64(b))
			cosetIndices = append(cosetIndices, uint64(c))
			proofs = append(proofs, setup.proofs[b][c])
			// Copy since VerifyMultiPointKZGProofBatch may mutate the evals.
			cosetEvals = append(cosetEvals, append([]fr.Element{}, setup.cosetsEvals[b][c]...))
		}
		return
	}

	t.Run("2 blobs sharing columns accept", func(t *testing.T) {
		var refs [][2]int
		for b := 0; b < 2; b++ {
			for c := 0; c < 128; c++ {
				refs = append(refs, [2]int{b, c})
			}
		}
		commitmentIndices, cosetIndices, proofs, cosetEvals := buildBatch(refs)
		err := VerifyMultiPointKZGProofBatch(setup.commitments, commitmentIndices, cosetIndices, proofs, cosetEvals, openKey)
		assert.NoError(t, err)
	})

	t.Run("duplicate column indices accept", func(t *testing.T) {
		refs := [][2]int{{0, 9}, {1, 9}, {0, 42}, {1, 42}, {1, 9}}
		commitmentIndices, cosetIndices, proofs, cosetEvals := buildBatch(refs)
		err := VerifyMultiPointKZGProofBatch(setup.commitments, commitmentIndices, cosetIndices, proofs, cosetEvals, openKey)
		assert.NoError(t, err)
	})

	t.Run("1-cell batch accept", func(t *testing.T) {
		commitmentIndices, cosetIndices, proofs, cosetEvals := buildBatch([][2]int{{1, 77}})
		err := VerifyMultiPointKZGProofBatch(setup.commitments, commitmentIndices, cosetIndices, proofs, cosetEvals, openKey)
		assert.NoError(t, err)
	})

	t.Run("tampered eval rejected", func(t *testing.T) {
		refs := [][2]int{{0, 9}, {1, 9}, {0, 42}, {1, 42}}
		commitmentIndices, cosetIndices, proofs, cosetEvals := buildBatch(refs)
		cosetEvals[2][3].SetUint64(123456789)
		err := VerifyMultiPointKZGProofBatch(setup.commitments, commitmentIndices, cosetIndices, proofs, cosetEvals, openKey)
		assert.ErrorIs(t, err, kzg.ErrVerifyOpeningProof)
	})

	t.Run("swapped proof rejected", func(t *testing.T) {
		refs := [][2]int{{0, 9}, {1, 9}, {0, 42}, {1, 42}}
		commitmentIndices, cosetIndices, proofs, cosetEvals := buildBatch(refs)
		proofs[0], proofs[1] = proofs[1], proofs[0]
		err := VerifyMultiPointKZGProofBatch(setup.commitments, commitmentIndices, cosetIndices, proofs, cosetEvals, openKey)
		assert.ErrorIs(t, err, kzg.ErrVerifyOpeningProof)
	})
}
