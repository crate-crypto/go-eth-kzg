package erasure_code

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
)

// The optimised recovery is checked against the implementation it replaced, which is the
// de facto specification for this code. The reference below is the pre-optimisation
// algorithm verbatim: five codeword-sized transforms, no exploitation of the vanishing
// polynomial's structure, no folding.
//
// This exists because the targeted tests written alongside the optimisation only
// exercised mainnet parameters and a handful of erasure patterns. A differential test
// against the old code over the whole parameter space also covers configurations and
// erasure patterns those tests never reach.

// referenceDomains holds the codeword-sized coset domain the old algorithm needed and the
// new one no longer builds.
type referenceDomains struct {
	dr                  *DataRecovery
	domainExtendedCoset *domain.CosetDomain
}

func newReferenceDomains(dr *DataRecovery) *referenceDomains {
	cosetGen := fr.NewElement(7)
	var invCosetGen fr.Element
	invCosetGen.Inverse(&cosetGen)

	return &referenceDomains{
		dr: dr,
		domainExtendedCoset: domain.NewCosetDomain(
			domain.NewDomain(uint64(dr.numScalarsInCodeword)),
			domain.FFTCoset{CosetGen: cosetGen, InvCosetGen: invCosetGen},
		),
	}
}

// constructVanishingPolyOnIndices is the original full-size construction: spread the
// short vanishing polynomial's coefficients at stride blockErasureSize.
func (r *referenceDomains) constructVanishingPolyOnIndices(missing []BlockErasureIndex) []fr.Element {
	roots := make([]fr.Element, len(missing))
	for i, index := range missing {
		roots[i] = r.dr.rootsOfUnityBlockErasureIndex.Roots[index]
	}
	short := vanishingPolyCoeff(roots)

	zeroPolyCoeff := make([]fr.Element, r.dr.numScalarsInCodeword)
	for i, coeff := range short {
		zeroPolyCoeff[i*r.dr.blockErasureSize] = coeff
	}

	return zeroPolyCoeff
}

// recover is the original algorithm, verbatim.
func (r *referenceDomains) recover(data []fr.Element, missing []BlockErasureIndex) []fr.Element {
	zX := r.constructVanishingPolyOnIndices(missing)

	zXForEval := make([]fr.Element, len(zX))
	copy(zXForEval, zX)
	r.dr.domainExtended.FftFr(zXForEval)

	eZEval := make([]fr.Element, len(data))
	for i := 0; i < len(data); i++ {
		eZEval[i].Mul(&data[i], &zXForEval[i])
	}
	r.dr.domainExtended.IfftFr(eZEval)
	dzPoly := eZEval

	r.domainExtendedCoset.CosetFFtFr(zX)
	r.domainExtendedCoset.CosetFFtFr(dzPoly)

	cosetZxInv := fr.BatchInvert(zX)
	quotient := make([]fr.Element, len(cosetZxInv))
	for i := range cosetZxInv {
		quotient[i].Mul(&dzPoly[i], &cosetZxInv[i])
	}
	r.domainExtendedCoset.CosetIFFtFr(quotient)

	return quotient[:r.dr.numScalarsInDataWord]
}

// erase zeroes the positions belonging to the given block indices. Block b owns the
// positions congruent to b modulo totalNumBlocks.
func erase(dr *DataRecovery, codeword []fr.Element, missing []BlockErasureIndex) []fr.Element {
	data := make([]fr.Element, len(codeword))
	copy(data, codeword)
	for _, index := range missing {
		for i := int(index); i < len(data); i += dr.totalNumBlocks {
			data[i] = fr.Element{}
		}
	}

	return data
}

// TestRecoveryMatchesReferenceAcrossParameters sweeps the parameter space, not just the
// mainnet configuration, and compares against the original algorithm bit for bit.
func TestRecoveryMatchesReferenceAcrossParameters(t *testing.T) {
	type params struct{ block, dataWord, expansion int }

	configs := []params{
		{64, 4096, 2}, // mainnet
		{1, 8, 2},
		{2, 8, 2},
		{4, 8, 2},
		{8, 8, 2},
		{1, 16, 4},
		{2, 16, 4},
		{4, 16, 4},
		{2, 32, 8},
		{4, 32, 2},
		{16, 64, 2},
		{8, 64, 4},
		{32, 256, 2},
	}

	rng := rand.New(rand.NewSource(20260815))

	for _, cfg := range configs {
		t.Run(fmt.Sprintf("b=%d_k=%d_e=%d", cfg.block, cfg.dataWord, cfg.expansion), func(t *testing.T) {
			dr := NewDataRecovery(cfg.block, cfg.dataWord, cfg.expansion)
			ref := newReferenceDomains(dr)

			poly := make([]fr.Element, cfg.dataWord)
			for i := range poly {
				poly[i].SetUint64(rng.Uint64())
			}
			buf := make([]fr.Element, cfg.dataWord, dr.numScalarsInCodeword)
			copy(buf, poly)
			codeword := dr.Encode(buf)

			maxMissing := dr.totalNumBlocks - dr.NumBlocksNeededToReconstruct()

			// Every erasure count from none up to the maximum recoverable, with a random
			// subset at each count, plus the two extreme contiguous patterns.
			for numMissing := 0; numMissing <= maxMissing; numMissing++ {
				patterns := [][]BlockErasureIndex{
					randomBlocks(rng, dr.totalNumBlocks, numMissing),
					prefixBlocks(numMissing),
					suffixBlocks(dr.totalNumBlocks, numMissing),
				}

				for pi, missing := range patterns {
					data := erase(dr, codeword, missing)

					want := ref.recover(erase(dr, codeword, missing), missing)
					got, err := dr.RecoverPolynomialCoefficients(data, missing)
					if err != nil {
						t.Fatalf("missing=%d pattern=%d: %v", numMissing, pi, err)
					}

					for i := range want {
						if !got[i].Equal(&want[i]) {
							t.Fatalf("missing=%d pattern=%d: coefficient %d differs from the reference",
								numMissing, pi, i)
						}
						if !got[i].Equal(&poly[i]) {
							t.Fatalf("missing=%d pattern=%d: coefficient %d differs from the original polynomial",
								numMissing, pi, i)
						}
					}
				}
			}
		})
	}
}

func randomBlocks(rng *rand.Rand, total, count int) []BlockErasureIndex {
	perm := rng.Perm(total)[:count]
	out := make([]BlockErasureIndex, 0, count)
	for _, p := range perm {
		out = append(out, BlockErasureIndex(p))
	}
	// The construction does not require sorted indices, but keep it deterministic.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}

	return out
}

func prefixBlocks(count int) []BlockErasureIndex {
	out := make([]BlockErasureIndex, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, BlockErasureIndex(i))
	}

	return out
}

func suffixBlocks(total, count int) []BlockErasureIndex {
	out := make([]BlockErasureIndex, 0, count)
	for i := total - count; i < total; i++ {
		out = append(out, BlockErasureIndex(i))
	}

	return out
}

// benchmarkRecoveryInputs builds deterministic inputs at the production shape: a
// 4096-scalar data word, 2x expansion, 64-scalar blocks, and half of the blocks missing.
// The two benchmarks below share them, so the speedup of the three-transform recovery over
// the five-transform reference can be reproduced from this branch alone with
//
//	go test -bench . -run '^$' ./internal/erasure_code
func benchmarkRecoveryInputs() (*DataRecovery, *referenceDomains, []fr.Element, []BlockErasureIndex) {
	dr := NewDataRecovery(64, 4096, 2)
	ref := newReferenceDomains(dr)

	rng := rand.New(rand.NewSource(20260815))
	poly := make([]fr.Element, dr.numScalarsInDataWord)
	for i := range poly {
		poly[i].SetUint64(rng.Uint64())
	}
	buf := make([]fr.Element, dr.numScalarsInDataWord, dr.numScalarsInCodeword)
	copy(buf, poly)
	codeword := dr.Encode(buf)

	missing := randomBlocks(rng, dr.totalNumBlocks, dr.totalNumBlocks/2)
	data := erase(dr, codeword, missing)

	return dr, ref, data, missing
}

func BenchmarkRecoverPolynomialCoefficients(b *testing.B) {
	dr, _, data, missing := benchmarkRecoveryInputs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dr.RecoverPolynomialCoefficients(data, missing); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRecoverReference(b *testing.B) {
	_, ref, data, missing := benchmarkRecoveryInputs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ref.recover(data, missing)
	}
}

// FuzzRecoveryMatchesReference randomises the polynomial and the erasure pattern.
func FuzzRecoveryMatchesReference(f *testing.F) {
	f.Add(int64(1), uint(3))
	f.Add(int64(99), uint(0))
	f.Add(int64(12345), uint(8))

	dr := NewDataRecovery(4, 32, 2)
	ref := newReferenceDomains(dr)
	maxMissing := dr.totalNumBlocks - dr.NumBlocksNeededToReconstruct()

	f.Fuzz(func(t *testing.T, seed int64, rawCount uint) {
		rng := rand.New(rand.NewSource(seed))
		// Reduce while unsigned: int(rawCount) is negative for rawCount >= 1<<63, which
		// would make numMissing negative and panic in randomBlocks rather than test
		// anything.
		numMissing := int(rawCount % uint(maxMissing+1))

		poly := make([]fr.Element, 32)
		for i := range poly {
			poly[i].SetUint64(rng.Uint64())
		}
		buf := make([]fr.Element, 32, dr.numScalarsInCodeword)
		copy(buf, poly)
		codeword := dr.Encode(buf)

		missing := randomBlocks(rng, dr.totalNumBlocks, numMissing)
		data := erase(dr, codeword, missing)

		want := ref.recover(erase(dr, codeword, missing), missing)
		got, err := dr.RecoverPolynomialCoefficients(data, missing)
		if err != nil {
			t.Fatal(err)
		}
		for i := range want {
			if !got[i].Equal(&want[i]) {
				t.Fatalf("coefficient %d differs from the reference (missing=%v)", i, missing)
			}
		}
	})
}
