package erasure_code

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
)

const (
	testBlockErasureSize = 64
	testNumScalars       = 4096
	testExpansionFactor  = 2
)

func testDataRecovery() *DataRecovery {
	return NewDataRecovery(testBlockErasureSize, testNumScalars, testExpansionFactor)
}

// testCodeword returns a codeword together with the polynomial it encodes.
func testCodeword(dr *DataRecovery) (codeword, polyCoeff []fr.Element) {
	polyCoeff = make([]fr.Element, testNumScalars)
	for i := range polyCoeff {
		polyCoeff[i].SetUint64(uint64(i)*7919 + 13)
	}

	buf := make([]fr.Element, testNumScalars, testNumScalars*testExpansionFactor)
	copy(buf, polyCoeff)

	return dr.Encode(buf), polyCoeff
}

// eraseBlocks zeroes the evaluations belonging to the given block erasure indices.
//
// Block index b owns the positions congruent to b modulo totalNumBlocks, i.e. a coset of
// the subgroup of order blockErasureSize, which is what the vanishing polynomial vanishes
// on. The positions are strided rather than contiguous; contiguity only holds in bit
// reversed order.
func eraseBlocks(dr *DataRecovery, codeword []fr.Element, missing []BlockErasureIndex) []fr.Element {
	data := make([]fr.Element, len(codeword))
	copy(data, codeword)
	for _, index := range missing {
		for i := int(index); i < len(data); i += dr.totalNumBlocks {
			data[i] = fr.Element{}
		}
	}

	return data
}

// TestRecoveryRoundTrip checks that recovery returns the original polynomial for a range
// of erasure counts and patterns, up to the maximum recoverable number of erasures.
func TestRecoveryRoundTrip(t *testing.T) {
	dr := testDataRecovery()
	codeword, polyCoeff := testCodeword(dr)
	maxMissing := dr.totalNumBlocks - dr.NumBlocksNeededToReconstruct()

	patterns := map[string]func(numMissing int) []BlockErasureIndex{
		"prefix": func(numMissing int) []BlockErasureIndex {
			missing := make([]BlockErasureIndex, 0, numMissing)
			for i := 0; i < numMissing; i++ {
				missing = append(missing, BlockErasureIndex(i))
			}

			return missing
		},
		"suffix": func(numMissing int) []BlockErasureIndex {
			missing := make([]BlockErasureIndex, 0, numMissing)
			for i := dr.totalNumBlocks - numMissing; i < dr.totalNumBlocks; i++ {
				missing = append(missing, BlockErasureIndex(i))
			}

			return missing
		},
		"strided": func(numMissing int) []BlockErasureIndex {
			missing := make([]BlockErasureIndex, 0, numMissing)
			for i := 0; i < numMissing; i++ {
				missing = append(missing, BlockErasureIndex(i*dr.totalNumBlocks/numMissing))
			}

			return missing
		},
	}

	for name, pattern := range patterns {
		for _, numMissing := range []int{1, 2, 7, 32, maxMissing - 1, maxMissing} {
			t.Run(fmt.Sprintf("%s/missing=%d", name, numMissing), func(t *testing.T) {
				missing := pattern(numMissing)
				data := eraseBlocks(dr, codeword, missing)

				got, err := dr.RecoverPolynomialCoefficients(data, missing)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != testNumScalars {
					t.Fatalf("expected %d coefficients, got %d", testNumScalars, len(got))
				}
				for i := range polyCoeff {
					if !got[i].Equal(&polyCoeff[i]) {
						t.Fatalf("coefficient %d does not match the encoded polynomial", i)
					}
				}
			})
		}
	}
}

// TestRecoveryNoErasures checks the degenerate case where nothing is missing.
func TestRecoveryNoErasures(t *testing.T) {
	dr := testDataRecovery()
	codeword, polyCoeff := testCodeword(dr)

	got, err := dr.RecoverPolynomialCoefficients(codeword, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range polyCoeff {
		if !got[i].Equal(&polyCoeff[i]) {
			t.Fatalf("coefficient %d does not match the encoded polynomial", i)
		}
	}
}

func TestRecoveryRejectsWrongCodewordLength(t *testing.T) {
	dr := testDataRecovery()
	if _, err := dr.RecoverPolynomialCoefficients(make([]fr.Element, 8), nil); err == nil {
		t.Fatal("expected an error for a codeword of the wrong length")
	}
}

func TestRecoveryRejectsTooManyMissingBlocks(t *testing.T) {
	dr := testDataRecovery()
	codeword, _ := testCodeword(dr)

	missing := make([]BlockErasureIndex, 0, dr.totalNumBlocks)
	for i := 0; i <= dr.totalNumBlocks-dr.NumBlocksNeededToReconstruct(); i++ {
		missing = append(missing, BlockErasureIndex(i))
	}

	data := eraseBlocks(dr, codeword, missing)
	if _, err := dr.RecoverPolynomialCoefficients(data, missing); err == nil {
		t.Fatal("expected an error for more missing blocks than the code can correct")
	}
}

// TestVanishingPolyIsCompressible pins the property the recovery algorithm relies on:
// the vanishing polynomial satisfies Z(x) = Zhat(x^blockErasureSize), so evaluating it
// over the codeword domain only ever produces totalNumBlocks distinct values.
//
// If this ever stops holding, RecoverPolynomialCoefficients is wrong rather than slow,
// so it is asserted directly rather than left as a comment.
func TestVanishingPolyIsCompressible(t *testing.T) {
	dr := testDataRecovery()

	missing := []BlockErasureIndex{0, 3, 17, 64, 127}
	zHat := dr.compressedVanishingPoly(missing)

	// Expand Zhat into the full vanishing polynomial the naive way, by spreading its
	// coefficients at stride blockErasureSize.
	zFull := make([]fr.Element, dr.numScalarsInCodeword)
	for i, coeff := range zHat {
		zFull[i*dr.blockErasureSize] = coeff
	}
	dr.domainExtended.FftFr(zFull)

	// The compressed evaluation used by the recovery algorithm.
	zSmall := make([]fr.Element, dr.totalNumBlocks)
	copy(zSmall, zHat)
	dr.rootsOfUnityBlockErasureIndex.FftFr(zSmall)

	for i := range zFull {
		if !zFull[i].Equal(&zSmall[i%dr.totalNumBlocks]) {
			t.Fatalf("vanishing polynomial evaluation %d is not periodic with period %d", i, dr.totalNumBlocks)
		}
	}

	// It must vanish exactly on the missing blocks and nowhere else.
	isMissing := make(map[uint64]bool, len(missing))
	for _, index := range missing {
		isMissing[index] = true
	}
	for i := range zSmall {
		if zSmall[i].IsZero() != isMissing[uint64(i)] {
			t.Fatalf("vanishing polynomial has the wrong root structure at block %d", i)
		}
	}
}

// TestVanishingPolyHasNoRootsOnCoset pins the other precondition: the division performed
// during recovery is only well defined because Z has no roots on the coset it is
// evaluated over.
func TestVanishingPolyHasNoRootsOnCoset(t *testing.T) {
	dr := testDataRecovery()

	missing := make([]BlockErasureIndex, 0, dr.totalNumBlocks)
	for i := 0; i < dr.totalNumBlocks-dr.NumBlocksNeededToReconstruct(); i++ {
		missing = append(missing, BlockErasureIndex(i))
	}

	zHat := dr.compressedVanishingPoly(missing)
	folded := make([]fr.Element, dr.numScalarsInDataWord/dr.blockErasureSize)
	for i := range zHat {
		var scaled fr.Element
		scaled.Mul(&zHat[i], &dr.foldPowers[i/len(folded)])
		folded[i%len(folded)].Add(&folded[i%len(folded)], &scaled)
	}
	dr.vanishingCoset.CosetFFtFr(folded)

	for i := range folded {
		if folded[i].IsZero() {
			t.Fatalf("vanishing polynomial has a root on the coset at index %d", i)
		}
	}
}

// TestFoldToDataWordPreservesCosetEvaluations pins the folding step: reducing a codeword
// sized polynomial to data word size must not change its values on the coset.
func TestFoldToDataWordPreservesCosetEvaluations(t *testing.T) {
	dr := testDataRecovery()

	full := make([]fr.Element, dr.numScalarsInCodeword)
	for i := range full {
		full[i].SetUint64(uint64(i)*31 + 7)
	}

	// Evaluate the unfolded polynomial on the coset directly, at codeword size.
	cosetGen := fr.NewElement(7)
	var invCosetGen fr.Element
	invCosetGen.Inverse(&cosetGen)
	wide := make([]fr.Element, len(full))
	copy(wide, full)
	domain.NewCosetDomain(
		dr.domainExtended,
		domain.FFTCoset{CosetGen: cosetGen, InvCosetGen: invCosetGen},
	).CosetFFtFr(wide)

	folded := dr.foldToDataWord(full)
	dr.dataWordCoset.CosetFFtFr(folded)

	// The data word coset is every expansionFactor'th point of the codeword coset.
	for i := range folded {
		if !folded[i].Equal(&wide[i*dr.expansionFactor]) {
			t.Fatalf("folding changed the evaluation at coset point %d", i)
		}
	}
}
