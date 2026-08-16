package goethkzg_test

// Tests for the concurrent deserialization path in VerifyCellKZGProofBatch.
//
// The consensus-spec vectors never exercise it: the largest vector has 3 cells,
// below the threshold at which parallelizeDeserialization spawns goroutines at
// all. These tests build large batches so the parallel path runs, and check
// that error reporting stays deterministic under scheduling (run with -race).

import (
	"testing"

	goethkzg "github.com/crate-crypto/go-eth-kzg"
	"github.com/stretchr/testify/require"
)

// buildVerifyBatch returns a valid size-entry batch built from one random blob,
// cycling through its cells.
func buildVerifyBatch(t *testing.T, size int) ([]goethkzg.KZGCommitment, []uint64, []*goethkzg.Cell, []goethkzg.KZGProof) {
	t.Helper()

	blob := GetRandBlob(0xC0FFEE)
	commitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
	require.NoError(t, err)
	cells, proofs, err := ctx.ComputeCellsAndKZGProofs(blob, NumGoRoutines)
	require.NoError(t, err)

	commitments := make([]goethkzg.KZGCommitment, size)
	cellIndices := make([]uint64, size)
	cellPtrs := make([]*goethkzg.Cell, size)
	proofList := make([]goethkzg.KZGProof, size)
	for i := 0; i < size; i++ {
		j := i % goethkzg.CellsPerExtBlob
		commitments[i] = commitment
		cellIndices[i] = uint64(j)
		cellPtrs[i] = cells[j]
		proofList[i] = proofs[j]
	}
	return commitments, cellIndices, cellPtrs, proofList
}

// TestVerifyCellKZGProofBatchParallelPath verifies batches large enough that
// proof and cell deserialization fan out over goroutines.
func TestVerifyCellKZGProofBatchParallelPath(t *testing.T) {
	for _, size := range []int{32, goethkzg.CellsPerExtBlob} {
		commitments, cellIndices, cells, proofs := buildVerifyBatch(t, size)
		err := ctx.VerifyCellKZGProofBatch(commitments, cellIndices, cells, proofs)
		require.NoError(t, err, "valid batch of size %d must verify", size)
	}
}

// corruptProof returns a proof that fails deserialization. Two modes produce
// two distinct errors, so the tests can tell which corrupted index was
// reported.
func corruptProof(t *testing.T, mode int) (goethkzg.KZGProof, error) {
	t.Helper()

	var proof goethkzg.KZGProof
	switch mode {
	case 0:
		// All bits set: invalid compression-flag combination.
		for i := range proof {
			proof[i] = 0xFF
		}
	case 1:
		// Compressed flag with an x-coordinate that is not on the curve.
		proof[0] = 0x80
		proof[47] = 0x01
	default:
		t.Fatalf("unknown corruption mode %d", mode)
	}
	_, err := goethkzg.DeserializeKZGProof(proof)
	require.Error(t, err, "corruption mode %d must not deserialize", mode)
	return proof, err
}

// corruptCell returns a cell that fails deserialization: all bits set, so every
// scalar is non-canonical and the expected error is ErrNonCanonicalScalar.
func corruptCell() (*goethkzg.Cell, error) {
	var cell goethkzg.Cell
	for i := range cell {
		cell[i] = 0xFF
	}
	return &cell, goethkzg.ErrNonCanonicalScalar
}

// TestVerifyCellKZGProofBatchErrorDeterminism checks that with several corrupt
// entries in one batch the reported error never depends on goroutine
// scheduling: proof errors win over cell errors, and among proof errors the
// lowest index wins. Each case is repeated to give the scheduler chances to
// misorder.
func TestVerifyCellKZGProofBatchErrorDeterminism(t *testing.T) {
	const iterations = 50
	size := goethkzg.CellsPerExtBlob
	commitments, cellIndices, goodCells, goodProofs := buildVerifyBatch(t, size)

	proofErrA, expectedProofErrA := corruptProof(t, 0)
	proofErrB, expectedProofErrB := corruptProof(t, 1)
	// The two proof corruptions must be distinguishable, otherwise the
	// lowest-index assertions below would be vacuous.
	require.NotEqual(t, expectedProofErrA.Error(), expectedProofErrB.Error())
	badCell, expectedCellErr := corruptCell()
	require.NotEqual(t, expectedProofErrA.Error(), expectedCellErr.Error())
	require.NotEqual(t, expectedProofErrB.Error(), expectedCellErr.Error())

	t.Run("ProofErrorBeatsCellError", func(t *testing.T) {
		// Cell corrupted at index 0, proof corrupted at a high index: the
		// proof error must still be the one reported, every time.
		cells := append([]*goethkzg.Cell(nil), goodCells...)
		proofs := append([]goethkzg.KZGProof(nil), goodProofs...)
		cells[0] = badCell
		proofs[size-1] = proofErrA

		for i := 0; i < iterations; i++ {
			err := ctx.VerifyCellKZGProofBatch(commitments, cellIndices, cells, proofs)
			require.Error(t, err)
			require.Equal(t, expectedProofErrA.Error(), err.Error(),
				"iteration %d: expected the proof error, not the cell error", i)
		}
	})

	t.Run("LowestIndexProofErrorWins", func(t *testing.T) {
		// Two corrupted proofs with distinguishable errors: the lower index
		// must be reported, every time.
		proofs := append([]goethkzg.KZGProof(nil), goodProofs...)
		proofs[3] = proofErrB
		proofs[size-1] = proofErrA

		for i := 0; i < iterations; i++ {
			err := ctx.VerifyCellKZGProofBatch(commitments, cellIndices, goodCells, proofs)
			require.Error(t, err)
			require.Equal(t, expectedProofErrB.Error(), err.Error(),
				"iteration %d: expected the lowest-index proof error", i)
		}
	})

	t.Run("LowestIndexCellErrorWins", func(t *testing.T) {
		// Only cells corrupted: the cell error is reported.
		cells := append([]*goethkzg.Cell(nil), goodCells...)
		cells[size-1] = badCell

		for i := 0; i < iterations; i++ {
			err := ctx.VerifyCellKZGProofBatch(commitments, cellIndices, cells, goodProofs)
			require.Error(t, err)
			require.Equal(t, expectedCellErr.Error(), err.Error(),
				"iteration %d: expected the cell error", i)
		}
	})
}
