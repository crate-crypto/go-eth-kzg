package goethkzg_test

import (
	"testing"

	goethkzg "github.com/crate-crypto/go-eth-kzg"
	"github.com/stretchr/testify/require"
)

func BenchmarkEIP7594(b *testing.B) {
	blob := GetRandBlob(int64(42))
	commitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
	require.NoError(b, err)

	// Compute cells and proofs once for verification benchmarks
	cells, proofs, err := ctx.ComputeCellsAndKZGProofs(blob, NumGoRoutines)
	require.NoError(b, err)

	b.Run("ComputeCells", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			_, _ = ctx.ComputeCells(blob, NumGoRoutines)
		}
	})

	b.Run("ComputeCellsAndKZGProofs", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			_, _, _ = ctx.ComputeCellsAndKZGProofs(blob, NumGoRoutines)
		}
	})

	// Prepare data for VerifyCellKZGProofBatch
	commitments := make([]goethkzg.KZGCommitment, len(cells))
	cellIndices := make([]uint64, len(cells))
	cellPtrs := make([]*goethkzg.Cell, len(cells))
	proofsList := make([]goethkzg.KZGProof, len(cells))
	for i := range cells {
		commitments[i] = commitment
		cellIndices[i] = uint64(i)
		cellPtrs[i] = cells[i]
		proofsList[i] = proofs[i]
	}

	b.Run("VerifyCellKZGProofBatch(count=128)", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			_ = ctx.VerifyCellKZGProofBatch(commitments, cellIndices, cellPtrs, proofsList)
		}
	})

	// Benchmark with smaller batches
	for _, count := range []int{1, 8, 32, 64} {
		b.Run("VerifyCellKZGProofBatch(count="+string(rune('0'+count/10))+string(rune('0'+count%10))+")", func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				_ = ctx.VerifyCellKZGProofBatch(commitments[:count], cellIndices[:count], cellPtrs[:count], proofsList[:count])
			}
		})
	}

	// Benchmark recovery
	// Use half the cells for recovery
	halfCells := make([]*goethkzg.Cell, 64)
	halfCellIDs := make([]uint64, 64)
	for i := 0; i < 64; i++ {
		halfCellIDs[i] = uint64(i * 2) // Even indices only
		halfCells[i] = cells[i*2]
	}

	b.Run("RecoverCellsAndComputeKZGProofs", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			_, _, _ = ctx.RecoverCellsAndComputeKZGProofs(halfCellIDs, halfCells, NumGoRoutines)
		}
	})
}

// BenchmarkVerifyCellKZGProofBatchShapes benchmarks VerifyCellKZGProofBatch on
// multi-blob batch shapes, where cells from different blobs share column
// indices:
//
//   - 1 blob x 128 cells: 128 entries over 128 distinct columns (control:
//     entry count equals distinct-column count)
//   - 8 blobs x 128 cells: 1024 entries over 128 distinct columns (full-node
//     style batch)
//   - 32 blobs x 8 columns: 256 entries over 8 distinct columns (the sampling
//     regime: the same few columns sampled across many blobs)
func BenchmarkVerifyCellKZGProofBatchShapes(b *testing.B) {
	const numBlobs = 32

	commitments := make([]goethkzg.KZGCommitment, numBlobs)
	blobCells := make([][goethkzg.CellsPerExtBlob]*goethkzg.Cell, numBlobs)
	blobProofs := make([][goethkzg.CellsPerExtBlob]goethkzg.KZGProof, numBlobs)
	for i := 0; i < numBlobs; i++ {
		blob := GetRandBlob(int64(1000 + i))
		commitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
		require.NoError(b, err)
		commitments[i] = commitment
		blobCells[i], blobProofs[i], err = ctx.ComputeCellsAndKZGProofs(blob, NumGoRoutines)
		require.NoError(b, err)
	}

	type shape struct {
		name       string
		numBlobs   int
		numColumns int
	}
	shapes := []shape{
		{"1 blob x 128 cells", 1, 128},
		{"8 blobs x 128 cells", 8, 128},
		{"32 blobs x 8 columns", 32, 8},
	}

	for _, s := range shapes {
		batchCommitments := make([]goethkzg.KZGCommitment, 0, s.numBlobs*s.numColumns)
		cellIndices := make([]uint64, 0, s.numBlobs*s.numColumns)
		cells := make([]*goethkzg.Cell, 0, s.numBlobs*s.numColumns)
		proofs := make([]goethkzg.KZGProof, 0, s.numBlobs*s.numColumns)
		for blobIdx := 0; blobIdx < s.numBlobs; blobIdx++ {
			for col := 0; col < s.numColumns; col++ {
				batchCommitments = append(batchCommitments, commitments[blobIdx])
				cellIndices = append(cellIndices, uint64(col))
				cells = append(cells, blobCells[blobIdx][col])
				proofs = append(proofs, blobProofs[blobIdx][col])
			}
		}

		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				err := ctx.VerifyCellKZGProofBatch(batchCommitments, cellIndices, cells, proofs)
				require.NoError(b, err)
			}
		})
	}
}
