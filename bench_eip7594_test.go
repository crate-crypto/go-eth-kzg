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
