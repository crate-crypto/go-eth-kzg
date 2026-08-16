package goethkzg_test

import (
	"fmt"
	"testing"

	goethkzg "github.com/crate-crypto/go-eth-kzg"
	"github.com/stretchr/testify/require"
)

// TestNumGoRoutinesDoesNotAffectResults checks that the goroutine budget is only ever a
// performance knob: every setting must produce identical output.
//
// The budget is threaded into the G1 transforms and the multi-exponentiation loop used
// when computing cell proofs, so this covers work that is genuinely split across
// goroutines rather than a parameter that is accepted and dropped.
func TestNumGoRoutinesDoesNotAffectResults(t *testing.T) {
	blob := GetRandBlob(1234)

	wantCells, wantProofs, err := ctx.ComputeCellsAndKZGProofs(blob, 1)
	require.NoError(t, err)

	cellIDs := make([]uint64, 0, goethkzg.CellsPerExtBlob/2)
	partialCells := make([]*goethkzg.Cell, 0, goethkzg.CellsPerExtBlob/2)
	for i := 0; i < goethkzg.CellsPerExtBlob/2; i++ {
		cellIDs = append(cellIDs, uint64(i))
		partialCells = append(partialCells, wantCells[i])
	}

	wantRecovered, wantRecoveredProofs, err := ctx.RecoverCellsAndComputeKZGProofs(cellIDs, partialCells, 1)
	require.NoError(t, err)

	// 0 and negative mean "use every core"; the rest are explicit budgets.
	for _, numGoRoutines := range []int{-1, 0, 2, 3, 8, 64} {
		t.Run(fmt.Sprintf("numGoRoutines=%d", numGoRoutines), func(t *testing.T) {
			gotCells, gotProofs, err := ctx.ComputeCellsAndKZGProofs(blob, numGoRoutines)
			require.NoError(t, err)
			require.Equal(t, wantCells, gotCells)
			require.Equal(t, wantProofs, gotProofs)

			gotRecovered, gotRecoveredProofs, err := ctx.RecoverCellsAndComputeKZGProofs(cellIDs, partialCells, numGoRoutines)
			require.NoError(t, err)
			require.Equal(t, wantRecovered, gotRecovered)
			require.Equal(t, wantRecoveredProofs, gotRecoveredProofs)

			gotOnlyCells, err := ctx.ComputeCells(blob, numGoRoutines)
			require.NoError(t, err)
			require.Equal(t, wantCells, gotOnlyCells)

			gotRecoveredCells, err := ctx.RecoverCells(cellIDs, partialCells, numGoRoutines)
			require.NoError(t, err)
			require.Equal(t, wantRecovered, gotRecoveredCells)
		})
	}
}
