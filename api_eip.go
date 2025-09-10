package goethkzg

import (
	"slices"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
)

func (ctx *Context) RecoverCells(cellIDs []uint64, cells []*Cell) ([CellsPerExtBlob]*Cell, error) {
	if len(cellIDs) != len(cells) {
		return [CellsPerExtBlob]*Cell{}, ErrNumCellIDsNotEqualNumCells
	}
	if err := ctx.verifyCellIndices(cellIDs); err != nil {
		return [CellsPerExtBlob]*Cell{}, err
	}
	// Find the missing cell IDs and bit reverse them
	// So that they are in normal order
	missingCellIds := make([]uint64, 0, CellsPerExtBlob)
	for cellID := uint64(0); cellID < CellsPerExtBlob; cellID++ {
		if !slices.Contains(cellIDs, cellID) {
			missingCellIds = append(missingCellIds, (domain.BitReverseInt(cellID, CellsPerExtBlob)))
		}
	}

	// Convert Cells to field elements
	extendedBlob := make([]fr.Element, scalarsPerExtBlob)
	// for each cellId, we get the corresponding cell in cells
	// then use the cellId to place the cell in the correct position in the data(extendedBlob) array
	for i, cellID := range cellIDs {
		cell := cells[i]
		// Deserialize the cell
		cellEvals, err := deserializeCell(cell)
		if err != nil {
			return [CellsPerExtBlob]*Cell{}, err
		}
		// Place the cell in the correct position in the data array
		copy(extendedBlob[cellID*scalarsPerCell:], cellEvals)
	}
	// Bit reverse the extendedBlob so that it is in normal order
	domain.BitReverse(extendedBlob)

	polyCoeff, err := ctx.dataRecovery.RecoverPolynomialCoefficients(extendedBlob, missingCellIds)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, err
	}

	evals := ctx.fk20.ComputeExtendedPolynomial(polyCoeff)
	return serializeCells(evals)
}
