package goethkzg

import (
	"slices"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	kzgmulti "github.com/crate-crypto/go-eth-kzg/internal/kzg_multi"
)

func (ctx *Context) ComputeCellsAndKZGProofs(blob *Blob, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	polynomial, err := DeserializeBlob(blob)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, err
	}

	// Bit reverse the polynomial representing the Blob so that it is in normal order
	domain.BitReverse(polynomial)

	// Convert the polynomial in lagrange form to a polynomial in monomial form
	polyCoeff := ctx.domain.IfftFr(polynomial)

	return ctx.computeCellsAndKZGProofsFromPolyCoeff(polyCoeff, numGoRoutines)
}

func (ctx *Context) computeCellsAndKZGProofsFromPolyCoeff(polyCoeff []fr.Element, _ int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	// Compute all proofs and cells
	proofs, cosetEvaluations, err := kzgmulti.ComputeMultiPointKZGProofs(ctx.fk20, polyCoeff)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, err
	}

	if len(cosetEvaluations) != CellsPerExtBlob {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrNumCosetEvaluationsCheck
	}
	if len(proofs) != CellsPerExtBlob {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrNumProofsCheck
	}

	// Serialize proofs
	var serializedProofs [CellsPerExtBlob]KZGProof
	for i, proof := range proofs {
		serializedProofs[i] = KZGProof(SerializeG1Point(proof))
	}

	// Serialize Cells
	var Cells [CellsPerExtBlob]*Cell
	for i, cosetEval := range cosetEvaluations {
		if len(cosetEval) != scalarsPerCell {
			return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrCosetEvaluationLengthCheck
		}
		cosetEvalArr := (*[scalarsPerCell]fr.Element)(cosetEval)

		Cells[i] = serializeEvaluations(cosetEvalArr)
	}

	return Cells, serializedProofs, nil
}

func (ctx *Context) RecoverCellsAndComputeKZGProofs(cellIDs []uint64, cells []*Cell, _proofs []KZGProof, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	// Check each proof can be deserialized
	// TODO: This gets removed when we update the specs.
	for _, proof := range _proofs {
		_, err := DeserializeKZGProof(proof)
		if err != nil {
			return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, err
		}
	}

	if len(cellIDs) != len(cells) {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrNumCellIDsNotEqualNumCells
	}
	if len(cellIDs) != len(_proofs) {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrNumCellIDsNotEqualNumProofs
	}

	// Check that the cell Ids are unique
	if !isUniqueUint64(cellIDs) {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrCellIDsNotUnique
	}

	// Check that each CellId is less than CellsPerExtBlob
	for _, cellID := range cellIDs {
		if cellID >= CellsPerExtBlob {
			return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrFoundInvalidCellID
		}
	}

	// Check that we have enough cells to perform reconstruction
	if len(cellIDs) < ctx.dataRecovery.NumBlocksNeededToReconstruct() {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrNotEnoughCellsForReconstruction
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
			return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, err
		}
		// Place the cell in the correct position in the data array
		copy(extendedBlob[cellID*scalarsPerCell:], cellEvals)
	}
	// Bit reverse the extendedBlob so that it is in normal order
	domain.BitReverse(extendedBlob)

	polyCoeff, err := ctx.dataRecovery.RecoverPolynomialCoefficients(extendedBlob, missingCellIds)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, err
	}

	return ctx.computeCellsAndKZGProofsFromPolyCoeff(polyCoeff, numGoRoutines)
}

func (ctx *Context) VerifyCellKZGProofBatch(rowCommitments []KZGCommitment, rowIndices, columnIndices []uint64, cells []*Cell, proofs []KZGProof) error {
	// Check that all components in the batch have the same size, expect the rowCommitments
	batchSize := len(rowIndices)
	lengthsAreEqual := batchSize == len(columnIndices) && batchSize == len(cells) && batchSize == len(proofs)
	if !lengthsAreEqual {
		return ErrBatchLengthCheck
	}

	if batchSize == 0 {
		return nil
	}

	// Check that the row indices do not exceed len(rowCommitments)
	for _, rowIndex := range rowIndices {
		if rowIndex >= uint64(len(rowCommitments)) {
			return ErrInvalidRowIndex
		}
	}

	for _, cellIndex := range columnIndices {
		if cellIndex >= CellsPerExtBlob {
			return ErrInvalidCellID
		}
	}

	commitments := make([]bls12381.G1Affine, len(rowCommitments))
	for i := 0; i < len(rowCommitments); i++ {
		comm, err := DeserializeKZGCommitment(rowCommitments[i])
		if err != nil {
			return err
		}
		commitments[i] = comm
	}
	proofsG1 := make([]bls12381.G1Affine, len(proofs))
	for i := 0; i < len(proofs); i++ {
		proof, err := DeserializeKZGProof(proofs[i])
		if err != nil {
			return err
		}
		proofsG1[i] = proof
	}
	cosetsEvals := make([][]fr.Element, len(cells))
	for i := 0; i < len(cells); i++ {
		cosetEvals, err := deserializeCell(cells[i])
		if err != nil {
			return err
		}
		cosetsEvals[i] = cosetEvals
	}
	return kzgmulti.VerifyMultiPointKZGProofBatch(commitments, rowIndices, columnIndices, proofsG1, cosetsEvals, ctx.openKey7594)
}

// isUniqueUint64 returns true if the slices contains no duplicate elements
func isUniqueUint64(slice []uint64) bool {
	elementMap := make(map[uint64]bool)

	for _, element := range slice {
		if elementMap[element] {
			// Element already seen
			return false
		}
		// Mark the element as seen
		elementMap[element] = true
	}

	// All elements are unique
	return true
}
