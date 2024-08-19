package goethkzg

import (
	"errors"
	"slices"

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

	// TODO: We could return an error -- though its unrecoverable
	if len(cosetEvaluations) != CellsPerExtBlob {
		panic("expected coset evaluations to be of length `CellsPerExtBlob`")
	}
	if len(proofs) != CellsPerExtBlob {
		panic("expected proofs to be of length `CellsPerExtBlob`")
	}

	// Serialize proofs
	var serializedProofs [CellsPerExtBlob]KZGProof
	for i, proof := range proofs {
		serializedProofs[i] = KZGProof(SerializeG1Point(proof))
	}

	// Serialize Cells
	var Cells [CellsPerExtBlob]*Cell
	for i, cosetEval := range cosetEvaluations {
		// TODO: We could return an error -- though its unrecoverable
		if len(cosetEval) != scalarsPerCell {
			panic("expected cell to be of length `scalarsPerCell`")
		}
		cosetEvalArr := (*[scalarsPerCell]fr.Element)(cosetEval)

		Cells[i] = serializeEvaluations(cosetEvalArr)
	}

	return Cells, serializedProofs, nil
}

func (ctx *Context) RecoverCellsAndComputeKZGProofs(cellIDs []uint64, cells []*Cell, _proofs []KZGProof, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	// Check each proof can be deserialized
	// TODO: This seems somewhat useless as we should not be calling this method with proofs
	// TODO: that are not valid.
	for _, proof := range _proofs {
		_, err := DeserializeKZGProof(proof)
		if err != nil {
			return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, err
		}
	}

	if len(cellIDs) != len(cells) {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, errors.New("number of cell IDs should be equal to the number of cells")
	}
	if len(cellIDs) != len(_proofs) {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, errors.New("number of cell IDs should be equal to the number of proofs")
	}

	// Check that the cell Ids are unique
	if !isUniqueUint64(cellIDs) {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, errors.New("cell IDs should be unique")
	}

	// Check that each CellId is less than CellsPerExtBlob
	for _, cellID := range cellIDs {
		if cellID >= CellsPerExtBlob {
			return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, errors.New("cell ID should be less than CellsPerExtBlob")
		}
	}

	// Check that we have enough cells to perform reconstruction
	if len(cellIDs) < ctx.dataRecovery.NumBlocksNeededToReconstruct() {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, errors.New("not enough cells to perform reconstruction")
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

func (ctx *Context) VerifyCellKZGProof(commitment KZGCommitment, cellID uint64, cell *Cell, proof KZGProof) error {
	// Check if the cell ID is less than CellsPerExtBlob
	if cellID >= CellsPerExtBlob {
		return ErrInvalidCellID
	}

	// Deserialize the commitment
	commitmentG1, err := DeserializeKZGCommitment(commitment)
	if err != nil {
		return err
	}

	// Deserialize the proof
	proofG1, err := DeserializeKZGProof(proof)
	if err != nil {
		return err
	}

	// Deserialize the cell
	cosetEvals, err := deserializeCell(cell)
	if err != nil {
		return err
	}

	// partition the extended roots to form cosets
	cosets := partition(ctx.domainExtended.Roots, scalarsPerCell)

	return kzgmulti.VerifyMultiPointKZGProof(commitmentG1, proofG1, cosetEvals, cosets[cellID], ctx.openKey)
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

	for i := 0; i < batchSize; i++ {
		err := ctx.VerifyCellKZGProof(rowCommitments[rowIndices[i]], columnIndices[i], cells[i], proofs[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// partition groups a slice into chunks of size k
// Example:
// Input: [1, 2, 3, 4, 5, 6, 7, 8, 9], k: 3
// Output: [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
//
// Panics if the slice cannot be divided into chunks of size k
// TODO: Remove, once we make verification not require the cosets
// TODO: These are not needed in a optimized version
func partition(slice []fr.Element, k int) [][]fr.Element {
	var result [][]fr.Element

	for i := 0; i < len(slice); i += k {
		end := i + k
		if end > len(slice) {
			panic("all partitions should have the same size")
		}
		result = append(result, slice[i:end])
	}

	return result
}

// isUniqueUint64 returns true if all elements
// in the slice are unique
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
