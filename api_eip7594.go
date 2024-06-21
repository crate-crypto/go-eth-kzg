package goethkzg

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	kzgmulti "github.com/crate-crypto/go-eth-kzg/internal/kzg_multi"
)

//lint:ignore U1000 still fleshing out the API
func (ctx *Context) ComputeCellsAndKZGProofs(blob *Blob, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	polynomial, err := DeserializeBlob(blob)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, err
	}

	// Bit reverse the polynomial representing the Blob so that it is in normal order
	kzg.BitReverse(polynomial)

	// Convert the polynomial in lagrange form to a polynomial in monomial form
	polyCoeff := ctx.domain.IfftFr(polynomial)

	return ctx.computeCellsAndKZGProofsFromPolyCoeff(polyCoeff, numGoRoutines)
}

//lint:ignore U1000 still fleshing out the API
func (ctx *Context) computeCellsAndKZGProofsFromPolyCoeff(polyCoeff []fr.Element, _ int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	// Partition the extended roots to form cosets
	cosets := partition(ctx.domainExtended.Roots, scalarsPerCell)

	// Compute all proofs and cells
	proofs, cosetEvaluations, err := kzgmulti.ComputeMultiPointKZGProofs(polyCoeff, cosets, ctx.commitKeyMonomial)
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

//lint:ignore U1000 still fleshing out the API
func (ctx *Context) RecoverCellsAndComputeKZGProofs(cellIDs []uint64, cells []*Cell, _proofs []KZGProof, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, nil
}

//lint:ignore U1000 still fleshing out the API
func (ctx *Context) VerifyCellKZGProof(commitment KZGCommitment, cellID uint64, cell *Cell, proof KZGProof) error {
	return nil
}

//lint:ignore U1000 still fleshing out the API
func (ctx *Context) VerifyCellKZGProofBatch(rowCommitments []KZGCommitment, rowIndices, columnIndices []uint64, cells []*Cell, proofs []KZGProof) error {
	return nil
}

// partition groups a slice into chunks of size k
// Example:
// Input: [1, 2, 3, 4, 5, 6, 7, 8, 9], k: 3
// Output: [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
//
// Panics if the slice cannot be divided into chunks of size k
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
