package goethkzg

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

//lint:ignore U1000 still fleshing out the API
func (ctx *Context) ComputeCellsAndKZGProofs(blob *Blob, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, nil
}

//lint:ignore U1000 still fleshing out the API
func (ctx *Context) computeCellsAndKZGProofsFromPolyCoeff(polyCoeff []fr.Element, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, nil
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
