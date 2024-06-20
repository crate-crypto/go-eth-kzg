package goethkzg

import "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

func (ctx *Context) ComputeCellsAndKZGProofs(blob *Blob, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, nil
}

func (ctx *Context) computeCellsAndKZGProofsFromPolyCoeff(polyCoeff []fr.Element, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, nil
}

func (ctx *Context) RecoverCellsAndComputeKZGProofs(cellIDs []uint64, cells []*Cell, _proofs []KZGProof, numGoRoutines int) ([CellsPerExtBlob]*Cell, [CellsPerExtBlob]KZGProof, error) {
	return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, nil
}

func (ctx *Context) VerifyCellKZGProof(commitment KZGCommitment, cellID uint64, cell *Cell, proof KZGProof) error {
	return nil
}

func (ctx *Context) VerifyCellKZGProofBatch(rowCommitments []KZGCommitment, rowIndices []uint64, columnIndices []uint64, cells []*Cell, proofs []KZGProof) error {
	return nil
}
