package goethkzg

import "errors"

var (
	ErrBatchLengthCheck   = errors.New("all designated elements in the batch should have the same size")
	ErrNonCanonicalScalar = errors.New("scalar is not canonical when interpreted as a big integer in big-endian")
	ErrInvalidCellID      = errors.New("cell ID should be less than CellsPerExtBlob")
	ErrInvalidRowIndex    = errors.New("row index should be less than the number of row commitments")
)
