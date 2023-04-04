package api

import "errors"

var (
	ErrBatchLengthCheck               = errors.New("the number of blobs, commitments, and proofs must be the same")
	errLagrangeMonomialLengthMismatch = errors.New("the number of points in monomial SRS should equal number of points in lagrange SRS")
)
