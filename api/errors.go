package api

import "errors"

var ErrBatchLengthCheck = errors.New("the number of blobs, commitments, and proofs must be the same")
var ErrMonomialLagrangeMismatch = errors.New("lagrange G1 setup and monomial G1 setup should have the same number of elements")
