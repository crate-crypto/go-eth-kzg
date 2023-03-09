package api

import "errors"

var ErrBatchLengthCheck = errors.New("the number of blobs, commitments, and proofs must be the same")
