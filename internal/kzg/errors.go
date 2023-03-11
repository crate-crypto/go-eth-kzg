package kzg

import "errors"

var (
	ErrInvalidNumDigests              = errors.New("number of digests is not the same as the number of polynomials")
	ErrInvalidPolynomialSize          = errors.New("invalid polynomial size (larger than SRS or == 0)")
	ErrVerifyOpeningProof             = errors.New("can't verify opening proof")
	ErrVerifyBatchOpeningSinglePoint  = errors.New("can't verify batch opening proof at single point")
	ErrPolynomialMismatchedSizeDomain = errors.New("domain size does not equal the number of evaluations in the polynomial")
	ErrMinSRSSize                     = errors.New("minimum srs size is 2")
	ErrSRSPow2                        = errors.New("srs size must be a power of 2")
)
