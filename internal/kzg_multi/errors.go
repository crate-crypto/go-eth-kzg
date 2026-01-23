package kzgmulti

import "errors"

var (
	ErrMinSRSSize        = errors.New("minimum srs size is 2")
	ErrInvalidPoolBuffer = errors.New("invalid buffer from pool")
)
