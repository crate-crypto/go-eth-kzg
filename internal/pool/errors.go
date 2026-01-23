package pool

import "errors"

var (
	// ErrPoolIsNil is returned when a nil pool is passed to Get.
	ErrPoolIsNil = errors.New("pool is nil")

	// ErrPoolReturnedNil is returned when the pool's Get returns nil.
	ErrPoolReturnedNil = errors.New("pool returned nil")

	// ErrPoolWrongType is returned when the pool returns an unexpected type.
	ErrPoolWrongType = errors.New("pool returned wrong type")
)
