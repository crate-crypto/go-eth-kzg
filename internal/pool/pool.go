// Package pool provides type-safe generic wrappers around sync.Pool.
//
// This package eliminates repetitive type assertions and provides
// better error messages when pool operations fail.
//
// Example usage:
//
//	type buffers struct {
//	    data []byte
//	}
//
//	var bufferPool = sync.Pool{
//	    New: func() any {
//	        return &buffers{data: make([]byte, 1024)}
//	    },
//	}
//
//	func processData() error {
//	    buf, err := pool.Get[*buffers](&bufferPool)
//	    if err != nil {
//	        return err
//	    }
//	    defer pool.Put(&bufferPool, buf)
//
//	    // Use buf.data...
//	    return nil
//	}
package pool

import (
	"fmt"
	"sync"
)

// Get retrieves a value from the pool with type safety.
// Returns an error if:
//   - the pool is nil
//   - the pool returns nil
//   - the pool returns a value of the wrong type
func Get[T any](p *sync.Pool) (T, error) {
	var zero T

	if p == nil {
		return zero, ErrPoolIsNil
	}

	v := p.Get()
	if v == nil {
		return zero, ErrPoolReturnedNil
	}

	typed, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("%w: expected %T, got %T",
			ErrPoolWrongType, zero, v)
	}

	return typed, nil
}

// Put returns a value to the pool.
// This is a thin wrapper around sync.Pool.Put for API consistency.
// Silently ignores nil pool to avoid panics in defer statements.
func Put[T any](p *sync.Pool, v T) {
	if p == nil {
		return
	}
	p.Put(v)
}
