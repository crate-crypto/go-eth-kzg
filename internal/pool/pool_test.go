package pool

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPool_HappyPath(t *testing.T) {
	type testBuffer struct {
		data []int
	}

	p := &sync.Pool{
		New: func() any {
			return &testBuffer{data: make([]int, 10)}
		},
	}

	buf, err := Get[*testBuffer](p)
	require.NoError(t, err)
	require.NotNil(t, buf)
	require.Len(t, buf.data, 10)

	Put(p, buf)
}

func TestPool_WrongType(t *testing.T) {
	p := &sync.Pool{
		New: func() any {
			return "wrong type"
		},
	}

	_, err := Get[*int](p)
	require.ErrorIs(t, err, ErrPoolWrongType)
	require.ErrorContains(t, err, "expected *int, got string")
}

func TestPool_ReturnsNil(t *testing.T) {
	p := &sync.Pool{
		New: func() any {
			return nil
		},
	}

	_, err := Get[*int](p)
	require.ErrorIs(t, err, ErrPoolReturnedNil)
}

func TestPool_NilPool(t *testing.T) {
	_, err := Get[*int](nil)
	require.ErrorIs(t, err, ErrPoolIsNil)

	// Put should not panic with nil pool
	require.NotPanics(t, func() {
		Put[*int](nil, nil)
	})
}
