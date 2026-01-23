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

func TestPool_Concurrent(t *testing.T) {
	type testBuffer struct {
		id int
	}

	p := &sync.Pool{
		New: func() any {
			return &testBuffer{}
		},
	}

	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			buf, err := Get[*testBuffer](p)
			require.NoError(t, err)
			Put(p, buf)
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestPool_Reuse(t *testing.T) {
	type testBuffer struct {
		counter int
	}

	callCount := 0
	p := &sync.Pool{
		New: func() any {
			callCount++
			return &testBuffer{counter: callCount}
		},
	}

	// First get - should call New
	buf1, err := Get[*testBuffer](p)
	require.NoError(t, err)
	require.Equal(t, 1, callCount)

	// Put it back
	Put(p, buf1)

	// Second get - should reuse, not call New
	buf2, err := Get[*testBuffer](p)
	require.NoError(t, err)
	require.NotNil(t, buf2)
	require.Equal(t, 1, callCount) // Still 1, not 2
}
