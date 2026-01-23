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
