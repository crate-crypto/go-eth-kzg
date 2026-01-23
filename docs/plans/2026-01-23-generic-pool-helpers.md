# Generic Pool Helpers Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create type-safe generic helper functions for sync.Pool to eliminate repetitive type assertion boilerplate across 7 call sites.

**Architecture:** New `internal/pool` package with `Get[T]` and `Put[T]` functions that work with existing sync.Pool fields. Migrate call sites incrementally, then remove duplicate error definitions.

**Tech Stack:** Go 1.22+ generics, sync.Pool, testify for testing

---

## Task 1: Create Pool Package Structure

**Files:**
- Create: `internal/pool/errors.go`

**Step 1: Create errors.go with error definitions**

```go
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
```

**Step 2: Verify it compiles**

Run: `go build ./internal/pool`
Expected: Success

**Step 3: Commit**

```bash
git add internal/pool/errors.go
git commit -m "feat(pool): add error definitions

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Implement Generic Pool Helpers

**Files:**
- Create: `internal/pool/pool.go`

**Step 1: Create pool.go with package documentation**

```go
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
```

**Step 2: Implement Get function**

```go
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
```

**Step 3: Implement Put function**

```go
// Put returns a value to the pool.
// This is a thin wrapper around sync.Pool.Put for API consistency.
// Silently ignores nil pool to avoid panics in defer statements.
func Put[T any](p *sync.Pool, v T) {
	if p == nil {
		return
	}
	p.Put(v)
}
```

**Step 4: Verify it compiles**

Run: `go build ./internal/pool`
Expected: Success

**Step 5: Commit**

```bash
git add internal/pool/pool.go
git commit -m "feat(pool): implement generic Get and Put functions

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Write Tests for Happy Path

**Files:**
- Create: `internal/pool/pool_test.go`

**Step 1: Write happy path test**

```go
package pool_test

import (
	"sync"
	"testing"

	"github.com/crate-crypto/go-eth-kzg/internal/pool"
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

	buf, err := pool.Get[*testBuffer](p)
	require.NoError(t, err)
	require.NotNil(t, buf)
	require.Len(t, buf.data, 10)

	pool.Put(p, buf)
}
```

**Step 2: Run test to verify it passes**

Run: `go test ./internal/pool -v -run TestPool_HappyPath`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/pool/pool_test.go
git commit -m "test(pool): add happy path test

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Write Tests for Error Conditions

**Files:**
- Modify: `internal/pool/pool_test.go`

**Step 1: Add wrong type test**

```go
func TestPool_WrongType(t *testing.T) {
	p := &sync.Pool{
		New: func() any {
			return "wrong type"
		},
	}

	_, err := pool.Get[*int](p)
	require.ErrorIs(t, err, pool.ErrPoolWrongType)
	require.ErrorContains(t, err, "expected *int, got string")
}
```

**Step 2: Run test to verify it passes**

Run: `go test ./internal/pool -v -run TestPool_WrongType`
Expected: PASS

**Step 3: Add nil return test**

```go
func TestPool_ReturnsNil(t *testing.T) {
	p := &sync.Pool{
		New: func() any {
			return nil
		},
	}

	_, err := pool.Get[*int](p)
	require.ErrorIs(t, err, pool.ErrPoolReturnedNil)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/pool -v -run TestPool_ReturnsNil`
Expected: PASS

**Step 5: Add nil pool test**

```go
func TestPool_NilPool(t *testing.T) {
	_, err := pool.Get[*int](nil)
	require.ErrorIs(t, err, pool.ErrPoolIsNil)

	// Put should not panic with nil pool
	require.NotPanics(t, func() {
		pool.Put[*int](nil, nil)
	})
}
```

**Step 6: Run test to verify it passes**

Run: `go test ./internal/pool -v -run TestPool_NilPool`
Expected: PASS

**Step 7: Commit**

```bash
git add internal/pool/pool_test.go
git commit -m "test(pool): add error condition tests

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Write Tests for Concurrency and Reuse

**Files:**
- Modify: `internal/pool/pool_test.go`

**Step 1: Add concurrent access test**

```go
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
			buf, err := pool.Get[*testBuffer](p)
			require.NoError(t, err)
			pool.Put(p, buf)
			done <- true
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}
```

**Step 2: Run test to verify it passes**

Run: `go test ./internal/pool -v -run TestPool_Concurrent`
Expected: PASS

**Step 3: Add reuse test**

```go
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
	buf1, err := pool.Get[*testBuffer](p)
	require.NoError(t, err)
	require.Equal(t, 1, callCount)

	// Put it back
	pool.Put(p, buf1)

	// Second get - should reuse, not call New
	buf2, err := pool.Get[*testBuffer](p)
	require.NoError(t, err)
	require.Equal(t, 1, callCount) // Still 1, not 2
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/pool -v -run TestPool_Reuse`
Expected: PASS

**Step 5: Run all pool tests**

Run: `go test ./internal/pool -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add internal/pool/pool_test.go
git commit -m "test(pool): add concurrency and reuse tests

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Migrate api_eip7594.go - ComputeCells

**Files:**
- Modify: `api_eip7594.go:1-41`

**Step 1: Add pool import**

At the top of `api_eip7594.go`, add to imports:

```go
import (
	"slices"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	kzgmulti "github.com/crate-crypto/go-eth-kzg/internal/kzg_multi"
	"github.com/crate-crypto/go-eth-kzg/internal/pool"
)
```

**Step 2: Replace pool usage in ComputeCells (lines 13-17)**

Replace:
```go
	buf, ok := ctx.bufferPool.Get().(*buffers)
	if !ok {
		return [CellsPerExtBlob]*Cell{}, ErrInvalidPoolBuffer
	}
	defer ctx.bufferPool.Put(buf)
```

With:
```go
	buf, err := pool.Get[*buffers](&ctx.bufferPool)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, err
	}
	defer pool.Put(&ctx.bufferPool, buf)
```

**Step 3: Run tests to verify**

Run: `go test . -v -run TestComputeCells`
Expected: PASS

**Step 4: Commit**

```bash
git add api_eip7594.go
git commit -m "refactor(pool): migrate ComputeCells to generic pool helpers

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Migrate api_eip7594.go - ComputeCellsAndKZGProofs

**Files:**
- Modify: `api_eip7594.go:44-48`

**Step 1: Replace pool usage in ComputeCellsAndKZGProofs**

Replace lines 44-48:
```go
	buf, ok := ctx.bufferPool.Get().(*buffers)
	if !ok {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, ErrInvalidPoolBuffer
	}
	defer ctx.bufferPool.Put(buf)
```

With:
```go
	buf, err := pool.Get[*buffers](&ctx.bufferPool)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, [CellsPerExtBlob]KZGProof{}, err
	}
	defer pool.Put(&ctx.bufferPool, buf)
```

**Step 2: Run tests to verify**

Run: `go test . -v -run TestComputeCellsAndKZGProofs`
Expected: PASS

**Step 3: Commit**

```bash
git add api_eip7594.go
git commit -m "refactor(pool): migrate ComputeCellsAndKZGProofs to generic pool helpers

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 8: Migrate api_eip7594.go - computeCellsFromPolyCoeff

**Files:**
- Modify: `api_eip7594.go:81-85`

**Step 1: Replace pool usage in computeCellsFromPolyCoeff**

Replace lines 81-85:
```go
	buf, ok := ctx.bufferPool.Get().(*buffers)
	if !ok {
		return [CellsPerExtBlob]*Cell{}, ErrInvalidPoolBuffer
	}
	defer ctx.bufferPool.Put(buf)
```

With:
```go
	buf, err := pool.Get[*buffers](&ctx.bufferPool)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, err
	}
	defer pool.Put(&ctx.bufferPool, buf)
```

**Step 2: Run tests to verify**

Run: `go test . -v -run TestRecoverCellsAndComputeKZGProofs`
Expected: PASS

**Step 3: Commit**

```bash
git add api_eip7594.go
git commit -m "refactor(pool): migrate computeCellsFromPolyCoeff to generic pool helpers

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 9: Migrate api_eip7594.go - VerifyCellKZGProofBatch

**Files:**
- Modify: `api_eip7594.go:233-237`

**Step 1: Replace pool usage in VerifyCellKZGProofBatch**

Replace lines 233-237:
```go
	buf, ok := ctx.bufferPool.Get().(*buffers)
	if !ok {
		return ErrInvalidPoolBuffer
	}
	defer ctx.bufferPool.Put(buf)
```

With:
```go
	buf, err := pool.Get[*buffers](&ctx.bufferPool)
	if err != nil {
		return err
	}
	defer pool.Put(&ctx.bufferPool, buf)
```

**Step 2: Run tests to verify**

Run: `go test . -v -run TestVerifyCellKZGProofBatch`
Expected: PASS

**Step 3: Run all tests in package**

Run: `go test . -v`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add api_eip7594.go
git commit -m "refactor(pool): migrate VerifyCellKZGProofBatch to generic pool helpers

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 10: Migrate internal/erasure_code/erasure_code.go

**Files:**
- Modify: `internal/erasure_code/erasure_code.go:148-152`

**Step 1: Add pool import**

At the top of `internal/erasure_code/erasure_code.go`, add to imports:

```go
import (
	"errors"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/poly"
	"github.com/crate-crypto/go-eth-kzg/internal/pool"
)
```

**Step 2: Replace pool usage in RecoverPolynomialCoefficients**

Replace lines 148-152:
```go
	buf, ok := dr.bufferPool.Get().(*recoveryBuffers)
	if !ok {
		return nil, errInvalidPoolBuffer
	}
	defer dr.bufferPool.Put(buf)
```

With:
```go
	buf, err := pool.Get[*recoveryBuffers](&dr.bufferPool)
	if err != nil {
		return nil, err
	}
	defer pool.Put(&dr.bufferPool, buf)
```

**Step 3: Run tests to verify**

Run: `go test ./internal/erasure_code -v`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add internal/erasure_code/erasure_code.go
git commit -m "refactor(pool): migrate erasure_code to generic pool helpers

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 11: Migrate internal/kzg_multi/kzg_verify.go

**Files:**
- Modify: `internal/kzg_multi/kzg_verify.go:33-37`

**Step 1: Add pool import**

At the top of `internal/kzg_multi/kzg_verify.go`, add to imports:

```go
import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/multiexp"
	"github.com/crate-crypto/go-eth-kzg/internal/pool"
	"github.com/crate-crypto/go-eth-kzg/internal/utils"
)
```

**Step 2: Replace pool usage in VerifyMultiPointKZGProofBatch**

Replace lines 33-37:
```go
	buf, ok := openKey.verifyBufPool.Get().(*VerifyBuffers)
	if !ok {
		return ErrInvalidPoolBuffer
	}
	defer openKey.verifyBufPool.Put(buf)
```

With:
```go
	buf, err := pool.Get[*VerifyBuffers](&openKey.verifyBufPool)
	if err != nil {
		return err
	}
	defer pool.Put(&openKey.verifyBufPool, buf)
```

**Step 3: Run tests to verify**

Run: `go test ./internal/kzg_multi -v`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add internal/kzg_multi/kzg_verify.go
git commit -m "refactor(pool): migrate kzg_verify to generic pool helpers

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 12: Migrate internal/kzg_multi/fk20/toeplitz.go

**Files:**
- Modify: `internal/kzg_multi/fk20/toeplitz.go:113`

**Step 1: Add pool import**

At the top of `internal/kzg_multi/fk20/toeplitz.go`, add to imports (add pool to existing imports):

```go
import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/pool"
)
```

**Step 2: Replace pool usage in MultiplyScalarVector**

Find line 113 which has:
```go
	bufsPtr, _ := bt.fftBufferPool.Get().(*[][]fr.Element)
	bufs := *bufsPtr
```

Replace with:
```go
	bufs, err := pool.Get[*[][]fr.Element](&bt.fftBufferPool)
	if err != nil {
		// Handle error - need to check function signature
		panic(err) // Temporary - will refine based on function signature
	}
```

**Step 3: Check function signature and handle error properly**

Check what error handling is appropriate for this function. If it returns an error, propagate it. Otherwise, panic may be acceptable for pool errors.

**Step 4: Update defer statement**

Find the corresponding Put call and update it to:
```go
defer pool.Put(&bt.fftBufferPool, bufs)
```

**Step 5: Run tests to verify**

Run: `go test ./internal/kzg_multi/fk20 -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add internal/kzg_multi/fk20/toeplitz.go
git commit -m "refactor(pool): migrate toeplitz to generic pool helpers

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 13: Remove Duplicate Error Definitions

**Files:**
- Modify: `errors.go:16`
- Modify: `internal/kzg_multi/errors.go:7`
- Modify: `internal/erasure_code/erasure_code.go:12`

**Step 1: Remove ErrInvalidPoolBuffer from errors.go**

Remove line 16 from `errors.go`:
```go
ErrInvalidPoolBuffer               = errors.New("invalid buffer from pool")
```

**Step 2: Verify no remaining references**

Run: `grep -r "ErrInvalidPoolBuffer" . --exclude-dir=.git --exclude-dir=docs`
Expected: Only occurrences in internal/kzg_multi/errors.go and internal/erasure_code/erasure_code.go

**Step 3: Remove ErrInvalidPoolBuffer from internal/kzg_multi/errors.go**

Remove line 7 from `internal/kzg_multi/errors.go`:
```go
ErrInvalidPoolBuffer = errors.New("invalid buffer from pool")
```

**Step 4: Remove errInvalidPoolBuffer from internal/erasure_code/erasure_code.go**

Remove line 12 from `internal/erasure_code/erasure_code.go`:
```go
var errInvalidPoolBuffer = errors.New("invalid buffer from pool")
```

**Step 5: Verify no remaining references**

Run: `grep -r "InvalidPoolBuffer" . --exclude-dir=.git --exclude-dir=docs`
Expected: No results

**Step 6: Run all tests**

Run: `go test ./...`
Expected: All tests PASS

**Step 7: Commit**

```bash
git add errors.go internal/kzg_multi/errors.go internal/erasure_code/erasure_code.go
git commit -m "refactor(pool): remove duplicate error definitions

All pool errors now use pool.ErrPoolWrongType

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 14: Final Verification

**Step 1: Run full test suite**

Run: `go test ./... -v`
Expected: All tests PASS with same count as baseline

**Step 2: Run benchmarks to verify no regression**

Run: `go test -bench=. -benchmem -run=^$ ./...`
Expected: Similar performance to baseline (no major regressions)

**Step 3: Verify all imports are used**

Run: `go build ./...`
Expected: No "imported and not used" errors

**Step 4: Check code coverage for pool package**

Run: `go test ./internal/pool -cover`
Expected: High coverage (>90%)

**Step 5: Final commit if any cleanup needed**

```bash
git add .
git commit -m "chore: final cleanup and verification

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Summary

**Files Created:**
- `internal/pool/errors.go` - Error definitions
- `internal/pool/pool.go` - Generic Get/Put functions
- `internal/pool/pool_test.go` - Comprehensive test suite

**Files Modified:**
- `api_eip7594.go` - 4 call sites migrated
- `internal/erasure_code/erasure_code.go` - 1 call site migrated, error removed
- `internal/kzg_multi/kzg_verify.go` - 1 call site migrated
- `internal/kzg_multi/fk20/toeplitz.go` - 1 call site migrated
- `internal/kzg_multi/errors.go` - Duplicate error removed
- `errors.go` - Duplicate error removed

**Total Changes:**
- 3 files created
- 7 call sites migrated
- 3 duplicate error definitions removed
- ~30 lines of boilerplate eliminated

**Benefits:**
- Type safety via generics
- Better error messages
- Centralized pool logic
- Reduced code duplication
