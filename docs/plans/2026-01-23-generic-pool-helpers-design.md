# Generic Pool Helpers Design

**Date:** 2026-01-23
**Status:** Approved
**Context:** Follow-up to PR #123 (Performance: decreased allocs via in place DFT and reusing buffers)

## Overview

Create type-safe generic helper functions for `sync.Pool` to eliminate repetitive type assertion boilerplate and provide better error messages. This is a follow-up improvement to PR #123 which introduced buffer pooling in multiple subsystems.

## Problem

PR #123 introduced `sync.Pool` usage in 4 locations with 7 total call sites:
- `Context.bufferPool` (4 call sites)
- `DataRecovery.bufferPool` (1 call site)
- `OpeningKey.verifyBufPool` (1 call site)
- `BlsToeplitzVectorMultiplier.fftBufferPool` (1 call site)

Each call site repeats the same pattern:
```go
buf, ok := pool.Get().(*bufferType)
if !ok {
    return ..., ErrInvalidPoolBuffer
}
defer pool.Put(buf)
```

This results in:
- ~30 lines of repetitive boilerplate
- Custom error types per subsystem
- No compile-time type safety
- Poor error messages (just "invalid pool buffer")

## Solution

Create `internal/pool` package with generic helper functions that work with existing `sync.Pool` instances.

### Core API

```go
package pool

// Get retrieves a value from the pool with type safety.
func Get[T any](p *sync.Pool) (T, error)

// Put returns a value to the pool.
func Put[T any](p *sync.Pool, v T)
```

### Error Types

```go
var (
    ErrPoolIsNil       = errors.New("pool is nil")
    ErrPoolReturnedNil = errors.New("pool returned nil")
    ErrPoolWrongType   = errors.New("pool returned wrong type")
)
```

### Usage Example

**Before:**
```go
buf, ok := ctx.bufferPool.Get().(*buffers)
if !ok {
    return [CellsPerExtBlob]*Cell{}, ErrInvalidPoolBuffer
}
defer ctx.bufferPool.Put(buf)
```

**After:**
```go
buf, err := pool.Get[*buffers](&ctx.bufferPool)
if err != nil {
    return [CellsPerExtBlob]*Cell{}, err
}
defer pool.Put(&ctx.bufferPool, buf)
```

## Design Decisions

### Why Generic Helper Functions (Option B)?

Three approaches were considered:

**A) Generic Pool Type** - Wrap `sync.Pool` in `Pool[T]`
- ❌ Requires changing all struct field definitions
- ❌ Requires updating all pool initialization code
- ❌ Large refactor on top of PR #123

**B) Generic Helper Functions** - Work with existing `sync.Pool`
- ✅ No changes to struct definitions
- ✅ No changes to pool initialization
- ✅ Minimal, surgical changes only at call sites
- ✅ Can be applied incrementally

**C) Generic Pool with Must-Get** - Both safe and panic versions
- Unnecessary complexity for this use case

**Decision:** Option B provides maximum compatibility with PR #123.

### Why Return Errors Instead of Panic?

Options considered:
- Panic immediately (fail fast on programmer errors)
- Return errors (defensive programming)
- Make it impossible at compile time

**Decision:** Return errors. For a cryptography library, defensive programming is appropriate even for "impossible" conditions.

### Why Add Nil Pool Check?

The nil pool check in `Get()` provides defense against programmer errors. In `Put()`, we silently ignore nil to avoid panics in defer statements.

## Implementation Details

### Zero Value Handling

```go
func Get[T any](p *sync.Pool) (T, error) {
    var zero T  // Ensures proper zero value on error

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

Key points:
- `var zero T` returns proper zero value for type (e.g., `nil` for pointers)
- Error wrapping with `%w` allows `errors.Is()` checking
- Type information in error message helps debugging

### Pointer Types

All current usage uses pointer types (`*buffers`, `*recoveryBuffers`, etc.). This is correct because:
- Pool reuses objects - they must be addressable
- Factory functions return pointers: `return &buffers{...}`
- Non-pointer types would be copied, defeating the purpose

## Migration Plan

### Phase 1: Create Package (Independent)

1. Add `internal/pool/pool.go`
2. Add `internal/pool/errors.go`
3. Add `internal/pool/pool_test.go`
4. Run tests: `go test ./internal/pool`

### Phase 2: Update Call Sites (Incremental)

Can be done file-by-file:

1. **api_eip7594.go** (4 call sites):
   - `ComputeCells`
   - `ComputeCellsAndKZGProofs`
   - `computeCellsFromPolyCoeff`
   - `VerifyCellKZGProofBatch`

2. **internal/erasure_code/erasure_code.go** (1 call site):
   - `RecoverPolynomialCoefficients`

3. **internal/kzg_multi/kzg_verify.go** (1 call site):
   - `VerifyMultiPointKZGProofBatch`

4. **internal/kzg_multi/fk20/toeplitz.go** (1 call site):
   - `MultiplyScalarVector`

For each file:
- Add import: `"github.com/crate-crypto/go-eth-kzg/internal/pool"`
- Replace `buf, ok := p.Get().(*Type)` with `buf, err := pool.Get[*Type](&p)`
- Replace `!ok` checks with `err != nil`
- Replace `p.Put(buf)` with `pool.Put(&p, buf)`

### Phase 3: Clean Up (After Migration)

- Remove per-subsystem `ErrInvalidPoolBuffer` definitions
- Update to use `pool.ErrPoolWrongType`

## Testing Strategy

### Test Coverage

```go
// Happy path
func TestPool_HappyPath(t *testing.T)

// Error conditions
func TestPool_WrongType(t *testing.T)
func TestPool_ReturnsNil(t *testing.T)
func TestPool_NilPool(t *testing.T)

// Concurrency
func TestPool_Concurrent(t *testing.T)

// Pool behavior
func TestPool_Reuse(t *testing.T)
```

Categories:
1. ✅ Normal Get/Put cycle
2. ✅ Error handling (wrong type, nil returns, nil pool)
3. ✅ Thread safety
4. ✅ Pool reuse verification
5. ✅ Error message quality

## Benefits

- **Type Safety:** Generics enforce type correctness at call sites
- **Less Boilerplate:** Eliminates ~30 lines of repetitive code
- **Better Errors:** Type information in error messages aids debugging
- **Centralized Logic:** Future pool improvements only need one place
- **Documentation:** Type parameter documents what pool returns
- **No Breaking Changes:** All changes are internal implementation details
- **Incremental Migration:** Can be adopted file-by-file

## Non-Goals

- ✗ Shared buffer pool across subsystems (each keeps its own pool)
- ✗ Automatic buffer clearing/reset logic (remains caller responsibility)
- ✗ Pool statistics or monitoring (can be added later if needed)
- ✗ Changes to pool initialization or struct definitions

## Compatibility

- ✅ No breaking changes to public API
- ✅ Works with existing `sync.Pool` fields in PR #123
- ✅ Go 1.22+ required (generics support)
- ✅ No external dependencies

## Future Enhancements

Potential improvements (not in scope for this design):

- Pool statistics (Get/Put count, miss rate)
- Automatic buffer clearing on Put
- Pool size limits or monitoring
- Custom allocator functions
- Typed pool wrapper (if more features needed)

## References

- PR #123: https://github.com/crate-crypto/go-eth-kzg/pull/123
- Go sync.Pool: https://pkg.go.dev/sync#Pool
- Go Generics: https://go.dev/doc/tutorial/generics
