package utils

import (
	"runtime"
	"sync"
)

// NumWorkers resolves a caller supplied goroutine budget into a worker count.
//
// Zero or negative means "use every core", which is the same convention the
// multi-exponentiation wrapper in internal/multiexp uses for its own parameter.
func NumWorkers(numGoRoutines int) int {
	if numGoRoutines <= 0 {
		return runtime.NumCPU()
	}

	return numGoRoutines
}

// Parallelize splits [0, n) into contiguous chunks, runs body on each concurrently, and
// waits for all of them.
//
// numGoRoutines caps the number of goroutines; see NumWorkers. minWorkPerGoRoutine keeps
// the work per goroutine above the point where starting one is worth it, so small inputs
// stay on the calling goroutine; values below 1 are treated as 1.
func Parallelize(n, numGoRoutines, minWorkPerGoRoutine int, body func(start, end int)) {
	if n <= 0 {
		return
	}
	if minWorkPerGoRoutine < 1 {
		minWorkPerGoRoutine = 1
	}

	numWorkers := NumWorkers(numGoRoutines)
	if maxUseful := (n + minWorkPerGoRoutine - 1) / minWorkPerGoRoutine; numWorkers > maxUseful {
		numWorkers = maxUseful
	}
	if numWorkers <= 1 {
		body(0, n)
		return
	}

	chunk := (n + numWorkers - 1) / numWorkers

	var wg sync.WaitGroup
	for start := 0; start < n; start += chunk {
		end := min(start+chunk, n)
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			body(start, end)
		}(start, end)
	}
	wg.Wait()
}
