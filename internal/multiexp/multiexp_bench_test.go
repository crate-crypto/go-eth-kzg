package multiexp

import (
	"runtime"
	"strconv"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func generateBenchInputs(size int) ([]fr.Element, []bls12381.G1Affine) {
	scalars := make([]fr.Element, size)
	points := make([]bls12381.G1Affine, size)

	// Generate random points and scalars
	for i := 0; i < size; i++ {
		scalars[i].SetRandom()
		points[i] = randomPoint()
	}

	return scalars, points
}

func BenchmarkMSM(b *testing.B) {
	sizes := []int{32, 64, 128}
	windowSizes := []uint8{4, 8, 9}

	for _, size := range sizes {
		scalars, points := generateBenchInputs(size)

		// Benchmark MultiExpG1
		b.Run("MultiExpG1/size_"+strconv.Itoa(size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := MultiExpG1(scalars, points, runtime.NumCPU())
				if err != nil {
					b.Fatal(err)
				}
				_ = result
			}
		})

		// Benchmark MSMTable with different window sizes
		for _, wbits := range windowSizes {
			name := "MSMTable/size_" + strconv.Itoa(size) + "/window_" + strconv.Itoa(int(wbits))
			b.Run(name, func(b *testing.B) {
				// Don't include table creation in timing
				table := NewMSMTable(points, wbits)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					result := table.MultiScalarMul(scalars)
					_ = result
				}
			})
		}

		// Benchmark just the table creation
		for _, wbits := range windowSizes {
			name := "TableCreation/size_" + strconv.Itoa(size) + "/window_" + strconv.Itoa(int(wbits))
			b.Run(name, func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					table := NewMSMTable(points, wbits)
					_ = table
				}
			})
		}
	}
}

// Memory usage benchmark
func BenchmarkMSMMemory(b *testing.B) {
	sizes := []int{64, 128}
	windowSizes := []uint8{4, 8, 9}

	for _, size := range sizes {
		scalars, points := generateBenchInputs(size)

		b.Run("MultiExpG1/size_"+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := MultiExpG1(scalars, points, runtime.NumCPU())
				if err != nil {
					b.Fatal(err)
				}
				_ = result
			}
		})

		for _, wbits := range windowSizes {
			name := "MSMTable/size_" + strconv.Itoa(size) + "/window_" + strconv.Itoa(int(wbits))
			b.Run(name, func(b *testing.B) {
				table := NewMSMTable(points, wbits)

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					result := table.MultiScalarMul(scalars)
					_ = result
				}
			})
		}
	}
}

func BenchmarkMSMParallel(b *testing.B) {
	size := 10000
	scalars, points := generateBenchInputs(size)

	threads := []int{1, 2, 4, 8, 16}
	for _, numThreads := range threads {
		name := "MultiExpG1/threads_" + strconv.Itoa(numThreads)
		b.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := MultiExpG1(scalars, points, numThreads)
				if err != nil {
					b.Fatal(err)
				}
				_ = result
			}
		})
	}
}
