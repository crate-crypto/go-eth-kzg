package goethkzg_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	goethkzg "github.com/crate-crypto/go-eth-kzg"
)

func BenchmarkComputeCellsAndKZGProofs(b *testing.B) {
	// Setup: Create a Context and prepare input data
	// ctx := NewContext() // Replace with actual initialization
	polyCoeff := make([]fr.Element, goethkzg.ScalarsPerBlob)
	for i := 0; i < goethkzg.ScalarsPerBlob; i++ {
		element := fr.NewElement(uint64(i))
		element.Neg(&element)
		polyCoeff[i] = element
	}
	blob := goethkzg.SerializePoly(polyCoeff)

	// Reset the timer before the loop
	b.ResetTimer()

	// Run the benchmark
	for i := 0; i < b.N; i++ {
		cells, proofs, err := ctx.ComputeCellsAndKZGProofs(blob, 0)
		if err != nil {
			b.Fatal(err)
		}
		// Optionally use cells and proofs to prevent compiler optimization
		// Use the results in a way that can't be optimized out
		if cells[0] == nil {
			b.StopTimer()
			b.Fatal("Unexpected nil result")
			b.StartTimer()
		}
		if (proofs[0] == goethkzg.KZGProof{}) {
			b.StopTimer()
			b.Fatal("Unexpected nil result")
			b.StartTimer()
		}
	}
}
