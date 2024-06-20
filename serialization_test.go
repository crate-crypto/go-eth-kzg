package goethkzg_test

import (
	"bytes"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	goethkzg "github.com/crate-crypto/go-eth-kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/stretchr/testify/require"
)

func TestG1RoundTripSmoke(t *testing.T) {
	_, _, g1Aff, _ := bls12381.Generators()
	g1Bytes := goethkzg.SerializeG1Point(g1Aff)
	aff, err := goethkzg.DeserializeKZGProof(goethkzg.KZGProof(g1Bytes))
	if err != nil {
		t.Error(err)
	}
	if !aff.Equal(&g1Aff) {
		t.Error("G1 serialization roundtrip fail")
	}
}

func TestSerializePolyNotZero(t *testing.T) {
	// Check that blobs are not all zeroes
	// This would indicate that serialization
	// did not do anything.

	poly := randPoly4096()
	blob := goethkzg.SerializePoly(poly)

	var zeroBlob goethkzg.Blob
	if bytes.Equal(blob[:], zeroBlob[:]) {
		t.Error("blobs are all zeroes, which can only happen with negligible probability")
	}
}

func TestSerializePolyRoundTrip(t *testing.T) {
	expectedPolyA := randPoly4096()
	expectedPolyB := randPoly4096()

	blobA := goethkzg.SerializePoly(expectedPolyA)
	blobB := goethkzg.SerializePoly(expectedPolyB)

	gotPolyA, err := goethkzg.DeserializeBlob(blobA)
	if err != nil {
		t.Error(err)
	}
	gotPolyB, err := goethkzg.DeserializeBlob(blobB)
	if err != nil {
		t.Error(err)
	}
	assertPolyEqual(t, expectedPolyA, gotPolyA)
	assertPolyEqual(t, expectedPolyB, gotPolyB)

	assertPolyNotEqual(t, expectedPolyA, gotPolyB)
}

// Check element-wise that each evaluation in the polynomial is the same
func assertPolyEqual(t *testing.T, lhs, rhs kzg.Polynomial) {
	t.Helper()
	polyLen := assertPolySameLength(t, lhs, rhs)

	for i := 0; i < polyLen; i++ {
		if !lhs[i].Equal(&rhs[i]) {
			t.Errorf("polynomials differ at index %d, therefore they are not the same", i)
		}
	}
}

// Assert that two polynomials are different -- at least one evaluation differs
func assertPolyNotEqual(t *testing.T, lhs, rhs kzg.Polynomial) {
	t.Helper()
	polyLen := assertPolySameLength(t, lhs, rhs)

	// element at index `i` in polyPredicate stores whether the
	// evaluations at index `i` are the same
	//
	// We need this because two polynomials are different
	// if at least one evaluation differs
	// If this slice has a single false, then the polynomials
	// differ
	polyPredicate := make([]bool, polyLen)

	// Check element-wise that they are the same
	for i := 0; i < polyLen; i++ {
		polyPredicate[i] = lhs[i].Equal(&rhs[i])
	}

	for _, pred := range polyPredicate {
		// If we encounter a false, then the evaluations
		// differed and so we return early
		if !pred {
			return
		}
	}
	// If we get here then the polynomials were the same at every index
	t.Error("polynomials had the same evaluations and are therefore the same")
}

func assertPolySameLength(t *testing.T, lhs, rhs kzg.Polynomial) int {
	t.Helper()
	// Assert that the polynomials are the same size
	require.Equal(t, len(lhs), len(rhs))
	return len(lhs)
}

func randPoly4096() kzg.Polynomial {
	poly := make(kzg.Polynomial, 4096)
	for i := 0; i < 4096; i++ {
		var eval fr.Element
		_, err := eval.SetRandom()
		if err != nil {
			panic(err)
		}
		poly[i] = eval
	}
	return poly
}
