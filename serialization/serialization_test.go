package serialization

import (
	"bytes"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
)

func TestG1RoundTripSmoke(t *testing.T) {
	_, _, g1Aff, _ := bls12381.Generators()
	g1Bytes := SerializeG1Point(g1Aff)
	aff, err := DeserializeG1Point(g1Bytes)
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
	blob := SerializePoly(poly)

	var zeroBlob Blob
	if bytes.Equal(blob[:], zeroBlob[:]) {
		t.Error("blobs are all zeroes, which can only happen with negligible probability")
	}
}

func TestSerializePolyRoundTrip(t *testing.T) {

	expectedPolyA := randPoly4096()
	expectedPolyB := randPoly4096()

	blobA := SerializePoly(expectedPolyA)
	blobB := SerializePoly(expectedPolyB)

	gotPolyA, err := DeserializeBlob(blobA)
	if err != nil {
		t.Error(err)
	}
	gotPolyB, err := DeserializeBlob(blobB)
	if err != nil {
		t.Error(err)
	}
	assertPolyEqual(t, expectedPolyA, gotPolyA)
	assertPolyEqual(t, expectedPolyB, gotPolyB)

	assertPolyNotEqual(t, expectedPolyA, gotPolyB)
}

// Check element-wise that each evaluation in the polynomial is the same
func assertPolyEqual(t *testing.T, lhs kzg.Polynomial, rhs kzg.Polynomial) {
	polyLen := assertPolySameLength(t, lhs, rhs)

	for i := 0; i < polyLen; i++ {
		if !lhs[i].Equal(&rhs[i]) {
			t.Errorf("polynomials differ at index %d, therefore they are not the same", i)
		}
	}
}

// Assert that two polynomials are different -- differ at atleast one
// evaluation
func assertPolyNotEqual(t *testing.T, lhs kzg.Polynomial, rhs kzg.Polynomial) {
	polyLen := assertPolySameLength(t, lhs, rhs)

	// element at index `i` in polyPredicate stores whether the
	// evaluations at index `i` are the same
	//
	// We need this because two polynomials are different
	// if they differ at atleast one evaluation
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
func assertPolySameLength(t *testing.T, lhs kzg.Polynomial, rhs kzg.Polynomial) int {
	// Assert that the polynomials are the same size
	lenLhs := len(lhs)
	lenRhs := len(rhs)
	if lenLhs != lenRhs {
		t.Errorf("polynomials cannot be equal as they are not the same size, lhs : %d, rhs : %d", lenLhs, lenRhs)
	}
	return lenLhs
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
