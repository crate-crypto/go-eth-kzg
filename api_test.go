package api

import (
	"bytes"
	"fmt"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
)

func TestModulus(t *testing.T) {
	expected_modulus := fr.Modulus()
	if !bytes.Equal(expected_modulus.Bytes(), MODULUS[:]) {
		t.Error("expected modulus does not match the modulus of the scalar field")
	}
}

// This is both an interop test and a regression check
// If the way computeChallenge is computed is updated
// then this test will fail
func TestComputeChallengeInterop(t *testing.T) {
	blob := serialisation.Blob{}
	commitment := serialisation.SerialiseG1Point(bls12381.G1Affine{})
	challenge := computeChallenge(serialisation.SCALARS_PER_BLOB, blob, commitment)
	expected := []byte{
		59, 127, 233, 79, 178, 22, 242, 95,
		176, 209, 125, 10, 193, 90, 102, 229,
		56, 104, 204, 58, 237, 60, 121, 97,
		77, 194, 248, 45, 172, 7, 224, 74,
	}
	got := serialisation.SerialiseScalar(challenge)
	if !bytes.Equal(expected, got[:]) {
		t.Fatalf("computeChallenge has changed and or regressed")
	}
}

func TestXxx2(t *testing.T) {
	ctx, err := NewContext4096Insecure1337()
	if err != nil {
		panic(err)
	}

	polynomial := make([]fr.Element, ctx.domain.Cardinality)
	for i := 0; i < 4096; i++ {
		polynomial[i] = fr.NewElement(uint64(i))
	}

	for i := 0; i < int(ctx.domain.Cardinality); i++ {
		if i > 100 {
			return
		}
		evalPoint := ctx.domain.Roots[i]
		serEval := serialisation.SerialiseScalar(evalPoint)
		proof, comm, claimedValue, err := ctx.ComputeKZGProof(serialisation.SerialisePoly(polynomial), serEval)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(claimedValue)
		err = ctx.VerifyKZGProof(comm, proof, serialisation.SerialiseScalar(evalPoint), claimedValue)
		if err != nil {
			t.Fatal(err)
		}
	}
	// t.Fail()

}
