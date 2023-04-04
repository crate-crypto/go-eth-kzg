package api_test

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/api"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

func TestModulus(t *testing.T) {
	expectedModulus := fr.Modulus()
	if !bytes.Equal(expectedModulus.Bytes(), api.MODULUS[:]) {
		t.Error("expected modulus does not match the defined constant")
	}
}

func TestZeroPoint(t *testing.T) {
	var zeroPoint bls12381.G1Affine
	expectedZeroPoint := serialization.SerializeG1Point(zeroPoint)

	if !bytes.Equal(expectedZeroPoint[:], api.ZERO_POINT[:]) {
		t.Error("expected zero point does not match the defined constant")
	}
}

func TestNonCanonicalSmoke(t *testing.T) {
	blobGood := GetRandBlob(123456789)

	blobBad := GetRandBlob(123456789)
	unreducedScalar := nonCanonicalScalar(123445)
	modifyBlob(&blobBad, unreducedScalar, 0)

	commitment, err := ctx.BlobToKZGCommitment(blobGood)
	if err != nil {
		t.Error(err)
	}
	_, err = ctx.BlobToKZGCommitment(blobBad)
	if err == nil {
		t.Errorf("expected an error as we gave a non-canonical blob")
	}

	inputPointGood := GetRandFieldElement(123)
	inputPointBad := createScalarNonCanonical(inputPointGood)
	proof, claimedValueGood, err := ctx.ComputeKZGProof(blobGood, inputPointGood)
	if err != nil {
		t.Error(err)
	}
	claimedValueBad := createScalarNonCanonical(claimedValueGood)

	_, _, err = ctx.ComputeKZGProof(blobGood, inputPointBad)
	if err == nil {
		t.Errorf("expected an error since input point was not canonical")
	}

	_, _, err = ctx.ComputeKZGProof(blobBad, inputPointGood)
	if err == nil {
		t.Errorf("expected an error since blob was not canonical")
	}

	err = ctx.VerifyKZGProof(commitment, proof, inputPointGood, claimedValueGood)
	if err != nil {
		t.Error(err)
	}

	err = ctx.VerifyKZGProof(commitment, proof, inputPointGood, claimedValueBad)
	if err == nil {
		t.Errorf("expected an error since claimed value was not canonical")
	}
	err = ctx.VerifyKZGProof(commitment, proof, inputPointBad, claimedValueGood)
	if err == nil {
		t.Errorf("expected an error since input point was not canonical")
	}

	blobProof, err := ctx.ComputeBlobKZGProof(blobBad, commitment)
	if err == nil {
		t.Errorf("expected an error since blob was not canonical")
	}

	err = ctx.VerifyBlobKZGProof(blobBad, commitment, blobProof)
	if err == nil {
		t.Errorf("expected an error since blob was not canonical")
	}

	err = ctx.VerifyBlobKZGProofBatch([]serialization.Blob{blobBad}, []serialization.KZGCommitment{commitment}, []serialization.KZGProof{blobProof})
	if err == nil {
		t.Errorf("expected an error since blob was not canonical")
	}
}

// Below are helper methods which allow us to change a serialized element into
// its non-canonical counterpart by adding the modulus
func modifyBlob(blob *serialization.Blob, newValue serialization.Scalar, index int) {
	copy(blob[index:index+serialization.SerializedScalarSize], newValue[:])
}

func nonCanonicalScalar(seed int64) serialization.Scalar {
	return createScalarNonCanonical(GetRandFieldElement(seed))
}

func createScalarNonCanonical(serScalar serialization.Scalar) serialization.Scalar {
	scalar, err := serialization.DeserializeScalar(serScalar)
	if err != nil {
		panic(err)
	}
	// Convert scalar to big int to add modulus to it
	var scalarBi big.Int
	scalar.BigInt(&scalarBi)

	nonCanonicalScalar := addModP(scalarBi)
	if len(nonCanonicalScalar.Bytes()) != fr.Bytes {
		panic("unreduced scalar should fit into 32 bytes")
	}
	var serNonCanonScalar serialization.Scalar
	copy(serNonCanonScalar[:], nonCanonicalScalar.Bytes())
	return serNonCanonScalar
}

func addModP(x big.Int) big.Int {
	modulus := fr.Modulus()

	var x_plus_modulus big.Int
	x_plus_modulus.Add(&x, modulus)

	return x_plus_modulus
}
