package api_test

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/api"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
	"github.com/stretchr/testify/require"
)

func TestBlsModulus(t *testing.T) {
	expectedModulus := fr.Modulus()
	require.Equal(t, expectedModulus.Bytes(), api.BlsModulus[:])
}

func TestPointAtInfinity(t *testing.T) {
	var pointAtInfinity bls12381.G1Affine
	expectedPointAtInfinity := serialization.SerializeG1Point(pointAtInfinity)
	require.Equal(t, expectedPointAtInfinity, api.PointAtInfinity)
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

	err = ctx.VerifyKZGProof(commitment, inputPointGood, claimedValueGood, proof)
	if err != nil {
		t.Error(err)
	}

	err = ctx.VerifyKZGProof(commitment, inputPointGood, claimedValueBad, proof)
	if err == nil {
		t.Errorf("expected an error since claimed value was not canonical")
	}
	err = ctx.VerifyKZGProof(commitment, inputPointBad, claimedValueGood, proof)
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

	var xPlusModulus big.Int
	xPlusModulus.Add(&x, modulus)

	return xPlusModulus
}
