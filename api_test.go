package gokzg4844_test

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/stretchr/testify/require"
)

func TestBlsModulus(t *testing.T) {
	expectedModulus := fr.Modulus()
	require.Equal(t, expectedModulus.Bytes(), gokzg4844.BlsModulus[:])
}

func TestPointAtInfinity(t *testing.T) {
	var pointAtInfinity bls12381.G1Affine
	expectedPointAtInfinity := gokzg4844.SerializeG1Point(pointAtInfinity)
	require.Equal(t, expectedPointAtInfinity[:], gokzg4844.PointAtInfinity[:])
}

func TestNonCanonicalSmoke(t *testing.T) {
	blobGood := GetRandBlob(123456789)
	blobBad := GetRandBlob(123456789)
	unreducedScalar := nonCanonicalScalar(123445)
	modifyBlob(&blobBad, unreducedScalar, 0)

	commitment, err := ctx.BlobToKZGCommitment(blobGood)
	require.NoError(t, err)
	_, err = ctx.BlobToKZGCommitment(blobBad)
	require.Error(t, err, "expected an error as we gave a non-canonical blob")

	inputPointGood := GetRandFieldElement(123)
	inputPointBad := createScalarNonCanonical(inputPointGood)
	proof, claimedValueGood, err := ctx.ComputeKZGProof(blobGood, inputPointGood)
	require.NoError(t, err)
	claimedValueBad := createScalarNonCanonical(claimedValueGood)

	_, _, err = ctx.ComputeKZGProof(blobGood, inputPointBad)
	require.Error(t, err, "expected an error since input point was not canonical")

	_, _, err = ctx.ComputeKZGProof(blobBad, inputPointGood)
	require.Error(t, err, "expected an error since blob was not canonical")

	err = ctx.VerifyKZGProof(commitment, inputPointGood, claimedValueGood, proof)
	require.NoError(t, err)

	err = ctx.VerifyKZGProof(commitment, inputPointGood, claimedValueBad, proof)
	require.Error(t, err, "expected an error since claimed value was not canonical")

	err = ctx.VerifyKZGProof(commitment, inputPointBad, claimedValueGood, proof)
	require.Error(t, err, "expected an error since input point was not canonical")

	blobProof, err := ctx.ComputeBlobKZGProof(blobBad, commitment)
	require.Error(t, err, "expected an error since blob was not canonical")

	err = ctx.VerifyBlobKZGProof(blobBad, commitment, blobProof)
	require.Error(t, err, "expected an error since blob was not canonical")

	err = ctx.VerifyBlobKZGProofBatch([]gokzg4844.Blob{blobBad}, []gokzg4844.KZGCommitment{commitment}, []gokzg4844.KZGProof{blobProof})
	require.Error(t, err, "expected an error since blob was not canonical")
}

// Below are helper methods which allow us to change a serialized element into
// its non-canonical counterpart by adding the modulus
func modifyBlob(blob *gokzg4844.Blob, newValue gokzg4844.Scalar, index int) {
	copy(blob[index:index+gokzg4844.SerializedScalarSize], newValue[:])
}

func nonCanonicalScalar(seed int64) gokzg4844.Scalar {
	return createScalarNonCanonical(GetRandFieldElement(seed))
}

func createScalarNonCanonical(serScalar gokzg4844.Scalar) gokzg4844.Scalar {
	scalar, err := gokzg4844.DeserializeScalar(serScalar)
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
	var serNonCanonScalar gokzg4844.Scalar
	copy(serNonCanonScalar[:], nonCanonicalScalar.Bytes())
	return serNonCanonScalar
}

func addModP(x big.Int) big.Int {
	modulus := fr.Modulus()

	var xPlusModulus big.Int
	xPlusModulus.Add(&x, modulus)

	return xPlusModulus
}
