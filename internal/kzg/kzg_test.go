package kzg

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestProofVerifySmoke(t *testing.T) {
	domain := domain.NewDomain(4)
	srs, _ := newMonomialSRSInsecure(*domain, big.NewInt(1234))

	// polynomial in monomial form
	poly := Polynomial{fr.NewElement(2), fr.NewElement(3), fr.NewElement(4), fr.NewElement(5)}

	comm, _ := srs.CommitKey.Commit(poly, 0)
	point := randomScalar(t)
	proof, _ := Open(domain, poly, point, &srs.CommitKey, 0)

	err := Verify(comm, &proof, &srs.OpeningKey)
	if err != nil {
		t.Error("proof failed to verify")
	}
}

func TestBatchVerifySmoke(t *testing.T) {
	domain := domain.NewDomain(4)
	srs, _ := newMonomialSRSInsecure(*domain, big.NewInt(1234))

	numProofs := 10
	commitments := make([]Commitment, 0, numProofs)
	proofs := make([]OpeningProof, 0, numProofs)
	for i := 0; i < numProofs-1; i++ {
		proof, commitment := randValidOpeningProof(t, *domain, *srs)
		commitments = append(commitments, commitment)
		proofs = append(proofs, proof)
	}

	// Check that these verify successfully.
	err := BatchVerifyMultiPoints(commitments, proofs, &srs.OpeningKey)
	require.NoError(t, err)

	// Add an invalid proof, to ensure that it fails
	proof, _ := randValidOpeningProof(t, *domain, *srs)
	commitments = append(commitments, bls12381.G1Affine{})
	proofs = append(proofs, proof)
	err = BatchVerifyMultiPoints(commitments, proofs, &srs.OpeningKey)
	require.Error(t, err, "An invalid proof was added to the list, however verification returned true")
}

func randValidOpeningProof(t *testing.T, domain domain.Domain, srs SRS) (OpeningProof, Commitment) {
	t.Helper()
	poly := randPoly(t, domain)
	comm, _ := srs.CommitKey.Commit(poly, 0)
	point := randomScalar(t)
	proof, _ := Open(&domain, poly, point, &srs.CommitKey, 0)
	return proof, *comm
}

func randPoly(t *testing.T, domain domain.Domain) Polynomial {
	t.Helper()
	var poly Polynomial
	for i := 0; i < int(domain.Cardinality); i++ {
		randFr := randomScalar(t)
		poly = append(poly, randFr)
	}
	return poly
}

func randomScalar(t *testing.T) fr.Element {
	t.Helper()
	var randFr fr.Element
	_, err := randFr.SetRandom()
	if err != nil {
		t.Fatalf("could not generate a random integer %s", err.Error())
	}

	return randFr
}
