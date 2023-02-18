package kzg

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestProofVerifySmoke(t *testing.T) {
	domain := NewDomain(4)
	srs, _ := NewSRSInsecure(*domain, big.NewInt(1234))

	// polynomial in lagrange form
	poly := []fr.Element{fr.NewElement(2), fr.NewElement(3), fr.NewElement(4), fr.NewElement(5)}

	comm, _ := Commit(poly, &srs.CommitKey)
	point := samplePointOutsideDomain(*domain)
	proof, _ := Open(domain, poly, *point, &srs.CommitKey)

	err := Verify(comm, &proof, &srs.OpeningKey)
	if err != nil {
		t.Error("proof down bad")
	}
}

func TestBatchVerifySmoke(t *testing.T) {
	domain := NewDomain(4)
	srs, _ := NewSRSInsecure(*domain, big.NewInt(1234))

	numProofs := 10

	commitments := make([]Commitment, numProofs)
	proofs := make([]OpeningProof, numProofs)
	for i := 0; i < numProofs; i++ {
		proof, comm := randValidOpeningProof(t, *domain, *srs)
		commitments = append(commitments, comm)
		proofs = append(proofs, proof)
	}
	err := BatchVerifyMultiPoints(commitments, proofs, &srs.OpeningKey)
	if err != nil {
		t.Fatalf(err.Error())
	}
	// Add an invalid proof, to ensure that it fails
	proof, _ := randValidOpeningProof(t, *domain, *srs)
	commitments = append(commitments, bls12381.G1Affine{})
	proofs = append(proofs, proof)
	err = BatchVerifyMultiPoints(commitments, proofs, &srs.OpeningKey)
	if err == nil {
		t.Fatalf("An invalid proof was added to the list, however verification returned true")
	}
}

func randValidOpeningProof(t *testing.T, domain Domain, srs SRS) (OpeningProof, Commitment) {
	var poly []fr.Element
	for i := 0; i < int(domain.Cardinality); i++ {
		var randFr = RandomScalarNotInDomain(t, domain)
		poly = append(poly, randFr)
	}
	comm, _ := Commit(poly, &srs.CommitKey)
	point := samplePointOutsideDomain(domain)
	proof, _ := Open(&domain, poly, *point, &srs.CommitKey)
	return proof, *comm
}

func RandomScalarNotInDomain(t *testing.T, domain Domain) fr.Element {
	var randFr fr.Element
	for {
		_, err := randFr.SetRandom()
		if err != nil {
			t.Fatalf("could not generate a random integer %s", err.Error())
		}
		if !domain.isInDomain(randFr) {
			break
		}
	}
	return randFr
}
