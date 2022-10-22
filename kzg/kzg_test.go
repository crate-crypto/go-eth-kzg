package kzg

import (
	"math/big"
	"testing"

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

	err := Verify(&comm, &proof, &srs.OpeningKey)
	if err != nil {
		t.Error("proof down bad")
	}
}
