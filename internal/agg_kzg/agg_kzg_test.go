package agg_kzg

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
)

func TestProofVerifySmoke(t *testing.T) {
	domain := kzg.NewDomain(4)
	srs, _ := kzg.NewSRSInsecure(*domain, big.NewInt(1234))

	poly_a := []fr.Element{fr.NewElement(2), fr.NewElement(3), fr.NewElement(4), fr.NewElement(5)}
	poly_b := []fr.Element{fr.NewElement(1), fr.NewElement(4), fr.NewElement(1), fr.NewElement(6)}

	polys := []kzg.Polynomial{poly_a, poly_b}

	proof, err := BatchOpenSinglePoint(domain, polys, &srs.CommitKey)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = VerifyBatchOpen(domain, polys, proof, &srs.OpeningKey)
	if err != nil {
		t.Errorf(err.Error())
	}
}
