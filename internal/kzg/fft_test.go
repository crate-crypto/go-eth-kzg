package kzg

import (
	"math/big"
	"testing"
)

func TestSRSConversion(t *testing.T) {
	n := uint64(4096)
	domain := NewDomain(n)
	secret := big.NewInt(100)
	srsMonomial, err := newMonomialSRS(n, secret)
	if err != nil {
		t.Error(err)
	}
	srsLagrange, err := NewLagrangeSRSInsecure(*domain, secret)
	if err != nil {
		t.Error(err)
	}

	lagrangeSRS := IfftG1(srsMonomial.CommitKey.G1, domain.GeneratorInv)

	for i := uint64(0); i < n; i++ {
		if !lagrangeSRS[i].Equal(&srsLagrange.CommitKey.G1[i]) {
			t.Fatalf("conversion incorrect")
		}
	}
}
