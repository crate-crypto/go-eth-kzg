package kzg

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func newMonomialSRSInsecure(domain Domain, bAlpha *big.Int) (*SRS, error) {
	return newSRS(domain, bAlpha, false)
}

func TestLagrangeSRSSmoke(t *testing.T) {
	domain := NewDomain(4)
	srs_lagrange, _ := newLagrangeSRSInsecure(*domain, big.NewInt(100))
	srs_monomial, _ := newMonomialSRSInsecure(*domain, big.NewInt(100))

	// 1 + x + x^2
	poly_monomial := []fr.Element{fr.One(), fr.One(), fr.One()}
	f_x := func(x fr.Element) fr.Element {
		one := fr.One()
		var tmp fr.Element
		tmp.Square(&x)
		tmp.Add(&tmp, &x)
		tmp.Add(&tmp, &one)

		return tmp
	}
	poly_lagrange := []fr.Element{f_x(domain.Roots[0]), f_x(domain.Roots[1]), f_x(domain.Roots[2]), f_x(domain.Roots[3])}

	c_l, _ := Commit(poly_lagrange, &srs_lagrange.CommitKey)
	c_m, _ := Commit(poly_monomial, &srs_monomial.CommitKey)
	if !c_l.Equal(c_m) {
		t.Error("commitment mismatch between monomial srs and lagrange srs")
	}
}

func TestCommitRegression(t *testing.T) {
	domain := NewDomain(4)
	srs_lagrange, _ := newLagrangeSRSInsecure(*domain, big.NewInt(100))

	poly := []fr.Element{fr.NewElement(12345), fr.NewElement(123456), fr.NewElement(1234567), fr.NewElement(12345678)}
	c_l, _ := Commit(poly, &srs_lagrange.CommitKey)
	c_l_bytes := c_l.Bytes()
	got_commitment := hex.EncodeToString(c_l_bytes[:])
	expected_commitment := "85bdf872da5b8561d23055d32db3fc86c672b0be7543b8c1e48634af07231bf7ab6385b765750921017cbcdbcd14f8e0"

	if got_commitment != expected_commitment {
		t.Fatalf("code has changed or introduced a bug, since this test vector's value has changed")
	}

}
