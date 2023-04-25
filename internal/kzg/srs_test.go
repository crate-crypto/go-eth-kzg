package kzg

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

func TestLagrangeSRSSmoke(t *testing.T) {
	size := uint64(4)
	domain := NewDomain(size)
	srsLagrange, _ := newLagrangeSRSInsecure(*domain, big.NewInt(100))
	srsMonomial, _ := newMonomialSRSInsecure(*domain, big.NewInt(100))

	// 1 + x + x^2
	polyMonomial := Polynomial{fr.One(), fr.One(), fr.One()}
	f := func(x fr.Element) fr.Element {
		one := fr.One()
		var tmp fr.Element
		tmp.Square(&x)
		tmp.Add(&tmp, &x)
		tmp.Add(&tmp, &one)
		return tmp
	}
	polyLagrange := Polynomial{f(domain.Roots[0]), f(domain.Roots[1]), f(domain.Roots[2]), f(domain.Roots[3])}

	commitmentLagrange, _ := Commit(polyLagrange, &srsLagrange.CommitKey, 0)
	commitmentMonomial, _ := Commit(polyMonomial, &srsMonomial.CommitKey, 0)
	require.Equal(t, commitmentLagrange, commitmentMonomial)
}

func TestCommitRegression(t *testing.T) {
	domain := NewDomain(4)
	srsLagrange, _ := newLagrangeSRSInsecure(*domain, big.NewInt(100))

	poly := Polynomial{fr.NewElement(12345), fr.NewElement(123456), fr.NewElement(1234567), fr.NewElement(12345678)}
	cLagrange, _ := Commit(poly, &srsLagrange.CommitKey, 0)
	cLagrangeBytes := cLagrange.Bytes()
	gotCommitment := hex.EncodeToString(cLagrangeBytes[:])
	expectedCommitment := "85bdf872da5b8561d23055d32db3fc86c672b0be7543b8c1e48634af07231bf7ab6385b765750921017cbcdbcd14f8e0"
	require.Equal(t, expectedCommitment, gotCommitment)
}
