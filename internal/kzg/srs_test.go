package kzg

import (
	"encoding/hex"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestSRSConversion(t *testing.T) {
	n := uint64(4096)
	domain := domain.NewDomain(n)
	secret := big.NewInt(100)
	srsMonomial, err := newMonomialSRSInsecureUint64(n, secret)
	if err != nil {
		t.Error(err)
	}
	srsLagrange, err := newLagrangeSRSInsecure(*domain, secret)
	if err != nil {
		t.Error(err)
	}

	lagrangeSRS := make([]bls12381.G1Affine, len(srsMonomial.CommitKey.G1))
	copy(lagrangeSRS, srsMonomial.CommitKey.G1)
	domain.IfftG1(lagrangeSRS)

	for i := uint64(0); i < n; i++ {
		if !lagrangeSRS[i].Equal(&srsLagrange.CommitKey.G1[i]) {
			t.Fatalf("conversion incorrect")
		}
	}
}

func TestLagrangeSRSSmoke(t *testing.T) {
	size := uint64(4)
	domain := domain.NewDomain(size)
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

	commitmentLagrange, _ := srsLagrange.CommitKey.Commit(polyLagrange, 0)
	commitmentMonomial, _ := srsMonomial.CommitKey.Commit(polyMonomial, 0)
	require.Equal(t, commitmentLagrange, commitmentMonomial)
}

func TestCommitRegression(t *testing.T) {
	domain := domain.NewDomain(4)
	srsLagrange, _ := newLagrangeSRSInsecure(*domain, big.NewInt(100))

	poly := Polynomial{fr.NewElement(12345), fr.NewElement(123456), fr.NewElement(1234567), fr.NewElement(12345678)}
	cLagrange, _ := srsLagrange.CommitKey.Commit(poly, 0)
	cLagrangeBytes := cLagrange.Bytes()
	gotCommitment := hex.EncodeToString(cLagrangeBytes[:])
	expectedCommitment := "85bdf872da5b8561d23055d32db3fc86c672b0be7543b8c1e48634af07231bf7ab6385b765750921017cbcdbcd14f8e0"
	require.Equal(t, expectedCommitment, gotCommitment)
}
