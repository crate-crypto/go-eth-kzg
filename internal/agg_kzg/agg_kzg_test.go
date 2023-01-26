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

var num_polys = 16
var num_evaluations_of_poly = 4096

// Setup code
var domain = kzg.NewDomain(uint64(num_evaluations_of_poly))
var srs, _ = kzg.NewSRSInsecure(*domain, big.NewInt(1234))

var polys = GeneratePolys(num_polys, num_evaluations_of_poly)
var proof, _ = BatchOpenSinglePoint(domain, polys, &srs.CommitKey)

func BenchmarkVerifyAggregate(b *testing.B) {

	for n := 0; n < b.N; n++ {
		err := VerifyBatchOpen(domain, polys, proof, &srs.OpeningKey)
		if err != nil {
			panic("")
		}
	}
}

func GeneratePolys(numPolys int, degree int) [][]fr.Element {
	polys := make([]kzg.Polynomial, numPolys)
	for i := 0; i < numPolys; i++ {
		polys[i] = randPoly(degree)
	}
	return polys
}

func randPoly(polyDegree int) []fr.Element {
	poly := make([]fr.Element, polyDegree)
	for i := 0; i < polyDegree; i++ {
		var eval fr.Element
		_, err := eval.SetRandom()
		if err != nil {
			panic("err is not nil")
		}
		poly[i] = eval
	}
	return poly
}
