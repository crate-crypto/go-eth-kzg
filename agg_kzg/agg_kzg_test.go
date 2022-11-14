package agg_kzg

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/kzg"
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

var globalErr error

func BenchAggProofVerify(num_polynomials int, b *testing.B) {
	domain := kzg.NewDomain(4096)
	srs, _ := kzg.NewSRSInsecure(*domain, big.NewInt(1234))

	polys := []kzg.Polynomial{}

	for i := 0; i < num_polynomials; i++ {
		polys = append(polys, randomPoly(4096))
	}

	proof, err := BatchOpenSinglePoint(domain, polys, &srs.CommitKey)
	if err != nil {
		panic("")
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		err = VerifyBatchOpen(domain, polys, proof, &srs.OpeningKey)
	}

	globalErr = err
}

func BenchmarkAggVerify1(b *testing.B)  { BenchAggProofVerify(1, b) }
func BenchmarkAggVerify2(b *testing.B)  { BenchAggProofVerify(2, b) }
func BenchmarkAggVerify3(b *testing.B)  { BenchAggProofVerify(3, b) }
func BenchmarkAggVerify4(b *testing.B)  { BenchAggProofVerify(4, b) }
func BenchmarkAggVerify5(b *testing.B)  { BenchAggProofVerify(5, b) }
func BenchmarkAggVerify6(b *testing.B)  { BenchAggProofVerify(6, b) }
func BenchmarkAggVerify7(b *testing.B)  { BenchAggProofVerify(7, b) }
func BenchmarkAggVerify8(b *testing.B)  { BenchAggProofVerify(8, b) }
func BenchmarkAggVerify9(b *testing.B)  { BenchAggProofVerify(9, b) }
func BenchmarkAggVerify10(b *testing.B) { BenchAggProofVerify(10, b) }
func BenchmarkAggVerify11(b *testing.B) { BenchAggProofVerify(11, b) }
func BenchmarkAggVerify12(b *testing.B) { BenchAggProofVerify(12, b) }
func BenchmarkAggVerify13(b *testing.B) { BenchAggProofVerify(13, b) }
func BenchmarkAggVerify14(b *testing.B) { BenchAggProofVerify(14, b) }
func BenchmarkAggVerify15(b *testing.B) { BenchAggProofVerify(15, b) }
func BenchmarkAggVerify16(b *testing.B) { BenchAggProofVerify(16, b) }

func randomPoly(size int) []fr.Element {
	res := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		var k fr.Element
		k.SetRandom()
		res[i] = k
	}
	return res
}
