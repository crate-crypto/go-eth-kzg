package serialisation

import (
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func TestG1RoundTripSmoke(t *testing.T) {
	_, _, g1Aff, _ := curve.Generators()
	g1Bytes := SerialiseG1Point(g1Aff)
	aff, err := DeserialiseG1Point(g1Bytes)
	if err != nil {
		t.Error(err)
	}
	if !aff.Equal(&g1Aff) {
		t.Error("G1 serialisation roundtrip fail")
	}
}
