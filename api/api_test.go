package api_test

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/api"
)

func TestModulus(t *testing.T) {
	expectedModulus := fr.Modulus()
	if !bytes.Equal(expectedModulus.Bytes(), api.MODULUS[:]) {
		t.Error("expected modulus does not match the modulus of the scalar field")
	}
}
