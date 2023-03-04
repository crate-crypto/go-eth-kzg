package api

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestModulus(t *testing.T) {
	expected_modulus := fr.Modulus()
	if !bytes.Equal(expected_modulus.Bytes(), MODULUS[:]) {
		t.Error("expected modulus does not match the modulus of the scalar field")
	}
}
