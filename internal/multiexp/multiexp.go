package multiexp

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func MultiExp(scalars []fr.Element, points []bls12381.G1Affine) (*bls12381.G1Affine, error) {
	var result bls12381.G1Affine
	return result.MultiExp(points, scalars, ecc.MultiExpConfig{})
}
