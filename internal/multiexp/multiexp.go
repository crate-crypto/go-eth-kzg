package multiexp

import (
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func MultiExp(scalars []fr.Element, points []curve.G1Affine) (*curve.G1Affine, error) {
	var result curve.G1Affine
	return result.MultiExp(points, scalars, ecc.MultiExpConfig{})
}
