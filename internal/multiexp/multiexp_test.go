package multiexp

import (
	"errors"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-kzg-4844/internal/utils"
)

func TestMultiExpSmoke(t *testing.T) {
	var base fr.Element
	base.SetInt64(1234567)

	instanceSize := uint(256)

	powers := utils.ComputePowers(base, instanceSize)
	points := genG1Points(instanceSize)

	got, err := MultiExp(powers, points, -1)
	if err != nil {
		t.Fail()
	}
	expected, err := slowMultiExp(powers, points)
	if err != nil {
		t.Fail()
	}
	if !got.Equal(expected) {
		t.Error("inconsistent multi-exp result")
	}
}

func TestMultiExpMismatchedLength(t *testing.T) {
	var base fr.Element
	base.SetInt64(123)

	instanceSize := uint(16)

	powers := utils.ComputePowers(base, instanceSize)
	points := genG1Points(instanceSize + 1)

	_, err := MultiExp(powers, points, 0)
	if err == nil {
		t.Error("number of points != number of scalars. Should produce an error")
	}

	powers = utils.ComputePowers(base, instanceSize+1)
	points = genG1Points(instanceSize)
	_, err = MultiExp(powers, points, 0)
	if err == nil {
		t.Error("number of points != number of scalars. Should produce an error")
	}
}

func TestMultiExpZeroLength(t *testing.T) {
	result, err := MultiExp([]fr.Element{}, []bls12381.G1Affine{}, 0)
	if err != nil {
		t.Error("number of points != number of scalars. Should produce an error")
	}

	if !result.Equal(&bls12381.G1Affine{}) {
		t.Error("result should be identity when instance size is 0")
	}
}

func TestMultiExpErrOnMoreThan1024(t *testing.T) {
	_, err := MultiExp([]fr.Element{}, []bls12381.G1Affine{}, 1024)
	if err == nil {
		t.Error("when the number of go-routines is set to more than 1024, an error is expected")
	}
	if !errors.Is(err, ErrTooManyGoRoutines) {
		t.Errorf("expected %v but got %v", ErrTooManyGoRoutines, err)
	}
}

func TestIsIdentitySmoke(t *testing.T) {
	// Check that the identity point is encoded as (0,0) which is the point at infinity
	// Really this is an abstraction leak from gnark
	// as we don't care about the point being an infinity point
	// just that its the identity point.
	// For Edwards, the identity point is rational

	var identity bls12381.G1Affine
	if !identity.IsInfinity() {
		t.Error("(0,0) is not the point at infinity")
	}

	_, _, genG1Aff, _ := bls12381.Generators()
	genG1Aff.Add(&genG1Aff, &identity)

	if !genG1Aff.Equal(&genG1Aff) {
		t.Error("identity point is not the point at infinity")
	}
}

func slowMultiExp(scalars []fr.Element, points []bls12381.G1Affine) (*bls12381.G1Affine, error) {
	if len(scalars) != len(points) {
		return nil, errors.New("number of scalars != number of points")
	}
	n := len(scalars)

	var result bls12381.G1Affine

	for i := 0; i < n; i++ {
		var tmp bls12381.G1Affine
		var bi big.Int
		tmp.ScalarMultiplication(&points[i], scalars[i].BigInt(&bi))

		result.Add(&result, &tmp)
	}

	return &result, nil
}

func genG1Points(n uint) []bls12381.G1Affine {
	if n == 0 {
		return []bls12381.G1Affine{}
	}

	_, _, g1Gen, _ := bls12381.Generators()

	var points []bls12381.G1Affine
	points = append(points, g1Gen)

	for i := uint(1); i < n; i++ {
		var tmp bls12381.G1Affine
		tmp.Add(&g1Gen, &points[i-1])
		points = append(points, tmp)
	}
	return points
}
