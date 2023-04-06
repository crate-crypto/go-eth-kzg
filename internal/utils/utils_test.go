package utils

import (
	"bytes"
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestSliceReverse(t *testing.T) {
	type TestCase struct {
		slice, reversedSlice []byte
	}

	testCases := []TestCase{
		{[]byte{1, 2, 3, 4}, []byte{4, 3, 2, 1}},
		{[]byte{1, 2, 3, 4, 5}, []byte{5, 4, 3, 2, 1}},
		{[]byte{1}, []byte{1}},
		{[]byte{}, []byte{}},
	}

	for _, test := range testCases {
		got := test.slice
		expected := test.reversedSlice
		Reverse(got)

		if !bytes.Equal(got, expected) {
			t.Error("expected reversed slice does not match the computed reversed slice")
		}
	}
}

func TestArrReverseSmoke(t *testing.T) {
	arr := [32]uint8{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
		31, 32,
	}
	Reverse(arr[:])
	expected := [32]uint8{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	if !bytes.Equal(expected[:], arr[:]) {
		t.Error("expected the reverse of the array")
	}
}

func TestIsPow2(t *testing.T) {
	powInt := func(x, y uint64) uint64 {
		return uint64(math.Pow(float64(x), float64(y)))
	}

	// 0 is not a power of two
	ok := IsPowerOfTwo(0)
	if ok {
		t.Error("zero is not a power of two")
	}

	// Numbers of the form 2^x are all powers of two
	// Do this up to x=63, since we are using u64
	for i := 0; i < 63; i++ {
		pow2 := powInt(2, uint64(i))
		ok := IsPowerOfTwo(pow2)
		if !ok {
			t.Error("numbers of the form 2^x are powers of two")
		}
	}
	// Numbers of the form 2^x -1 are not powers of two
	// from x=2 until x=63
	for i := 2; i < 63; i++ {
		pow2Minus1 := powInt(2, uint64(i)) - 1
		ok := IsPowerOfTwo(pow2Minus1)
		if ok {
			t.Error("numbers of the form 2^x -1 are not powers of two from x=2")
		}
	}
}

func TestComputePowersBaseOne(t *testing.T) {
	one := fr.One()

	powers := ComputePowers(one, 10)
	for _, pow := range powers {
		if !pow.Equal(&one) {
			t.Error("powers should all be 1")
		}
	}
}

func TestComputePowersZero(t *testing.T) {
	x := fr.NewElement(1234)

	powers := ComputePowers(x, 0)
	// When given a number of 0
	// this will return an empty slice
	if len(powers) != 0 {
		t.Error("number of powers to compute was `0`, but got more than `0` powers computed")
	}
	if powers == nil {
		t.Error("Returned nil slice when asked to compute 0 powers of x")
	}
}

func TestComputePowersSmoke(t *testing.T) {
	var base fr.Element
	base.SetInt64(123)

	powers := ComputePowers(base, 16)

	for index, pow := range powers {
		var expected fr.Element
		expected.Exp(base, big.NewInt(int64(index)))

		powCopy := pow
		if !expected.Equal(&powCopy) {
			t.Error("incorrect exponentiation result")
		}
	}
}

func TestCanonicalEncoding(t *testing.T) {
	x := randReducedBigInt()
	xPlusModulus := addModP(x)

	unreducedBytes := xPlusModulus.Bytes()

	// `SetBytes` will read the unreduced bytes and
	// return a field element. Does not matter if its canonical
	var reduced fr.Element
	reduced.SetBytes(unreducedBytes)

	// `Bytes` will return a canonical representation of the
	// field element, ie a reduced version
	reducedBytes := reduced.Bytes()

	// First we should check that the reduced version
	// is different to the unreduced version, incase one changes the
	// implementation in the future
	if bytes.Equal(unreducedBytes, reducedBytes[:]) {
		t.Error("unreduced representation of field element, is the same as the reduced representation")
	}

	// Reduce canonical should produce an error
	_, err := reduceCanonicalBigEndian(unreducedBytes)
	if err == nil {
		t.Error("input to ReduceCanonical was unreduced bytes")
	}

	// Now we call the method which will reduce the bytes unconditionally
	var gotReduced fr.Element
	gotReduced.SetBytes(unreducedBytes)
	if !gotReduced.Equal(&reduced) {
		t.Error("incorrect field element interpretation from unreduced byte representation")
	}
}

// Adds the modulus to the big integer
// we need to do it with a big.Int
// since an fr.Element will apply the
// reduction
func addModP(x big.Int) big.Int {
	modulus := fr.Modulus()

	var xPlusModulus big.Int
	xPlusModulus.Add(&x, modulus)

	return xPlusModulus
}

func randReducedBigInt() big.Int {
	var randFr fr.Element
	_, _ = randFr.SetRandom()

	var randBigInt big.Int
	randFr.BigInt(&randBigInt)

	if randBigInt.Cmp(fr.Modulus()) != -1 {
		panic("big integer is not reduced")
	}

	return randBigInt
}
