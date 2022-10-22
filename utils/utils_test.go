package utils

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestIsPow2(t *testing.T) {
	powInt := func(x, y uint64) uint64 {
		return uint64(math.Pow(float64(x), float64(y)))
	}

	// 0 is now a power of two
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

func TestComputePowersOne(t *testing.T) {
	one := fr.One()

	powers := ComputePowers(one, 10)
	for _, pow := range powers {
		if !pow.Equal(&one) {
			t.Error("powers should all be 1")
		}
	}
}

func TestComputePowersSmoke(t *testing.T) {
	var base fr.Element
	base.SetInt64(123)

	powers := ComputePowers(base, 16)

	for index, pow := range powers {
		var expected fr.Element
		expected.Exp(base, big.NewInt(int64(index)))

		if !expected.Equal(&pow) {
			t.Error("incorrect exponentiation result")
		}
	}
}

func TestExponentiate(t *testing.T) {
	var base fr.Element
	base.SetInt64(123)
	var result fr.Element

	result.Exp(base, big.NewInt(16))
	res2 := Pow2(base, 16)

	if !res2.Equal(&result) {
		t.Fail()
	}
}
