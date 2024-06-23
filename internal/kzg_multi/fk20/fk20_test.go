package fk20

import (
	"slices"
	"testing"
)

func TestTakeEvery(t *testing.T) {
	list := []int{0, 1, 2, 3, 4, 5, 6}
	chunks := takeEveryNth(list, 2)
	if len(chunks) != 2 {
		t.Fatalf("slices should have a size of 2")
	}

	expected := [][]int{{0, 3, 5}, {1, 4, 6}}
	for i := 0; i < 2; i++ {
		if slices.Equal(chunks[i], expected[i]) {
			t.Fatalf("slices are not equal")
		}
	}
}

func TestTransposeVectors(t *testing.T) {
	intVectors := [][]int{
		{1, 2, 3},
		{4, 5, 6},
		{7, 8, 9},
	}
	transposedInts := transposeVectors(intVectors)
	transposedVectors := [][]int{
		{1, 4, 7},
		{2, 5, 8},
		{3, 6, 9},
	}

	for i := 0; i < len(transposedVectors); i++ {
		if !slices.Equal(transposedInts[i], transposedVectors[i]) {
			t.Fatalf("vectors are not equal")
		}
	}
}
