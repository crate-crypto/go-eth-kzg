package goethkzg

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestIsAscending(t *testing.T) {
	tests := []struct {
		input    []uint64
		expected bool
	}{
		{[]uint64{}, true},  // empty slice
		{[]uint64{1}, true}, // single element
		{[]uint64{1, 2, 3, 4, 5}, true},
		{[]uint64{1, 3, 5, 7, 9}, true},
		{[]uint64{1, 2, 2, 3}, false}, // also returns false on duplicates
		{[]uint64{1, 2, 3, 2}, false},
		{[]uint64{3, 2, 1}, false},
		{[]uint64{1, 1, 1}, false},
		{[]uint64{5, 4, 3, 2, 1}, false},
		{[]uint64{1, 3, 2, 4}, false},
		{[]uint64{0, 1, 2}, true},
		{[]uint64{10, 20, 30}, true},
	}

	for _, test := range tests {
		result := isAscending(test.input)
		if result != test.expected {
			t.Errorf("isAscending(%v) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestSerializeCellsCosetEvaluationCount(t *testing.T) {
	validCosetEval := make([]fr.Element, scalarsPerCell)

	tests := []struct {
		name        string
		input       [][]fr.Element
		expectedErr error
	}{
		{
			name:        "empty input",
			input:       [][]fr.Element{},
			expectedErr: ErrNumCosetEvaluationsCheck,
		},
		{
			name:        "too few evaluations",
			input:       [][]fr.Element{validCosetEval, validCosetEval},
			expectedErr: ErrNumCosetEvaluationsCheck,
		},
		{
			name: "too many evaluations",
			input: func() [][]fr.Element {
				evals := make([][]fr.Element, CellsPerExtBlob+1)
				for i := range evals {
					evals[i] = make([]fr.Element, scalarsPerCell)
				}
				return evals
			}(),
			expectedErr: ErrNumCosetEvaluationsCheck,
		},
		{
			name: "exact count",
			input: func() [][]fr.Element {
				evals := make([][]fr.Element, CellsPerExtBlob)
				for i := range evals {
					evals[i] = make([]fr.Element, scalarsPerCell)
				}
				return evals
			}(),
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := serializeCells(tt.input)
			if err != tt.expectedErr {
				t.Errorf("serializeCells() error = %v, expected %v", err, tt.expectedErr)
			}
		})
	}
}
