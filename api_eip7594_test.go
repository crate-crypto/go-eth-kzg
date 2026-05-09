package goethkzg

import "testing"

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

func TestVerifyCellKZGProofBatch_LengthValidation(t *testing.T) {
	ctx, err := NewContext4096Secure()
	if err != nil {
		t.Skip(err)
	}

	validCommitment := KZGCommitment{}
	validCellIndex := uint64(0)
	validCell := &Cell{}
	validProof := KZGProof{}

	tests := []struct {
		name        string
		commitments []KZGCommitment
		cellIndices []uint64
		cells       []*Cell
		proofs      []KZGProof
		expectedErr error
	}{
		{
			name:        "all empty",
			commitments: []KZGCommitment{},
			cellIndices: []uint64{},
			cells:       []*Cell{},
			proofs:      []KZGProof{},
			expectedErr: nil,
		},
		{
			name:        "all same length",
			commitments: []KZGCommitment{validCommitment},
			cellIndices: []uint64{validCellIndex},
			cells:       []*Cell{validCell},
			proofs:      []KZGProof{validProof},
			expectedErr: nil,
		},
		{
			name:        "mismatched commitments",
			commitments: []KZGCommitment{validCommitment, validCommitment},
			cellIndices: []uint64{validCellIndex},
			cells:       []*Cell{validCell},
			proofs:      []KZGProof{validProof},
			expectedErr: ErrBatchLengthCheck,
		},
		{
			name:        "mismatched cell indices",
			commitments: []KZGCommitment{validCommitment},
			cellIndices: []uint64{validCellIndex, validCellIndex},
			cells:       []*Cell{validCell},
			proofs:      []KZGProof{validProof},
			expectedErr: ErrBatchLengthCheck,
		},
		{
			name:        "mismatched cells",
			commitments: []KZGCommitment{validCommitment},
			cellIndices: []uint64{validCellIndex},
			cells:       []*Cell{validCell, validCell},
			proofs:      []KZGProof{validProof},
			expectedErr: ErrBatchLengthCheck,
		},
		{
			name:        "mismatched proofs",
			commitments: []KZGCommitment{validCommitment},
			cellIndices: []uint64{validCellIndex},
			cells:       []*Cell{validCell},
			proofs:      []KZGProof{validProof, validProof},
			expectedErr: ErrBatchLengthCheck,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ignore other validation errors, we only care about ErrBatchLengthCheck
			// or if it successfully passes the length check.
			err := ctx.VerifyCellKZGProofBatch(tt.commitments, tt.cellIndices, tt.cells, tt.proofs)

			if tt.expectedErr == ErrBatchLengthCheck {
				if err != ErrBatchLengthCheck {
					t.Errorf("expected ErrBatchLengthCheck, got %v", err)
				}
			} else {
				if err == ErrBatchLengthCheck {
					t.Errorf("did not expect ErrBatchLengthCheck, but got it")
				}
			}
		})
	}
}
