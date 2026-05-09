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

func TestRecoverPolynomialCoeffsNilCell(t *testing.T) {
	ctx, err := NewContext4096Secure()
	if err != nil {
		t.Skip(err)
	}

	numCells := ctx.dataRecovery.NumBlocksNeededToReconstruct()
	cellIDs := make([]uint64, numCells)
	for i := range cellIDs {
		cellIDs[i] = uint64(i)
	}

	tests := []struct {
		name    string
		cells   []*Cell
		wantErr error
	}{
		{
			name: "first cell nil",
			cells: func() []*Cell {
				c := make([]*Cell, numCells)
				for i := range c {
					c[i] = &Cell{}
				}
				c[0] = nil
				return c
			}(),
			wantErr: ErrDeserializeNilInput,
		},
		{
			name: "last cell nil",
			cells: func() []*Cell {
				c := make([]*Cell, numCells)
				for i := range c {
					c[i] = &Cell{}
				}
				c[numCells-1] = nil
				return c
			}(),
			wantErr: ErrDeserializeNilInput,
		},
		{
			name: "all cells non-nil",
			cells: func() []*Cell {
				c := make([]*Cell, numCells)
				for i := range c {
					c[i] = &Cell{}
				}
				return c
			}(),
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ctx.recoverPolynomialCoeffs(cellIDs, tt.cells)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("recoverPolynomialCoeffs() error = %v, expected %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVerifyCellKZGProofBatchNilCell(t *testing.T) {
	ctx, err := NewContext4096Secure()
	if err != nil {
		t.Skip(err)
	}

	tests := []struct {
		name    string
		cells   []*Cell
		wantErr error
	}{
		{
			name:    "nil cell element",
			cells:   []*Cell{nil},
			wantErr: ErrDeserializeNilInput,
		},
		{
			name:    "non-nil cell element",
			cells:   []*Cell{{}},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commitments := make([]KZGCommitment, len(tt.cells))
			cellIndices := make([]uint64, len(tt.cells))
			proofs := make([]KZGProof, len(tt.cells))

			err := ctx.VerifyCellKZGProofBatch(commitments, cellIndices, tt.cells, proofs)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("VerifyCellKZGProofBatch() error = %v, expected %v", err, tt.wantErr)
				}
			}
		})
	}
}
