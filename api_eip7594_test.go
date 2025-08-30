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
