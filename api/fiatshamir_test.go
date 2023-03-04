package api

import (
	"bytes"
	"testing"
)

func TestTo16Bytes(t *testing.T) {
	number := uint64(4096)
	// Generated using the following python snippet:
	// FIELD_ELEMENTS_PER_BLOB = 4096
	// degree_poly = int.to_bytes(FIELD_ELEMENTS_PER_BLOB, 16, 'little')
	// " ".join(format(x, "d") for x in degree_poly)
	expected := []byte{0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	got := u64ToByteArray16(number)
	if !bytes.Equal(expected, got) {
		t.Fatalf("unexpected byte array when converting a u64 to bytes,\n got %v \n expected %v", got, expected)
	}
}
