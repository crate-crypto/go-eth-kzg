package multiexp

import (
	"encoding/binary"
	"slices"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func getBoothIndex(windowIndex, windowSize int, el []byte) int32 {
	// Calculate bits to skip
	skipBits := int(0)
	if windowIndex*windowSize > 1 {
		skipBits = windowIndex*windowSize - 1
	}
	skipBytes := skipBits / 8

	// Fill into a uint32
	v := make([]byte, 4)
	for i := int(0); i < 4 && int(skipBytes)+i < len(el); i++ {
		v[i] = el[skipBytes+i]
	}
	tmp := binary.LittleEndian.Uint32(v)

	// Pad with one 0 if slicing the least significant window
	if windowIndex == 0 {
		tmp <<= 1
	}

	// Remove further bits
	tmp >>= skipBits - (skipBytes * 8)

	// Apply the booth window
	tmp &= (1 << (windowSize + 1)) - 1

	// Check sign
	sign := tmp&(1<<windowSize) == 0

	// Div ceil by 2
	tmp = (tmp + 1) >> 1

	// Find the booth action index
	if sign {
		return int32(tmp)
	}

	// Handle negative case
	mask := (uint32(1) << windowSize) - 1
	return -int32((^(tmp - 1)) & mask)
}

func scalarsToBytes(scalars []fr.Element) [][]uint8 {
	recodedScalars := make([][]uint8, len(scalars))
	for i := 0; i < len(scalars); i++ {
		byts := scalars[i].Bytes()
		slices.Reverse(byts[:])
		recodedScalars[i] = byts[:]
	}
	return recodedScalars
}
