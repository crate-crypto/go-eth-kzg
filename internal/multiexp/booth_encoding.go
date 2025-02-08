package multiexp

import (
	"encoding/binary"
	"slices"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// getBoothIndex computes the Booth encoding index.
// The algorithm:
//   - Steps by `windowSize` bits per window and slices out `windowSize+1` bits (overlapping by one bit)
//   - For the least-significant window (windowIndex == 0) the value is padded by one extra zero bit.
//   - The slice is interpreted according to the Booth indexing rule.
func getBoothIndex(windowIndex, windowSize int, el []byte) int32 {
	// Compute the number of bits to skip.
	skipBits := windowIndex * windowSize
	if skipBits > 0 {
		skipBits--
	}

	// Compute how many whole bytes to skip.
	skipBytes := skipBits / 8

	// Fill a 4-byte buffer from el starting at skipBytes.
	var v [4]byte
	for i := 0; i < 4 && skipBytes+i < len(el); i++ {
		v[i] = el[skipBytes+i]
	}

	// Interpret the 4 bytes as a little-endian uint32.
	tmp := binary.LittleEndian.Uint32(v[:])

	// For the least-significant window, pad with an extra zero bit.
	if windowIndex == 0 {
		tmp <<= 1
	}

	// Shift right to drop any extra bits that are not part of the window.
	shiftAmount := skipBits - skipBytes*8
	tmp >>= uint(shiftAmount)

	// Mask out only windowSize+1 bits.
	mask := uint32((1 << (windowSize + 1)) - 1)
	tmp &= mask

	// Determine the sign bit.
	signBit := uint32(1 << windowSize)
	sign := (tmp & signBit) == 0

	// Divide by 2 (using (x+1)>>1, which handles rounding)
	tmp = (tmp + 1) >> 1

	// Return the computed booth index.
	if sign {
		return int32(tmp)
	} else {
		negMask := uint32((1 << windowSize) - 1)
		return -int32((^(tmp - 1)) & negMask)
	}
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
