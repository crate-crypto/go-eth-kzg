package multiexp

import (
	"encoding/binary"
	"runtime"
	"slices"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// func getBoothIndex(windowIndex, windowSize int, el []byte) int32 {
// 	// Equivalent to Rust's saturating_sub(1)
// 	skipBits := windowIndex * windowSize
// 	if skipBits > 0 {
// 		skipBits--
// 	}
// 	skipBytes := skipBits / 8

// 	// Collect up to 4 bytes into v, skipping skipBytes
// 	var v [4]byte
// 	for i := 0; i < 4; i++ {
// 		srcIndex := skipBytes + i
// 		if srcIndex < len(el) {
// 			v[i] = el[srcIndex]
// 		} else {
// 			v[i] = 0
// 		}
// 	}

// 	// Convert little-endian bytes to uint32
// 	tmp := binary.LittleEndian.Uint32(v[:])

// 	// Pad with one 0 bit if slicing the least significant window
// 	if windowIndex == 0 {
// 		tmp <<= 1
// 	}

// 	// Shift right by the remaining bits
// 	shift := skipBits - (skipBytes * 8)
// 	tmp >>= shift

// 	// Mask off only (windowSize + 1) bits
// 	tmp &= (1 << (windowSize + 1)) - 1

// 	// Determine sign (0 => positive, 1 => negative)
// 	sign := (tmp & (1 << windowSize)) == 0

// 	// Divide (ceil) by 2
// 	tmp = (tmp + 1) >> 1

// 	// If sign is true => positive, otherwise compute negative version
// 	if sign {
// 		return int32(tmp)
// 	} else {
// 		// ~(tmp-1) & ((1 << windowSize) - 1)
// 		masked := ^(tmp - 1) & ((1 << windowSize) - 1)
// 		return -int32(masked)
// 	}
// }

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

// recodeWindow processes a window and returns the recoded digit and carry
func recodeWindow(value int, c uint64) (digit int, carry int) {
	max := int(1<<(c-1)) - 1
	if value > max {
		digit = value - (1 << c)
		carry = 1
	} else {
		digit = value
		carry = 0
	}
	return digit, carry
}

// recodeScalar recodes a single scalar into windowed digits
func recodeScalar(scalar [4]uint64, c uint64, nbChunks uint64) []int {
	digits := make([]int, nbChunks)
	mask := uint64((1 << c) - 1)
	carry := 0

	// Process all chunks except the last
	for i := uint64(0); i < nbChunks-1; i++ {
		wordIdx := (i * c) / 64
		bitPos := (i * c) % 64

		value := carry

		if bitPos <= 64-c {
			value += int((scalar[wordIdx] >> bitPos) & mask)
		} else {
			lowBits := (scalar[wordIdx] >> bitPos)
			highBits := scalar[wordIdx+1] << (64 - bitPos)
			value += int((lowBits | highBits) & mask)
		}

		digits[i], carry = recodeWindow(value, c)
	}

	// Handle last chunk
	wordIdx := ((nbChunks - 1) * c) / 64
	bitPos := ((nbChunks - 1) * c) % 64
	value := carry

	if bitPos <= 64-c {
		value += int((scalar[wordIdx] >> bitPos) & mask)
	} else {
		lowBits := (scalar[wordIdx] >> bitPos)
		if wordIdx+1 < uint64(len(scalar)) {
			highBits := scalar[wordIdx+1] << (64 - bitPos)
			value += int((lowBits | highBits) & mask)
		} else {
			value += int(lowBits & mask)
		}
	}
	digits[nbChunks-1] = value

	return digits
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

// partitionScalars recodes multiple scalars in parallel
func partitionScalars(scalars []fr.Element, c uint64, nbTasks int) []uint16 {
	if nbTasks > runtime.NumCPU() {
		nbTasks = runtime.NumCPU()
	}

	nbChunks := (fr.Bits + c - 1) / c
	result := make([]uint16, len(scalars)*int(nbChunks))

	Execute(len(scalars), func(start, end int) {
		for i := start; i < end; i++ {
			if scalars[i].IsZero() {
				continue
			}

			// Recode this scalar
			scalar := scalars[i].Bits()
			digits := recodeScalar(scalar, c, nbChunks)

			// Convert recoded digits to uint16 format:
			// - Positive digits: (value << 1)
			// - Negative digits: ((-value) << 1) | 1
			for j := uint64(0); j < nbChunks; j++ {
				if digits[j] == 0 {
					continue
				}

				var bits uint16
				if digits[j] > 0 {
					bits = uint16(digits[j]) << 1
				} else {
					bits = (uint16(-digits[j]) << 1) | 1
				}
				result[int(j)*len(scalars)+i] = bits
			}
		}
	}, nbTasks)

	return result
}

func Execute(nbIterations int, work func(int, int), maxCpus ...int) {

	nbTasks := runtime.NumCPU()
	if len(maxCpus) == 1 {
		nbTasks = maxCpus[0]
		if nbTasks < 1 {
			nbTasks = 1
		} else if nbTasks > 512 {
			nbTasks = 512
		}
	}

	if nbTasks == 1 {
		// no go routines
		work(0, nbIterations)
		return
	}

	nbIterationsPerCpus := nbIterations / nbTasks

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	extraTasks := nbIterations - (nbTasks * nbIterationsPerCpus)
	extraTasksOffset := 0

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		go func() {
			work(_start, _end)
			wg.Done()
		}()
	}

	wg.Wait()
}
