package api

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialisation"
)

// Domain Separator to identify the protocol
const DOM_SEP_PROTOCOL = "FSBLOBVERIFY_V1_"

func computeChallenge(blob serialisation.Blob, commitment serialisation.Commitment) fr.Element {

	polyDegreeBytes := u64ToByteArray16(serialisation.SCALARS_PER_BLOB)
	data := append([]byte(DOM_SEP_PROTOCOL), polyDegreeBytes...)
	data = append(data, blob[:]...)
	data = append(data, commitment[:]...)

	digest := sha256.Sum256(data)

	// Reverse the digest, so that we reduce the little-endian
	// representation
	utils.ReverseSlice(digest[:])

	// Now interpret those bytes as a field element
	// If gnark had a SetBytesLE method, we would not need to reverse
	// the bytes
	var challenge fr.Element
	challenge.SetBytes(digest[:])

	return challenge
}

// Convert a u64 to a 16 byte slice
func u64ToByteArray16(number uint64) []byte {
	bytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(bytes, uint64(number))
	return bytes
}
