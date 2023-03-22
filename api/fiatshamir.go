package api

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/utils"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
)

// Domain Separator to identify the protocol
const DomSepProtocol = "FSBLOBVERIFY_V1_"

// [compute_challenge](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#compute_challenge)
func computeChallenge(blob serialization.Blob, commitment serialization.KZGCommitment) fr.Element {
	polyDegreeBytes := u64ToByteArray16(serialization.ScalarsPerBlob)
	data := append([]byte(DomSepProtocol), polyDegreeBytes...)
	data = append(data, blob[:]...)
	data = append(data, commitment[:]...)

	return hashToBLSField(data)
}

// [hash_to_bls_field](https://github.com/ethereum/consensus-specs/blob/3a2304981a3b820a22b518fe4859f4bba0ebc83b/specs/deneb/polynomial-commitments.md#hash_to_bls_field)
func hashToBLSField(data []byte) fr.Element {
	digest := sha256.Sum256(data)

	// Reverse the digest, so that we reduce the little-endian
	// representation
	utils.Reverse(digest[:])

	// Now interpret those bytes as a field element
	// If gnark had a SetBytesLE method, we would not need to reverse
	// the bytes
	var challenge fr.Element
	challenge.SetBytes(digest[:])

	return challenge
}

// Convert a u64 to a 16 byte slice in little endian format
func u64ToByteArray16(number uint64) []byte {
	bytes := make([]byte, 16)
	binary.LittleEndian.PutUint64(bytes, number)

	return bytes
}
