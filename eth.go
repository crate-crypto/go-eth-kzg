package api

// This file has been copied and modified from go-kzg. The original author is
// Roberto Bayardo.
// TODO: This file will eventually be moved entirely into the clients and is here
// TODO: so that the integration to gnark-kzg is easier.
import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const (
	BlobCommitmentVersionKZG uint8 = 0x01
	FieldElementsPerBlob     int   = 4096
)

type VersionedHash [32]byte
type Root [32]byte
type Slot uint64

type BlobsSidecar struct {
	BeaconBlockRoot    Root
	BeaconBlockSlot    Slot
	Blobs              []Blob
	KZGAggregatedProof KZGProof
}

const (
	BlobTxType                = 5
	PrecompileInputLength     = 192
	BlobVersionedHashesOffset = 258 // position of blob_versioned_hashes offset in a serialized blob tx, see TxPeekBlobVersionedHashes
)

var (
	errInvalidInputLength = errors.New("invalid input length")
)

// The value that gets returned when the `verify_kzg_proof“ precompile is called
var precompileReturnValue [64]byte

// The context object stores all of the necessary configurations
// to allow one to create and verify blob proofs
var crypto_ctx Context

func init() {
	// Initialise using `1337` as the trusted secret.
	// We eventually want to load it from a JSON file
	crypto_ctx = *NewContextInsecure(1337)

	// Initialise the precompile return value
	new(big.Int).SetUint64(FIELD_ELEMENTS_PER_BLOB).FillBytes(precompileReturnValue[:32])
	copy(MODULUS[:], precompileReturnValue[32:])
}

// PointEvaluationPrecompile implements point_evaluation_precompile from EIP-4844
func PointEvaluationPrecompile(input []byte) ([]byte, error) {
	if len(input) != PrecompileInputLength {
		return nil, errInvalidInputLength
	}
	// versioned hash: first 32 bytes
	var versionedHash [32]byte
	copy(versionedHash[:], input[:32])

	var x, y [32]byte
	// Evaluation point: next 32 bytes
	copy(x[:], input[32:64])
	// Expected output: next 32 bytes
	copy(y[:], input[64:96])

	// input kzg point: next 48 bytes
	var dataKZG [48]byte
	copy(dataKZG[:], input[96:144])
	if KZGToVersionedHash(KZGCommitment(dataKZG)) != VersionedHash(versionedHash) {
		return nil, errors.New("mismatched versioned hash")
	}

	// Quotient kzg: next 48 bytes
	var quotientKZG [48]byte
	copy(quotientKZG[:], input[144:PrecompileInputLength])

	err := crypto_ctx.VerifyKZGProof(dataKZG, quotientKZG, x, y)
	if err != nil {
		return nil, fmt.Errorf("verify_kzg_proof error: %v", err)
	}

	result := precompileReturnValue // copy the value
	return result[:], nil
}

// ValidateBlobsSidecar implements validate_blobs_sidecar from the EIP-4844 consensus spec:
// https://github.com/roberto-bayardo/consensus-specs/blob/dev/specs/eip4844/beacon-chain.md#validate_blobs_sidecar
func ValidateBlobsSidecar(slot Slot, beaconBlockRoot Root, expectedKZGCommitments []KZGCommitment, blobsSidecar BlobsSidecar) error {
	if slot != blobsSidecar.BeaconBlockSlot {
		return fmt.Errorf(
			"slot doesn't match sidecar's beacon block slot (%v != %v)",
			slot, blobsSidecar.BeaconBlockSlot)
	}
	if beaconBlockRoot != blobsSidecar.BeaconBlockRoot {
		return errors.New("roots not equal")
	}
	blobs := blobsSidecar.Blobs
	if len(blobs) != len(expectedKZGCommitments) {
		return fmt.Errorf(
			"blob len doesn't match expected kzg commitments len (%v != %v)",
			len(blobs), len(expectedKZGCommitments))
	}
	err := crypto_ctx.VerifyAggregateKZGProof(blobs, blobsSidecar.KZGAggregatedProof, expectedKZGCommitments)
	if err != nil {
		return fmt.Errorf("verify_aggregate_kzg_proof error: %v", err)
	}

	return nil
}

// TxPeekBlobVersionedHashes implements tx_peek_blob_versioned_hashes from EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/beacon-chain.md#tx_peek_blob_versioned_hashes
//
// Format of the blob tx relevant to this function is as follows:
//
//		0: type (value should always be BlobTxType)
//		1: message offset: 4 bytes
//		5: ECDSA signature: 65 bytes
//		70: start of "message": 192 bytes
//			70: chain_id: 32 bytes
//			102: nonce: 8 bytes
//			110: priority_fee_per_gas: 32 bytes
//			142: max_basefee_per_gas: 32 bytes
//			174: gas: 8 bytes
//			182: to: 4 bytes - offset (relative to "message")
//			186: value: 32 bytes
//			218: data: 4 bytes - offset (relative to "message")
//			222: access_list: 4 bytes - offset (relative to "message")
//			226: max_fee_per_data_gas: 32 bytes
//			258: blob_versioned_hashes: 4 bytes - offset (relative to "message")
//	     262: start of dynamic data of "message"
//
// This function does not fully verify the encoding of the provided tx, but will sanity-check the tx type,
// and will never panic on malformed inputs.
func TxPeekBlobVersionedHashes(tx []byte) ([]VersionedHash, error) {
	// we start our reader at the versioned hash offset within the serialized tx
	if len(tx) < BlobVersionedHashesOffset+4 {
		return nil, errors.New("blob tx invalid: too short")
	}
	if tx[0] != BlobTxType {
		return nil, errors.New("invalid blob tx type")
	}
	offset := uint64(binary.LittleEndian.Uint32(tx[BlobVersionedHashesOffset:BlobVersionedHashesOffset+4])) + 70
	if offset > uint64(len(tx)) {
		return nil, errors.New("offset to versioned hashes is out of bounds")
	}
	hashBytesLen := uint64(len(tx)) - offset
	if hashBytesLen%32 != 0 {
		return nil, errors.New("expected trailing data starting at versioned-hashes offset to be a multiple of 32 bytes")
	}
	hashes := make([]VersionedHash, hashBytesLen/32)
	for i := range hashes {
		copy(hashes[i][:], tx[offset:offset+32])
		offset += 32
	}
	return hashes, nil
}

// VerifyKZGCommitmentsAgainstTransactions implements verify_kzg_commitments_against_transactions
// from the EIP-4844 consensus spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/eip4844/beacon-chain.md#verify_kzg_commitments_against_transactions
func VerifyKZGCommitmentsAgainstTransactions(transactions [][]byte, kzgCommitments []KZGCommitment) error {
	var versionedHashes []VersionedHash
	for _, tx := range transactions {
		if tx[0] == BlobTxType {
			v, err := TxPeekBlobVersionedHashes(tx)
			if err != nil {
				return err
			}
			versionedHashes = append(versionedHashes, v...)
		}
	}
	if len(kzgCommitments) != len(versionedHashes) {
		return fmt.Errorf("invalid number of blob versioned hashes: %v vs %v", len(kzgCommitments), len(versionedHashes))
	}
	for i := 0; i < len(kzgCommitments); i++ {
		h := KZGToVersionedHash(kzgCommitments[i])
		if h != versionedHashes[i] {
			return errors.New("invalid version hashes vs kzg")
		}
	}
	return nil
}

// KZGToVersionedHash implements kzg_to_versioned_hash from EIP-4844
func KZGToVersionedHash(kzg KZGCommitment) VersionedHash {
	h := sha256.Sum256(kzg[:])
	h[0] = BlobCommitmentVersionKZG
	return VersionedHash(h)
}
