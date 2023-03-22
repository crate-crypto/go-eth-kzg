// This code was copied from @jtraglia here: https://github.com/ethereum/c-kzg-4844/blob/599ae2fe2138e3085453b5424254e0a7c22b2ca3/bindings/go/main_test.go#L1

package api_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/crate-crypto/go-proto-danksharding-crypto/internal/kzg"
	"github.com/crate-crypto/go-proto-danksharding-crypto/serialization"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

var (
	testDir                      = "../tests"
	blobToKZGCommitmentTests     = filepath.Join(testDir, "blob_to_kzg_commitment/*/*/*")
	computeKZGProofTests         = filepath.Join(testDir, "compute_kzg_proof/*/*/*")
	computeBlobKZGProofTests     = filepath.Join(testDir, "compute_blob_kzg_proof/*/*/*")
	verifyKZGProofTests          = filepath.Join(testDir, "verify_kzg_proof/*/*/*")
	verifyBlobKZGProofTests      = filepath.Join(testDir, "verify_blob_kzg_proof/*/*/*")
	verifyBlobKZGProofBatchTests = filepath.Join(testDir, "verify_blob_kzg_proof_batch/*/*/*")
)

func TestBlobToKZGCommitment(t *testing.T) {
	type Test struct {
		Input struct {
			BlobHexStr string `yaml:"blob"`
		}
		CommitmentHexStr *string `yaml:"output"`
	}

	tests, err := filepath.Glob(blobToKZGCommitmentTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			if err != nil {
				t.Fail()
			}

			testCaseValid := test.CommitmentHexStr != nil

			blob, err := hexStrToBlob(test.Input.BlobHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			gotSerializedCommitment, err := ctx.BlobToKZGCommitment(blob)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}
			assertTestCaseValid(t, testCaseValid)

			expectedCommitment, err := hexStrToG1Point(*test.CommitmentHexStr)
			if err != nil {
				t.Fatalf("unexpected error encountered")
			}
			if !bytes.Equal(gotSerializedCommitment[:], expectedCommitment[:]) {
				t.Fatalf("commitments are not the same")
			}
		})
	}
}

func TestComputeKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			BlobHexStr       string `yaml:"blob"`
			InputPointHexStr string `yaml:"z"`
		}
		ProofAndOutput *[2]string `yaml:"output"`
	}

	tests, err := filepath.Glob(computeKZGProofTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			testCaseValid := test.ProofAndOutput != nil

			blob, err := hexStrToBlob(test.Input.BlobHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			z, err := hexStrToScalar(test.Input.InputPointHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			proof, outputPoint, err := ctx.ComputeKZGProof(blob, z)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			// Test case is valid so lets check the output
			assertTestCaseValid(t, testCaseValid)

			expectedProof, err := hexStrToG1Point((test.ProofAndOutput)[0])
			if err != nil {
				panic(err)
			}
			expectedOutputPoint, err := hexStrToScalar((test.ProofAndOutput)[1])
			if err != nil {
				panic(err)
			}
			if !bytes.Equal(expectedProof[:], proof[:]) {
				t.Fatalf("proofs are different")
			}
			if !bytes.Equal(expectedOutputPoint[:], outputPoint[:]) {
				t.Fatalf("output points are different")
			}
		})
	}
}

func TestComputeBlobKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			BlobHexStr       string `yaml:"blob"`
			CommitmentHexStr string `yaml:"commitment"`
		}
		KZGProof *string `yaml:"output"`
	}

	tests, err := filepath.Glob(computeBlobKZGProofTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			testCaseValid := test.KZGProof != nil

			blob, err := hexStrToBlob(test.Input.BlobHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			commitment, err := hexStrToCommitment(test.Input.CommitmentHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			proof, err := ctx.ComputeBlobKZGProof(blob, commitment)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}
			assertTestCaseValid(t, testCaseValid)

			expectedProof, err := hexStrToG1Point(*test.KZGProof)
			if err != nil {
				panic(err)
			}

			if !bytes.Equal(proof[:], expectedProof[:]) {
				t.Fatalf("proofs are different")
			}
		})
	}
}

func TestVerifyKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			CommitmentHexStr  string `yaml:"commitment"`
			InputPointHexStr  string `yaml:"z"`
			OutputPointHexStr string `yaml:"y"`
			Proof             string `yaml:"proof"`
		}
		ProofIsValidPredicate *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyKZGProofTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			testCaseValid := test.ProofIsValidPredicate != nil

			commitment, err := hexStrToCommitment(test.Input.CommitmentHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			z, err := hexStrToScalar(test.Input.InputPointHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			y, err := hexStrToScalar(test.Input.OutputPointHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			proof, err := hexStrToCommitment(test.Input.Proof)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}
			err = ctx.VerifyKZGProof(serialization.KZGCommitment(commitment), serialization.KZGProof(proof), z, y)
			// Test specifically distinguish between the test failing
			// because of the pairing check and failing because of
			// validation errors

			if err != nil && !errors.Is(err, kzg.ErrVerifyOpeningProof) {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.ProofIsValidPredicate
				gotOutput := !errors.Is(err, kzg.ErrVerifyOpeningProof)
				if expectedOutput != gotOutput {
					t.Fatalf("unexpected output from verification algorithm")
				}
			}
		})
	}
}

func TestVerifyBlobKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			BlobHexStr       string `yaml:"blob"`
			CommitmentHexStr string `yaml:"commitment"`
			ProofHexStr      string `yaml:"proof"`
		}
		ProofIsValidPredicate *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyBlobKZGProofTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			testCaseValid := test.ProofIsValidPredicate != nil

			blob, err := hexStrToBlob(test.Input.BlobHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			commitment, err := hexStrToCommitment(test.Input.CommitmentHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}

			proof, err := hexStrToCommitment(test.Input.ProofHexStr)
			if err != nil {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
				return
			}
			err = ctx.VerifyBlobKZGProof(blob, commitment, serialization.KZGProof(proof))
			if err != nil && !errors.Is(err, kzg.ErrVerifyOpeningProof) {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.ProofIsValidPredicate
				gotOutput := !errors.Is(err, kzg.ErrVerifyOpeningProof)
				if expectedOutput != gotOutput {
					t.Fatalf("unexpected output from verification algorithm")
				}
			}
		})
	}
}

func TestVerifyBlobKZGProofBatch(t *testing.T) {
	type Test struct {
		Input struct {
			Blobs       []string `yaml:"blobs"`
			Commitments []string `yaml:"commitments"`
			Proofs      []string `yaml:"proofs"`
		}
		ProofIsValidPredicate *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyBlobKZGProofBatchTests)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)

			testCaseValid := test.ProofIsValidPredicate != nil

			var blobs []serialization.Blob
			for _, b := range test.Input.Blobs {
				blob, err := hexStrToBlob(b)
				if err != nil {
					if testCaseValid {
						t.Fatalf("unexpected error encountered")
					}
					return
				}
				blobs = append(blobs, blob)
			}

			var commitments []serialization.KZGCommitment
			for _, c := range test.Input.Commitments {
				commitment, err := hexStrToCommitment(c)
				if err != nil {
					if testCaseValid {
						t.Fatalf("unexpected error encountered")
					}
					return
				}
				commitments = append(commitments, commitment)
			}

			var proofs []serialization.KZGProof
			for _, p := range test.Input.Proofs {
				proof, err := hexStrToCommitment(p)
				if err != nil {
					if testCaseValid {
						t.Fatalf("unexpected error encountered")
					}
					return
				}
				proofs = append(proofs, serialization.KZGProof(proof))
			}
			err = ctx.VerifyBlobKZGProofBatch(blobs, commitments, proofs)
			errPar := ctx.VerifyBlobKZGProofBatchPar(blobs, commitments, proofs)

			if err != nil && err != kzg.ErrVerifyOpeningProof {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.ProofIsValidPredicate
				gotOutput := err != kzg.ErrVerifyOpeningProof
				if expectedOutput != gotOutput {
					t.Fatalf("unexpected output from verification algorithm")
				}
			}
			if errPar != nil && errPar != kzg.ErrVerifyOpeningProof {
				if testCaseValid {
					t.Fatalf("unexpected error encountered")
				}
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.ProofIsValidPredicate
				gotOutput := errPar != kzg.ErrVerifyOpeningProof
				if expectedOutput != gotOutput {
					t.Fatalf("unexpected output from verification algorithm")
				}
			}
		})
	}
}

func hexStrToBlob(hexStr string) (serialization.Blob, error) {
	var blob serialization.Blob
	byts, err := hexStrToBytes(hexStr)
	if err != nil {
		return blob, err
	}

	if len(blob) != len(byts) {
		return blob, fmt.Errorf("blob does not have the correct length, %d ", len(byts))
	}
	copy(blob[:], byts)
	return blob, nil
}
func hexStrToScalar(hexStr string) (serialization.Scalar, error) {
	var scalar serialization.Scalar
	byts, err := hexStrToBytes(hexStr)
	if err != nil {
		return scalar, err
	}

	if len(scalar) != len(byts) {
		return scalar, fmt.Errorf("scalar does not have the correct length, %d ", len(byts))
	}
	copy(scalar[:], byts)
	return scalar, nil
}
func hexStrToCommitment(hexStr string) (serialization.KZGCommitment, error) {
	return hexStrToG1Point(hexStr)
}
func hexStrToG1Point(hexStr string) (serialization.G1Point, error) {
	var point serialization.G1Point
	byts, err := hexStrToBytes(hexStr)
	if err != nil {
		return point, err
	}

	if len(point) != len(byts) {
		return point, fmt.Errorf("point does not have the correct length, %d ", len(byts))
	}
	copy(point[:], byts)
	return point, nil
}

func hexStrToBytes(hexStr string) ([]byte, error) {
	hexStr = trim0xPrefix(hexStr)
	return hex.DecodeString(hexStr)
}

func trim0xPrefix(hexString string) string {
	// Check that we are trimming off 0x
	if hexString[0:2] != "0x" {
		panic("hex string is not prefixed with 0x")
	}
	return hexString[2:]
}

func assertTestCaseValid(t *testing.T, testCaseValid bool) {
	if !testCaseValid {
		t.Fatalf("test case was invalid however no error has been emitted")
	}
}
