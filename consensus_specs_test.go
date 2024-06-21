// This code was copied from @jtraglia here: https://github.com/ethereum/c-kzg-4844/blob/599ae2fe2138e3085453b5424254e0a7c22b2ca3/bindings/go/main_test.go#L1

package goethkzg_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	goethkzg "github.com/crate-crypto/go-eth-kzg"
	"github.com/crate-crypto/go-eth-kzg/internal/kzg"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

var (
	testDir                       = "tests"
	blobToKZGCommitmentTests      = filepath.Join(testDir, "blob_to_kzg_commitment/*/*/*")
	computeKZGProofTests          = filepath.Join(testDir, "compute_kzg_proof/*/*/*")
	computeBlobKZGProofTests      = filepath.Join(testDir, "compute_blob_kzg_proof/*/*/*")
	verifyKZGProofTests           = filepath.Join(testDir, "verify_kzg_proof/*/*/*")
	verifyBlobKZGProofTests       = filepath.Join(testDir, "verify_blob_kzg_proof/*/*/*")
	verifyBlobKZGProofBatchTests  = filepath.Join(testDir, "verify_blob_kzg_proof_batch/*/*/*")
	computeCellsAndKZGProofsTests = filepath.Join(testDir, "compute_cells_and_kzg_proofs/*/*/*")
	verifyCellKZGProofTests       = filepath.Join(testDir, "verify_cell_kzg_proof/*/*/*")
	verifyCellKZGProofBatchTests  = filepath.Join(testDir, "verify_cell_kzg_proof_batch/*/*/*")
)

func TestBlobToKZGCommitment(t *testing.T) {
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
		}
		Commitment *string `yaml:"output"`
	}

	tests, err := filepath.Glob(blobToKZGCommitmentTests)
	require.True(t, len(tests) > 0)

	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, err)
			testCaseValid := test.Commitment != nil

			blob, err := hexStrToBlob(test.Input.Blob)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			gotCommitment, err := ctx.BlobToKZGCommitment(blob, NumGoRoutines)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			require.True(t, testCaseValid)
			expectedCommitment, err := hexStrToCommitment(*test.Commitment)
			require.NoError(t, err)
			require.Equal(t, expectedCommitment, gotCommitment)
		})
	}
}

func TestComputeKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			InputPoint string `yaml:"z"`
		}
		ProofAndOutputPoint *[2]string `yaml:"output"`
	}

	tests, err := filepath.Glob(computeKZGProofTests)
	require.True(t, len(tests) > 0)
	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.ProofAndOutputPoint != nil

			blob, err := hexStrToBlob(test.Input.Blob)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			inputPoint, err := hexStrToScalar(test.Input.InputPoint)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			proof, outputPoint, err := ctx.ComputeKZGProof(blob, inputPoint, NumGoRoutines)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			require.True(t, testCaseValid)
			expectedProof, err := hexStrToProof(test.ProofAndOutputPoint[0])
			require.NoError(t, err)
			expectedOutputPoint, err := hexStrToScalar(test.ProofAndOutputPoint[1])
			require.NoError(t, err)
			require.Equal(t, expectedProof, proof)
			require.Equal(t, expectedOutputPoint, outputPoint)
		})
	}
}

func TestComputeBlobKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			Commitment string `yaml:"commitment"`
		}
		Proof *string `yaml:"output"`
	}

	tests, err := filepath.Glob(computeBlobKZGProofTests)
	require.True(t, len(tests) > 0)

	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.Proof != nil

			blob, err := hexStrToBlob(test.Input.Blob)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			commitment, err := hexStrToCommitment(test.Input.Commitment)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			proof, err := ctx.ComputeBlobKZGProof(blob, commitment, NumGoRoutines)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			require.True(t, testCaseValid)
			expectedProof, err := hexStrToProof(*test.Proof)
			require.NoError(t, err)
			require.Equal(t, expectedProof, proof)
		})
	}
}

func TestVerifyKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Commitment  string `yaml:"commitment"`
			InputPoint  string `yaml:"z"`
			OutputPoint string `yaml:"y"`
			Proof       string `yaml:"proof"`
		}
		ProofIsValid *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyKZGProofTests)
	require.True(t, len(tests) > 0)

	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.ProofIsValid != nil

			commitment, err := hexStrToCommitment(test.Input.Commitment)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			inputPoint, err := hexStrToScalar(test.Input.InputPoint)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			outputPoint, err := hexStrToScalar(test.Input.OutputPoint)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			proof, err := hexStrToProof(test.Input.Proof)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			err = ctx.VerifyKZGProof(commitment, inputPoint, outputPoint, proof)

			// Test specifically distinguish between the test failing
			// because of the pairing check and failing because of
			// validation errors
			if err != nil && !errors.Is(err, kzg.ErrVerifyOpeningProof) {
				require.False(t, testCaseValid)
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.ProofIsValid
				gotOutput := !errors.Is(err, kzg.ErrVerifyOpeningProof)
				require.Equal(t, expectedOutput, gotOutput)
			}
		})
	}
}

func TestVerifyBlobKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Blob       string `yaml:"blob"`
			Commitment string `yaml:"commitment"`
			Proof      string `yaml:"proof"`
		}
		ProofIsValid *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyBlobKZGProofTests)
	require.True(t, len(tests) > 0)

	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.ProofIsValid != nil

			blob, err := hexStrToBlob(test.Input.Blob)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			commitment, err := hexStrToCommitment(test.Input.Commitment)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			proof, err := hexStrToProof(test.Input.Proof)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			err = ctx.VerifyBlobKZGProof(blob, commitment, proof)

			// Test specifically distinguish between the test failing
			// because of the pairing check and failing because of
			// validation errors
			if err != nil && !errors.Is(err, kzg.ErrVerifyOpeningProof) {
				require.False(t, testCaseValid)
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.ProofIsValid
				gotOutput := !errors.Is(err, kzg.ErrVerifyOpeningProof)
				require.Equal(t, expectedOutput, gotOutput)
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
		ProofIsValid *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyBlobKZGProofBatchTests)
	require.True(t, len(tests) > 0)

	require.NoError(t, err)
	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.ProofIsValid != nil

			var blobs []goethkzg.Blob
			for _, b := range test.Input.Blobs {
				blob, err := hexStrToBlob(b)
				if err != nil {
					require.False(t, testCaseValid)
					return
				}
				blobs = append(blobs, *blob)
			}

			var commitments []goethkzg.KZGCommitment
			for _, c := range test.Input.Commitments {
				commitment, err := hexStrToCommitment(c)
				if err != nil {
					require.False(t, testCaseValid)
					return
				}
				commitments = append(commitments, commitment)
			}

			var proofs []goethkzg.KZGProof
			for _, p := range test.Input.Proofs {
				proof, err := hexStrToProof(p)
				if err != nil {
					require.False(t, testCaseValid)
					return
				}
				proofs = append(proofs, proof)
			}

			err = ctx.VerifyBlobKZGProofBatch(blobs, commitments, proofs)
			errPar := ctx.VerifyBlobKZGProofBatchPar(blobs, commitments, proofs)
			require.Equal(t, err, errPar)

			// Test specifically distinguish between the test failing
			// because of the pairing check and failing because of
			// validation errors
			if err != nil && err != kzg.ErrVerifyOpeningProof {
				require.False(t, testCaseValid)
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.ProofIsValid
				gotOutput := err != kzg.ErrVerifyOpeningProof
				require.Equal(t, expectedOutput, gotOutput)
			}
		})
	}
}

func TestComputeCellsAndKZGProofs(t *testing.T) {
	type Test struct {
		Input struct {
			Blob string `yaml:"blob"`
		}
		Output *[][]string `yaml:"output"`
	}

	tests, err := filepath.Glob(computeCellsAndKZGProofsTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, err)
			testCaseValid := test.Output != nil

			blob, err := hexStrToBlob(test.Input.Blob)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			cells, proofs, err := ctx.ComputeCellsAndKZGProofs(blob, 0)

			if err == nil {
				expectedCellStrs := (*test.Output)[0]
				expectedCells, err := hexStrArrToCells(expectedCellStrs)
				require.NoError(t, err)
				require.Equal(t, expectedCells, cells[:])

				expectedProofStrs := (*test.Output)[1]
				expectedProofs, err := HexStrArrToProofs(expectedProofStrs)
				require.NoError(t, err)
				require.Equal(t, expectedProofs, proofs[:])
			} else {
				require.Nil(t, test.Output)
			}
		})
	}
}

func TestVerifyCellKZGProof(t *testing.T) {
	type Test struct {
		Input struct {
			Commitment string `yaml:"commitment"`
			CellId     uint64 `yaml:"cell_id"`
			Cell       string `yaml:"cell"`
			Proof      string `yaml:"proof"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyCellKZGProofTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.Output != nil

			commitment, err := hexStrToCommitment(test.Input.Commitment)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			cellId := test.Input.CellId

			cell, err := hexStrToCell(test.Input.Cell)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			proof, err := hexStrToProof(test.Input.Proof)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			err = ctx.VerifyCellKZGProof(commitment, cellId, cell, proof)
			// Test specifically distinguish between the test failing
			// because of the pairing check and failing because of
			// validation errors on the input
			if err != nil && !errors.Is(err, kzg.ErrVerifyOpeningProof) {
				require.False(t, testCaseValid)
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.Output
				gotOutput := !errors.Is(err, kzg.ErrVerifyOpeningProof)
				require.Equal(t, expectedOutput, gotOutput)
			}
		})
	}
}

func TestVerifyCellKZGProofBatch(t *testing.T) {
	type Test struct {
		Input struct {
			RowCommitments []string `yaml:"row_commitments"`
			RowIndices     []uint64 `yaml:"row_indices"`
			ColumnIndices  []uint64 `yaml:"column_indices"`
			Cells          []string `yaml:"cells"`
			Proofs         []string `yaml:"proofs"`
		}
		Output *bool `yaml:"output"`
	}

	tests, err := filepath.Glob(verifyCellKZGProofBatchTests)
	require.NoError(t, err)
	require.True(t, len(tests) > 0)

	for _, testPath := range tests {
		t.Run(testPath, func(t *testing.T) {
			testFile, err := os.Open(testPath)
			require.NoError(t, err)
			test := Test{}
			err = yaml.NewDecoder(testFile).Decode(&test)
			require.NoError(t, testFile.Close())
			require.NoError(t, err)
			testCaseValid := test.Output != nil

			rowCommitments, err := HexStrArrToCommitments(test.Input.RowCommitments)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}

			rowIndices := test.Input.RowIndices
			columnIndices := test.Input.ColumnIndices

			cells, err := hexStrArrToCells(test.Input.Cells)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			proofs, err := HexStrArrToProofs(test.Input.Proofs)
			if err != nil {
				require.False(t, testCaseValid)
				return
			}
			err = ctx.VerifyCellKZGProofBatch(rowCommitments, rowIndices, columnIndices, cells, proofs)
			// Test specifically distinguish between the test failing
			// because of the pairing check and failing because of
			// validation errors on the input
			if err != nil && !errors.Is(err, kzg.ErrVerifyOpeningProof) {
				require.False(t, testCaseValid)
			} else {
				// Either the error is nil or it is a verification error
				expectedOutput := *test.Output
				gotOutput := !errors.Is(err, kzg.ErrVerifyOpeningProof)
				require.Equal(t, expectedOutput, gotOutput)
			}
		})
	}
}

func hexStrToCell(hexStr string) (*goethkzg.Cell, error) {
	var cell goethkzg.Cell
	byts, err := hexStrToBytes(hexStr)
	if err != nil {
		return nil, err
	}

	if len(cell) != len(byts) {
		return nil, fmt.Errorf("cell does not have the correct length, %d ", len(byts))
	}
	copy(cell[:], byts)
	return &cell, nil
}

func hexStrArrToCells(hexStrs []string) ([]*goethkzg.Cell, error) {
	cells := make([]*goethkzg.Cell, len(hexStrs))

	for i, hexStr := range hexStrs {
		cell, err := hexStrToCell(hexStr)
		if err != nil {
			return nil, err
		}
		cells[i] = cell
	}

	return cells, nil
}

func HexStrArrToProofs(hexStrs []string) ([]goethkzg.KZGProof, error) {
	proofs := make([]goethkzg.KZGProof, len(hexStrs))

	for i, hexStr := range hexStrs {
		proof, err := hexStrToProof(hexStr)
		if err != nil {
			return nil, err
		}
		proofs[i] = proof
	}

	return proofs, nil
}

func HexStrArrToCommitments(hexStrs []string) ([]goethkzg.KZGCommitment, error) {
	commitments := make([]goethkzg.KZGCommitment, len(hexStrs))

	for i, hexStr := range hexStrs {
		commitment, err := hexStrToCommitment(hexStr)
		if err != nil {
			return nil, err
		}
		commitments[i] = commitment
	}

	return commitments, nil
}

func hexStrToBlob(hexStr string) (*goethkzg.Blob, error) {
	var blob goethkzg.Blob
	byts, err := hexStrToBytes(hexStr)
	if err != nil {
		return nil, err
	}

	if len(blob) != len(byts) {
		return nil, fmt.Errorf("blob does not have the correct length, %d ", len(byts))
	}
	copy(blob[:], byts)
	return &blob, nil
}

func hexStrToScalar(hexStr string) (goethkzg.Scalar, error) {
	var scalar goethkzg.Scalar
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

func hexStrToCommitment(hexStr string) (goethkzg.KZGCommitment, error) {
	point, err := hexStrToG1Point(hexStr)
	return goethkzg.KZGCommitment(point), err
}

func hexStrToProof(hexStr string) (goethkzg.KZGProof, error) {
	point, err := hexStrToG1Point(hexStr)
	return goethkzg.KZGProof(point), err
}

func hexStrToG1Point(hexStr string) (goethkzg.G1Point, error) {
	var point goethkzg.G1Point
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
