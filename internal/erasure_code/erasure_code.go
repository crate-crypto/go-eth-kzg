package erasure_code

import (
	"errors"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/crate-crypto/go-eth-kzg/internal/domain"
	"github.com/crate-crypto/go-eth-kzg/internal/poly"
	"github.com/crate-crypto/go-eth-kzg/internal/pool"
)

var errInvalidPoolBuffer = errors.New("invalid buffer from pool")

// BlockErasureIndex is used to indicate the index of the block erasure that is missing
// from the codeword.
type BlockErasureIndex = uint64

// recoveryBuffers holds preallocated buffers for FFT operations
type recoveryBuffers struct {
	zXEvalBuf          []fr.Element
	eZEvalBuf          []fr.Element
	dzPolyBuf          []fr.Element
	cosetZxEvalBuf     []fr.Element
	cosetDzEvalBuf     []fr.Element
	cosetQuotientBuf   []fr.Element
	polyCoeffResultBuf []fr.Element
}

// DataRecovery implements a unique decoding algorithm.
//
// The algorithm is not generic and is specific to the use-case where:
//   - We have block erasures. ie we do not lose data in random locations, but in contiguous chunks.
//     The chunks themselves are predetermined.
type DataRecovery struct {
	// rootsOfUnityBlockErasureIndex is a domain that corresponds to the number of blocks
	// that we can have in the codeword.
	rootsOfUnityBlockErasureIndex *domain.Domain
	domainExtended                *domain.Domain
	domainExtendedCoset           *domain.CosetDomain
	// blockErasureSize indicates the size of `blocks of evaluations` that
	// can be missing. For example, if blockErasureSize is 4, then 4 evaluations
	// can be missing, or 8 or 16.
	//
	// This is contrary to a general unique decoding algorithm where the number of
	// missing elements can be any number and the evaluations do not need to
	// be in blocks.
	blockErasureSize int
	// numScalarsInCodeword is the number of scalars in the codeword
	// ie the number of scalars we get when we get encode the data.
	numScalarsInCodeword int
	// numScalarsInDataWord is the number of scalars in the message
	// that we encode.
	numScalarsInDataWord int
	// expansionFactor is the factor by which the data word or message is expanded
	expansionFactor int
	// totalNumBlocks is the total number of blocks(groups of evaluations) in the codeword
	totalNumBlocks int

	// Thread-safe buffer pool for FFT operations
	bufferPool sync.Pool
}

func NewDataRecovery(blockErasureSize, numScalarsInDataWord, expansionFactor int) *DataRecovery {
	// Compute the number of scalars that will be in the codeword
	numScalarsInCodeword := numScalarsInDataWord * expansionFactor

	// Compute the total number of blocks that we will need to
	// represent the codeword
	totalNumBlocks := numScalarsInCodeword / blockErasureSize

	rootsOfUnityBlockErasureIndex := domain.NewDomain(uint64(totalNumBlocks))
	domainExtended := domain.NewDomain(uint64(numScalarsInCodeword))

	fftCoset := domain.FFTCoset{}
	fftCoset.CosetGen = fr.NewElement(7)
	fftCoset.InvCosetGen.Inverse(&fftCoset.CosetGen)
	domainExtendedCoset := domain.NewCosetDomain(domainExtended, fftCoset)

	dr := &DataRecovery{
		rootsOfUnityBlockErasureIndex: rootsOfUnityBlockErasureIndex,
		domainExtended:                domainExtended,
		domainExtendedCoset:           domainExtendedCoset,
		blockErasureSize:              blockErasureSize,
		numScalarsInCodeword:          numScalarsInCodeword,
		numScalarsInDataWord:          numScalarsInDataWord,
		expansionFactor:               expansionFactor,
		totalNumBlocks:                totalNumBlocks,
	}

	// Initialize the buffer pool with a factory function
	dr.bufferPool = sync.Pool{
		New: func() any {
			return &recoveryBuffers{
				zXEvalBuf:          make([]fr.Element, numScalarsInCodeword),
				eZEvalBuf:          make([]fr.Element, numScalarsInCodeword),
				dzPolyBuf:          make([]fr.Element, numScalarsInCodeword),
				cosetZxEvalBuf:     make([]fr.Element, numScalarsInCodeword),
				cosetDzEvalBuf:     make([]fr.Element, numScalarsInCodeword),
				cosetQuotientBuf:   make([]fr.Element, numScalarsInCodeword),
				polyCoeffResultBuf: make([]fr.Element, numScalarsInCodeword),
			}
		},
	}

	return dr
}

// Note: These blockErasure indices should not be in bit reversed order
func (dr *DataRecovery) constructVanishingPolyOnIndices(missingBlockErasureIndices []BlockErasureIndex) []fr.Element {
	// Collect all of the roots that are associated with the missing block erasure indices
	missingBlockErasureIndexRoots := make([]fr.Element, len(missingBlockErasureIndices))
	for i, index := range missingBlockErasureIndices {
		missingBlockErasureIndexRoots[i] = dr.rootsOfUnityBlockErasureIndex.Roots[index]
	}

	shortZeroPoly := vanishingPolyCoeff(missingBlockErasureIndexRoots)

	zeroPolyCoeff := make([]fr.Element, dr.numScalarsInCodeword)
	for i, coeff := range shortZeroPoly {
		zeroPolyCoeff[i*dr.blockErasureSize] = coeff
	}

	return zeroPolyCoeff
}

// Encode the polynomial by evaluating it on the extended domain.
//
// Note: `polyCoeff` is mutated in-place, ie it should be seen as mutable reference.
func (dr *DataRecovery) Encode(polyCoeff []fr.Element) []fr.Element {
	// Pad to the correct length
	for i := len(polyCoeff); i < len(dr.domainExtended.Roots); i++ {
		polyCoeff = append(polyCoeff, fr.Element{})
	}
	dr.domainExtended.FftFr(polyCoeff)
	return polyCoeff
}

// NumBlocksNeededToReconstruct returns the number of blocks that are needed to reconstruct
// the original data word.
func (dr *DataRecovery) NumBlocksNeededToReconstruct() int {
	return dr.numScalarsInDataWord / dr.blockErasureSize
}

func (dr *DataRecovery) RecoverPolynomialCoefficients(data []fr.Element, missingIndices []BlockErasureIndex) ([]fr.Element, error) {
	zX := dr.constructVanishingPolyOnIndices(missingIndices)

	// Get buffers from pool (thread-safe)
	buf, err := pool.Get[*recoveryBuffers](&dr.bufferPool)
	if err != nil {
		return nil, err
	}
	defer pool.Put(&dr.bufferPool, buf)

	// Compute zX evaluations without mutating zX since we need zX later for a coset FFT
	//
	// Use pooled buffer for zXEval
	zXEval := buf.zXEvalBuf
	copy(zXEval, zX)
	dr.domainExtended.FftFr(zXEval)

	if len(zXEval) != len(data) {
		return nil, errors.New("length of data and zXEval should be equal")
	}

	// Use pooled buffer for eZEval
	eZEval := buf.eZEvalBuf
	for i := 0; i < len(data); i++ {
		eZEval[i].Mul(&data[i], &zXEval[i])
	}

	// Use pooled buffer for dzPoly
	dzPoly := buf.dzPolyBuf
	copy(dzPoly, eZEval)
	dr.domainExtended.IfftFr(dzPoly)

	// Use pooled buffers for coset FFTs
	cosetZxEval := buf.cosetZxEvalBuf
	copy(cosetZxEval, zX)
	dr.domainExtendedCoset.CosetFFtFr(cosetZxEval)

	cosetDzEval := buf.cosetDzEvalBuf
	copy(cosetDzEval, dzPoly)
	dr.domainExtendedCoset.CosetFFtFr(cosetDzEval)

	// Use pooled buffer for quotient
	cosetQuotientEval := buf.cosetQuotientBuf
	cosetZxEvalInv := fr.BatchInvert(cosetZxEval)

	for i := 0; i < len(cosetZxEvalInv); i++ {
		cosetQuotientEval[i].Mul(&cosetDzEval[i], &cosetZxEvalInv[i])
	}

	polyCoeff := buf.polyCoeffResultBuf
	copy(polyCoeff, cosetQuotientEval)
	dr.domainExtendedCoset.CosetIFFtFr(polyCoeff)

	// Copy result since we're returning the buffer to the pool
	result := make([]fr.Element, dr.numScalarsInDataWord)
	copy(result, polyCoeff[:dr.numScalarsInDataWord])

	return result, nil
}

// vanishingPolyCoeff returns the polynomial that has roots at the given points
func vanishingPolyCoeff(xs []fr.Element) poly.PolynomialCoeff {
	result := []fr.Element{fr.One()}

	for _, x := range xs {
		// This is to silence: G601: Implicit memory aliasing in for loop.
		x := x

		negX := fr.Element{}
		negX.Neg(&x)
		result = poly.PolyMul(result, []fr.Element{negX, fr.One()})
	}

	return result
}
