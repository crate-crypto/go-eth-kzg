package context

import (
	"bytes"
	"errors"
)

// Alternative API that may make it easier for clients to do less work

func (c *Context) ComputeAggregateKzgProofAlt(serPolysFlat []byte, poly_size uint) (KZGProof, SerialisedCommitments, error) {
	polys, err := deserialisePolyFlatBytes(serPolysFlat, poly_size)
	if err != nil {
		return KZGProof{}, nil, err
	}

	return c.ComputeAggregateKzgProof(polys)
}

func (c *Context) VerifyAggregateKzgProofAlt(serPolysFlat []byte, poly_size uint, serProof KZGProof, serCommsFlat []byte) error {
	polys, err := deserialisePolyFlatBytes(serPolysFlat, poly_size)
	if err != nil {
		return err
	}

	comms, err := deserialiseCommsFlatBytes(serCommsFlat)
	if err != nil {
		return err
	}
	return c.VerifyAggregateKzgProof(polys, serProof, comms)

}

func deserialisePolyFlatBytes(serPolysFlat []byte, polySize uint) ([]SerialisedPoly, error) {
	// 1. Check that byte vector is a multiple of 32
	//
	// Since each polynomial coefficient is 32 bytes
	// We expect the number of bytes to be a multiple of 32
	numBytes := len(serPolysFlat)
	if numBytes%32 != 0 {
		return nil, errors.New("polynomial byte vector is not a multiple of 32")
	}

	// 2a. Compute how many polynomials we have
	numCoeffs := numBytes / 32
	numPolys := numCoeffs / int(polySize)

	// 2b. Check that poly_size parameter was correct
	// by checking for rounding
	derivedNumBytes := numPolys * int(polySize) * 32
	if derivedNumBytes != numBytes {
		errors.New("polynomial size parameter is incorrect")
	}

	//3. Deserialise flat byte vector into a vector of polynomials
	polys := make([]SerialisedPoly, numPolys)
	reader := bytes.NewReader(serPolysFlat)
	for i := 0; i < numPolys; i++ {
		poly, err := readPolynomial(reader, polySize)
		if err != nil {
			return nil, err
		}
		polys[i] = poly
	}

	return polys, nil
}

func deserialiseCommsFlatBytes(serCommsFlat []byte) (SerialisedCommitments, error) {
	// Flat bytes should be a multiple of 48

	numBytes := len(serCommsFlat)
	if numBytes%48 != 0 {
		return nil, errors.New("commitment byte vector is not a multiple of 48")
	}

	reader := bytes.NewReader(serCommsFlat)

	numComms := numBytes / 48

	comms := make(SerialisedCommitments, numComms)
	for i := 0; i < numComms; i++ {
		comm, err := readComm(reader)
		if err != nil {
			return nil, err
		}
		comms[i] = comm
	}

	return comms, nil
}

func readN(reader *bytes.Reader, n uint) ([]byte, error) {
	buf := make([]byte, n)
	_, err := reader.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
func readPolynomial(reader *bytes.Reader, poly_size uint) (SerialisedPoly, error) {
	serPoly := SerialisedPoly{}
	for i := uint(0); i < poly_size; i++ {
		coeff, err := readN(reader, 32)
		if err != nil {
			return SerialisedPoly{}, err
		}
		serPoly[i] = coeff
	}
	return serPoly, nil
}
func readComm(reader *bytes.Reader) (SerialisedG1Point, error) {

	coeff, err := readN(reader, 48)
	if err != nil {
		return SerialisedG1Point{}, err
	}

	return coeff, nil
}
