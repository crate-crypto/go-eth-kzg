package context

import (
	"bytes"
)

// Alternative API that may make it easier for clients to do less work

func (c *Context) ComputeAggregateKzgProofAlt(serPolys [][]byte, polySize uint) (KZGProof, SerialisedCommitments, error) {
	polys, err := deserialisePolysBytes(serPolys, polySize)
	if err != nil {
		return KZGProof{}, nil, err
	}

	return c.ComputeAggregateKzgProof(polys)
}

func (c *Context) VerifyAggregateKzgProofAlt(serPolysFlat [][]byte, polySize uint, serProof KZGProof, serCommsFlat [][]byte) error {
	polys, err := deserialisePolysBytes(serPolysFlat, polySize)
	if err != nil {
		return err
	}

	comms, err := deserialiseCommsBytes(serCommsFlat)
	if err != nil {
		return err
	}
	return c.VerifyAggregateKzgProof(polys, serProof, comms)

}

// polySize is the degree of the polynomial
func deserialisePolysBytes(serPolys [][]byte, polySize uint) ([]SerialisedPoly, error) {
	numPolys := len(serPolys)
	polys := make([]SerialisedPoly, numPolys)

	for i := 0; i < numPolys; i++ {

		reader := bytes.NewReader(serPolys[i])
		poly, err := readPolynomial(reader, polySize)
		if err != nil {
			return nil, err
		}
		polys[i] = poly
	}

	return polys, nil
}

func deserialiseCommsBytes(serComms [][]byte) (SerialisedCommitments, error) {
	numComms := len(serComms)

	comms := make(SerialisedCommitments, numComms)
	for i := 0; i < numComms; i++ {
		reader := bytes.NewReader(serComms[i])
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
	serPoly := make(SerialisedPoly, poly_size)
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

func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
