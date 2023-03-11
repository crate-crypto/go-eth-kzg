package serialization

import "errors"

var ErrNonCanonicalScalar = errors.New("scalar is not canonical when interpreted as a big integer in little-endian")
