package goethkzg

func (ctx *Context) RecoverCells(cellIDs []uint64, cells []*Cell, numGoroutines int) ([CellsPerExtBlob]*Cell, error) {
	polyCoeff, err := ctx.recoverPolynomialCoeffs(cellIDs, cells)
	if err != nil {
		return [CellsPerExtBlob]*Cell{}, err
	}

	return ctx.computeCellsFromPolyCoeff(polyCoeff, numGoroutines)
}
