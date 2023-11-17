package recrypt

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"walk-client/curve"
)

func TestFuck(t *testing.T) {
	a, _ := new(big.Int).SetString(string("113601389569471409244240450974267137733159501559511414116776140760974085226955"), 10)
	b, _ := new(big.Int).SetString(string("107137165172102906021212508267030648306855218160902600943224873973501008565947"), 10)
	c, _ := new(big.Int).SetString(string("40860382230733015526996509030022831214578018002752685215151193437984241444022"), 10)
	d := &ecdsa.PublicKey{
		X: a,
		Y: b,
	}
	curve.PointScalarMul(d, c)
}
