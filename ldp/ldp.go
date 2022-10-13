package ldp

import (
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

func GetCoinsFromRho(rho fr.Element) (c0, c1 int) {

	rhoB := rho.Text(2)
	l := len(rhoB)
	c0 = int(rhoB[l-1] - '0')
	c1 = int(rhoB[l-2] - '0')
	return
}

func RandomResponse(rho fr.Element, msg *big.Int) (res big.Int, c0, c1 int) {
	c0, c1 = GetCoinsFromRho(rho)

	if c0 == 0 {
		res = *msg
	} else {
		if c1 == 0 {
			res.SetInt64(int64(1))
		} else {
			res.SetInt64(int64(0))
		}
	}
	return
}
