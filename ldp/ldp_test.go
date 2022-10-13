package ldp

import (
	"fmt"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestLDP(t *testing.T) {
	assert := test.NewAssert(t)
	//c := twistededwards.GetEdwardsCurve()
	//rho := elgamal.GenScalar(&c.Order)

	var rho fr.Element
	_, err := rho.SetRandom()
	assert.NoError(err)
	c0, c1 := GetCoinsFromRho(rho)

	id := big.NewInt(int64(1))

	delta, _, _ := RandomResponse(rho, id)

	//fmt.Println("delta = ", delta.Text(2))

	if c0 == 0 {
		assert.Equal(id, &delta)
		fmt.Println("c0 == 0, print ID == ", delta)
	} else {
		if c1 == 0 {
			fmt.Println("c0 == 1, c1 == 0, print 1")
		} else {
			fmt.Println("c0 == 1, c1 == 1, print 0")
		}
	}

	// Output:
	// Decryption succeeded: 1
}
