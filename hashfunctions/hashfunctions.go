package hashfunctions

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
)

// PFRZerocash computes the different PRF functions used by zerocash.
// x is the seed (256 bits). z is the input (256 bits).
// t is the type of the PRF we are using: 0 - PRF_addr, 1 - PRF_sn, 2 - PRF_pk
func PFRSN(x fr.Element, z fr.Element) (res fr.Element) {

	var c fr.Element
	c.SetBytes([]byte{0b0, 0b1})
	//z.FromMont()

	//fmt.Println(x.String(), "\n", c.String(), "\n", z.String())
	hfunc := hash.MIMC_BN254.New()
	hfunc.Write(x.Marshal())
	hfunc.Write(c.Marshal())
	hfunc.Write(z.Marshal())
	resB := hfunc.Sum(nil)

	res.SetBytes(resB)
	return res
}

func PRFNu(omega []fr.Element, i fr.Element) (nu []byte) {

	hNu1 := hash.MIMC_BN254.New()
	for i := 0; i < len(omega); i++ {
		hNu1.Write(omega[i].Marshal())
	}
	hNu1.Write(i.Marshal())
	nu = hNu1.Sum(nil)

	return nu
}
