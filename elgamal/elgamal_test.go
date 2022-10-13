package elgamal

import (
	"crypto/rand"
	"fmt"
	//"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"math/big"
)

func Example() {

	MessageMapInit()

	// Create a public/private keypair
	privateKey, _ := GenerateKey(rand.Reader) // Alice's private key
	publicKey := privateKey.PublicKey         // Alice's public key

	c := twistededwards.GetEdwardsCurve()
	r := GenScalar(&c.Order)
	//var r fr.Element
	//r.SetRandom()
	////fmt.Println("Scalar:", r)
	//var rInt big.Int
	//r.ToBigIntRegular(&rInt)

	// ElGamal-encrypt a message using the public key.
	m := big.NewInt(int64(45))
	K, C := Encrypt(publicKey, r, m)

	// Decrypt it using the corresponding private key.
	mm := Decrypt(*privateKey, K, C)

	// Make sure it worked!
	if mm.Cmp(m) != 0 {
		fmt.Println(fmt.Sprint("decryption produced wrong output: ", mm.Int64()))
	} else {
		fmt.Println(fmt.Sprint("Decryption succeeded: ", mm.Int64()))
	}

	// Output:
	// Decryption succeeded: 45
}
