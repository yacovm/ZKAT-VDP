package deltacircuit

import (
	//"crypto/subtle"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/math/bits"
	eddsa "github.com/consensys/gnark/std/signature/eddsa"

	"github.com/consensys/gnark/std/hash/mimc"
)

type Point struct {
	X, Y frontend.Variable
}

type deltaCircuit struct {

	// Random value agreed upon with the census
	Coin0 frontend.Variable
	Coin1 frontend.Variable
	Xi    frontend.Variable
	CMXi  frontend.Variable `gnark:",public"`

	// private value hidden by LDP
	ID     frontend.Variable
	LDPVal frontend.Variable
	Delta  Point `gnark:",public"` // Delta = Encrypt(LDP(ID,Xi))

	curveID tedwards.ID

	// Variables used for the elgamal encryption
	RNDscalar frontend.Variable
	CensusPK  eddsa.PublicKey `gnark:",public"` // Public key of the census

	ApkList               []frontend.Variable
	RegAuthorityPK        eddsa.PublicKey `gnark:",public"`
	RegAuthoritySignature eddsa.Signature
}

// Define declares the circuit logic. The compiler then produces a list of constraints
// which must be satisfied (valid witness) in order to create a valid zk-SNARK
func (circuit *deltaCircuit) Define(api frontend.API) error {

	// Create the encryption circuit
	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	hfunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hfunc.Write(circuit.Xi)
	result := hfunc.Sum()

	api.AssertIsEqual(result, circuit.CMXi)

	ldpval, _ := LDP(api, circuit.Coin0, circuit.Coin1, circuit.Xi, circuit.ID)

	api.AssertIsEqual(ldpval, circuit.LDPVal)

	err = Encrypt(curve, circuit.RNDscalar, circuit.CensusPK, ldpval, circuit.Delta)
	if err != nil {
		return err
	}

	hfunc.Reset()
	hfunc.Write(circuit.ApkList[:]...)
	hfunc.Write(circuit.ID)
	signdata := hfunc.Sum()

	// Verify sign_R
	mimcSign, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	err = eddsa.Verify(curve, circuit.RegAuthoritySignature, signdata, circuit.RegAuthorityPK, &mimcSign)
	if err != nil {
		return err
	}

	return nil
}

func LDP(api frontend.API, coin0, coin1, xi, msg frontend.Variable) (frontend.Variable, error) {

	coins := bits.ToBinary(api, xi)
	api.AssertIsEqual(coins[0], coin0)
	api.AssertIsEqual(coins[1], coin1)

	// Create the LDP circuit
	c0 := api.IsZero(coins[0]) // Check first coin toss
	c1 := api.IsZero(coins[1]) // Check second coin toss

	ldp := api.Select(c0, msg, c1) // Calculate Random Response result

	return ldp, nil

}

// Encrypt creates the circuit matching the elgamal encryption
func Encrypt(curve twistededwards.Curve, r frontend.Variable, pubkey eddsa.PublicKey, msg frontend.Variable, delta Point) error {

	base := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	// project the message on to the curve
	M := curve.ScalarMul(base, msg)
	curve.AssertIsOnCurve(M)

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	//K := curve.ScalarMul(base, r) // K = r * Base - Public key

	S := curve.ScalarMul(pubkey.A, r) // S = r*A
	curve.AssertIsOnCurve(S)

	Cipher := curve.Add(S, M) // C = S + M

	curve.API().AssertIsEqual(Cipher.X, delta.X)
	curve.API().AssertIsEqual(Cipher.Y, delta.Y)

	return nil
}
