package deltacircuit

import (
	"blockchain_DP/elgamal"
	"blockchain_DP/ldp"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tedwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/test"
)

type InputOutput struct {
	// Random value agreed upon with the census
	Coin0 int
	Coin1 int
	Xi    fr.Element
	CMXi  []byte

	// private value hidden by LDP
	ID     *big.Int
	LDPVal big.Int
	Delta  tedwardsbn254.PointAffine

	curveID tedwards.ID

	// Variables used for the elgamal encryption
	RNDscalar *big.Int
	CensusPK  elgamal.PublicKey

	ApkList               []fr.Element
	RegAuthorityPK        signature.PublicKey
	RegAuthoritySignature []byte
}

func TestDeltaCircuit(t *testing.T) {
	for _, numInputs := range []int{
		1, 2, 4, 8, 16,
	} {
		var sumS time.Duration
		var sumP time.Duration
		var sumV time.Duration

		n := 100

		for i := 0; i < n; i++ {
			timeS, timeP, timeV := RunBenchmark(t, numInputs, i)
			sumS += timeS
			sumP += timeP
			sumV += timeV
		}

		fmt.Println(numInputs, "Avg. setup time:", sumS/time.Duration(n))
		fmt.Println(numInputs, "Avg. proof time:", sumP/time.Duration(n))
		fmt.Println(numInputs, "Avg. verification time:", sumV/time.Duration(n))
	}
}

func RunBenchmark(t *testing.T, numInputs int, iteration int) (time.Duration, time.Duration, time.Duration) {

	assert := test.NewAssert(t)

	snarkCurve, err := twistededwards.GetSnarkCurve(tedwards.BN254)
	assert.NoError(err)

	vals := setUpInputOutput(t, numInputs)

	var circuit deltaCircuit
	circuit.curveID = tedwards.BN254
	circuit.ApkList = make([]frontend.Variable, len(vals.ApkList))

	// verification with the correct Message
	var assignment deltaCircuit
	assignment.Coin0 = vals.Coin0
	assignment.Coin1 = vals.Coin1

	assignment.Xi = vals.Xi.Marshal()
	assignment.ID = vals.ID
	assignment.LDPVal = vals.LDPVal

	assignment.Delta.X = vals.Delta.X
	assignment.Delta.Y = vals.Delta.Y

	assignment.CMXi = vals.CMXi

	assignment.RNDscalar = vals.RNDscalar

	//public key bytes
	_publicKey := vals.CensusPK.A.Bytes()
	// assign public key values
	assignment.CensusPK.Assign(snarkCurve, _publicKey[:32])

	assignment.ApkList = make([]frontend.Variable, len(vals.ApkList))
	for i := 0; i < len(vals.ApkList); i++ {
		assignment.ApkList[i] = vals.ApkList[i]
	}

	assignment.RegAuthorityPK.Assign(snarkCurve, vals.RegAuthorityPK.Bytes())
	assignment.RegAuthoritySignature.Assign(snarkCurve, vals.RegAuthoritySignature)

	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	t1 := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	tSetUP := time.Since(t1)

	if iteration == 0 {
		fmt.Println("Total", ccs.GetNbConstraints(), "constraints")
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	t1 = time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}
	tProof := time.Since(t1)

	t1 = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	tVerify := time.Since(t1)

	return tSetUP, tProof, tVerify
}

func setUpInputOutput(t *testing.T, numInputs int) InputOutput {

	assert := test.NewAssert(t)

	var vals InputOutput
	params, err := twistededwards.GetCurveParams(tedwards.BN254)
	assert.NoError(err)

	_, err = vals.Xi.SetRandom()
	assert.NoError(err, "Setting random value (xi_C)")

	// running MiMC (Go)
	goMimc := hash.MIMC_BN254.New()
	goMimc.Write(vals.Xi.Marshal())
	vals.CMXi = goMimc.Sum(nil)

	vals.ID = big.NewInt(int64(1))
	vals.LDPVal, vals.Coin0, vals.Coin1 = ldp.RandomResponse(vals.Xi, vals.ID)

	// Calculate encrypt(delta)
	elgamal.MessageMapInit()

	// Create a public/private keypair
	privateKey, err := elgamal.GenerateKey(rand.Reader) // Alice's private key
	assert.NoError(err, "generating elgamal private key")
	vals.CensusPK = privateKey.PublicKey // Alice's public key

	vals.RNDscalar = elgamal.GenScalar(params.Order) // bob's random scalar

	// ElGamal-encrypt a message using the public key.
	//var K tedwardsbn254.PointAffine
	K, delta := elgamal.Encrypt(vals.CensusPK, vals.RNDscalar, &vals.LDPVal)
	vals.Delta.X = delta.X
	vals.Delta.Y = delta.Y

	// Decrypt it using the corresponding private key.
	mm := elgamal.Decrypt(*privateKey, K, vals.Delta)
	assert.Equal(mm, vals.LDPVal, "Decryption succeeded")

	vals.ApkList = make([]fr.Element, numInputs)

	hfunc := hash.MIMC_BN254.New()
	for i := 0; i < numInputs; i++ {
		// Compute a_sk
		var aSK, zero, apkElement fr.Element
		_, err = aSK.SetRandom()
		assert.NoError(err, "Setting random value (xi_C)")

		// Compute a_pk
		zero.SetZero()
		hfunc.Reset()
		hfunc.Write(aSK.Marshal())
		hfunc.Write(zero.Marshal())
		apk := hfunc.Sum(nil)
		vals.ApkList[i].Set(apkElement.SetBytes(apk))
	}

	// Sign and Verify "a_pk||id"
	privKey, err := eddsa.GenerateKey(rand.Reader)
	assert.NoError(err, "generating eddsa key pair")

	hfunc.Reset()
	for i := 0; i < numInputs; i++ {
		hfunc.Write(vals.ApkList[i].Marshal())
	}
	hfunc.Write(vals.ID.Bytes())
	signData := hfunc.Sum(nil)

	// generate signature
	vals.RegAuthoritySignature, err = privKey.Sign(signData[:], hash.MIMC_BN254.New())
	assert.NoError(err, "signing message")

	// check if there is no problem with the signature
	vals.RegAuthorityPK = privKey.Public()
	checkSig, err := vals.RegAuthorityPK.Verify(vals.RegAuthoritySignature, signData[:], hash.MIMC_BN254.New())
	assert.NoError(err, "verifying signature")
	assert.True(checkSig, "signature verification failed")

	return vals
}
