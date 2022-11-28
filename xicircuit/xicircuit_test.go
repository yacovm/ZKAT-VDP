package xicircuit

import (
	"blockchain_DP/hashfunctions"
	crand "crypto/rand"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
	Omega     []fr.Element
	AskList   []fr.Element
	SNOldList []fr.Element

	Nu1     []byte
	Nu2     []byte
	CMOmega []byte

	XiUser   fr.Element
	XiCensus fr.Element
	Xi       fr.Element
	CMXi     []byte
	CMXiUser []byte

	SignedData []byte

	CensusPK        signature.PublicKey
	CensusSignature []byte
}

func TestXiCircuit(t *testing.T) {
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

	var circuit xiCircuit
	circuit.curveID = tedwards.BN254
	circuit.Omega = make([]frontend.Variable, len(vals.Omega))
	circuit.AskList = make([]frontend.Variable, len(vals.AskList))
	circuit.SNOldList = make([]frontend.Variable, len(vals.SNOldList))

	// verification with the correct data
	var assignment xiCircuit

	assignment.Omega = make([]frontend.Variable, len(vals.Omega))
	for i := 0; i < len(vals.Omega); i++ {
		assignment.Omega[i] = vals.Omega[i]
	}

	assignment.AskList = make([]frontend.Variable, len(vals.AskList))
	for i := 0; i < len(vals.AskList); i++ {
		assignment.AskList[i] = vals.AskList[i]
	}

	assignment.SNOldList = make([]frontend.Variable, len(vals.SNOldList))
	for i := 0; i < len(vals.SNOldList); i++ {
		assignment.SNOldList[i] = vals.SNOldList[i]
	}

	assignment.Nu1 = vals.Nu1
	assignment.Nu2 = vals.Nu2
	assignment.CMOmega = vals.CMOmega

	assignment.XiUser = vals.XiUser.Marshal()
	assignment.XiCensus = vals.XiCensus.Marshal()
	assignment.Xi = vals.Xi
	assignment.CMXi = vals.CMXi
	assignment.CMXiUser = vals.CMXiUser

	assignment.CensusSignedData = vals.SignedData

	assignment.CensusPK.Assign(snarkCurve, vals.CensusPK.Bytes())
	assignment.CensusSignature.Assign(snarkCurve, vals.CensusSignature)

	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	t1 := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	timeS := time.Since(t1)

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
	timeP := time.Since(t1)

	t1 = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	timeV := time.Since(t1)

	return timeS, timeP, timeV
}

func setUpInputOutput(t *testing.T, numInputs int) InputOutput {

	assert := test.NewAssert(t)

	var vals InputOutput

	// generate values to sign
	_, err := vals.XiUser.SetRandom()
	assert.NoError(err, "Setting random value (xi_U)")

	// Creating commitment for xiUser using MiMC
	hfunc := hash.MIMC_BN254.New()
	hfunc.Write(vals.XiUser.Marshal())
	vals.CMXiUser = hfunc.Sum(nil)

	_, err = vals.XiCensus.SetRandom()
	assert.NoError(err, "Setting random value (xi_R)")

	vals.Xi.Add(&vals.XiUser, &vals.XiCensus)

	hfunc2 := hash.MIMC_BN254.New()
	hfunc2.Write(vals.Xi.Marshal())
	vals.CMXi = hfunc2.Sum(nil)

	//numInputs := 2

	vals.Omega = make([]fr.Element, numInputs)
	for i := 0; i < numInputs; i++ {
		var temp fr.Element
		_, err := temp.SetRandom()
		assert.NoError(err)
		vals.Omega[i].Set(&temp)
	}

	// Sort Omega in ascending order
	sort.Slice(vals.Omega, func(i, j int) bool {
		if vals.Omega[i].Cmp(&vals.Omega[j]) <= 0 {
			return true
		} else {
			return false
		}
	})

	vals.AskList = make([]fr.Element, numInputs)
	for i := 0; i < numInputs; i++ {
		var temp fr.Element
		_, err := temp.SetRandom()
		assert.NoError(err)
		vals.AskList[i].Set(&temp)
	}

	vals.SNOldList = make([]fr.Element, numInputs)
	for i := 0; i < numInputs; i++ {
		vals.SNOldList[i] = hashfunctions.PFRSN(vals.AskList[i], vals.Omega[i])
	}

	// Creating serial number Nu1
	vals.Nu1 = hashfunctions.PRFNu(vals.Omega, fr.NewElement(1))

	// Creating serial number Nu2
	vals.Nu2 = hashfunctions.PRFNu(vals.Omega, fr.NewElement(2))

	// Creating commitment over vals.Omega
	hCMomega := hash.MIMC_BN254.New()
	for i := 0; i < len(vals.Omega); i++ {
		hCMomega.Write(vals.Omega[i].Marshal())
	}
	vals.CMOmega = hCMomega.Sum(nil)

	hfunc3 := hash.MIMC_BN254.New()
	hfunc3.Write(vals.CMXiUser)
	hfunc3.Write(vals.Nu1)
	hfunc3.Write(vals.XiCensus.Marshal())
	vals.SignedData = hfunc3.Sum(nil)

	// generate parameters for the signatures
	privKey, err := eddsa.GenerateKey(crand.Reader)
	assert.NoError(err, "generating eddsa key pair")

	// generate signature
	vals.CensusSignature, err = privKey.Sign(vals.SignedData[:], hash.MIMC_BN254.New())
	assert.NoError(err, "signing message")

	// check if there is no problem in the signature
	vals.CensusPK = privKey.Public()
	checkSig, err := vals.CensusPK.Verify(vals.CensusSignature, vals.SignedData[:], hash.MIMC_BN254.New())
	assert.NoError(err, "verifying signature")
	assert.True(checkSig, "signature verification failed")

	return vals
}
