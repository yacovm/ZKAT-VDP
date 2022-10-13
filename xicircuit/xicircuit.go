package xicircuit

import (
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	eddsa "github.com/consensys/gnark/std/signature/eddsa"
)

type xiCircuit struct {
	curveID tedwards.ID
	Omega   []frontend.Variable
	CMOmega frontend.Variable `gnark:",public"`
	Nu1     frontend.Variable
	Nu2     frontend.Variable `gnark:",public"`

	AskList   []frontend.Variable
	SNOldList []frontend.Variable `gnark:",public"`

	// Variables needed for obtainRND
	XiUser           frontend.Variable
	CMXiUser         frontend.Variable
	XiCensus         frontend.Variable
	Xi               frontend.Variable
	CMXi             frontend.Variable `gnark:",public"`
	CensusSignedData frontend.Variable
	CensusPK         eddsa.PublicKey `gnark:",public"`
	CensusSignature  eddsa.Signature
}

func (circuit *xiCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	// Check that xi = Add(xiUser, xiRegulator)
	xiRes := api.Add(circuit.XiUser, circuit.XiCensus)
	api.AssertIsEqual(xiRes, circuit.Xi)

	// Check that cmXi = Commit(xi)
	err = Commit(api, circuit.Xi, circuit.CMXi)
	if err != nil {
		return err
	}

	// Check that cmXiUser = Commit(xiUser)
	err = Commit(api, circuit.XiUser, circuit.CMXiUser)
	if err != nil {
		return err
	}

	for i := 0; i < len(circuit.Omega); i++ {
		err := PRFSNOld(api, circuit.SNOldList[i], circuit.AskList[i], circuit.Omega[i])
		if err != nil {
			return err
		}
	}

	// Check that Nu1 = PRF(omega||1)
	err = PRFNu(api, circuit.Omega, circuit.Nu1, frontend.Variable(fr.NewElement(1)))
	if err != nil {
		return err
	}

	// Check that Nu1 = PRF(omega||2)
	err = PRFNu(api, circuit.Omega, circuit.Nu2, frontend.Variable(fr.NewElement(2)))

	// Check that CMomega = Commit(omega)
	mimcCMOmega, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimcCMOmega.Write(circuit.Omega[:]...)
	cmOmega := mimcCMOmega.Sum()
	api.AssertIsEqual(cmOmega, circuit.CMOmega)

	// Hash(cm_u||nu_1||xi_R)
	hfunc, err2 := mimc.NewMiMC(api)
	if err2 != nil {
		return err2
	}
	hfunc.Write(circuit.CMXiUser, circuit.Nu1, circuit.XiCensus)
	signData := hfunc.Sum()

	api.AssertIsEqual(signData, circuit.CensusSignedData)

	// Verify sign_R
	mimcSign, err3 := mimc.NewMiMC(api)
	if err3 != nil {
		return err3
	}
	err3 = eddsa.Verify(curve, circuit.CensusSignature, circuit.CensusSignedData, circuit.CensusPK, &mimcSign)
	if err3 != nil {
		return err3
	}

	return nil
}

func Commit(api frontend.API, data frontend.Variable, cmData frontend.Variable) error {

	hfunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hfunc.Write(data)
	result := hfunc.Sum()

	api.AssertIsEqual(result, cmData)

	return nil
}

func PRFSNOld(api frontend.API, snOld, sk, rho frontend.Variable) error {

	// Compute H(sk||01||rho)
	hfunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hfunc.Write(sk)
	hfunc.Write(frontend.Variable([]byte{0b0, 0b1}))
	hfunc.Write(rho)
	result := hfunc.Sum()

	// Check SN_old = H(sk||01||rho)
	api.AssertIsEqual(result, snOld)
	return nil
}

func PRFNu(api frontend.API, omega []frontend.Variable, nu, i frontend.Variable) error {

	mimcNu1, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimcNu1.Write(omega[:]...)
	mimcNu1.Write(i)
	result := mimcNu1.Sum()
	api.AssertIsEqual(result, nu)

	return nil
}
