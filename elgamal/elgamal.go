package elgamal

import (
	"crypto/rand"
	"golang.org/x/crypto/blake2b"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

const (
	sizeFr = fr.Bytes
	//sizePublicKey  = sizeFr
	//sizeSignature  = 2 * sizeFr
	//sizePrivateKey = 2*sizeFr + 32
)

var MessageMap = make(map[twistededwards.PointAffine]big.Int)

// PublicKey eddsa signature object
// cf https://en.wikipedia.org/wiki/EdDSA for notation
type PublicKey struct {
	A twistededwards.PointAffine
}

// PrivateKey private key of an eddsa instance
type PrivateKey struct {
	PublicKey PublicKey    // copy of the associated public key
	scalar    [sizeFr]byte // secret scalar, in big Endian
	randSrc   [32]byte     // source
}

func MessageMapInit() {
	c := twistededwards.GetEdwardsCurve()
	for i := 1; i < 100; i++ {
		P := &twistededwards.PointAffine{}
		P.ScalarMul(&c.Base, big.NewInt(int64(i)))
		MessageMap[*P] = *big.NewInt(int64(i))
	}
}

// GenerateKey generates a public and private key pair.
func GenerateKey(r io.Reader) (*PrivateKey, error) {
	c := twistededwards.GetEdwardsCurve()

	var pub PublicKey
	var priv PrivateKey
	// hash(h) = private_key || random_source, on 32 bytes each
	seed := make([]byte, 32)
	_, err := r.Read(seed)
	if err != nil {
		return nil, err
	}
	h := blake2b.Sum512(seed[:])
	for i := 0; i < 32; i++ {
		priv.randSrc[i] = h[i+32]
	}

	// prune the key
	// https://tools.ietf.org/html/rfc8032#section-5.1.5, key generation
	h[0] &= 0xF8
	h[31] &= 0x7F
	h[31] |= 0x40

	// reverse first bytes because setBytes interpret stream as big endian
	// but in eddsa specs s is the first 32 bytes in little endian
	for i, j := 0, sizeFr-1; i < sizeFr; i, j = i+1, j-1 {
		priv.scalar[i] = h[j]
	}

	var bScalar big.Int
	bScalar.SetBytes(priv.scalar[:])
	pub.A.ScalarMul(&c.Base, &bScalar)

	priv.PublicKey = pub

	return &priv, nil
}

// GenScalar returns a random scalar <= p.Order
func GenScalar(order *big.Int) *big.Int {
	r, _ := rand.Int(rand.Reader, order)
	return r
}

// Encrypt encrypts a message based on elgamal encryption.
// pubkey is Alice's public key used for encrypting the message. r is random scalar Bob generates.
func Encrypt(pubkey PublicKey, r *big.Int, msg *big.Int) (K, Ciph twistededwards.PointAffine) {

	curve := twistededwards.GetEdwardsCurve()

	var M, S twistededwards.PointAffine

	//msgBig := big.NewInt(int64(message))
	M.ScalarMul(&curve.Base, msg)

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	K.ScalarMul(&curve.Base, r) // K = r * Base - Public key
	S.ScalarMul(&pubkey.A, r)   // S = k*A
	Ciph.Add(&S, &M)            // C = S + M

	return
}

// Decrypt decrypts cipher C using Alice's private key prive, and Bob's value K
func Decrypt(priv PrivateKey, K, C twistededwards.PointAffine) (msg big.Int) {

	var M, S twistededwards.PointAffine
	var bScalar big.Int
	bScalar.SetBytes(priv.scalar[:])

	// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
	S.ScalarMul(&K, &bScalar)
	S.Neg(&S)
	M.Add(&C, &S)

	msg = MessageMap[M]
	return
}
