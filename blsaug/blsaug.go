package blsaug

import (
	chiabls "github.com/chuwt/chia-bls-go"
	"github.com/dashpay/tenderdash/internal/blscore"
	bls12381 "github.com/kilic/bls12-381"
)

var AugSchemeDst = blscore.DomainSeparationTag(
	"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
)

type AugSchemeMPL struct {
	// domainSeparationValue string
}

// Sign
func (asm *AugSchemeMPL) Sign(sk *chiabls.PrivateKey, message []byte) []byte {

	pk := sk.GetPublicKey()
	pkBytes := pk.Bytes()
	message = append(pkBytes, message...)
	sigPoint := blscore.SignMpl(sk, message, AugSchemeDst)
	sigBytes := bls12381.NewG2().ToCompressed(sigPoint)

	return sigBytes
}

// SignWithPrependPK
func (asm *AugSchemeMPL) SignWithPrependPK(sk *chiabls.PrivateKey, prependPK *chiabls.PublicKey, message []byte) []byte {

	pkBytes := prependPK.Bytes()
	message = append(pkBytes, message...)
	sigPoint := blscore.SignMpl(sk, message, AugSchemeDst)
	sigBytes := bls12381.NewG2().ToCompressed(sigPoint)

	return sigBytes
}

// Verify
func (asm *AugSchemeMPL) Verify(pk *chiabls.PublicKey, message []byte, sig []byte) bool {

	pkBytes := pk.Bytes()
	message = append(pkBytes, message...)
	verified := blscore.VerifyMpl(pk, message, sig, AugSchemeDst)

	return verified
}

// Aggregate
func (asm *AugSchemeMPL) Aggregate(signatures ...[]byte) ([]byte, error) {
	sigBytes, err := blscore.AggregateMpl(signatures...)

	return sigBytes, err
}

// AggregateVerify
func (asm *AugSchemeMPL) AggregateVerify(pksBytes [][]byte, messages [][]byte, sig []byte) bool {

	pkMessages := [][]byte{}
	for i, pkBytes := range pksBytes {
		message := messages[i]
		message = append(pkBytes, message...)
		pkMessages = append(pkMessages, message)
	}
	verified := blscore.AggregateVerify(pksBytes, pkMessages, sig, AugSchemeDst)

	return verified
}
