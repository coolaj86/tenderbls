package blscore

import (
	"errors"

	chiabls "github.com/chuwt/chia-bls-go"
	bls12381 "github.com/kilic/bls12-381"
)

type DomainSeparationTag []byte

type SchemeMPL interface {
	Sign(sk *chiabls.PrivateKey, message []byte) []byte
	Verify(pk *chiabls.PublicKey, message []byte, sig []byte) bool
	Aggregate(signatures ...[]byte) ([]byte, error)
	AggregateVerify(pks [][]byte, messages [][]byte, sig []byte) (bool, error)
}

func SignMpl(sk *chiabls.PrivateKey, message, dst DomainSeparationTag) *bls12381.PointG2 {
	g2Map := bls12381.NewG2()

	r := g2Map.New()
	pq, _ := g2Map.HashToCurve(message, dst)
	ske := bls12381.NewFr().FromBytes(sk.Bytes())

	sigPoint := g2Map.MulScalar(r, pq, ske)

	return sigPoint
}

func VerifyMpl(pk *chiabls.PublicKey, message []byte, sig, dst []byte) bool {

	g2Map := bls12381.NewG2()
	q, _ := g2Map.HashToCurve(message, dst)

	signature, err := bls12381.NewG2().FromCompressed(sig)
	if err != nil {
		return false
	}

	engine := bls12381.NewEngine()

	g1Neg := new(bls12381.PointG1)
	g1Neg = bls12381.NewG1().Neg(g1Neg, chiabls.G1Generator())

	engine = engine.AddPair(pk.G1(), q)
	engine = engine.AddPair(g1Neg, signature)

	return engine.Check()
}

func AggregateMpl(signatures ...[]byte) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, errors.New("must aggregate at least 1 signature ")
	}

	newG2 := bls12381.NewG2()
	aggSig := newG2.New()

	for _, sig := range signatures {
		g2, err := bls12381.NewG2().FromCompressed(sig)
		if err != nil {
			return nil, err
		}
		aggSig = bls12381.NewG2().Add(newG2.New(), aggSig, g2)
	}

	return bls12381.NewG2().ToCompressed(aggSig), nil
}

func AggregateVerify(pks, messages [][]byte, sig, dst []byte) bool {
	pksLen := len(pks)

	if pksLen != len(messages) || pksLen == 0 {
		return false
	}

	g1Neg := new(bls12381.PointG1)
	g1Neg = bls12381.NewG1().Neg(g1Neg, chiabls.G1Generator())

	signature, err := bls12381.NewG2().FromCompressed(sig)
	if err != nil {
		return false
	}

	engine := bls12381.NewEngine()
	engine.AddPair(g1Neg, signature)

	for index, pk := range pks {
		p, err := bls12381.NewG1().FromCompressed(pk)
		if err != nil {
			return false
		}

		g2Map := bls12381.NewG2()
		message := messages[index]
		q, err := g2Map.HashToCurve(message, dst)
		if err != nil {
			return false
		}

		engine.AddPair(p, q)
	}
	return engine.Check()
}
