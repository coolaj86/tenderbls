package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/dashpay/tenderdash/crypto/bls12381"
)

func main() {
	secret := []byte("it's a secret")
	message := []byte("Hello, World!")

	privKey := bls12381.GenPrivKeyFromSecret(secret)
	privStr := hex.EncodeToString(privKey)
	pubKey := privKey.PubKey()
	pubBytes := pubKey.Bytes()
	pubStr := hex.EncodeToString(pubBytes)

	fmt.Printf("\n")
	fmt.Printf("Secret: %q\n", secret)
	fmt.Printf("Private: %#v\n", privStr)
	fmt.Printf("Pub: %#v\n", pubStr)

	sigBytes, err := privKey.Sign(message)
	if err != nil {
		panic(err)
	}
	sigStr := hex.EncodeToString(sigBytes)

	fmt.Printf("\n")
	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Signature: %#v\n", sigStr)
	verify := pubKey.VerifySignature(message, sigBytes)
	if !verify {
		log.Fatal("bad signature using pubkey")
	}
	fmt.Printf("Verified: %#v\n", verify)

	fmt.Printf("\n")
}
