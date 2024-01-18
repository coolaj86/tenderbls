package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	blsbasic "github.com/dashpay/tenderdash/blsbasic"

	chiabls "github.com/chuwt/chia-bls-go"
)

func main() {
	secret := []byte("it's a secret")
	message := []byte("Hello, World!")

	seed := sha256.Sum256(secret)
	privKey := chiabls.KeyGen(seed[:])
	pubKey := privKey.GetPublicKey()
	privBytes := privKey.Bytes()
	pubBytes := pubKey.Bytes()
	privStr := hex.EncodeToString(privBytes)
	pubStr := hex.EncodeToString(pubBytes)

	fmt.Printf("Secret: %q\n", secret)
	fmt.Printf("Private: %#v\n", privStr)
	fmt.Printf("Pub: %#v\n", pubStr)

	scheme := blsbasic.New()

	sigBytes := scheme.Sign(&privKey, message)
	sigStr := hex.EncodeToString(sigBytes)

	fmt.Printf("\n")
	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Signature: %#v\n", sigStr)
	verify := scheme.Verify(&pubKey, message, sigBytes)
	if !verify {
		log.Fatal("bad signature using pubkey")
	}
	fmt.Printf("Verified: %#v\n", verify)

	fmt.Printf("\n")
}
