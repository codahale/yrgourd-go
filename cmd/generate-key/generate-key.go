package main

import (
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("private key: %s\n", hex.EncodeToString(dk.Bytes()))
	fmt.Printf("public key: %s\n", hex.EncodeToString(dk.EncapsulationKey().Bytes()))
}
