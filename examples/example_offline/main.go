package main

import (
	"errors"
	"fmt"
	"github.com/Cryptolens/cryptolens-golang/cryptolens"
	"io/ioutil"
	"time"
)

func ActivateAndSaveLicenseKey() (string, error) {
	token := "WyI0NjUiLCJBWTBGTlQwZm9WV0FyVnZzMEV1Mm9LOHJmRDZ1SjF0Vk52WTU0VzB2Il0="
	publicKey := "<RSAKeyValue><Modulus>khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

	licenseKey, err := cryptolens.KeyActivate(token, cryptolens.KeyActivateArguments{
		ProductId:   3646,
		Key:         "MPDWY-PQAOW-FKSCH-SGAAU",
		MachineCode: "289jf2afs3",
	})
	if err != nil || !licenseKey.HasValidSignature(publicKey) {
		return "", errors.New("Initial license key activation failed")
	}

	serialized, err := licenseKey.ToBytes()
	if err != nil {
		return "", err
	}

	f, err := ioutil.TempFile("", "cryptolens_example_offline_")
	if err != nil {
		return "", err
	}
	defer f.Close()

	_, err = f.Write(serialized)
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}

func main() {
	filename, err := ActivateAndSaveLicenseKey()
	if err != nil {
		fmt.Println("Failed to activate or save license key")
		return
	}

	fmt.Printf("License key saved to file %s\n\n", filename)

	savedKeyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Failed to read saved license key")
		return
	}

	licenseKey, err := cryptolens.KeyFromBytes(savedKeyBytes)
	if err != nil || !licenseKey.HasValidSignature(publicKey) {
		fmt.Println("Error in saved license key")
		return
	}

	fmt.Printf("License key sucessfully loaded from file!\n")

	if time.Now().After(licenseKey.Expires) {
		fmt.Println("License key has expired")
		return
	}

	if licenseKey.F1 {
		fmt.Println("Welcome! Pro version enabled!")
	} else {
		fmt.Println("Welcome!")
	}

}
