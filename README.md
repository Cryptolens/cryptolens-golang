# Cryptolens Licensing for Golang

This library serves to simplify communication with Cryptolens Web API (https://app.cryptolens.io/docs/api).

> **Note**: an updated version of the library (with support for offline activation) can be found in the [go_mod branch](https://github.com/cryptolens/cryptolens-golang/tree/go_mod).

In order to get started with the library, start by

```
go get github.com/Cryptolens/cryptolens-golang/cryptolens
```

Now we can use the library in our code. A working example of the following can be found
in the `examples/example_activate` directory.

We start by importing the library with:

```golang
import "github.com/Cryptolens/cryptolens-golang/cryptolens"
```

Now we can activate a license key as follows:

```golang
token := "WyI0NjUiLCJBWTBGTlQwZm9WV0FyVnZzMEV1Mm9LOHJmRDZ1SjF0Vk52WTU0VzB2Il0="
publicKey := "<RSAKeyValue><Modulus>khbyu3/vAEBHi339fTuo2nUaQgSTBj0jvpt5xnLTTF35FLkGI+5Z3wiKfnvQiCLf+5s4r8JB/Uic/i6/iNjPMILlFeE0N6XZ+2pkgwRkfMOcx6eoewypTPUoPpzuAINJxJRpHym3V6ZJZ1UfYvzRcQBD/lBeAYrvhpCwukQMkGushKsOS6U+d+2C9ZNeP+U+uwuv/xu8YBCBAgGb8YdNojcGzM4SbCtwvJ0fuOfmCWZvUoiumfE4x7rAhp1pa9OEbUe0a5HL+1v7+JLBgkNZ7Z2biiHaM6za7GjHCXU8rojatEQER+MpgDuQV3ZPx8RKRdiJgPnz9ApBHFYDHLDzDw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

licenseKey, err := cryptolens.KeyActivate(token, cryptolens.KeyActivateArguments{
	ProductId:   3646,
	Key:         "MPDWY-PQAOW-FKSCH-SGAAU",
	MachineCode: "289jf2afs3",
})
if err != nil || !licenseKey.HasValidSignature(publicKey) {
	fmt.Println("License key activation failed!")
	return
}
```

In order to use the code above with your account on cryptolens.io you need to change the
constants as follows:

 1. The `token` need to be changed to a valid access token for your account. Access tokens can be created at
    https://app.cryptolens.io/User/AccessToken/. In order to be able to use the `KeyActivate()` function
    the token needs to have the `Activate` scope.
 1. The correct value for `publicKey` for your account can be found when logged in on Cryptolens.io from
    the menu in the top-right corner ("Hello <username>!") and then *Security Settings*. Copy paste the
    value from the *Public key* field.
 1. The `ProductId` can be found at the page for the corresponding product at https://app.cryptolens.io/Product.
 1. The `Key` is the license key string, and would in most cases be entered by the user of the application
    in some application dependent manner.
 1. The `MachineCode` is an optional argument allowing you to provide an identifier for which
    device the application is running on, or something with a similar purpuse.

Finally, additional properties of the license key can be checked if desired:

```golang
fmt.Printf("License key for product with id: %d\n", licenseKey.ProductId)

if time.Now().After(licenseKey.Expires) {
	fmt.Println("License key has expired")
	return
}

if licenseKey.F1 {
	fmt.Println("Welcome! Pro version enabled!")
} else {
	fmt.Println("Welcome!")
}
```

## Examples

* [Key verification example](https://github.com/Cryptolens/cryptolens-golang/blob/master/examples/example_activate/main.go)
* [Offline verification example](https://github.com/Cryptolens/cryptolens-golang/blob/master/examples/example_offline/main.go)
