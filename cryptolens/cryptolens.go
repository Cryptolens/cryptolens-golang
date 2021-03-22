// Package cryptolens provides support for communicating with the Cryptolens Web API.
package cryptolens

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// LicenseKey represents a license key object returned by the Cryptolens Web API.
type LicenseKey struct {
	// ProductId is the id of the product that this license key belongs to.
	ProductId int

	// Id is the id of the license key, within the product it belongs to. C.f.
	// the GlobalId field.
	Id int

	// Key is the license key string, eg. ABCDE-EFGHI-JKLMO-PQRST.
	Key string

	// Created is the creation date of the license key.
	Created time.Time

	// Expires is the expiration date of the license key. Note, it's optional
	// and it's up to your program to interpret this field. See also
	// https://help.cryptolens.io/web-interface/keys-that-dont-expire
	Expires time.Time

	// Period is the duration of current license cycle counted in days.
	Period int

	// F1 is the value of feature 1 of the license key.
	F1 bool

	// F2 is the value of feature 2 of the license key.
	F2 bool

	// F3 is the value of feature 3 of the license key.
	F3 bool

	// F4 is the value of feature 4 of the license key.
	F4 bool

	// F5 is the value of feature 5 of the license key.
	F5 bool

	// F6 is the value of feature 6 of the license key.
	F6 bool

	// F7 is the value of feature 7 of the license key.
	F7 bool

	// F8 is the value of feature 8 of the license key.
	F8 bool

	// Notes is the notes field of the license key.
	Notes string

	// Block indicates wheather the key is blocked.
	Block bool

	// GlobalId is a unique identifier for the license key.
	GlobalId int64

	// Customer is the entire customer object assigned to this license key.
	Customer Customer

	// ActivatedMachines contain information about the currently activated
	// machines/devices for this license key.
	ActivatedMachines []ActivationData

	// TrialActivation indicates if trial activation is enabled. For more
	// information, see https://help.cryptolens.io/web-interface/trial-activation
	TrialActivation bool

	// MaxNoOfMachines is the maximum number of machines/devices that may
	// activate this license. A value of 0 indicates that the key may be
	// activated on an unlimited number of machines/devices.
	MaxNoOfMachines int

	// AllowedMachines contains the machine codes of those devices that will
	// be prioritized during activation. Even if the limit is achieved, these
	// devices will still be activated.
	AllowedMachines []string

	// DataObjects is the data objects that belong to this key.
	DataObjects []DataObject

	// SignDate is the time when the response was cryptographically signed by
	// the Cryptolens Web API.
	SignDate time.Time

	licenseKeyBytes []byte
	signatureBytes  []byte
}

// Customer describes an individual customer. The existing customers can be shown
// on https://app.cryptolens.io/Customer when logged in.
type Customer struct {
	// Id is a unique identifier for the customer.
	Id int

	// Name is the name of the customer.
	Name string

	// Email is the email of the customer.
	Email string

	// CompanyName is the company name for this customer.
	CompanyName string

	// Created is the creation time for this customer.
	Created time.Time
}

// ActivationData contain information about a particular activated device for a license key.
type ActivationData struct {
	// Mid is the machine code or machine identifier for this activation.
	Mid string

	// IP is the ip address that this device was first activated from.
	IP string

	// Time is the time when this device was first activated.
	Time time.Time
}

// DataObject represents a single data object.
type DataObject struct {
	// Id is a unique identifier for the data object.
	Id int

	// Name is the name of the data object.
	Name string

	// StringValue is the string payload belonging to the data object.
	StringValue string

	// IntValue is the integer payload belonging to the data object.
	IntValue int
}

type activateResponse struct {
	LicenseKey string `json:"licenseKey"`
	Signature  string `json:"signature"`
	Result     int    `json:"result"`
	Message    string `json:"message"`
}

// HasValidSignature verifies the cryptographic signature of the license key
// against publicKey. This makes sure that the license key has not been
// tampered with since it was signed by the server.
//
// The argument publicKey should contain XML and be on similar format to:
//
//	<RSAKeyValue><Modulus>AbC=</Modulus><Exponent>deFG</Exponent></RSAKeyValue>
//
// The public key is unique for each account and can be found on cryptolens.io
// under "Account Settings", which is located in the personal menu
// ("Hello, <account name>!" in the upper right corner).
func (licenseKey *LicenseKey) HasValidSignature(publicKey string) bool {
	type RSAKeyValue struct {
		Modulus  string
		Exponent string
	}
	var k RSAKeyValue
	err := xml.Unmarshal([]byte(publicKey), &k)
	if err != nil {
		return false
	}

	modulusBytes, err := base64.StdEncoding.DecodeString(k.Modulus)
	if err != nil {
		return false
	}

	exponentBytes, err := base64.StdEncoding.DecodeString(k.Exponent)
	if err != nil {
		return false
	}

	modulus := big.NewInt(0).SetBytes(modulusBytes)
	exponent := big.NewInt(0).SetBytes(exponentBytes)

	if !exponent.IsInt64() {
		return false
	}
	key := rsa.PublicKey{N: modulus, E: int(exponent.Int64())}

	hashed := sha256.Sum256(licenseKey.licenseKeyBytes)
	err = rsa.VerifyPKCS1v15(&key, crypto.SHA256, hashed[:], licenseKey.signatureBytes)

	return err == nil
}

// ToBytes returns a byte representation of the license key. This representation
// can for example be stored in a file. The representation contains the
// cryptographic signature for the license key. Thus when reading the byte
// representation again, it is possile to check that the license key has not
// been tampered with.
func (licenseKey *LicenseKey) ToBytes() ([]byte, error) {
	licenseKeyBase64 := base64.StdEncoding.EncodeToString(licenseKey.licenseKeyBytes)
	signatureBase64 := base64.StdEncoding.EncodeToString(licenseKey.signatureBytes)

	temp := activateResponse{
		LicenseKey: licenseKeyBase64,
		Signature:  signatureBase64,
		Result:     0,
		Message:    "",
	}

	return json.Marshal(temp)
}

// UnmarshalJSON is part of the Unmarshaler interface used by the "encoding/json"
// package in the standard library.
func (licenseKey *LicenseKey) UnmarshalJSON(b []byte) error {
	var temp struct {
		ProductId         int
		Id                int
		Key               string
		Created           int64
		Expires           int64
		Period            int
		F1                bool
		F2                bool
		F3                bool
		F4                bool
		F5                bool
		F6                bool
		F7                bool
		F8                bool
		Notes             string
		Block             bool
		GlobalId          int64
		Customer          Customer
		ActivatedMachines []ActivationData
		TrialActivation   bool
		MaxNoOfMachines   int
		AllowedMachines   string
		DataObjects       []DataObject
		SignDate          int64
	}

	err := json.Unmarshal(b, &temp)
	if err != nil {
		return err
	}

	licenseKey.ProductId = temp.ProductId
	licenseKey.Id = temp.Id
	licenseKey.Key = temp.Key
	licenseKey.Created = time.Unix(temp.Created, 0)
	licenseKey.Expires = time.Unix(temp.Expires, 0)
	licenseKey.Period = temp.Period
	licenseKey.F1 = temp.F1
	licenseKey.F2 = temp.F2
	licenseKey.F3 = temp.F3
	licenseKey.F4 = temp.F4
	licenseKey.F5 = temp.F5
	licenseKey.F6 = temp.F6
	licenseKey.F7 = temp.F7
	licenseKey.F8 = temp.F8
	licenseKey.Notes = temp.Notes
	licenseKey.Block = temp.Block
	licenseKey.GlobalId = temp.GlobalId
	licenseKey.Customer = temp.Customer
	licenseKey.ActivatedMachines = temp.ActivatedMachines
	licenseKey.TrialActivation = temp.TrialActivation
	licenseKey.MaxNoOfMachines = temp.MaxNoOfMachines
	licenseKey.AllowedMachines = strings.Split(temp.AllowedMachines, "\n")
	licenseKey.DataObjects = temp.DataObjects
	licenseKey.SignDate = time.Unix(temp.SignDate, 0)

	return nil
}

// UnmarshalJSON is part of the Unmarshaler interface used by the "encoding/json"
// package in the standard library.
func (customer *Customer) UnmarshalJSON(b []byte) error {
	var temp struct {
		Id          int
		Name        string
		Email       string
		CompanyName string
		Created     int64
	}

	err := json.Unmarshal(b, &temp)
	if err != nil {
		return err
	}

	customer.Id = temp.Id
	customer.Name = temp.Name
	customer.Email = temp.Email
	customer.CompanyName = temp.CompanyName
	customer.Created = time.Unix(temp.Created, 0)

	return nil
}

// UnmarshalJSON is part of the Unmarshaler interface used by the "encoding/json"
// package in the standard library.
func (activationData *ActivationData) UnmarshalJSON(b []byte) error {
	var temp struct {
		Mid  string
		IP   string
		Time int64
	}

	err := json.Unmarshal(b, &temp)
	if err != nil {
		return err
	}

	activationData.Mid = temp.Mid
	activationData.IP = temp.IP
	activationData.Time = time.Unix(temp.Time, 0)

	return nil
}

// KeyActivateArguments contains extra and optional arguments for the KeyActivate
// function.
type KeyActivateArguments struct {
	// ProductId is the id of the product which the key belongs to
	ProductId int

	// Key is the license key string, e.g. ABCD-1234-DCBA-4321
	Key string

	// MachineCode is a unique identifier for the current device
	MachineCode string

	// FieldsToReturn control which fields of the license key that is returned.
	// See https://app.cryptolens.io/docs/api/v3/Activate for more details.
	FieldsToReturn int

	// FloatingTimeInterval sets the interval when using floating licensing.
	// The default value of 0 disables floating activation.
	// See https://app.cryptolens.io/docs/api/v3/Activate for more details.
	FloatingTimeInterval int

	// MaxOverdraft is the maximum number of overdraft devices that can be
	// active. The default value of 0 disables overdraft devices.
	// See https://app.cryptolens.io/docs/api/v3/Activate for more details.
	MaxOverdraft int
}

// KeyActivate performs a request to the key method Activate in Cryptolens Web API 3.
// The parameter token is an access token and args is a struct with additional
// parameters, some of which are optional. See KeyActivateArguments for more
// information.
//
// Note that KeyActivate does not check the cryptographic signature of the
// returned response, or any other information such as the expiration field.
// Checking the cryptographic signature can be done using the HasValidSignature()
// method.
func KeyActivate(token string, args KeyActivateArguments) (LicenseKey, error) {
	activateResponse, err := makeActivateRequest(token, args)
	if err != nil {
		return LicenseKey{}, err
	}

	licenseKeyBytes, signatureBytes, err := parseActivateResponse(&activateResponse)
	if err != nil {
		return LicenseKey{}, err
	}

	return buildLicenseKey(licenseKeyBytes, signatureBytes)
}

// KeyFromBytes takes a byte slice and attempts to parse this into a LicenseKey.
// This function does not check the cryptographic signature or attempt to verify
// any other information on the resulting LicenseKey. Checking the cryptographic
// signature can be done using the HasValidSignature() method on the license key.
func KeyFromBytes(b []byte) (LicenseKey, error) {
	var r activateResponse
	err := json.Unmarshal(b, &r)
	if err != nil {
		return LicenseKey{}, err
	}

	licenseKeyBytes, signatureBytes, err := parseActivateResponse(&r)
	if err != nil {
		return LicenseKey{}, err
	}

	return buildLicenseKey(licenseKeyBytes, signatureBytes)
}

func makeActivateRequest(token string, args KeyActivateArguments) (activateResponse, error) {
	var http http.Client

	// From KeyActivateArguments struct
	data := url.Values{}
	data.Add("token", token)
	data.Add("ProductId", strconv.Itoa(args.ProductId))
	data.Add("Key", args.Key)
	data.Add("MachineCode", args.MachineCode)
	data.Add("FieldsToReturn", strconv.Itoa(args.FieldsToReturn))
	data.Add("FloatingTimeInterval", strconv.Itoa(args.FloatingTimeInterval))
	data.Add("MaxOverdraft", strconv.Itoa(args.MaxOverdraft))

	// Hardcoded by the library
	data.Add("Sign", "true")
	data.Add("SignMethod", "1")

	response, err := http.PostForm("https://app.cryptolens.io/api/key/Activate", data)
	if err != nil {
		return activateResponse{}, err
	}

	dec := json.NewDecoder(response.Body)
	var r activateResponse
	err = dec.Decode(&r)
	if err != nil {
		return activateResponse{}, err
	}

	return r, nil
}

func parseActivateResponse(response *activateResponse) ([]byte, []byte, error) {
	licenseKeyBytes, err := base64.StdEncoding.DecodeString(response.LicenseKey)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	return licenseKeyBytes, signatureBytes, nil
}

func buildLicenseKey(licenseKeyBytes []byte, signatureBytes []byte) (LicenseKey, error) {
	var k LicenseKey
	err := json.Unmarshal(licenseKeyBytes, &k)
	if err != nil {
		return LicenseKey{}, err
	}

	k.licenseKeyBytes = licenseKeyBytes
	k.signatureBytes = signatureBytes

	return k, nil
}
