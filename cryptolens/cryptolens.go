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

type LicenseKey struct {
	ProductId         int
	Id                int
	Key               string
	Created           time.Time
	Expires           time.Time
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
	AllowedMachines   []string
	DataObjects       []DataObject
	SignDate          time.Time

	licenseKeyBytes []byte
	signatureBytes  []byte
}

type Customer struct {
	Id          int
	Name        string
	Email       string
	CompanyName string
	Created     time.Time
}

type ActivationData struct {
	Mid  string
	IP   string
	Time time.Time
}

type DataObject struct {
	Id          int
	Name        string
	StringValue string
	IntValue    int
}

type activateResponse struct {
	LicenseKey string `json:"licenseKey"`
	Signature  string `json:"signature"`
	Result     int    `json:"result"`
	Message    string `json:"message"`
}

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

type KeyActivateArguments struct {
	ProductId            int
	Key                  string
	MachineCode          string
	FieldsToReturn       int
	FloatingTimeInterval int
	MaxOverdraft         int
}

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
