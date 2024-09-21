package pkcs7

import (
	"encoding/asn1"
	"errors"
	"signature/x509/pkix"
)

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional,explicit"`
}

const (
	// EncryptionAlgorithmDESCBC is the DES CBC encryption algorithm
	EncryptionAlgorithmDESCBC = iota

	// EncryptionAlgorithmAES128CBC is the AES 128 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES128CBC

	// EncryptionAlgorithmAES256CBC is the AES 256 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES256CBC

	// EncryptionAlgorithmAES128GCM is the AES 128 bits with GCM encryption algorithm
	EncryptionAlgorithmAES128GCM

	// EncryptionAlgorithmAES256GCM is the AES 256 bits with GCM encryption algorithm
	EncryptionAlgorithmAES256GCM
)

// ContentEncryptionAlgorithm determines the algorithm used to encrypt the
// plaintext message. Change the value of this variable to change which
// algorithm is used in the Encrypt() function.
var ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC, AES-CBC, and AES-GCM supported")

// ErrPSKNotProvided is returned when attempting to encrypt
// using a PSK without actually providing the PSK.
var ErrPSKNotProvided = errors.New("pkcs7: cannot encrypt content: PSK not provided")

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}
