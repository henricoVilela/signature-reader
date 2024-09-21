package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	pdf_sign "signature/pdf-sign"
	pkcs7 "signature/pkcs7"
	"time"

	pdf "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
)

// The SignedPdf type holds all relevant information for signature verification
type SignedPdf struct {

	// Content represents the signed content in the pdf
	Content []byte

	// ByteRange defines the portion of the pdf which is signed
	ByteRange pdf.Array

	// IsTimestampOnly is true if the pdf is only timestamped but not signed
	IsTimestampOnly bool

	// Signature is the pkcs7 object holding the signature (PAdES signature)
	Signature *pkcs7.PKCS7

	// Timetamp is the pkcs7 object holding the timestamp (CAdES signature)
	Timestamp *pkcs7.PKCS7

	// SigningTime is the signed time signed holded by the timestamp
	SigningTime time.Time

	// RevocationInfo holds the revocation information embedded in the pkcs7
	RevocationInfo pdf_sign.RevocationInfo

	// ValidationInfo holds the revocation information associated with all signatures
	ValidationInfo pdf_sign.RevocationInfo
}

type CertInfo struct {
	Emails []string
	Name   string
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Uso: go run main.go <caminho-do-arquivo>")
		return
	}

	// Caminho do arquivo PDF
	pdfPath := os.Args[1]

	var t string
	_, err := Init(pdfPath, t)
	if err != nil {
		log.Fatalf("Erro ao extrair o contexto do PDF: %v", err)
	}
}

func listarAssinaturas(context *pdf.Context) ([]CertInfo, error) {
	sigdicts, err := pdf_sign.ExtractSigDicts(context)
	if err != nil {
		return nil, errors.New("não possui dicionário de assinaturas")
	}

	var certs []CertInfo
	for _, sig := range sigdicts {

		signatureBytes, err := pdf_sign.ExtractSignatureBytes(&sig)
		if err != nil {
			return nil, err
		}

		signature, err := pkcs7.Parse(signatureBytes)
		if err != nil {
			return nil, err
		}

		if signature != nil && len(signature.Certificates) > 0 {
			certs = append(certs, CertInfo{Emails: signature.Certificates[0].EmailAddresses, Name: signature.Certificates[0].Subject.CommonName})
		}
	}

	return certs, nil
}

func Init(filepath string, trustedAnchorsPem string) (SignedPdf, error) {

	var mypdf SignedPdf

	// Extract pdf context
	context, err := pdf_sign.ExtractContext(filepath)
	if err != nil {
		return mypdf, err
	}

	certs, err := listarAssinaturas(context)
	if err != nil {
		return mypdf, err
	}

	log.Println("Assinantes: ", certs)

	return mypdf, nil
}
