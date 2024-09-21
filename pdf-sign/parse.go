package pdf_sign

import (
	"errors"
	"log"
	"signature/x509"
	"signature/x509/pkix"

	pdfcpu "github.com/pdfcpu/pdfcpu/pkg/api"
	pdf "github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"golang.org/x/crypto/ocsp"
)

type RevocationInfo struct {
	Base16cert string
	Crls       []*pkix.CertificateList
	Ocsps      []*ocsp.Response
	Certs      []*x509.Certificate
}

// ExtractContext extracts the PDF context from the PDF found on the given path
func ExtractContext(path string) (*pdf.Context, error) {

	context, err := pdfcpu.ReadContextFile(path)
	if err != nil {
		return nil, err
	}
	return context, nil
}

// ExtractSignatureBytes accesses the RootDictionary of the PDF and extracts the pkcs7 signature object
func ExtractSignatureBytes(sigdict *pdf.Dict) ([]byte, error) {

	// Access "Contents" on the Signature Dictionary
	contents, found := sigdict.Find("Contents")
	if !found {
		return nil, errors.New("contents not found")
	}

	// Read signature bytes
	contentsHexLiteral := contents.(pdf.HexLiteral)

	signatureBytes, err := contentsHexLiteral.Bytes()
	if err != nil {
		return nil, err
	}

	log.Println("parse: found pkcs7 signature")

	//sigbytesstring := hex.EncodeToString(signatureBytes)
	//fmt.Println(" ****** Signature bytes string: ", sigbytesstring)

	return signatureBytes, nil
}

func ExtractSigDicts(context *pdf.Context) ([]pdf.Dict, error) {

	// Access Root Dictionary (pdf.Dict)
	rootdict := context.RootDict
	log.Println("parse: root dictionary found in pdf")

	// Access AcroForm Dictionary (pdf.Object)
	acroformobj, found := rootdict.Find("AcroForm")

	if !found {
		return nil, errors.New("acroform dictionary not found")
	}
	log.Println("parse: acroform dictionary found in pdf")

	// Cast acroformobj (which is pdf.Object or an indirect reference) to pdf.Dict, so we can search for "Fields"
	acroformdict, err := context.DereferenceDict(acroformobj)
	if err != nil {
		return nil, err
	}

	// Access Fields (array?)
	fields, found := acroformdict.Find("Fields")

	if !found {
		return nil, errors.New("fields not found in acroform dictionary")
	}

	// Resolve Fields reference
	fieldsarray, err := context.DereferenceArray(fields)
	if err != nil {
		return nil, errors.New("can't dereference fields array")
	}

	var sigdicts []pdf.Dict
	for _, field := range fieldsarray {

		indirectreference, ok := field.(pdf.IndirectRef)
		if !ok {
			return nil, errors.New("can't cast indirect reference")
		}

		dict, err := context.DereferenceDict(indirectreference)
		if err != nil {
			return nil, errors.New("can't dereference dictionary")
		}

		// Access V
		v, found := dict.Find("V")
		if !found {
			return nil, errors.New("v not found")
		}

		// Resolve V reference to get Signature Dictionary
		sigdict, err := context.DereferenceDict(v)
		if err != nil {
			return nil, errors.New("can't dereference Signature dictionary")
		}

		sigdicts = append(sigdicts, sigdict)
	}

	log.Println("parse: signature dictionary found in pdf")
	return sigdicts, nil
}
