package x509

import (
	"encoding/asn1"
)

// An OID represents an ASN.1 OBJECT IDENTIFIER.
type OID struct {
	der []byte
}

func newOIDFromDER(der []byte) (OID, bool) {
	if len(der) == 0 || der[len(der)-1]&0x80 != 0 {
		return OID{}, false
	}

	start := 0
	for i, v := range der {
		// ITU-T X.690, section 8.19.2:
		// The subidentifier shall be encoded in the fewest possible octets,
		// that is, the leading octet of the subidentifier shall not have the value 0x80.
		if i == start && v == 0x80 {
			return OID{}, false
		}
		if v&0x80 == 0 {
			start = i + 1
		}
	}

	return OID{der}, true
}

func (oid OID) toASN1OID() (asn1.ObjectIdentifier, bool) {
	out := make([]int, 0, len(oid.der)+1)

	const (
		valSize         = 31 // amount of usable bits of val for OIDs.
		bitsPerByte     = 7
		maxValSafeShift = (1 << (valSize - bitsPerByte)) - 1
	)

	val := 0

	for _, v := range oid.der {
		if val > maxValSafeShift {
			return nil, false
		}

		val <<= bitsPerByte
		val |= int(v & 0x7F)

		if v&0x80 == 0 {
			if len(out) == 0 {
				if val < 80 {
					out = append(out, val/40)
					out = append(out, val%40)
				} else {
					out = append(out, 2)
					out = append(out, val-80)
				}
				val = 0
				continue
			}
			out = append(out, val)
			val = 0
		}
	}

	return out, true
}
