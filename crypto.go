package unbound

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" // DNSSEC/NSEC3 compatibility.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
)

// DNSSEC primitives are implemented with the Go standard library. RSASHA1
// algorithms 5 and 7 and ED448 are unsupported. Unsupported DNSKEY algorithms
// are reported as such so Unbound can apply its normal insecure-delegation
// behavior.

// IANA DNS security algorithm numbers.
const (
	algRSASHA256       = 8
	algRSASHA512       = 10
	algECDSAP256SHA256 = 13
	algECDSAP384SHA384 = 14
	algED25519         = 15
)

func cryptoSupported(alg uint32) bool {
	switch alg {
	case algRSASHA256, algRSASHA512, algECDSAP256SHA256, algECDSAP384SHA384, algED25519:
		return true
	default:
		return false
	}
}

func cryptoVerify(alg uint32, key, data, sig []byte) bool {
	switch alg {
	case algRSASHA256, algRSASHA512:
		pub, ok := parseDNSKEYRSA(key)
		if !ok {
			return false
		}
		var hash crypto.Hash
		var digest []byte
		if alg == algRSASHA256 {
			h := sha256.Sum256(data)
			digest, hash = h[:], crypto.SHA256
		} else {
			h := sha512.Sum512(data)
			digest, hash = h[:], crypto.SHA512
		}
		return rsa.VerifyPKCS1v15(pub, hash, digest, sig) == nil
	case algECDSAP256SHA256:
		return verifyECDSA(elliptic.P256(), crypto.SHA256, key, data, sig, 32)
	case algECDSAP384SHA384:
		return verifyECDSA(elliptic.P384(), crypto.SHA384, key, data, sig, 48)
	case algED25519:
		return len(key) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(key), data, sig)
	default:
		return false
	}
}

// cryptoDigest computes the digest selected by a DS digest type number.
func cryptoDigest(alg uint32, data []byte) ([]byte, bool) {
	switch alg {
	case 1: // SHA-1
		h := sha1.Sum(data)
		return h[:], true
	case 2: // SHA-256
		h := sha256.Sum256(data)
		return h[:], true
	case 4: // SHA-384
		h := sha512.Sum384(data)
		return h[:], true
	case 5: // ABI-private SHA-512 selector; not a DS digest number.
		h := sha512.Sum512(data)
		return h[:], true
	default:
		return nil, false
	}
}

func nsec3Hash(salt []byte, iterations uint32, name []byte) ([]byte, bool) {
	if iterations > 1<<20 {
		return nil, false
	}
	b := make([]byte, 0, len(name)+len(salt))
	b = append(b, name...)
	b = append(b, salt...)
	h := sha1.Sum(b)
	for i := uint32(0); i < iterations; i++ {
		b = b[:0]
		b = append(b, h[:]...)
		b = append(b, salt...)
		h = sha1.Sum(b)
	}
	return h[:], true
}

// parseDNSKEYRSA parses the RSA public key wire format of RFC 3110: an
// exponent length (one byte, or zero followed by two), the exponent, and
// the modulus.
func parseDNSKEYRSA(key []byte) (*rsa.PublicKey, bool) {
	if len(key) < 3 {
		return nil, false
	}
	var elen, off int
	if key[0] != 0 {
		elen, off = int(key[0]), 1
	} else {
		elen, off = int(binary.BigEndian.Uint16(key[1:3])), 3
	}
	if elen == 0 || off+elen >= len(key) {
		return nil, false
	}
	e := new(big.Int).SetBytes(key[off : off+elen])
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, false
	}
	n := new(big.Int).SetBytes(key[off+elen:])
	if n.Sign() <= 0 {
		return nil, false
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, true
}

// verifyECDSA verifies the DNSKEY/RRSIG encoding of RFC 6605: the key is
// X || Y and the signature is r || s, each coordinate width bytes.
func verifyECDSA(curve elliptic.Curve, hash crypto.Hash, key, data, sig []byte, width int) bool {
	if len(key) != 2*width || len(sig) != 2*width {
		return false
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, append([]byte{4}, key...))
	if err != nil {
		return false
	}
	var digest []byte
	switch hash {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		digest = h[:]
	case crypto.SHA384:
		h := sha512.Sum384(data)
		digest = h[:]
	default:
		return false
	}
	r, s := new(big.Int).SetBytes(sig[:width]), new(big.Int).SetBytes(sig[width:])
	return ecdsa.Verify(pub, digest, r, s)
}
