package unbound

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestCryptoPolicyAndHashes(t *testing.T) {
	if cryptoSupported(5) || !cryptoSupported(8) || cryptoSupported(16) {
		t.Fatal("unexpected algorithm policy")
	}
	got, ok := cryptoDigest(2, []byte("abc"))
	if !ok || len(got) != 32 {
		t.Fatal("SHA-256 digest failed")
	}
	h, ok := nsec3Hash(nil, 0, []byte{0})
	if !ok {
		t.Fatal("NSEC3 hash failed")
	}
	want := sha1.Sum([]byte{0})
	if string(h) != string(want[:]) {
		t.Fatal("NSEC3 mismatch")
	}
}

func TestCryptoRSAAndEd25519(t *testing.T) {
	msg := []byte("dnssec canonical rrset")
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	e := priv.PublicKey.E
	eb := make([]byte, 4)
	binary.BigEndian.PutUint32(eb, uint32(e))
	for len(eb) > 1 && eb[0] == 0 {
		eb = eb[1:]
	}
	key := append([]byte{byte(len(eb))}, eb...)
	key = append(key, priv.PublicKey.N.Bytes()...)
	if !cryptoVerify(8, key, msg, sig) {
		t.Fatal("RSA/SHA-256 verify failed")
	}
	sig[0] ^= 1
	if cryptoVerify(8, key, msg, sig) {
		t.Fatal("accepted bad RSA signature")
	}
	pub, edpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edsig := ed25519.Sign(edpriv, msg)
	if !cryptoVerify(15, pub, msg, edsig) {
		t.Fatal("Ed25519 verify failed")
	}
	edsig[0] ^= 1
	if cryptoVerify(15, pub, msg, edsig) {
		t.Fatal("accepted bad Ed25519 signature")
	}
}
