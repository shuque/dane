// Package danetest provides certificate-generation helpers for tests.
// It must not import package dane.
package danetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// CertOpts controls generated certificates.
type CertOpts struct {
	DNSNames    []string
	ExtKeyUsage []x509.ExtKeyUsage // nil = no EKU extension
	NotBefore   time.Time          // zero = now-1h
	NotAfter    time.Time          // zero = now+24h
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func create(t testing.TB, tmpl, parent *x509.Certificate, parentKey crypto.Signer, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	if parentKey == nil {
		parentKey = key
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func leafTemplate(t testing.TB, o CertOpts) *x509.Certificate {
	nb, na := o.NotBefore, o.NotAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(24 * time.Hour)
	}
	cn := "test"
	if len(o.DNSNames) > 0 {
		cn = o.DNSNames[0]
	}
	return &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  o.ExtKeyUsage,
		DNSNames:     o.DNSNames,
	}
}

// NewCA creates a self-signed CA certificate.
func NewCA(t testing.TB, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return create(t, tmpl, nil, nil, key), key
}

// NewLeaf creates an end-entity certificate signed by issuer.
func NewLeaf(t testing.TB, issuer *x509.Certificate, issuerKey crypto.Signer, opts CertOpts) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key := newKey(t)
	return create(t, leafTemplate(t, opts), issuer, issuerKey, key), key
}

// NewSelfSigned creates a self-signed end-entity certificate.
func NewSelfSigned(t testing.TB, opts CertOpts) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key := newKey(t)
	return create(t, leafTemplate(t, opts), nil, nil, key), key
}
