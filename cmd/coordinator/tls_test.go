package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCert(t *testing.T, dir, cn string, mtime time.Time) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	cert, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.Chtimes(cert, mtime, mtime)
	return cert, keyFile
}

func TestTLSCertReload(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir, "one.example", time.Now().Add(-time.Hour))
	cfg, err := tlsSetup("", "", cert, key, dir)
	if err != nil || cfg == nil {
		t.Fatalf("tlsSetup = %v, %v", cfg, err)
	}
	cn := func() string {
		c, err := cfg.GetCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		return leaf.Subject.CommonName
	}
	if got := cn(); got != "one.example" {
		t.Fatalf("serving %s", got)
	}
	writeCert(t, dir, "two.example", time.Now())
	if got := cn(); got != "two.example" {
		t.Fatalf("after renewal serving %s", got)
	}
	// A half-written file keeps the old certificate in service.
	_ = os.WriteFile(cert, []byte("garbage"), 0o600)
	_ = os.Chtimes(cert, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	if got := cn(); got != "two.example" {
		t.Fatalf("with a broken file serving %s", got)
	}

	if _, err := tlsSetup("a.example", "", cert, key, dir); err == nil {
		t.Fatal("accepted both --tls-domains and --tls-cert")
	}
	if cfg, _ := tlsSetup("", "", "", "", dir); cfg != nil {
		t.Fatal("TLS enabled without configuration")
	}
	if cfg, err := tlsSetup("mesh.example", "", "", "", dir); err != nil || cfg.GetCertificate == nil {
		t.Fatalf("ACME setup = %v, %v", cfg, err)
	}
}
