// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestLocalTrustBindsAuthorityAndExpiry(t *testing.T) {
	now := time.Now()
	identity, e := LocalIdentity("localhost", now)
	if e != nil {
		t.Fatal(e)
	}
	tls, e := TLSWithCA([]byte(identity.CA))
	if e != nil || tls.InsecureSkipVerify {
		t.Fatalf("trust: %v", e)
	}
	block, _ := pem.Decode([]byte(identity.Certificate))
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	if len(cert.AuthorityKeyId) == 0 {
		t.Fatal("issued server certificate lacks the authority key identifier required by strict stock clients")
	}
	if _, e = cert.Verify(x509.VerifyOptions{Roots: tls.RootCAs, DNSName: "localhost", CurrentTime: now}); e != nil {
		t.Fatal(e)
	}
	for _, o := range []x509.VerifyOptions{{Roots: tls.RootCAs, DNSName: "other.example", CurrentTime: now}, {Roots: tls.RootCAs, DNSName: "localhost", CurrentTime: now.Add(31 * 24 * time.Hour)}, {Roots: x509.NewCertPool(), DNSName: "localhost", CurrentTime: now}} {
		if _, e = cert.Verify(o); e == nil {
			t.Fatal("wrong authority, expiry or trust accepted")
		}
	}
	if _, e = LocalIdentity("registry.example", now); e == nil {
		t.Fatal("local issuer accepted network hostname")
	}
	if _, e = TLSWithCA([]byte("not a certificate")); e == nil {
		t.Fatal("empty trust accepted")
	}
}
