// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

type LocalTLS struct{ CA, Certificate, Key, Fingerprint string }

// LocalIdentity issues only for the loopback evaluation authority. The signing
// key is not retained; network deployments use operator-managed PKI.
func LocalIdentity(host string, now time.Time) (LocalTLS, error) {
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return LocalTLS{}, errors.New("generated TLS identity requires localhost or a literal loopback address")
	}
	issuerKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return LocalTLS{}, e
	}
	serverKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return LocalTLS{}, e
	}
	serial := func() (*big.Int, error) {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e == nil {
			n.Add(n, big.NewInt(1))
		}
		return n, e
	}
	caSerial, e := serial()
	if e != nil {
		return LocalTLS{}, e
	}
	leafSerial, e := serial()
	if e != nil {
		return LocalTLS{}, e
	}
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "cratectl local installation CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &issuerKey.PublicKey, issuerKey)
	if e != nil {
		return LocalTLS{}, e
	}
	// Parsing recovers the generated subject key identifier so the issued leaf
	// carries an authority key identifier accepted by strict native clients.
	ca, e = x509.ParseCertificate(caDER)
	if e != nil {
		return LocalTLS{}, e
	}
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: host}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, issuerKey)
	if e != nil {
		return LocalTLS{}, e
	}
	key, e := x509.MarshalPKCS8PrivateKey(serverKey)
	if e != nil {
		return LocalTLS{}, e
	}
	fingerprint := sha256.Sum256(caDER)
	return LocalTLS{CA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})), Fingerprint: hex.EncodeToString(fingerprint[:])}, nil
}
func TLSWithCA(data []byte) (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file contains no trusted certificates")
	}
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}
